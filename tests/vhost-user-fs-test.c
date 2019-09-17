/* SPDX-License-Identifer: GPL-2.0-or-later */
/*
 * vhost-user-fs device test
 *
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/iov.h"
#include "standard-headers/linux/virtio_fs.h"
#include "standard-headers/linux/fuse.h"
#include "libqos/virtio-fs.h"
#include "libqtest-single.h"

#define TIMEOUT_US (30 * 1000 * 1000)

#ifdef HOST_WORDS_BIGENDIAN
static const bool host_is_big_endian = true;
#else
static const bool host_is_big_endian; /* false */
#endif

/*
 * This macro skips tests when run in a cross-endian configuration.
 * virtiofsd does not byte-swap FUSE messages and therefore does not support
 * cross-endian.
 */
#define SKIP_TEST_IF_CROSS_ENDIAN() { \
    if (host_is_big_endian != qtest_big_endian(global_qtest)) { \
        g_test_skip("cross-endian is not supported by virtiofsd yet"); \
        return; \
    } \
}

static char *socket_path;
static char *shared_dir;

static bool remove_dir_and_children(const char *path)
{
    GDir *dir;
    const gchar *name;

    dir = g_dir_open(path, 0, NULL);
    if (!dir) {
        return false;
    }

    while ((name = g_dir_read_name(dir)) != NULL) {
        g_autofree gchar *child = g_strdup_printf("%s/%s", path, name);

        g_test_message("unlinking %s", child);

        if (unlink(child) == -1 && errno == EISDIR) {
            remove_dir_and_children(child);
        }
    }

    g_dir_close(dir);

    g_test_message("rmdir %s", path);
    return rmdir(path) == 0;
}

static void after_test(void *arg G_GNUC_UNUSED)
{
    unlink(socket_path);

    remove_dir_and_children(shared_dir);

    /*
     * Both QEMU and virtiofsd need to be restarted after each test and the
     * shared directory will be recreated.  This ensures isolation between test
     * runs.
     */
    qos_invalidate_command_line();
}

/* Called on SIGABRT */
static void abrt_handler(void *arg G_GNUC_UNUSED)
{
    after_test(NULL);
}

static int create_socket(const char *path)
{
    union {
        struct sockaddr sa;
        struct sockaddr_un un;
    } sa;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        g_test_message("socket failed (errno=%d)", errno);
        abort();
    }

    unlink(path); /* in case it already exists */

    sa.un.sun_family = AF_UNIX;
    snprintf(sa.un.sun_path, sizeof(sa.un.sun_path), "%s", path);

    if (bind(fd, &sa.sa, sizeof(sa.un)) < 0) {
        g_test_message("bind failed (errno=%d)", errno);
        abort();
    }

    if (listen(fd, 1) < 0) {
        g_test_message("listen failed (errno=%d)", errno);
        abort();
    }

    return fd;
}

static const char *qtest_virtiofsd(void)
{
    const char *virtiofsd_binary;

    virtiofsd_binary = getenv("QTEST_VIRTIOFSD");
    if (!virtiofsd_binary) {
        fprintf(stderr, "Environment variable QTEST_VIRTIOFSD required\n");
        exit(1);
    }

    return virtiofsd_binary;
}

/* Launch virtiofsd before each test with an empty shared directory */
static void *before_test(GString *cmd_line G_GNUC_UNUSED, void *arg)
{
    g_autofree char *command = NULL;
    char *virtiofsd_path;
    int fd;
    pid_t pid;

    fd = create_socket(socket_path);

    if (mkdir(shared_dir, 0777) < 0) {
        g_message("mkdir failed (errno=%d)", errno);
        abort();
    }

    virtiofsd_path = realpath(qtest_virtiofsd(), NULL);
    g_assert_nonnull(virtiofsd_path);

    command = g_strdup_printf("exec %s --fd=%d -o source=%s",
                              virtiofsd_path,
                              fd,
                              shared_dir);
    free(virtiofsd_path);
    g_test_message("starting virtiofsd: %s", command);

    /* virtiofsd terminates when QEMU closes the vhost-user socket connection,
     * so there is no need to kill it explicitly later on.
     */
    pid = fork();
    g_assert_cmpint(pid, >=, 0);
    if (pid == 0) {
        execlp("/bin/sh", "sh", "-c", command, NULL);
        exit(1);
    }

    close(fd);

    return arg;
}

/*
 * Send scatter-gather lists on the request virtqueue and return the number of
 * bytes filled by the device.
 *
 * Note that in/out have opposite meanings in FUSE and VIRTIO.  This function
 * uses VIRTIO terminology (out - to device, in - from device).
 */
static uint32_t do_request(QVirtioFS *vfs, QTestState *qts,
                           struct iovec *sg_out, unsigned out_num,
                           struct iovec *sg_in, unsigned in_num)
{
    QVirtioDevice *dev = vfs->vdev;
    QVirtQueue *vq = vfs->request_vq;
    size_t out_bytes = iov_size(sg_out, out_num);
    size_t in_bytes = iov_size(sg_in, in_num);
    uint64_t out_addr;
    uint64_t in_addr;
    uint64_t addr;
    uint32_t head = 0;
    uint32_t nfilled;
    unsigned i;

    g_assert_cmpint(out_num, >, 0);
    g_assert_cmpint(in_num, >, 0);

    /* Add out buffers */
    addr = out_addr = guest_alloc(vfs->alloc, out_bytes);
    for (i = 0; i < out_num; i++) {
        size_t len = sg_out[i].iov_len;
        uint32_t desc_idx;
        bool first = i == 0;

        qtest_memwrite(qts, addr, sg_out[i].iov_base, len);
        desc_idx = qvirtqueue_add(qts, vq, addr, len, false, true);

        if (first) {
            head = desc_idx;
        }

        addr += len;
    }

    /* Add in buffers */
    addr = in_addr = guest_alloc(vfs->alloc, in_bytes);
    for (i = 0; i < in_num; i++) {
        size_t len = sg_in[i].iov_len;
        bool next = i != in_num - 1;

        qvirtqueue_add(qts, vq, addr, len, true, next);

        addr += len;
    }

    /* Process the request */
    qvirtqueue_kick(qts, dev, vq, head);
    qvirtio_wait_used_elem(qts, dev, vq, head, &nfilled, TIMEOUT_US);

    /* Copy in buffers back */
    addr = in_addr;
    for (i = 0; i < in_num; i++) {
        size_t len = sg_in[i].iov_len;

        qtest_memread(qts, addr, sg_in[i].iov_base, len);
        addr += len;
    }

    guest_free(vfs->alloc, in_addr);
    guest_free(vfs->alloc, out_addr);

    return nfilled;
}

/* Byte-swap values if host endianness differs from guest */
static uint32_t guest32(uint32_t val)
{
    if (qtest_big_endian(global_qtest) != host_is_big_endian) {
        return bswap32(val);
    }
    return val;
}

static uint64_t guest64(uint64_t val)
{
    if (qtest_big_endian(global_qtest) != host_is_big_endian) {
        return bswap64(val);
    }
    return val;
}

/* Make a FUSE_INIT request */
static void fuse_init(QVirtioFS *vfs)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_INIT),
        .unique = guest64(virtio_fs_get_unique(vfs)),
    };
    struct fuse_init_in in = {
        .major = guest32(FUSE_KERNEL_VERSION),
        .minor = guest32(FUSE_KERNEL_MINOR_VERSION),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = &in, .iov_len = sizeof(in) },
    };
    struct fuse_out_header out_hdr;
    struct fuse_init_out out;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
        { .iov_base = &out, .iov_len = sizeof(out) },
    };

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
               sg_out, G_N_ELEMENTS(sg_out));

    g_assert_cmpint(guest32(out_hdr.error), ==, 0);
    g_assert_cmpint(guest32(out.major), ==, FUSE_KERNEL_VERSION);
}

/* Look up a directory entry by name using FUSE_LOOKUP */
static int32_t fuse_lookup(QVirtioFS *vfs, uint64_t parent, const char *name,
                           struct fuse_entry_out *entry)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_LOOKUP),
        .unique = guest64(virtio_fs_get_unique(vfs)),
        .nodeid = guest64(parent),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = (void *)name, .iov_len = strlen(name) + 1 },
    };
    struct fuse_out_header out_hdr;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
        { .iov_base = entry, .iov_len = sizeof(*entry) },
    };

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
               sg_out, G_N_ELEMENTS(sg_out));

    return guest32(out_hdr.error);
}

/* Open a file by nodeid using FUSE_OPEN */
static int32_t fuse_open(QVirtioFS *vfs, uint64_t nodeid, uint32_t flags,
                         uint64_t *fh)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_OPEN),
        .unique = guest64(virtio_fs_get_unique(vfs)),
        .nodeid = guest64(nodeid),
    };
    struct fuse_open_in in = {
        .flags = guest32(flags),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = &in, .iov_len = sizeof(in) },
    };
    struct fuse_out_header out_hdr;
    struct fuse_open_out out;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
        { .iov_base = &out, .iov_len = sizeof(out) },
    };
    int32_t error;

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
               sg_out, G_N_ELEMENTS(sg_out));

    error = guest32(out_hdr.error);
    if (!error) {
        *fh = guest64(out.fh);
    } else {
        *fh = 0;
    }
    return error;
}

/* Create a file using FUSE_CREATE */
static int32_t fuse_create(QVirtioFS *vfs, uint64_t parent, const char *name,
                           uint32_t mode, uint32_t flags,
                           uint64_t *nodeid, uint64_t *fh)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_CREATE),
        .unique = guest64(virtio_fs_get_unique(vfs)),
        .nodeid = guest64(parent),
    };
    struct fuse_create_in in = {
        .flags = guest32(flags),
        .mode = guest32(mode),
        .umask = guest32(0002),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = &in, .iov_len = sizeof(in) },
        { .iov_base = (void *)name, .iov_len = strlen(name) + 1 },
    };
    struct fuse_out_header out_hdr;
    struct fuse_entry_out entry;
    struct fuse_open_out out;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
        { .iov_base = &entry, .iov_len = sizeof(entry) },
        { .iov_base = &out, .iov_len = sizeof(out) },
    };
    int32_t error;

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
               sg_out, G_N_ELEMENTS(sg_out));

    error = guest32(out_hdr.error);
    if (!error) {
        *nodeid = guest64(entry.nodeid);
        *fh = guest64(out.fh);
    } else {
        *nodeid = 0;
        *fh = 0;
    }
    return error;
}

/* Read bytes from a file using FILE_READ */
static ssize_t fuse_read(QVirtioFS *vfs, uint64_t fh, uint64_t offset,
                         void *buf, size_t len)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_READ),
        .unique = guest64(virtio_fs_get_unique(vfs)),
    };
    struct fuse_read_in in = {
        .fh = guest64(fh),
        .offset = guest64(offset),
        .size = guest32(len),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = &in, .iov_len = sizeof(in) },
    };
    struct fuse_out_header out_hdr;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
        { .iov_base = buf, .iov_len = len },
    };
    uint32_t nread;

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    nread = do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
                       sg_out, G_N_ELEMENTS(sg_out));
    g_assert_cmpint(guest32(out_hdr.error), ==, 0);

    return nread - sizeof(out_hdr);
}

/* Write bytes to a file using FILE_WRITE */
static ssize_t fuse_write(QVirtioFS *vfs, uint64_t fh, uint64_t offset,
                          const void *buf, size_t len)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_WRITE),
        .unique = guest64(virtio_fs_get_unique(vfs)),
    };
    struct fuse_write_in in = {
        .fh = guest64(fh),
        .offset = guest64(offset),
        .size = guest32(len),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = &in, .iov_len = sizeof(in) },
        { .iov_base = (void *)buf, .iov_len = len },
    };
    struct fuse_out_header out_hdr;
    struct fuse_write_out out;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
        { .iov_base = &out, .iov_len = sizeof(out) },
    };

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
               sg_out, G_N_ELEMENTS(sg_out));
    g_assert_cmpint(guest32(out_hdr.error), ==, 0);

    return guest32(out.size);
}

/* Close a file handle using FUSE_RELEASE */
static void fuse_release(QVirtioFS *vfs, uint64_t fh)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_RELEASE),
        .unique = guest64(virtio_fs_get_unique(vfs)),
    };
    struct fuse_release_in in = {
        .fh = guest64(fh),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = &in, .iov_len = sizeof(in) },
    };
    struct fuse_out_header out_hdr;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
    };

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
               sg_out, G_N_ELEMENTS(sg_out));

    g_assert_cmpint(guest32(out_hdr.error), ==, 0);
}

/* Drop an inode reference using FUSE_FORGET */
static void fuse_forget(QVirtioFS *vfs, uint64_t nodeid)
{
    struct fuse_in_header in_hdr = {
        .opcode = guest32(FUSE_FORGET),
        .unique = guest64(virtio_fs_get_unique(vfs)),
        .nodeid = guest64(nodeid),
    };
    struct fuse_forget_in in = {
        .nlookup = guest64(1),
    };
    struct iovec sg_in[] = {
        { .iov_base = &in_hdr, .iov_len = sizeof(in_hdr) },
        { .iov_base = &in, .iov_len = sizeof(in) },
    };
    struct fuse_out_header out_hdr;
    struct iovec sg_out[] = {
        { .iov_base = &out_hdr, .iov_len = sizeof(out_hdr) },
    };

    in_hdr.len = guest32(iov_size(sg_in, G_N_ELEMENTS(sg_in)));

    do_request(vfs, global_qtest, sg_in, G_N_ELEMENTS(sg_in),
               sg_out, G_N_ELEMENTS(sg_out));

    g_assert_cmpint(guest32(out_hdr.error), ==, 0);
}

/* Check contents of VIRTIO Configuration Space */
static void test_config(void *parent, void *arg, QGuestAllocator *alloc)
{
    QVirtioFS *vfs = parent;
    size_t i;
    uint32_t num_request_queues;
    char tag[37];

    SKIP_TEST_IF_CROSS_ENDIAN();

    for (i = 0; i < sizeof(tag) - 1; i++) {
        tag[i] = qvirtio_config_readw(vfs->vdev, i);
    }
    tag[36] = '\0';

    g_assert_cmpstr(tag, ==, VIRTIO_FS_TAG);

    num_request_queues = qvirtio_config_readl(vfs->vdev,
            offsetof(struct virtio_fs_config, num_request_queues));

    g_assert_cmpint(num_request_queues, ==, 1);
}

/* Create file on host and check its contents and metadata in guest */
static void test_file_from_host(void *parent, void *arg, QGuestAllocator *alloc)
{
    g_autofree gchar *filename = g_strdup_printf("%s/%s", shared_dir, "foo");
    const char *str = "This is a test\n";
    char buf[strlen(str)];
    QVirtioFS *vfs = parent;
    struct fuse_entry_out entry;
    int32_t error;
    uint64_t nodeid;
    uint64_t fh;
    ssize_t nread;
    gboolean ok;

    SKIP_TEST_IF_CROSS_ENDIAN();

    /* Create the test file in the shared directory */
    ok = g_file_set_contents(filename, str, strlen(str), NULL);
    g_assert(ok);

    fuse_init(vfs);

    error = fuse_lookup(vfs, FUSE_ROOT_ID, "foo", &entry);
    g_assert_cmpint(error, ==, 0);
    g_assert_cmpint(guest64(entry.attr.size), ==, strlen(str));
    nodeid = guest64(entry.nodeid);

    error = fuse_open(vfs, nodeid, O_RDONLY, &fh);
    g_assert_cmpint(error, ==, 0);

    nread = fuse_read(vfs, fh, 0, buf, sizeof(buf));
    g_assert_cmpint(nread, ==, sizeof(buf));
    g_assert_cmpint(memcmp(buf, str, sizeof(buf)), ==, 0);

    fuse_release(vfs, fh);
    fuse_forget(vfs, nodeid);
}

/* Create file from host and check its contents and metadata on host */
static void test_file_from_guest(void *parent, void *arg,
                                 QGuestAllocator *alloc)
{
    g_autofree gchar *filename = g_strdup_printf("%s/%s", shared_dir, "foo");
    const char *str = "This is a test\n";
    gchar *contents = NULL;
    gsize length = 0;
    QVirtioFS *vfs = parent;
    int32_t error;
    uint64_t nodeid;
    uint64_t fh;
    ssize_t nwritten;
    gboolean ok;

    SKIP_TEST_IF_CROSS_ENDIAN();

    fuse_init(vfs);

    error = fuse_create(vfs, FUSE_ROOT_ID, "foo", 0644, O_CREAT | O_WRONLY,
                        &nodeid, &fh);
    g_assert_cmpint(error, ==, 0);

    nwritten = fuse_write(vfs, fh, 0, str, strlen(str));
    g_assert_cmpint(nwritten, ==, strlen(str));

    fuse_release(vfs, fh);
    fuse_forget(vfs, nodeid);

    /* Check the file on the host */
    ok = g_file_get_contents(filename, &contents, &length, NULL);
    g_assert(ok);
    g_assert_cmpint(length, ==, strlen(str));
    g_assert_cmpint(memcmp(contents, str, strlen(str)), ==, 0);
    g_free(contents);
}

static void register_vhost_user_fs_test(void)
{
    g_autofree gchar *cmd_line =
        g_strdup_printf("-chardev socket,id=char-virtio-fs,path=%s",
                        socket_path);
    QOSGraphTestOptions opts = {
        .edge.before_cmd_line = cmd_line,
        .before = before_test,
        .after = after_test,
    };

    if (geteuid() != 0) {
        g_test_message("Skipping vhost-user-fs tests because root is "
                       "required for virtiofsd");
        return;
    }

    qtest_add_abrt_handler(abrt_handler, NULL);

    qos_add_test("config", "virtio-fs", test_config, &opts);
    qos_add_test("file-from-host", "virtio-fs", test_file_from_host, &opts);
    qos_add_test("file-from-guest", "virtio-fs", test_file_from_guest, &opts);
}

libqos_init(register_vhost_user_fs_test);

static void __attribute__((constructor)) init_paths(void)
{
    socket_path = g_strdup_printf("/tmp/qtest-%d-vhost-fs.sock", getpid());
    shared_dir = g_strdup_printf("/tmp/qtest-%d-virtio-fs-dir", getpid());
}

static void __attribute__((destructor)) destroy_paths(void)
{
    g_free(shared_dir);
    shared_dir = NULL;

    g_free(socket_path);
    socket_path = NULL;
}
