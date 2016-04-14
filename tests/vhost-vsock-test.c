#include <glib.h>
#include <sys/socket.h>
#include <poll.h>
#include <linux/vm_sockets.h>
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/host-utils.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qlist.h"
#include "libqtest.h"
#include "libqos/virtio.h"
#include "libqos/virtio-pci.h"
#include "libqos/pci-pc.h"
#include "libqos/malloc.h"
#include "libqos/malloc-pc.h"
#include "libqos/malloc-generic.h"
#include "standard-headers/linux/virtio_vsock.h"

#define DATA_DIR                "tests/vhost-vsock-test-data"
#define PCI_SLOT                0x04
#define PCI_FN                  0x00
#define TIMEOUT_US              5 * 1000 * 1000
#define RXBUF_SIZE              (sizeof(struct virtio_vsock_hdr) + 4096)

enum TestOp {
    TEST_OP_SEND,
    TEST_OP_RECEIVE,
    TEST_OP_SOCK_ASYNC_CONNECT,
    TEST_OP_SOCK_POLL,
    TEST_OP_MAX
};

enum TestOpFlags {
    HDR_REQUIRED = 0x1,
    SOCK_ID_REQUIRED = 0x2,
    DST_REQUIRED = 0x4,
    POLL_REQUIRED = 0x8,
};

static const enum TestOpFlags op_flags[] = {
    HDR_REQUIRED, /* TEST_OP_SEND */
    HDR_REQUIRED, /* TEST_OP_RECEIVE */
    SOCK_ID_REQUIRED | DST_REQUIRED, /* TEST_OP_SOCK_ASYNC_CONNECT */
    SOCK_ID_REQUIRED | POLL_REQUIRED, /* TEST_OP_SOCK_POLL */
};

/* Avoid hard-coding port numbers into tests by providing a way to refer to the
 * port number of a given socket.
 */
typedef struct {
    unsigned int *port;
    char *sock_id;
} PortRef;

typedef struct TestCommand {
    enum TestOp op;
    struct virtio_vsock_hdr hdr;
    PortRef hdr_src_port_ref;
    PortRef hdr_dst_port_ref;
    char *sock_id;
    uint64_t dst_cid;
    unsigned int dst_port;
    PortRef dst_port_ref;
    short poll_events;
    int poll_so_error;
    QSIMPLEQ_ENTRY(TestCommand) node;
} TestCommand;

/* Host-side AF_VSOCK sockets */
typedef struct Socket {
    char *id;
    int fd;
    struct sockaddr_vm local_addr;
    QLIST_ENTRY(Socket) node;
} Socket;

typedef struct {
    uint64_t my_cid;
    uint64_t peer_cid;
    QSIMPLEQ_HEAD(, TestCommand) commands;
    QLIST_HEAD(, Socket) sockets;
} TestEngine;

typedef struct {
    QVirtioDevice *dev;
    const QVirtioBus *bus;
    QGuestAllocator *alloc;
    QVirtQueue *rx_vq;
    QVirtQueue *tx_vq;
    uint64_t rxbuf[8];
    size_t rx_idx;
} VHostVSock;

static unsigned int my_qdict_get_try_enum(QDict *dict, const char *key,
                                          const char **atoms, bool *found)
{
    unsigned int i;
    const char *atom;

    atom = qdict_get_try_str(dict, key);
    if (!atom) {
        g_test_message("Missing required \"%s\" required", key);
        g_assert(false);
    }

    for (i = 0; atoms[i]; i++) {
        if (!strcmp(atoms[i], atom)) {
            *found = true;
            return i;
        }
    }
    *found = false;
    return 0;
}

static int my_qdict_get_int(QDict *dict, const char *key)
{
    int64_t val;

    if (!qdict_haskey(dict, key)) {
        g_test_message("Missing required \"%s\" field", key);
        g_assert(false);
    }
    if (qobject_type(qdict_get(dict, key)) != QTYPE_QINT) {
        g_test_message("Wrong data type in \"%s\" field, expected int", key);
        g_assert(false);
    }

    val = qdict_get_int(dict, key);
    if (val < INT_MIN || val > INT_MAX) {
        g_test_message("Expected \"%s\" field value in range [%d, %d]",
                       key, INT_MIN, INT_MAX);
        g_assert(false);
    }

    return val;
}

static uint64_t my_qdict_get_uint64(QDict *dict, const char *key)
{
    if (!qdict_haskey(dict, key)) {
        g_test_message("Missing required \"%s\" field", key);
        g_assert(false);
    }
    if (qobject_type(qdict_get(dict, key)) != QTYPE_QINT) {
        g_test_message("Wrong data type in \"%s\" field, expected int", key);
        g_assert(false);
    }

    return qdict_get_int(dict, key);
}

static uint32_t my_qdict_get_uint32(QDict *dict, const char *key)
{
    int64_t val;

    if (!qdict_haskey(dict, key)) {
        g_test_message("Missing required \"%s\" field", key);
        g_assert(false);
    }
    if (qobject_type(qdict_get(dict, key)) != QTYPE_QINT) {
        g_test_message("Wrong data type in \"%s\" field, expected int", key);
        g_assert(false);
    }

    val = qdict_get_int(dict, key);
    if (val < 0 || val > UINT32_MAX) {
        g_test_message("Expected \"%s\" field value in range [0, %u]",
                       key, UINT32_MAX);
        g_assert(false);
    }

    return val;
}

static void my_qdict_get_port(QDict *dict, const char *key, PortRef *ref,
                              unsigned int *port)
{
    const char *str;

    *port = -1;
    ref->port = NULL;

    str = qdict_get_try_str(dict, key);
    if (!str) {
        *port = my_qdict_get_uint32(dict, key);
        return;
    }

    if (strncmp("SOCK_PORT_", str, strlen("SOCK_PORT_")) != 0) {
        g_test_message("Expected SOCK_PORT_<sock_id> port reference in "
                       "field \"%s\"", key);
        g_assert(false);
    }

    ref->port = port;
    ref->sock_id = g_strdup(str + strlen("SOCK_PORT_"));
}

static uint16_t my_qdict_get_uint16(QDict *dict, const char *key)
{
    int64_t val;

    if (!qdict_haskey(dict, key)) {
        g_test_message("Missing required \"%s\" field", key);
        g_assert(false);
    }
    if (qobject_type(qdict_get(dict, key)) != QTYPE_QINT) {
        g_test_message("Wrong data type in \"%s\" field, expected int", key);
        g_assert(false);
    }

    val = qdict_get_int(dict, key);
    if (val < 0 || val > UINT16_MAX) {
        g_test_message("Expected \"%s\" field value in range [0, %u]",
                       key, UINT16_MAX);
        g_assert(false);
    }

    return val;
}

static uint64_t engine_qdict_get_cid(TestEngine *engine, QDict *dict,
                                     const char *key)
{
    const char *atom = qdict_get_try_str(dict, key);

    if (atom) {
        if (!strcmp(atom, "MY_CID")) {
            return engine->my_cid;
        } else if (!strcmp(atom, "PEER_CID")) {
            return engine->peer_cid;
        }
    }

    return my_qdict_get_uint64(dict, key);
}

static void parse_hdr(TestEngine *engine, QDict *dict, TestCommand *command)
{
    QDict *hdr_dict;
    bool found;

    hdr_dict = qdict_get_qdict(dict, "hdr");
    if (!hdr_dict) {
        g_test_message("Missing required \"hdr\" field");
        g_assert(false);
    }

    command->hdr.src_cid = engine_qdict_get_cid(engine, hdr_dict, "src_cid");
    command->hdr.dst_cid = engine_qdict_get_cid(engine, hdr_dict, "dst_cid");
    my_qdict_get_port(hdr_dict, "src_port", &command->hdr_src_port_ref,
                      &command->hdr.src_port);
    my_qdict_get_port(hdr_dict, "dst_port", &command->hdr_dst_port_ref,
                      &command->hdr.dst_port);
    command->hdr.len = my_qdict_get_uint32(hdr_dict, "len");
    command->hdr.type = my_qdict_get_try_enum(hdr_dict, "type",
            (const char * []) {
                "",
                "VIRTIO_VSOCK_TYPE_STREAM",
                NULL
            },
            &found);
    if (!found) {
        command->hdr.type = my_qdict_get_uint16(hdr_dict, "type");
    }
    command->hdr.op = my_qdict_get_try_enum(hdr_dict, "op",
            (const char * []) {
                "VIRTIO_VSOCK_OP_INVALID",
                "VIRTIO_VSOCK_OP_REQUEST",
                "VIRTIO_VSOCK_OP_RESPONSE",
                "VIRTIO_VSOCK_OP_RST",
                "VIRTIO_VSOCK_OP_SHUTDOWN",
                "VIRTIO_VSOCK_OP_RW",
                "VIRTIO_VSOCK_OP_CREDIT_UPDATE",
                "VIRTIO_VSOCK_OP_CREDIT_REQUEST",
                NULL
            },
            &found);
    if (!found) {
        command->hdr.op = my_qdict_get_uint16(hdr_dict, "op");
    }
    command->hdr.flags = my_qdict_get_uint32(hdr_dict, "flags");
    command->hdr.buf_alloc = my_qdict_get_uint32(hdr_dict, "buf_alloc");
    command->hdr.fwd_cnt = my_qdict_get_uint32(hdr_dict, "fwd_cnt");
}

static void parse_dst(TestEngine *engine, QDict *dict, TestCommand *command)
{
    command->dst_cid = engine_qdict_get_cid(engine, dict, "dst_cid");
    my_qdict_get_port(dict, "dst_port", &command->dst_port_ref,
                      &command->dst_port);
}

static void parse_poll(TestEngine *engine, QDict *dict, TestCommand *command)
{
    bool found;

    command->poll_events = 1 << my_qdict_get_try_enum(dict, "poll_events",
            (const char * []) {
                "",
                "POLLIN",
                "POLLPRI",
                "POLLOUT",
                NULL
            },
            &found);
    if (!found) {
        command->poll_events = my_qdict_get_uint16(dict, "poll_events");
    }

    command->poll_so_error = my_qdict_get_int(dict, "poll_so_error");
}

static TestCommand *qobject_to_test_command(TestEngine *engine, QObject *obj)
{
    TestCommand *command = g_new0(TestCommand, 1);
    QDict *dict = qobject_to_qdict(obj);
    bool found;

    if (!dict) {
        g_test_message("Expected JSON object for test command");
        g_assert(false);
    }

    command->op = my_qdict_get_try_enum(dict, "op",
            (const char * []) {
                "send", "receive", "sock-async-connect", "sock-poll", NULL
            },
            &found);
    if (!found) {
        g_test_message("Unknown \"op\" field value");
        g_assert(false);
    }

    if (op_flags[command->op] & HDR_REQUIRED) {
        parse_hdr(engine, dict, command);
    }
    if (op_flags[command->op] & SOCK_ID_REQUIRED) {
        const char *val = qdict_get_try_str(dict, "sock_id");

        if (!val) {
            g_test_message("Expected string \"sock_id\" field");
            g_assert(false);
        }

        command->sock_id = g_strdup(val);
    }
    if (op_flags[command->op] & DST_REQUIRED) {
        parse_dst(engine, dict, command);
    }
    if (op_flags[command->op] & POLL_REQUIRED) {
        parse_poll(engine, dict, command);
    }

    return command;
}

static Socket *find_socket(TestEngine *engine, const char *sock_id)
{
    Socket *sock;

    QLIST_FOREACH(sock, &engine->sockets, node) {
        if (!strcmp(sock_id, sock->id)) {
            return sock;
        }
    }
    g_test_message("Unable to find sock_id \"%s\"", sock_id);
    g_assert(false);
    return NULL;
}

static void port_ref_resolve(PortRef *ref, TestEngine *engine)
{
    Socket *sock;

    if (!ref->port) {
        return;
    }

    sock = find_socket(engine, ref->sock_id);
    *ref->port = sock->local_addr.svm_port;
}

static void port_ref_cleanup(PortRef *ref)
{
    g_free(ref->sock_id);
}

static void test_command_destroy(TestCommand *command)
{
    port_ref_cleanup(&command->hdr_src_port_ref);
    port_ref_cleanup(&command->hdr_dst_port_ref);
    port_ref_cleanup(&command->dst_port_ref);
    g_free(command->sock_id);
    g_free(command);
}

static void load_test_commands(TestEngine *engine, const char *filename)
{
    gchar *contents;
    QObject *command_list_obj;
    QList *command_list;
    QObject *command_obj;

    g_assert(g_file_get_contents(filename, &contents, NULL, NULL));
    command_list_obj = qobject_from_json(contents);
    g_free(contents);

    if (!command_list_obj) {
        g_test_message("Failed to load JSON");
        g_assert(false);
    }

    command_list = qobject_to_qlist(command_list_obj);
    g_assert(command_list != NULL);

    while ((command_obj = qlist_pop(command_list))) {
        TestCommand *test_command =
            qobject_to_test_command(engine, command_obj);
        g_assert(test_command != NULL);
        qobject_decref(command_obj);
        QSIMPLEQ_INSERT_TAIL(&engine->commands, test_command, node);
    }

    qobject_decref(command_list_obj);
}

static TestEngine *test_engine_new(uint64_t my_cid, uint64_t peer_cid)
{
    TestEngine *engine;

    engine = g_new(TestEngine, 1);
    engine->my_cid = my_cid;
    engine->peer_cid = peer_cid;
    QSIMPLEQ_INIT(&engine->commands);
    QLIST_INIT(&engine->sockets);
    return engine;
}

static void test_engine_destroy(TestEngine *engine)
{
    while (!QSIMPLEQ_EMPTY(&engine->commands)) {
        TestCommand *command = QSIMPLEQ_FIRST(&engine->commands);
        QSIMPLEQ_REMOVE_HEAD(&engine->commands, node);
        test_command_destroy(command);
    }
    while (!QLIST_EMPTY(&engine->sockets)) {
        Socket *sock = QLIST_FIRST(&engine->sockets);
        QLIST_REMOVE(sock, node);
        close(sock->fd);
        g_free(sock->id);
        g_free(sock);
    }
    g_free(engine);
}

static void resolve_port_refs(TestCommand *command, TestEngine *engine)
{
    port_ref_resolve(&command->hdr_src_port_ref, engine);
    port_ref_resolve(&command->hdr_dst_port_ref, engine);
    port_ref_resolve(&command->dst_port_ref, engine);
}

static void vsock_setup_rx(VHostVSock *vs)
{
    size_t i;

    vs->rx_idx = 0;

    for (i = 0; i < ARRAY_SIZE(vs->rxbuf); i++) {
        uint32_t free_head;

        vs->rxbuf[i] = guest_alloc(vs->alloc, RXBUF_SIZE);
        free_head = qvirtqueue_add(vs->rx_vq, vs->rxbuf[i], RXBUF_SIZE,
                                   true, false, &vs->rxbuf[i]);
        qvirtqueue_kick(vs->bus, vs->dev, vs->rx_vq, free_head);
    }

}

static void vsock_cleanup_rx(VHostVSock *vs)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(vs->rxbuf); i++) {
        guest_free(vs->alloc, vs->rxbuf[i]);
    }
}

static void vsock_send(VHostVSock *vs, const struct virtio_vsock_hdr *hdr)
{
    uint64_t addr;
    uint32_t free_head;
    struct virtio_vsock_hdr le_hdr;

    le_hdr.src_cid = cpu_to_le64(hdr->src_cid);
    le_hdr.dst_cid = cpu_to_le64(hdr->dst_cid);
    le_hdr.src_port = cpu_to_le32(hdr->src_port);
    le_hdr.dst_port = cpu_to_le32(hdr->dst_port);
    le_hdr.len = cpu_to_le32(hdr->len);
    le_hdr.type = cpu_to_le16(hdr->type);
    le_hdr.op = cpu_to_le16(hdr->op);
    le_hdr.flags = cpu_to_le32(hdr->flags);
    le_hdr.buf_alloc = cpu_to_le32(hdr->buf_alloc);
    le_hdr.fwd_cnt = cpu_to_le32(hdr->fwd_cnt);

    addr = guest_alloc(vs->alloc, sizeof(le_hdr));
    bufwrite(addr, &le_hdr, sizeof(le_hdr));

    free_head = qvirtqueue_add(vs->tx_vq, addr, sizeof(le_hdr),
                               false, false, &le_hdr);
    qvirtqueue_kick(vs->bus, vs->dev, vs->tx_vq, free_head);

    qvirtio_wait_queue_buf(vs->bus, vs->dev, vs->tx_vq, &le_hdr, TIMEOUT_US);

    guest_free(vs->alloc, addr);
}

static void vsock_recv(VHostVSock *vs, struct virtio_vsock_hdr *hdr)
{
    struct virtio_vsock_hdr le_hdr;
    uint32_t free_head;

    qvirtio_wait_queue_buf(vs->bus, vs->dev, vs->rx_vq,
                           &vs->rxbuf[vs->rx_idx], TIMEOUT_US);

    bufread(vs->rxbuf[vs->rx_idx], &le_hdr, sizeof(le_hdr));

    hdr->src_cid = cpu_to_le64(le_hdr.src_cid);
    hdr->dst_cid = cpu_to_le64(le_hdr.dst_cid);
    hdr->src_port = cpu_to_le32(le_hdr.src_port);
    hdr->dst_port = cpu_to_le32(le_hdr.dst_port);
    hdr->len = cpu_to_le32(le_hdr.len);
    hdr->type = cpu_to_le16(le_hdr.type);
    hdr->op = cpu_to_le16(le_hdr.op);
    hdr->flags = cpu_to_le32(le_hdr.flags);
    hdr->buf_alloc = cpu_to_le32(le_hdr.buf_alloc);
    hdr->fwd_cnt = cpu_to_le32(le_hdr.fwd_cnt);

    free_head = qvirtqueue_add(vs->rx_vq, vs->rxbuf[vs->rx_idx], RXBUF_SIZE,
                               true, false, &vs->rxbuf[vs->rx_idx]);
    qvirtqueue_kick(vs->bus, vs->dev, vs->rx_vq, free_head);
    vs->rx_idx = (vs->rx_idx + 1) % ARRAY_SIZE(vs->rxbuf);
}

static void test_command_send(TestCommand *command, TestEngine *engine,
                              VHostVSock *vs)
{
    vsock_send(vs, &command->hdr);
}

static void test_command_receive(TestCommand *command, TestEngine *engine,
                                 VHostVSock *vs)
{
    struct virtio_vsock_hdr hdr;

    vsock_recv(vs, &hdr);

    g_assert_cmpint(command->hdr.src_cid, ==, hdr.src_cid);
    g_assert_cmpint(command->hdr.src_port, ==, hdr.src_port);
    g_assert_cmpint(command->hdr.dst_cid, ==, hdr.dst_cid);
    g_assert_cmpint(command->hdr.dst_port, ==, hdr.dst_port);
    g_assert_cmpint(command->hdr.len, ==, hdr.len);
    g_assert_cmpint(command->hdr.type, ==, hdr.type);
    g_assert_cmpint(command->hdr.op, ==, hdr.op);
    g_assert_cmpint(command->hdr.flags, ==, hdr.flags);
    g_assert_cmpint(command->hdr.buf_alloc, ==, hdr.buf_alloc);
    g_assert_cmpint(command->hdr.fwd_cnt, ==, hdr.fwd_cnt);
}

static void test_command_sock_async_connect(TestCommand *command,
                                            TestEngine *engine,
                                            VHostVSock *vs)
{
    Socket *sock = g_new0(Socket, 1);
    struct sockaddr_vm remote = {};
    socklen_t addrlen;
    int ret;
    int old_errno;

    sock->fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    g_assert_cmpint(sock->fd, >=, 0);

    remote.svm_family = AF_VSOCK;
    remote.svm_cid = command->dst_cid;
    remote.svm_port = command->dst_port;
    ret = connect(sock->fd, (struct sockaddr*)&remote, sizeof(remote));
    old_errno = errno;
    g_assert_cmpint(ret, ==, -1);
    g_assert_cmpint(old_errno, ==, EINPROGRESS);

    addrlen = sizeof(sock->local_addr);
    ret = getsockname(sock->fd, (struct sockaddr*)&sock->local_addr, &addrlen);
    g_assert_cmpint(ret, ==, 0);
    g_assert_cmpint(addrlen, ==, sizeof(sock->local_addr));

    sock->id = g_strdup(command->sock_id);
    QLIST_INSERT_HEAD(&engine->sockets, sock, node);
}

static void test_command_sock_poll(TestCommand *command,
                                   TestEngine *engine,
                                   VHostVSock *vs)
{
    struct pollfd pfd;
    Socket *sock;
    socklen_t len;
    int ret;
    int val;

    sock = find_socket(engine, command->sock_id);
    pfd.fd = sock->fd;
    pfd.events = command->poll_events;
    pfd.revents = 0;

    ret = poll(&pfd, 1, TIMEOUT_US / 1000);
    g_assert_cmpint(ret, ==, 1);
    g_assert_cmpint(pfd.revents, !=, 0);

    len = sizeof(val);
    ret = getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &val, &len);
    g_assert_cmpint(ret, ==, 0);
    g_assert_cmpint(val, ==, command->poll_so_error);
}

static void (*test_command_ops[])(TestCommand *command,
                                  TestEngine *engine,
                                  VHostVSock *vs) = {
    test_command_send,
    test_command_receive,
    test_command_sock_async_connect,
    test_command_sock_poll,
};

static void test_engine_run(TestEngine *engine, VHostVSock *vs)
{
    while (!QSIMPLEQ_EMPTY(&engine->commands)) {
        TestCommand *command = QSIMPLEQ_FIRST(&engine->commands);

        g_assert(command->op < TEST_OP_MAX);
        resolve_port_refs(command, engine);
        test_command_ops[command->op](command, engine, vs);
        QSIMPLEQ_REMOVE_HEAD(&engine->commands, node);
        test_command_destroy(command);
    }
}

static void pci_engine_test_one(TestEngine *engine, VHostVSock *vs)
{
    uint32_t features;

    qvirtio_reset(vs->bus, vs->dev);
    qvirtio_set_acknowledge(vs->bus, vs->dev);
    qvirtio_set_driver(vs->bus, vs->dev);

    features = qvirtio_get_features(vs->bus, vs->dev);
    features = features & ~(QVIRTIO_F_BAD_FEATURE |
                    (1 << VIRTIO_RING_F_INDIRECT_DESC) |
                    (1 << VIRTIO_RING_F_EVENT_IDX));
    qvirtio_set_features(vs->bus, vs->dev, features);

    vs->rx_vq = qvirtqueue_setup(vs->bus, vs->dev, vs->alloc, 0);
    vs->tx_vq = qvirtqueue_setup(vs->bus, vs->dev, vs->alloc, 1);

    qvirtio_set_driver_ok(vs->bus, vs->dev);

    vsock_setup_rx(vs);

    test_engine_run(engine, vs);

    qvirtio_reset(vs->bus, vs->dev);
    vsock_cleanup_rx(vs);
    qvirtqueue_cleanup(vs->bus, vs->rx_vq, vs->alloc);
    qvirtqueue_cleanup(vs->bus, vs->tx_vq, vs->alloc);
}

static void pci_engine(void)
{
    char *cmdline;
    QVirtioPCIDevice *pcidev;
    QPCIBus *bus;
    VHostVSock vs;
    TestEngine *engine;
    uint64_t guest_cid = getpid();
    GDir *dir;
    const gchar *filename;

    cmdline = g_strdup_printf("-device vhost-vsock-pci,id=vhost-vsock-pci0,"
                              "guest-cid=%" PRIu64 ",addr=%x.%x",
                              guest_cid,
                              PCI_SLOT,
                              PCI_FN);
    qtest_start(cmdline);
    g_free(cmdline);

    engine = test_engine_new(guest_cid, 2);

    bus = qpci_init_pc();
    pcidev = qvirtio_pci_device_find(bus, VIRTIO_ID_VSOCK);
    g_assert(pcidev);
    g_assert_cmphex(pcidev->vdev.device_type, ==, VIRTIO_ID_VSOCK);
    g_assert_cmphex(pcidev->pdev->devfn, ==, ((PCI_SLOT << 3) | PCI_FN));

    vs.alloc = pc_alloc_init();
    vs.dev = &pcidev->vdev;
    vs.bus = &qvirtio_pci;

    qvirtio_pci_device_enable(pcidev);

    dir = g_dir_open(DATA_DIR, 0, NULL);
    g_assert(dir != NULL);
    while ((filename = g_dir_read_name(dir)) != NULL) {
        gchar *fullpath;

        if (!g_str_has_suffix(filename, ".json")) {
            continue;
        }

        fullpath = g_build_filename(DATA_DIR, filename, NULL);
        load_test_commands(engine, fullpath);
        g_free(fullpath);

        pci_engine_test_one(engine, &vs);
    }
    g_dir_close(dir);

    pc_alloc_uninit(vs.alloc);
    qvirtio_pci_device_disable(pcidev);
    g_free(pcidev);
    qpci_free_pc(bus);
    test_engine_destroy(engine);
    qtest_end();
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    if (access("/dev/vhost-vsock", W_OK) == 0) {
        qtest_add_func("/vhost/vsock/pci/engine", pci_engine);
    } else if (g_test_verbose()) {
        switch (errno) {
        case ENOENT:
            fprintf(stderr, "vhost-vsock device not found, please check that "
                    "the kernel module is loaded\n");
            break;
        case EACCES:
            fprintf(stderr, "Unable to access vhost-vsock device, please "
                    "run test as root or modify permissions on "
                    "/dev/vhost-vsock\n");
            break;
        default:
            fprintf(stderr, "Failed to open /dev/vhost-vsock: %m\n");
            break;
        }
    }


    return g_test_run();
}
