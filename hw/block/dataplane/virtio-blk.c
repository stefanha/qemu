/*
 * Dedicated thread for virtio-blk I/O processing
 *
 * Copyright 2012 IBM, Corp.
 * Copyright 2012 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *   Stefan Hajnoczi <stefanha@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "trace.h"
#include "qemu/iov.h"
#include "qemu/thread.h"
#include "qemu/error-report.h"
#include "hw/virtio/dataplane/vring.h"
#include "block/block.h"
#include "hw/virtio/virtio-blk.h"
#include "virtio-blk.h"
#include "block/aio.h"
#include "hw/virtio/virtio-bus.h"

enum {
    SEG_MAX = 126,                  /* maximum number of I/O segments */
    VRING_MAX = SEG_MAX + 2,        /* maximum number of vring descriptors */
    REQ_MAX = VRING_MAX,            /* maximum number of requests in the vring,
                                     * is VRING_MAX / 2 with traditional and
                                     * VRING_MAX with indirect descriptors */
};

typedef struct {
    VirtIOBlockDataPlane *dataplane;
    QEMUIOVector data;              /* data buffer */
    QEMUIOVector inhdr;             /* iovecs for virtio_blk_inhdr */
    unsigned int head;              /* vring descriptor index */
} VirtIOBlockRequest;

struct VirtIOBlockDataPlane {
    bool started;
    bool stopping;
    QEMUBH *start_bh;
    QemuThread thread;

    VirtIOBlkConf *blk;
    BlockDriverState *bs;           /* block device */

    VirtIODevice *vdev;
    Vring vring;                    /* virtqueue vring */
    EventNotifier *guest_notifier;  /* irq */

    /* Note that these EventNotifiers are assigned by value.  This is
     * fine as long as you do not call event_notifier_cleanup on them
     * (because you don't own the file descriptor or handle; you just
     * use it).
     */
    AioContext *ctx;
    EventNotifier host_notifier;    /* doorbell */

    unsigned int num_reqs;
};

/* Raise an interrupt to signal guest, if necessary */
static void notify_guest(VirtIOBlockDataPlane *s)
{
    if (!vring_should_notify(s->vdev, &s->vring)) {
        return;
    }

    event_notifier_set(s->guest_notifier);
}

static void complete_request(VirtIOBlockRequest *req,
                             unsigned char status,
                             int len)
{
    VirtIOBlockDataPlane *s = req->dataplane;
    unsigned int head = req->head;
    struct virtio_blk_inhdr hdr = {
        .status = status,
    };

    qemu_iovec_from_buf(&req->inhdr, 0, &hdr, sizeof(hdr));
    qemu_iovec_destroy(&req->inhdr);
    qemu_iovec_destroy(&req->data);
    g_slice_free(VirtIOBlockRequest, req);

    /* According to the virtio specification len should be the number of bytes
     * written to, but for virtio-blk it seems to be the number of bytes
     * transferred plus the status bytes.
     */
    vring_push(&s->vring, head, len + sizeof(hdr));
    notify_guest(s);

    s->num_reqs--;
}

static void request_cb(void *opaque, int ret)
{
    VirtIOBlockRequest *req = opaque;
    VirtIOBlockDataPlane *s = req->dataplane;
    unsigned char status;
    int len;

    /* Completion must be invoked in our thread */
    assert(*tls_get_thread_aio_context() == s->ctx);

    if (likely(ret >= 0)) {
        status = VIRTIO_BLK_S_OK;
        len = ret;
    } else {
        status = VIRTIO_BLK_S_IOERR;
        len = 0;
    }

    trace_virtio_blk_data_plane_complete_request(s, req->head, ret);

    complete_request(req, status, len);
}

/* Get disk serial number */
static void do_get_id_cmd(VirtIOBlockRequest *req,
                          struct iovec *iov, unsigned int iov_cnt)
{
    VirtIOBlockDataPlane *s = req->dataplane;
    char id[VIRTIO_BLK_ID_BYTES];

    /* Serial number not NUL-terminated when shorter than buffer */
    strncpy(id, s->blk->serial ? s->blk->serial : "", sizeof(id));
    iov_from_buf(iov, iov_cnt, 0, id, sizeof(id));
    complete_request(req, VIRTIO_BLK_S_OK, 0);
}

static int do_rdwr_cmd(VirtIOBlockRequest *req, bool read,
                       struct iovec *iov, unsigned int iov_cnt,
                       long long offset)
{
    VirtIOBlockDataPlane *s = req->dataplane;
    int64_t sector_num = offset / BDRV_SECTOR_SIZE;
    int nb_sectors;
    unsigned int i;

    for (i = 0; i < iov_cnt; i++) {
        qemu_iovec_add(&req->data, iov[i].iov_base, iov[i].iov_len);
    }
    nb_sectors = req->data.size / BDRV_SECTOR_SIZE;

    if (read) {
        bdrv_aio_readv(s->bs, sector_num, &req->data, nb_sectors,
                       request_cb, req);
    } else {
        bdrv_aio_writev(s->bs, sector_num, &req->data, nb_sectors,
                        request_cb, req);
    }
    return 0;
}

static int process_request(VirtIOBlockDataPlane *s, struct iovec iov[],
                           unsigned int out_num, unsigned int in_num,
                           unsigned int head)
{
    VirtIOBlockRequest *req;
    struct iovec *in_iov = &iov[out_num];
    struct virtio_blk_outhdr outhdr;
    size_t in_size;

    req = g_slice_new(VirtIOBlockRequest);
    req->dataplane = s;
    req->head = head;
    qemu_iovec_init(&req->data, out_num + in_num);
    qemu_iovec_init(&req->inhdr, 1);

    s->num_reqs++;

    /* Copy in outhdr */
    if (unlikely(iov_to_buf(iov, out_num, 0, &outhdr,
                            sizeof(outhdr)) != sizeof(outhdr))) {
        error_report("virtio-blk request outhdr too short");
        goto fault;
    }
    iov_discard_front(&iov, &out_num, sizeof(outhdr));

    /* Grab inhdr for later */
    in_size = iov_size(in_iov, in_num);
    if (in_size < sizeof(struct virtio_blk_inhdr)) {
        error_report("virtio_blk request inhdr too short");
        goto fault;
    }
    qemu_iovec_concat_iov(&req->inhdr, in_iov, in_num,
            in_size - sizeof(struct virtio_blk_inhdr),
            sizeof(struct virtio_blk_inhdr));
    iov_discard_back(in_iov, &in_num, sizeof(struct virtio_blk_inhdr));

    /* TODO Linux sets the barrier bit even when not advertised! */
    outhdr.type &= ~VIRTIO_BLK_T_BARRIER;

    switch (outhdr.type) {
    case VIRTIO_BLK_T_IN:
        do_rdwr_cmd(req, true, in_iov, in_num, outhdr.sector * 512);
        return 0;

    case VIRTIO_BLK_T_OUT:
        do_rdwr_cmd(req, false, iov, out_num, outhdr.sector * 512);
        return 0;

    case VIRTIO_BLK_T_SCSI_CMD:
        /* TODO support SCSI commands */
        complete_request(req, VIRTIO_BLK_S_UNSUPP, 0);
        return 0;

    case VIRTIO_BLK_T_FLUSH:
        bdrv_aio_flush(s->bs, request_cb, req);
        return 0;

    case VIRTIO_BLK_T_GET_ID:
        do_get_id_cmd(req, in_iov, in_num);
        return 0;

    default:
        error_report("virtio-blk unsupported request type %#x", outhdr.type);
        goto fault;
    }

fault:
    qemu_iovec_destroy(&req->data);
    qemu_iovec_destroy(&req->inhdr);
    g_slice_free(VirtIOBlockRequest, req);
    s->num_reqs--;
    return -EFAULT;
}

static int flush_true(EventNotifier *e)
{
    return true;
}

static void handle_notify(EventNotifier *e)
{
    VirtIOBlockDataPlane *s = container_of(e, VirtIOBlockDataPlane,
                                           host_notifier);
    struct iovec iov[VRING_MAX];
    struct iovec *end = &iov[VRING_MAX];

    /* When a request is read from the vring, the index of the first descriptor
     * (aka head) is returned so that the completed request can be pushed onto
     * the vring later.
     *
     * The number of hypervisor read-only iovecs is out_num.  The number of
     * hypervisor write-only iovecs is in_num.
     */
    int head;
    unsigned int out_num = 0, in_num = 0;

    event_notifier_test_and_clear(&s->host_notifier);
    for (;;) {
        /* Disable guest->host notifies to avoid unnecessary vmexits */
        vring_disable_notification(s->vdev, &s->vring);

        for (;;) {
            head = vring_pop(s->vdev, &s->vring, iov, end, &out_num, &in_num);
            if (head < 0) {
                break; /* no more requests */
            }

            trace_virtio_blk_data_plane_process_request(s, out_num, in_num,
                                                        head);

            if (process_request(s, iov, out_num, in_num, head) < 0) {
                vring_set_broken(&s->vring);
                break;
            }
        }

        if (likely(head == -EAGAIN)) { /* vring emptied */
            /* Re-enable guest->host notifies and stop processing the vring.
             * But if the guest has snuck in more descriptors, keep processing.
             */
            if (vring_enable_notification(s->vdev, &s->vring)) {
                break;
            }
        } else {
            return; /* Fatal error, leave ring in broken state */
        }
    }
}

static void *data_plane_thread(void *opaque)
{
    VirtIOBlockDataPlane *s = opaque;

    *tls_alloc_thread_aio_context() = s->ctx;

    do {
        aio_poll(s->ctx, true);
    } while (!s->stopping || s->num_reqs > 0);
    return NULL;
}

static void start_data_plane_bh(void *opaque)
{
    VirtIOBlockDataPlane *s = opaque;

    qemu_bh_delete(s->start_bh);
    s->start_bh = NULL;
    qemu_thread_create(&s->thread, data_plane_thread,
                       s, QEMU_THREAD_JOINABLE);
}

bool virtio_blk_data_plane_create(VirtIODevice *vdev, VirtIOBlkConf *blk,
                                  VirtIOBlockDataPlane **dataplane)
{
    VirtIOBlockDataPlane *s;

    *dataplane = NULL;

    if (!blk->data_plane) {
        return true;
    }

    if (blk->scsi) {
        error_report("device is incompatible with x-data-plane, use scsi=off");
        return false;
    }

    if (blk->config_wce) {
        error_report("device is incompatible with x-data-plane, "
                     "use config-wce=off");
        return false;
    }

    /* If dataplane is (re-)enabled while the guest is running there could be
     * block jobs that can conflict.
     */
    if (bdrv_in_use(blk->conf.bs)) {
        error_report("cannot start dataplane thread while device is in use");
        return false;
    }

    s = g_new0(VirtIOBlockDataPlane, 1);
    s->vdev = vdev;
    s->blk = blk;
    s->bs = blk->conf.bs;

    /* Prevent block operations that conflict with data plane thread */
    bdrv_set_in_use(s->bs, 1);

    *dataplane = s;
    return true;
}

void virtio_blk_data_plane_destroy(VirtIOBlockDataPlane *s)
{
    if (!s) {
        return;
    }

    virtio_blk_data_plane_stop(s);
    bdrv_set_in_use(s->bs, 0);
    g_free(s);
}

void virtio_blk_data_plane_start(VirtIOBlockDataPlane *s)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(s->vdev)));
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(qbus);
    VirtQueue *vq;

    if (s->started) {
        return;
    }

    vq = virtio_get_queue(s->vdev, 0);
    if (!vring_setup(&s->vring, s->vdev, 0)) {
        return;
    }

    s->ctx = aio_context_new();

    /* Set up guest notifier (irq) */
    if (k->set_guest_notifiers(qbus->parent, 1, true) != 0) {
        fprintf(stderr, "virtio-blk failed to set guest notifier, "
                "ensure -enable-kvm is set\n");
        exit(1);
    }
    s->guest_notifier = virtio_queue_get_guest_notifier(vq);

    /* Set up virtqueue notify */
    if (k->set_host_notifier(qbus->parent, 0, true) != 0) {
        fprintf(stderr, "virtio-blk failed to set host notifier\n");
        exit(1);
    }
    s->host_notifier = *virtio_queue_get_host_notifier(vq);
    aio_set_event_notifier(s->ctx, &s->host_notifier, handle_notify, flush_true);

    s->started = true;
    trace_virtio_blk_data_plane_start(s);

    /* Kick right away to begin processing requests already in vring */
    event_notifier_set(virtio_queue_get_host_notifier(vq));

    /* Spawn thread in BH so it inherits iothread cpusets */
    s->start_bh = qemu_bh_new(start_data_plane_bh, s);
    qemu_bh_schedule(s->start_bh);
}

void virtio_blk_data_plane_stop(VirtIOBlockDataPlane *s)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(s->vdev)));
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(qbus);
    if (!s->started || s->stopping) {
        return;
    }
    s->stopping = true;
    trace_virtio_blk_data_plane_stop(s);

    /* Stop thread or cancel pending thread creation BH */
    if (s->start_bh) {
        qemu_bh_delete(s->start_bh);
        s->start_bh = NULL;
    } else {
        aio_notify(s->ctx);
        qemu_thread_join(&s->thread);
    }

    aio_set_event_notifier(s->ctx, &s->host_notifier, NULL, NULL);
    k->set_host_notifier(qbus->parent, 0, false);

    aio_context_unref(s->ctx);

    /* Clean up guest notifier (irq) */
    k->set_guest_notifiers(qbus->parent, 1, false);

    vring_teardown(&s->vring, s->vdev, 0);
    s->started = false;
    s->stopping = false;
}
