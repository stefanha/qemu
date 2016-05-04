/*
 * libqos virtio driver
 *
 * Copyright (c) 2014 Marc Marí
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/virtio.h"
#include "standard-headers/linux/virtio_config.h"
#include "standard-headers/linux/virtio_ring.h"

uint8_t qvirtio_config_readb(const QVirtioBus *bus, QVirtioDevice *d,
                                                                uint64_t addr)
{
    return bus->config_readb(d, addr);
}

uint16_t qvirtio_config_readw(const QVirtioBus *bus, QVirtioDevice *d,
                                                                uint64_t addr)
{
    return bus->config_readw(d, addr);
}

uint32_t qvirtio_config_readl(const QVirtioBus *bus, QVirtioDevice *d,
                                                                uint64_t addr)
{
    return bus->config_readl(d, addr);
}

uint64_t qvirtio_config_readq(const QVirtioBus *bus, QVirtioDevice *d,
                                                                uint64_t addr)
{
    return bus->config_readq(d, addr);
}

uint32_t qvirtio_get_features(const QVirtioBus *bus, QVirtioDevice *d)
{
    return bus->get_features(d);
}

void qvirtio_set_features(const QVirtioBus *bus, QVirtioDevice *d,
                                                            uint32_t features)
{
    bus->set_features(d, features);
}

QVirtQueue *qvirtqueue_setup(const QVirtioBus *bus, QVirtioDevice *d,
                                        QGuestAllocator *alloc, uint16_t index)
{
    return bus->virtqueue_setup(d, alloc, index);
}

void qvirtqueue_cleanup(const QVirtioBus *bus, QVirtQueue *vq,
                        QGuestAllocator *alloc)
{
    return bus->virtqueue_cleanup(vq, alloc);
}

void qvirtio_reset(const QVirtioBus *bus, QVirtioDevice *d)
{
    bus->set_status(d, 0);
    g_assert_cmphex(bus->get_status(d), ==, 0);
}

void qvirtio_set_acknowledge(const QVirtioBus *bus, QVirtioDevice *d)
{
    bus->set_status(d, bus->get_status(d) | VIRTIO_CONFIG_S_ACKNOWLEDGE);
    g_assert_cmphex(bus->get_status(d), ==, VIRTIO_CONFIG_S_ACKNOWLEDGE);
}

void qvirtio_set_driver(const QVirtioBus *bus, QVirtioDevice *d)
{
    bus->set_status(d, bus->get_status(d) | VIRTIO_CONFIG_S_DRIVER);
    g_assert_cmphex(bus->get_status(d), ==,
                    VIRTIO_CONFIG_S_DRIVER | VIRTIO_CONFIG_S_ACKNOWLEDGE);
}

void qvirtio_set_driver_ok(const QVirtioBus *bus, QVirtioDevice *d)
{
    bus->set_status(d, bus->get_status(d) | VIRTIO_CONFIG_S_DRIVER_OK);
    g_assert_cmphex(bus->get_status(d), ==, VIRTIO_CONFIG_S_DRIVER_OK |
                    VIRTIO_CONFIG_S_DRIVER | VIRTIO_CONFIG_S_ACKNOWLEDGE);
}

void qvirtio_wait_queue_isr(const QVirtioBus *bus, QVirtioDevice *d,
                            QVirtQueue *vq, gint64 timeout_us)
{
    gint64 start_time = g_get_monotonic_time();

    for (;;) {
        clock_step(100);
        if (bus->get_queue_isr_status(d, vq)) {
            return;
        }
        g_assert(g_get_monotonic_time() - start_time <= timeout_us);
    }
}

/* Wait for the status byte at given guest memory address to be set
 *
 * The virtqueue interrupt must not be raised, making this useful for testing
 * event_index functionality.
 */
uint8_t qvirtio_wait_status_byte_no_isr(const QVirtioBus *bus,
                                        QVirtioDevice *d,
                                        QVirtQueue *vq,
                                        uint64_t addr,
                                        gint64 timeout_us)
{
    gint64 start_time = g_get_monotonic_time();
    uint8_t val;

    while ((val = readb(addr)) == 0xff) {
        clock_step(100);
        g_assert(!bus->get_queue_isr_status(d, vq));
        g_assert(g_get_monotonic_time() - start_time <= timeout_us);
    }
    return val;
}

void qvirtio_wait_config_isr(const QVirtioBus *bus, QVirtioDevice *d,
                             gint64 timeout_us)
{
    gint64 start_time = g_get_monotonic_time();

    for (;;) {
        clock_step(100);
        if (bus->get_config_isr_status(d)) {
            return;
        }
        g_assert(g_get_monotonic_time() - start_time <= timeout_us);
    }
}

/**
 * qvirtio_wait_queue_buf:
 * @bus: the virtio bus
 * @d: the virtio device
 * @vq: the virtqueue
 *
 * Wait for the next buffer and check that it has the given token.
 *
 * Returns: the number of bytes written by the device.
 */
unsigned int qvirtio_wait_queue_buf(const QVirtioBus *bus, QVirtioDevice *d,
                                    QVirtQueue *vq, void *token,
                                    gint64 timeout_us)
{
    unsigned int len;
    void *actual_token;

    actual_token = qvirtqueue_get_buf(vq, &len);
    if (!actual_token) {
        qvirtio_wait_queue_isr(bus, d, vq, timeout_us);
        actual_token = qvirtqueue_get_buf(vq, &len);
    }
    g_assert(actual_token != NULL);
    g_assert(actual_token == token);

    return len;
}

void qvring_init(const QGuestAllocator *alloc, QVirtQueue *vq, uint64_t addr)
{
    int i;

    vq->desc = addr;
    vq->avail = vq->desc + vq->size * sizeof(struct vring_desc);
    vq->used = (uint64_t)((vq->avail + sizeof(uint16_t) * (3 + vq->size)
        + vq->align - 1) & ~(vq->align - 1));
    vq->free_head = 0;
    vq->num_free = vq->size;
    vq->last_used_idx = 0;

    for (i = 0; i < vq->size - 1; i++) {
        /* vq->desc[i].addr */
        writew(vq->desc + (16 * i), 0);
        /* vq->desc[i].next */
        writew(vq->desc + (16 * i) + 14, i + 1);

        vq->tokens[i] = NULL;
    }

    /* vq->avail->flags */
    writew(vq->avail, 0);
    /* vq->avail->idx */
    writew(vq->avail + 2, 0);
    /* vq->avail->used_event */
    writew(vq->avail + 4 + (2 * vq->size), 0);

    /* vq->used->flags */
    writew(vq->used, 0);
    /* vq->used->avail_event */
    writew(vq->used + 2 + sizeof(struct vring_used_elem) * vq->size, 0);
}

QVRingIndirectDesc *qvring_indirect_desc_setup(QVirtioDevice *d,
                                        QGuestAllocator *alloc, uint16_t elem)
{
    int i;
    QVRingIndirectDesc *indirect = g_malloc(sizeof(*indirect));

    indirect->index = 0;
    indirect->elem = elem;
    indirect->desc = guest_alloc(alloc, sizeof(struct vring_desc) * elem);

    for (i = 0; i < elem - 1; ++i) {
        /* indirect->desc[i].addr */
        writeq(indirect->desc + (16 * i), 0);
        /* indirect->desc[i].flags */
        writew(indirect->desc + (16 * i) + 12, VRING_DESC_F_NEXT);
        /* indirect->desc[i].next */
        writew(indirect->desc + (16 * i) + 14, i + 1);
    }

    return indirect;
}

void qvring_indirect_desc_add(QVRingIndirectDesc *indirect, uint64_t data,
                                                    uint32_t len, bool write)
{
    uint16_t flags;

    g_assert_cmpint(indirect->index, <, indirect->elem);

    flags = readw(indirect->desc + (16 * indirect->index) + 12);

    if (write) {
        flags |= VRING_DESC_F_WRITE;
    }

    /* indirect->desc[indirect->index].addr */
    writeq(indirect->desc + (16 * indirect->index), data);
    /* indirect->desc[indirect->index].len */
    writel(indirect->desc + (16 * indirect->index) + 8, len);
    /* indirect->desc[indirect->index].flags */
    writew(indirect->desc + (16 * indirect->index) + 12, flags);

    indirect->index++;
}

uint32_t qvirtqueue_add(QVirtQueue *vq, uint64_t data, uint32_t len, bool write,
                        bool next, void *token)
{
    uint16_t flags = 0;
    uint16_t idx = vq->free_head;

    g_assert_cmpint(vq->num_free, >=, 1);
    vq->num_free--;

    if (write) {
        flags |= VRING_DESC_F_WRITE;
    }

    if (next) {
        flags |= VRING_DESC_F_NEXT;
    }

    /* vq->desc[vq->free_head].addr */
    writeq(vq->desc + (16 * idx), data);
    /* vq->desc[vq->free_head].len */
    writel(vq->desc + (16 * idx) + 8, len);
    /* vq->desc[vq->free_head].flags */
    writew(vq->desc + (16 * idx) + 12, flags);

    vq->free_head = readw(vq->desc + sizeof(struct vring_desc) * idx +
                          offsetof(struct vring_desc, next));
    vq->tokens[idx] = token;

    return idx;
}

uint32_t qvirtqueue_add_indirect(QVirtQueue *vq, QVRingIndirectDesc *indirect,
                                 void *token)
{
    uint16_t idx = vq->free_head;

    g_assert(vq->indirect);
    g_assert_cmpint(vq->size, >=, indirect->elem);
    g_assert_cmpint(indirect->index, ==, indirect->elem);

    g_assert_cmpint(vq->num_free, >=, 1);
    vq->num_free--;

    /* vq->desc[vq->free_head].addr */
    writeq(vq->desc + (16 * idx), indirect->desc);
    /* vq->desc[vq->free_head].len */
    writel(vq->desc + (16 * idx) + 8,
           sizeof(struct vring_desc) * indirect->elem);
    /* vq->desc[vq->free_head].flags */
    writew(vq->desc + (16 * idx) + 12, VRING_DESC_F_INDIRECT);

    vq->free_head = readw(vq->desc + sizeof(struct vring_desc) * idx +
                          offsetof(struct vring_desc, next));
    vq->tokens[idx] = token;

    return idx;
}

static uint16_t get_desc_flags(QVirtQueue *vq, uint16_t idx)
{
    return readw(vq->desc + idx * sizeof(struct vring_desc) +
                 offsetof(struct vring_desc, flags));
}

static uint16_t get_desc_next(QVirtQueue *vq, uint16_t idx)
{
    return readw(vq->desc + idx * sizeof(struct vring_desc) +
                 offsetof(struct vring_desc, next));
}

static void set_desc_next(QVirtQueue *vq, uint16_t idx, uint16_t val)
{
    writew(vq->desc + idx * sizeof(struct vring_desc) +
           offsetof(struct vring_desc, next), val);
}

static void free_descs(QVirtQueue *vq, uint16_t head)
{
    uint16_t idx = head;

    for (idx = head;
         get_desc_flags(vq, idx) & VRING_DESC_F_NEXT;
         idx = get_desc_next(vq, idx)) {
        vq->num_free++;
    }
    vq->num_free++; /* also count the final descriptor */

    /* Add descriptors to free list */
    set_desc_next(vq, idx, vq->free_head);
    vq->free_head = head;
}

/**
 * qvirtqueue_get_buf:
 * @vq: the virtqueue
 * @len: the number of bytes written by the device
 *
 * Get the next used buffer from a virtqueue.
 *
 * Returns: the token given to qvirtqueue_add()/qvirtqueue_add_indirect() or
 * NULL if there are no more buffers.
 */
void *qvirtqueue_get_buf(QVirtQueue *vq, unsigned int *len)
{
    unsigned int head;
    void *token;
    /* vq->used->idx */
    uint16_t idx = readw(vq->used + offsetof(struct vring_used, idx));

    if (vq->last_used_idx == idx) {
        return NULL;
    }

    idx = vq->last_used_idx % vq->size;

    /* vq->used->ring[idx].id */
    head = readl(vq->used + offsetof(struct vring_used, ring) +
                 sizeof(struct vring_used_elem) * idx);
    g_assert_cmpint(head, <, vq->size);

    g_assert(vq->tokens[head]);
    token = vq->tokens[head];
    vq->tokens[head] = NULL;

    free_descs(vq, head);

    /* vq->used->ring[idx].len */
    *len = readl(vq->used + offsetof(struct vring_used, ring) +
                 sizeof(struct vring_used_elem) * idx +
                 offsetof(struct vring_used_elem, len));

    vq->last_used_idx++;

    return token;
}

void qvirtqueue_kick(const QVirtioBus *bus, QVirtioDevice *d, QVirtQueue *vq,
                                                            uint32_t free_head)
{
    /* vq->avail->idx */
    uint16_t idx = readl(vq->avail + 2);
    /* vq->used->flags */
    uint16_t flags;
    /* vq->used->avail_event */
    uint16_t avail_event;

    /* vq->avail->ring[idx % vq->size] */
    writel(vq->avail + 4 + (2 * (idx % vq->size)), free_head);
    /* vq->avail->idx */
    writel(vq->avail + 2, idx + 1);

    /* Must read after idx is updated */
    flags = readw(vq->avail);
    avail_event = readw(vq->used + 4 +
                                sizeof(struct vring_used_elem) * vq->size);

    /* < 1 because we add elements to avail queue one by one */
    if ((flags & VRING_USED_F_NO_NOTIFY) == 0 &&
                            (!vq->event || (uint16_t)(idx-avail_event) < 1)) {
        bus->virtqueue_kick(d, vq);
    }
}

void qvirtqueue_set_used_event(QVirtQueue *vq, uint16_t idx)
{
    g_assert(vq->event);

    /* vq->avail->used_event */
    writew(vq->avail + 4 + (2 * vq->size), idx);
}
