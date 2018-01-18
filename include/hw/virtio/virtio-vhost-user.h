/*
 * Virtio Vhost-user Device
 *
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Authors:
 *  Stefan Hajnoczi   <stefanha@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_VIRTIO_VHOST_USER_H
#define QEMU_VIRTIO_VHOST_USER_H

#include "hw/virtio/virtio.h"
#include "hw/virtio/vhost-user.h"
#include "chardev/char-fe.h"

#define TYPE_VIRTIO_VHOST_USER "virtio-vhost-user-device"
#define VIRTIO_VHOST_USER(obj) \
        OBJECT_CHECK(VirtIOVhostUser, (obj), TYPE_VIRTIO_VHOST_USER)

/* The virtio configuration space fields */
typedef struct {
    uint32_t status;
#define VIRTIO_VHOST_USER_STATUS_SLAVE_UP 0
#define VIRTIO_VHOST_USER_STATUS_MASTER_UP 1
    uint32_t max_vhost_queues;
    uint8_t uuid[16];
} QEMU_PACKED VirtIOVhostUserConfig;

/* Keep track of the mmap for each memory table region */
typedef struct {
    MemoryRegion mr;
    void *mmap_addr;
    size_t total_size;
} VirtIOVhostUserMemTableRegion;

typedef struct VirtIOVhostUser VirtIOVhostUser;
struct VirtIOVhostUser {
    VirtIODevice parent_obj;

    /* The vhost-user socket */
    CharBackend chr;

    /* TODO implement "Additional Device Resources over PCI" so that PCI
     * details are hidden:
     * https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2920007
     */
    MemoryRegion additional_resources_bar;
    MemoryRegion doorbell_region;

    /* Eventfds from VHOST_USER_SET_VRING_CALL */
    int callfds[VIRTIO_QUEUE_MAX];

    /* Mapped memory regions from VHOST_USER_SET_MEM_TABLE */
    VirtIOVhostUserMemTableRegion mem_table[VHOST_MEMORY_MAX_NREGIONS];

    VirtIOVhostUserConfig config;

    /* Connection establishment state */
    int conn_state;

    /* Device-to-driver message queue */
    VirtQueue *rxq;

    /* Driver-to-device message queue */
    VirtQueue *txq;

    /* Asynchronous read state */
    int read_bytes_needed;
    void *read_ptr;
    void (*read_done)(VirtIOVhostUser *s);
    VhostUserMsg read_msg;
    bool read_waiting_on_rxq; /* need rx buffer? */
    size_t read_msg_size;

    /* Asynchronous write state */
    int write_bytes_avail;
    void *write_ptr;
    void (*write_done)(VirtIOVhostUser *s);
    VhostUserMsg write_msg;
    guint write_watch_tag;
};

#endif /* QEMU_VIRTIO_VHOST_USER_H */
