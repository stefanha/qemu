/* SPDX-License-Identifer: GPL-2.0-or-later */
/*
 * libqos virtio-fs device driver
 *
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef TESTS_LIBQOS_VIRTIO_FS_H
#define TESTS_LIBQOS_VIRTIO_FS_H

#include "libqos/virtio-pci.h"

#define VIRTIO_FS_TAG "myfs"

typedef struct {
    QVirtioDevice *vdev;
    QGuestAllocator *alloc;
    QVirtQueue *hiprio_vq;
    QVirtQueue *request_vq;
    uint64_t unique_counter;
} QVirtioFS;

typedef struct {
    QVirtioPCIDevice pci_vdev;
    QVirtioFS vfs;
} QVirtioFSPCI;

typedef struct {
    QOSGraphObject obj;
    QVirtioFS vfs;
} QVirtioFSDevice;

static inline uint64_t virtio_fs_get_unique(QVirtioFS *vfs)
{
    /*
     * Interrupt requests share the unique ID of the request, except the
     * least-significant bit.
     *
     * Note that unique ID 0 is invalid so we increment right away.
     */
    vfs->unique_counter += 2;

    return vfs->unique_counter;
}

#endif /* TESTS_LIBQOS_VIRTIO_FS_H */
