/* SPDX-License-Identifer: GPL-2.0-or-later */
/*
 * libqos virtio-fs device driver
 *
 * Copyright (C) 2019 Red Hat, Inc.
 */

#include "qemu/osdep.h"
#include "standard-headers/linux/virtio_fs.h"
#include "libqos/virtio-fs.h"

static void virtio_fs_cleanup(QVirtioFS *vfs)
{
    QVirtioDevice *vdev = vfs->vdev;

    qvirtqueue_cleanup(vdev->bus, vfs->hiprio_vq, vfs->alloc);
    qvirtqueue_cleanup(vdev->bus, vfs->request_vq, vfs->alloc);
    vfs->hiprio_vq = NULL;
    vfs->request_vq = NULL;
}

static void virtio_fs_setup(QVirtioFS *vfs)
{
    QVirtioDevice *vdev = vfs->vdev;
    uint64_t features;

    features = qvirtio_get_features(vdev);
    features &= ~(QVIRTIO_F_BAD_FEATURE |
                  (1ull << VIRTIO_RING_F_EVENT_IDX));
    qvirtio_set_features(vdev, features);

    vfs->hiprio_vq = qvirtqueue_setup(vdev, vfs->alloc, 0);
    vfs->request_vq = qvirtqueue_setup(vdev, vfs->alloc, 1);

    qvirtio_set_driver_ok(vdev);
}

static void vhost_user_fs_pci_destructor(QOSGraphObject *obj)
{
    QVirtioFSPCI *vfs_pci = (QVirtioFSPCI *)obj;
    QVirtioFS *vfs = &vfs_pci->vfs;

    virtio_fs_cleanup(vfs);
    qvirtio_pci_destructor(&vfs_pci->pci_vdev.obj);
}

static void vhost_user_fs_pci_start_hw(QOSGraphObject *obj)
{
    QVirtioFSPCI *vfs_pci = (QVirtioFSPCI *)obj;
    QVirtioFS *vfs = &vfs_pci->vfs;

    qvirtio_pci_start_hw(&vfs_pci->pci_vdev.obj);
    virtio_fs_setup(vfs);
}

static void *vhost_user_fs_pci_get_driver(void *object, const char *interface)
{
    QVirtioFSPCI *vfs_pci = object;

    if (g_strcmp0(interface, "virtio-fs") == 0) {
        return &vfs_pci->vfs;
    }

    fprintf(stderr, "%s not present in virtio-fs\n", interface);
    g_assert_not_reached();
}

static void *vhost_user_fs_pci_create(void *pci_bus, QGuestAllocator *alloc, void *addr)
{
    QVirtioFSPCI *vfs_pci = g_new0(QVirtioFSPCI, 1);
    QVirtioFS *vfs = &vfs_pci->vfs;
    QOSGraphObject *obj = &vfs_pci->pci_vdev.obj;

    virtio_pci_init(&vfs_pci->pci_vdev, pci_bus, addr);
    vfs->vdev = &vfs_pci->pci_vdev.vdev;
    vfs->alloc = alloc;

    g_assert_cmphex(vfs->vdev->device_type, ==, VIRTIO_ID_FS);

    obj->destructor = vhost_user_fs_pci_destructor;
    obj->start_hw = vhost_user_fs_pci_start_hw;
    obj->get_driver = vhost_user_fs_pci_get_driver;

    return obj;
}

static void virtio_fs_register_nodes(void)
{
    QOSGraphEdgeOptions opts = {
        .extra_device_opts = "chardev=char-virtio-fs,addr=04.0,tag=" VIRTIO_FS_TAG,
        .before_cmd_line = "-m 512M -object memory-backend-file,id=mem,"
            "size=512M,mem-path=/dev/shm,share=on -numa node,memdev=mem",
    };
    QPCIAddress addr = {
        .devfn = QPCI_DEVFN(4, 0),
    };

    add_qpci_address(&opts, &addr);
    qos_node_create_driver("vhost-user-fs-pci", vhost_user_fs_pci_create);
    qos_node_consumes("vhost-user-fs-pci", "pci-bus", &opts);
    qos_node_produces("vhost-user-fs-pci", "virtio-fs");
}

libqos_init(virtio_fs_register_nodes);
