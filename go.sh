#!/bin/bash
set -e

modprobe vfio-pci

if [ -f /sys/bus/pci/devices/0000\:00\:1f.0/driver/unbind ]; then
	# The LPC controller is in the same iommu_group so it needs to be
	# unbound too (yikes, but it seems to work)
	echo 0000\:00\:1f.0 >/sys/bus/pci/devices/0000\:00\:1f.0/driver/unbind
fi

if [ -f /sys/bus/pci/devices/0000\:00\:1f.2/driver/unbind ]; then
	echo 0000\:00\:1f.2 >/sys/bus/pci/devices/0000\:00\:1f.2/driver/unbind
	echo 8086 1d02 >/sys/bus/pci/drivers/vfio-pci/new_id
fi

exec x86_64-softmmu/qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -M q35 -vnc :0 -device vfio-pci,host=0000\:00\:1f.2,id=vfio-ahci -usb -usbdevice tablet "$@"
