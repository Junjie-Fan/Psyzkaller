#!/bin/bash
#   usage: this script is used to build the syzkaller needed kernel
set -e
echo "!!!make sure that you are in the linux sourcecode dir!!!"


echo "make defconfig start..."
make defconfig
echo "make defconfig end!"
echo "make kvm_guest.config start..."
make kvm_guest.config
echo "make kvm_guest.config end!"

echo "config the kernel start..."
./scripts/config -e CONFIG_KCOV -e CONFIG_DEBUG_INFO -e CONFIG_KASAN \
-e CONFIG_KASAN_INLINE -e CONFIG_CONFIGFS_FS -e CONFIG_SECURITYFS \
-e CONFIG_CMDLINE_BOOL --set-str CONFIG_CMDLINE net.ifnames=0 -e CONFIG_VIRTIO_NET \
-e CONFIG_E1000 -e CONFIG_E1000E

echo "make olddefconfig start..."
make olddefconfig
echo "make olddefconfig end!"
echo "stating build... wait a minutes"
make -j 128


