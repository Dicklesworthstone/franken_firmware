#!/bin/sh
# Boot the BE-MIPS hello-init under QEMU (Malta, 4.19 BE kernel).
# Usage: boot-mips.sh <path-to-vmlinux-4kc-malta> [initramfs]
set -eu
KERNEL="${1:?usage: boot-mips.sh <vmlinux-4kc-malta> [initramfs]}"
INITRD="${2:-$(dirname "$0")/../build/initramfs/initramfs-mips-v2.cpio.gz}"
exec qemu-system-mips -M malta -cpu 24Kf \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append "console=ttyS0,38400 rdinit=/init panic=-1" \
  -nographic -no-reboot
