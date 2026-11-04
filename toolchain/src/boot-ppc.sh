#!/bin/sh
# Boot the BE-PPC hello-init under QEMU (g3beige/OpenBIOS, 4.9 BE kernel).
# Note: ppce500 needs an e500-flavored (cuImage) kernel; the Debian `powerpc`
# flavor boots via OpenBIOS on g3beige. Console fd wiring on g3beige (escc)
# is a known open item — see results/RESULTS.md.
# Usage: boot-ppc.sh <path-to-vmlinux-powerpc> [initramfs]
set -eu
KERNEL="${1:?usage: boot-ppc.sh <vmlinux-powerpc> [initramfs]}"
INITRD="${2:-$(dirname "$0")/../build/initramfs/initramfs-ppc-v2.cpio.gz}"
exec qemu-system-ppc -M g3beige \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append "console=ttyS0 rdinit=/init panic=-1" \
  -nographic -no-reboot
