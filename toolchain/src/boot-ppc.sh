#!/usr/bin/env bash
# Boot ffw-hello-init under qemu-system-ppc (g3beige, G3/750 BE, 64 MB RAM).
# Kernel: Debian jessie-backports linux-image-4.9.0-0.bpo.6-powerpc (32-bit BE PPC).
# Note: On QEMU g3beige, OpenFirmware attaches the serial port to Z85c30 ESCC
# (`pmac_zilog`, /dev/ttyPZ0, major 204 minor 192).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD="${FFW_BUILD_DIR:-${REPO_ROOT}/build}"
INITRAMFS="${FFW_INITRAMFS:-${BUILD}/initramfs/initramfs-ppc.cpio.gz}"

exec qemu-system-ppc \
  -M g3beige -cpu G3 -m 64M \
  -nographic -no-reboot \
  -kernel "${BUILD}/kernels/x/boot/vmlinux-4.9.0-0.bpo.6-powerpc" \
  -initrd "${INITRAMFS}" \
  -append "console=ttyPZ0,38400 rdinit=/init panic=-1"
