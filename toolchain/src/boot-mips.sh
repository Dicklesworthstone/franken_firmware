#!/usr/bin/env bash
# Boot ffw-hello-init under qemu-system-mips (Malta, 24Kc BE, 64 MB RAM).
# Kernel: Debian stretch linux-image-4.19.0-0.bpo.5-4kc-malta (MIPS32R2 BE).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD="${FFW_BUILD_DIR:-${REPO_ROOT}/build}"
INITRAMFS="${FFW_INITRAMFS:-${BUILD}/initramfs/initramfs-mips.cpio.gz}"

exec qemu-system-mips \
  -M malta -cpu 24Kf -m 64M \
  -nographic -no-reboot \
  -kernel "${BUILD}/kernels/xm/boot/vmlinux-4.19.0-21-4kc-malta" \
  -initrd "${INITRAMFS}" \
  -append "console=ttyS0,38400 rdinit=/init panic=-1"
