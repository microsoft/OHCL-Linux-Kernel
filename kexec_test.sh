#!/bin/sh
# Minimal reproducible kexec test for Underhill / VTL2 flow.
# Only what is needed to reproduce the original VTL2 protection (AccessDenied)
# issue prior to the init.rs idempotent fix.
set -euo pipefail

echo "[KEXEC] Building minimal initramfs"
INITRD_DIR="/dev/shm/initrd"
rm -rf "$INITRD_DIR"
mkdir -p "$INITRD_DIR" "$INITRD_DIR/bin" "$INITRD_DIR/dev" "$INITRD_DIR/etc" "$INITRD_DIR/run"

# Busybox + init
cp /bin/busybox "$INITRD_DIR/bin/busybox"; chmod 755 "$INITRD_DIR/bin/busybox"
for l in sh mount mkdir echo mknod dd od hexdump printf; do ln -sf busybox "$INITRD_DIR/bin/$l"; done
cp /bin/busybox "$INITRD_DIR/init" && chmod 755 "$INITRD_DIR/init"

# Devices
mknod "$INITRD_DIR/dev/console" c 5 1
mknod "$INITRD_DIR/dev/ttyS2" c 4 66
mknod "$INITRD_DIR/dev/null" c 1 3
mknod "$INITRD_DIR/dev/kmsg" c 1 11
mknod "$INITRD_DIR/dev/mem" c 1 1
mknod "$INITRD_DIR/dev/ttyprintk" c 5 3 || true
chmod 600 "$INITRD_DIR/dev/console" "$INITRD_DIR/dev/ttyS2" "$INITRD_DIR/dev/mem"
chmod 666 "$INITRD_DIR/dev/null" "$INITRD_DIR/dev/kmsg"
[ -e "$INITRD_DIR/dev/ttyprintk" ] || ln -sf kmsg "$INITRD_DIR/dev/ttyprintk"

# Underhill binary
TARGET=$(readlink -f /underhill-init 2>/dev/null || echo /usr/bin/openvmm_hcl)
[ -f "$TARGET" ] || { echo "[KEXEC] ERROR: underhill binary not found at $TARGET" >&2; exit 1; }
cp "$TARGET" "$INITRD_DIR/underhill-init"
cp "$TARGET" "$INITRD_DIR/bin/openvmm_hcl"
chmod 755 "$INITRD_DIR/underhill-init" "$INITRD_DIR/bin/openvmm_hcl"

# Module staging (updated layout: modules are flat under /boot/modules)
echo "[KEXEC] Staging required kernel modules"
mkdir -p "$INITRD_DIR/lib/modules"
stage_mod() {
    m=$1; src="/boot/modules/$m"; dst="$INITRD_DIR/lib/modules/$m";
    if [ -f "$src" ]; then
        cp "$src" "$dst"
    else
        echo "[KEXEC] WARN missing $src" >&2
    fi
}
stage_mod pci-hyperv-intf.ko
stage_mod pci-hyperv.ko
stage_mod hv_storvsc.ko

# Initramfs
IMG_PATH="/tmp/initramfs.gz"
( cd "$INITRD_DIR" && find . -print0 | cpio --null -o -H newc | gzip -1 > "$IMG_PATH" )

# Kernel cmdline (original reproduction set)
CMDLINE="loglevel=8 log_buf_len=128K printk.time=1 console_msg_format=syslog"
CMDLINE="$CMDLINE uio_hv_generic.no_mask=1 coredump_filter=0x33"
CMDLINE="$CMDLINE cpufreq.off=1 cpuidle.off=1 cryptomgr.notests idle=halt"
CMDLINE="$CMDLINE initcall_blacklist=init_real_mode,sbf_init lpj=3000000"
CMDLINE="$CMDLINE no_timer_check noxsave oops=panic panic_on_warn=0 panic_print=0 panic=-1"
CMDLINE="$CMDLINE printk.devkmsg=on reboot=t rootfstype=tmpfs tsc=reliable unknown_nmi_panic=1"
CMDLINE="$CMDLINE vfio_pci.ids=1414:00ba vfio.enable_unsafe_noiommu_mode=1"
CMDLINE="$CMDLINE hv_storvsc.storvsc_vcpus_per_sub_channel=2048 hv_storvsc.storvsc_max_hw_queues=2 hv_storvsc.storvsc_ringbuffer_size=0x8000"
CMDLINE="$CMDLINE MIMALLOC_ARENA_EAGER_COMMIT=0"
CMDLINE="$CMDLINE clearcpuid=pcid iommu=off pci=off swiotlb=1,1"
CMDLINE="$CMDLINE console=ttyS2,115200 boot_cpus=0 hv_vmbus.message_connection_id=0x800074"
CMDLINE="$CMDLINE rdinit=/underhill-init UNDERHILL_DIAG=1 HVLITE_LOG=debug RUST_BACKTRACE=full OPENHCL_NVME_VFIO=1"
[ -n "${EXTRA_CMDLINE:-}" ] && CMDLINE="$CMDLINE $EXTRA_CMDLINE"

# Locate measured VTL2 config page
echo "[KEXEC] Locating measured VTL2 config page"
parse_reg() { b=$(hexdump -v -n16 -e '16/1 "%02x"' "$1" 2>/dev/null || true); [ -z "$b" ] && return 1; a_hi=${b:0:8}; a_lo=${b:8:8}; s_hi=${b:16:8}; s_lo=${b:24:8}; REG_ADDR=$(( (0x$a_hi << 32) | 0x$a_lo )); REG_SIZE=$(( (0x$s_hi << 32) | 0x$s_lo )); }
ACCEPTED_BASE=
for f in /proc/device-tree/openhcl/memory@*/reg; do [ -f "$f" ] || continue; parse_reg "$f" || continue; if [ "$REG_SIZE" -eq 8192 ]; then ACCEPTED_BASE=$REG_ADDR; break; fi; done
[ -n "$ACCEPTED_BASE" ] || { echo "[KEXEC] ERROR: 8K accepted+measured region not found" >&2; exit 1; }
MEASURED_ADDR=$((ACCEPTED_BASE + 0x1000))
printf '[KEXEC] accepted_base=0x%016x measured_page=0x%016x\n' "$ACCEPTED_BASE" "$MEASURED_ADDR"

EXPECT=324c54564c43484f
CUR=$(dd if=/dev/mem bs=8 count=1 skip=$((MEASURED_ADDR/8)) 2>/dev/null | od -An -tx1 | tr -d ' \n')
echo "[KEXEC] current_magic=$CUR expect=$EXPECT"
if [ "$CUR" != "$EXPECT" ]; then
    printf '\x32\x4c\x54\x56\x4c\x43\x48\x4f' | dd of=/dev/mem bs=8 count=1 seek=$((MEASURED_ADDR/8)) conv=notrunc 2>/dev/null
    CUR=$(dd if=/dev/mem bs=8 count=1 skip=$((MEASURED_ADDR/8)) 2>/dev/null | od -An -tx1 | tr -d ' \n')
    echo "[KEXEC] magic_after=$CUR"
fi
[ "$CUR" = "$EXPECT" ] || { echo "[KEXEC] ERROR: failed to set magic" >&2; exit 1; }

# Patch VTL0 config magic at physical page 0 (needed to avoid second assert in vtl0_config.rs)
VTL0_EXPECT=304c54564c43484f
VTL0_CUR=$(dd if=/dev/mem bs=8 count=1 skip=0 2>/dev/null | od -An -tx1 | tr -d ' \n')
echo "[KEXEC] vtl0_current_magic=$VTL0_CUR expect=$VTL0_EXPECT"
if [ "$VTL0_CUR" != "$VTL0_EXPECT" ]; then
    printf '\x30\x4c\x54\x56\x4c\x43\x48\x4f' | dd of=/dev/mem bs=8 count=1 seek=0 conv=notrunc 2>/dev/null
    VTL0_CUR=$(dd if=/dev/mem bs=8 count=1 skip=0 2>/dev/null | od -An -tx1 | tr -d ' \n')
    echo "[KEXEC] vtl0_magic_after=$VTL0_CUR"
fi
[ "$VTL0_CUR" = "$VTL0_EXPECT" ] || { echo "[KEXEC] ERROR: failed to set VTL0 magic" >&2; exit 1; }

# Compile kexec_file_load helper if needed
KEXEC_DTB_HELPER="$(dirname "$0")/kexec_file_load_dtb"
if [ ! -x "$KEXEC_DTB_HELPER" ]; then
    echo "[KEXEC] Compiling kexec_file_load_dtb helper"
    gcc -o "$KEXEC_DTB_HELPER" "$(dirname "$0")/kexec_file_load_dtb.c" || {
        echo "[KEXEC] ERROR: failed to compile helper" >&2
        exit 1
    }
fi

# Kexec using kexec_file_load() with KEXEC_FILE_FORCE_DTB flag
echo "[KEXEC] Loading kernel with cmdline: $CMDLINE"
"$KEXEC_DTB_HELPER" /boot/bzImage "$IMG_PATH" "$CMDLINE" || {
    echo "[KEXEC] ERROR: kexec_file_load failed" >&2
    exit 1
}

echo "[KEXEC] Executing kexec"
sync
sleep 1
exec reboot -f
