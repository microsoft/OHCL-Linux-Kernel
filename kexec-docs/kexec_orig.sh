#!/bin/sh
# Test 3: Remove kernel modules copying

set -e

echo "[TEST3] Creating minimal static initramfs..."

# Use RAM-based directory to avoid disk space issues
mkdir -p /dev/shm 2>/dev/null || true
INITRD_DIR="/dev/shm/initrd"
rm -rf "$INITRD_DIR"
mkdir -p "$INITRD_DIR"
mkdir -p "$INITRD_DIR/bin"

# Add busybox and required libraries
if [ -f "/bin/busybox" ]; then
    echo "[TEST3] Setting up busybox..."
    mkdir -p "$INITRD_DIR/bin" "$INITRD_DIR/lib" "$INITRD_DIR/lib64" "$INITRD_DIR/etc" "$INITRD_DIR/dev"
    
    # Create essential device nodes including ttyprintk for underhill_init
    mknod "$INITRD_DIR/dev/console" c 5 1
    mknod "$INITRD_DIR/dev/ttyS0" c 4 64
    mknod "$INITRD_DIR/dev/ttyS2" c 4 66
    mknod "$INITRD_DIR/dev/null" c 1 3
    mknod "$INITRD_DIR/dev/kmsg" c 1 11
    mknod "$INITRD_DIR/dev/ttyprintk" c 5 3
    chmod 600 "$INITRD_DIR/dev/console" "$INITRD_DIR/dev/ttyS0" "$INITRD_DIR/dev/ttyS2" "$INITRD_DIR/dev/ttyprintk"
    chmod 666 "$INITRD_DIR/dev/null" "$INITRD_DIR/dev/kmsg"
    
    # Copy busybox to /bin for commands
    cp "/bin/busybox" "$INITRD_DIR/bin/busybox"
    chmod 755 "$INITRD_DIR/bin/busybox"
    
    # Create minimal essential symlinks
    cd "$INITRD_DIR/bin"
    for cmd in sh mount mkdir echo mknod; do
        ln -sf busybox "$cmd"
    done
    cd -

    echo "[TEST3] Using busybox-based init (no C compilation, no lib copying, no kernel modules)"
    # Copy busybox as init directly
    cp "/bin/busybox" "$INITRD_DIR/init"
    chmod 755 "$INITRD_DIR/init"
    
    # Create minimal inittab that only runs underhill-init
    cat > "$INITRD_DIR/etc/inittab" << 'INITTAB_EOF'
# /etc/inittab - Minimal version that only runs underhill-init

# Try to run underhill-init (it will mount devtmpfs)
::sysinit:/bin/busybox echo "Trying to run underhill-init..." >/dev/console 2>&1
::sysinit:/bin/sh -c 'for p in /underhill-init /usr/bin/underhill-init /bin/underhill-init /usr/bin/openvmm_hcl; do if [ -x "$p" ]; then exec "$p"; fi; done'
INITTAB_EOF
fi

# Copy underhill-init to root location like original boot
REAL_TARGET=$(readlink -f /underhill-init 2>/dev/null || echo "/usr/bin/openvmm_hcl")
if [ -f "$REAL_TARGET" ]; then
    echo "[TEST3] Found target binary at $REAL_TARGET"
    cp "$REAL_TARGET" "$INITRD_DIR/underhill-init"
    chmod 755 "$INITRD_DIR/underhill-init"
    echo "[TEST3] Copied underhill-init to /underhill-init in initramfs"
fi

# Create initramfs
echo "[TEST3] Creating initramfs..."
IMG_PATH="/tmp/initramfs.gz"
rm -f "$IMG_PATH"

(cd "$INITRD_DIR" && find . -print0 | cpio --null -o -H newc | gzip -1 > "$IMG_PATH") || {
    echo "[TEST3] Failed to create initramfs"
    exit 1
}

# Build minimal cmdline - use rdinit like original boot and remove conflicting parameters
CMDLINE="console=ttyS2,115200n8 console=ttyS0,115200n8"
CMDLINE="$CMDLINE rootfstype=tmpfs rw"
CMDLINE="$CMDLINE rdinit=/underhill-init"  # Use rdinit like original boot
CMDLINE="$CMDLINE debug loglevel=8 ignore_loglevel"
# Remove nosmp maxcpus=1 that may interfere with VMBus
# CMDLINE="$CMDLINE nosmp maxcpus=1"
CMDLINE="$CMDLINE noxsave"  # Required in this environment
# All working parameters from original boot
CMDLINE="$CMDLINE log_buf_len=128K printk.time=1 console_msg_format=syslog"
CMDLINE="$CMDLINE uio_hv_generic.no_mask=1 coredump_filter=0x33"
CMDLINE="$CMDLINE cpufreq.off=1 cpuidle.off=1 cryptomgr.notests idle=halt"
CMDLINE="$CMDLINE initcall_blacklist=init_real_mode,sbf_init lpj=3000000"
CMDLINE="$CMDLINE no_timer_check oops=panic panic_on_warn=0 panic_print=0 panic=-1"
CMDLINE="$CMDLINE printk.devkmsg=on reboot=t tsc=reliable unknown_nmi_panic=1"
CMDLINE="$CMDLINE vfio_pci.ids=1414:00ba vfio.enable_unsafe_noiommu_mode=1"
CMDLINE="$CMDLINE hv_storvsc.storvsc_vcpus_per_sub_channel=2048 hv_storvsc.storvsc_max_hw_queues=2 hv_storvsc.storvsc_ringbuffer_size=0x8000"
CMDLINE="$CMDLINE clearcpuid=pcid iommu=off pci=off swiotlb=1,1"
CMDLINE="$CMDLINE console=ttyS2,115200 boot_cpus=0 hv_vmbus.message_connection_id=0x800074"
# SKIP: sysctl.vm.compaction_proactiveness=0 - BREAKS BOOT
CMDLINE="$CMDLINE OPENHCL_NVME_VFIO=1 MIMALLOC_ARENA_EAGER_COMMIT=0 UNDERHILL_DIAG=1 HVLITE_LOG=debug RUST_BACKTRACE=full"

echo "[TEST3] Loading kernel..."
/sbin/kexec -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga || {
    echo "[TEST3] Failed to load kernel"
    dmesg | tail -n 20
    exit 1
}

echo "[TEST3] Executing kexec..."
sync
sleep 1
dmesg > /tmp/dmesg.log 2>/dev/null || true
exec /sbin/kexec -e