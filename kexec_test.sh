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
    for cmd in sh mount mkdir echo mknod timeout find; do
        ln -sf busybox "$cmd"
    done
    cd -

    echo "[TEST3] Using busybox-based init (no C compilation, no lib copying, no kernel modules)"
    # Create a shell script as init that will run busybox properly
    cat > "$INITRD_DIR/init" << 'INIT_SCRIPT_EOF'
#!/bin/sh
echo "[DIAG] Custom init script starting busybox init..."
exec /bin/busybox init
INIT_SCRIPT_EOF
    chmod 755 "$INITRD_DIR/init"
    
    # Create minimal inittab that shows DTB status and waits for VMBus before underhill-init
    cat > "$INITRD_DIR/etc/inittab" << 'INITTAB_EOF'
# /etc/inittab - DTB diagnostics and VMBus-aware init

# Show DTB diagnostic info first
::sysinit:/bin/busybox echo "[DIAG] Starting init diagnostics..." >/dev/console 2>&1
::sysinit:/bin/busybox mount -t proc proc /proc >/dev/null 2>&1 || /bin/busybox echo "[DIAG] Failed to mount /proc" >/dev/console
::sysinit:/bin/busybox mount -t sysfs sysfs /sys >/dev/null 2>&1 || /bin/busybox echo "[DIAG] Failed to mount /sys" >/dev/console

# Check DTB status
::sysinit:/bin/busybox sh -c 'if [ -e /sys/firmware/fdt ]; then echo "[DIAG] DTB present: $(stat -c %s /sys/firmware/fdt 2>/dev/null || echo unknown) bytes"; else echo "[DIAG] No DTB in /sys/firmware/fdt"; fi' >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'if [ -e /extra/original_fdt.dtb ]; then echo "[DIAG] Embedded DTB: $(stat -c %s /extra/original_fdt.dtb 2>/dev/null || echo unknown) bytes"; else echo "[DIAG] No embedded DTB"; fi' >/dev/console 2>&1

# Check for VMBus and DeviceTree messages in dmesg
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Checking dmesg for VMBus messages..."; dmesg | grep -i vmbus' >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Checking dmesg for DeviceTree messages..."; dmesg | grep -i "devicetree\|device.tree\|dtb\|fdt\|unflatten"' >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Checking for hv_vmbus specific messages..."; dmesg | grep "hv_vmbus"' >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Checking for platform device messages..."; dmesg | grep -i "platform.*vmbus\|vmbus.*platform"' >/dev/console 2>&1

# Wait for VMBus to initialize before checking sysfs
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Waiting for VMBus initialization..."; for i in 1 2 3 4 5; do if [ -d /sys/bus/vmbus ]; then break; fi; sleep 1; done' >/dev/console 2>&1

# Check VMBus status
::sysinit:/bin/busybox sh -c 'if [ -d /sys/bus/vmbus ]; then echo "[DIAG] VMBus sysfs present"; if [ -d /sys/bus/vmbus/drivers/uio_hv_generic ]; then echo "[DIAG] uio_hv_generic driver present"; else echo "[DIAG] uio_hv_generic driver missing"; fi; ls /sys/bus/vmbus/devices 2>/dev/null | sed "s/^/[DIAG] VMBus device: /" || echo "[DIAG] No VMBus devices"; else echo "[DIAG] No VMBus sysfs"; fi' >/dev/console 2>&1

# Try to run underhill-init (it will mount devtmpfs) - but continue on failure for diagnostics
::sysinit:/bin/busybox echo "[DIAG] Trying to run underhill-init..." >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'timeout 5 /underhill-init noxsave || echo "[DIAG] underhill-init failed after 5 seconds, continuing with diagnostics..."' >/dev/console 2>&1

# Run extended diagnostics even if underhill-init fails
::sysinit:/bin/busybox echo "[DIAG] === EXTENDED DIAGNOSTICS ===" >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Full dmesg VMBus search:"; dmesg | grep -i vmbus | while read line; do echo "[DIAG] $line"; done' >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Searching for DeviceTree messages:"; dmesg | grep -i "devicetree\|device.tree" | while read line; do echo "[DIAG] $line"; done' >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'echo "[DIAG] Checking /sys/firmware structure:"; find /sys/firmware -type f 2>/dev/null | head -10 | while read f; do echo "[DIAG] Found: $f"; done' >/dev/console 2>&1

# Try to manually create VMBus platform device since DTB register is lost
::sysinit:/bin/busybox echo "[DIAG] Attempting to manually create VMBus platform device..." >/dev/console 2>&1
::sysinit:/bin/busybox sh -c 'if [ -d /sys/bus/platform/devices ] && [ ! -d /sys/bus/platform/devices/vmbus ]; then echo vmbus > /sys/bus/platform/drivers_probe 2>/dev/null || echo "[DIAG] Failed to manually probe vmbus driver"; fi' >/dev/console 2>&1

::sysinit:/bin/busybox sh -c 'sleep 2; if [ -d /sys/bus/vmbus ]; then echo "[DIAG] SUCCESS: VMBus created after manual intervention"; else echo "[DIAG] FAILED: VMBus still not available"; fi' >/dev/console 2>&1

# Keep console open for manual inspection
::respawn:/bin/busybox sh >/dev/console 2>&1
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

# Handle DTB (Device Tree Blob) - save from /sys/firmware/fdt if present
ORIG_DTB="/boot/original_fdt.dtb"
DTB_SOURCE=""
if [ -f /sys/firmware/fdt ]; then
    if [ ! -f "$ORIG_DTB" ]; then
        cp /sys/firmware/fdt "$ORIG_DTB" && echo "[TEST3] Saved original DTB to $ORIG_DTB"
    fi
    DTB_SOURCE="$ORIG_DTB"
    echo "[TEST3] DTB found: $(stat -c %s /sys/firmware/fdt) bytes"
    
    # Verify DTB contains VMBus information
    if command -v strings >/dev/null 2>&1; then
        if strings /sys/firmware/fdt | grep -i vmbus >/dev/null 2>&1; then
            echo "[TEST3] DTB contains VMBus references"
            strings /sys/firmware/fdt | grep -i vmbus | head -3 | sed 's/^/[TEST3] DTB VMBus: /'
        else
            echo "[TEST3] WARNING: DTB does not contain VMBus references"
        fi
    else
        echo "[TEST3] Cannot verify DTB contents (strings command not available)"
    fi
elif [ -f "$ORIG_DTB" ]; then
    DTB_SOURCE="$ORIG_DTB"
    echo "[TEST3] Using previously saved DTB: $DTB_SOURCE"
    
    # Verify saved DTB contains VMBus information
    if command -v strings >/dev/null 2>&1 && strings "$DTB_SOURCE" | grep -i vmbus >/dev/null 2>&1; then
        echo "[TEST3] Saved DTB contains VMBus references"
    else
        echo "[TEST3] WARNING: Saved DTB may not contain VMBus references"
    fi
else
    echo "[TEST3] No DTB found in /sys/firmware/fdt or $ORIG_DTB"
fi

# Embed DTB in initramfs for reference
if [ -n "$DTB_SOURCE" ] && [ -f "$DTB_SOURCE" ]; then
    mkdir -p "$INITRD_DIR/extra"
    cp "$DTB_SOURCE" "$INITRD_DIR/extra/original_fdt.dtb"
    echo "[TEST3] Embedded DTB in initramfs at /extra/original_fdt.dtb"
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
CMDLINE="$CMDLINE init=/init"  # Use our busybox init to run diagnostics first
CMDLINE="$CMDLINE debug loglevel=8 ignore_loglevel"
# Remove nosmp maxcpus=1 that may interfere with VMBus
# CMDLINE="$CMDLINE nosmp maxcpus=1"
CMDLINE="$CMDLINE noxsave"  # Required in this environment
CMDLINE="$CMDLINE acpi=off"  # Force DeviceTree path for VMBus  
CMDLINE="$CMDLINE of_platform.disable_pseudo_devices=0"  # Enable OF platform device creation
CMDLINE="$CMDLINE earlycon=ttyS2,115200n8"  # Early console to catch DTB messages
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
# TESTING: Enable compaction_proactiveness to match original boot exactly
# CMDLINE="$CMDLINE sysctl.vm.compaction_proactiveness=0"  # Commented out - may break boot
CMDLINE="$CMDLINE OPENHCL_NVME_VFIO=1 MIMALLOC_ARENA_EAGER_COMMIT=0 UNDERHILL_DIAG=1 HVLITE_LOG=debug RUST_BACKTRACE=full"

# Add DTB path to kernel command line if we have one
if [ -n "$DTB_SOURCE" ] && [ -f "$DTB_SOURCE" ]; then
    CMDLINE="$CMDLINE ORIG_DTB_PATH=/extra/original_fdt.dtb"
fi

echo "[TEST3] Loading kernel..."
echo "[TEST3] Command line: $CMDLINE"

# Try to pass DTB explicitly with --dtb if supported and available
if [ -n "$DTB_SOURCE" ] && [ -f "$DTB_SOURCE" ]; then
    # Test if kexec supports --dtb for bzImage
    if /sbin/kexec --help 2>&1 | awk '/^bzImage$/{f=1;next}/^bzImage64$/{f=0}f && /--dtb=FILE/{print;exit}' | grep -q dtb; then
        TMP_DTB="/tmp/kexec-dtb.dtb"
        cp "$DTB_SOURCE" "$TMP_DTB"
        echo "[TEST3] Trying to load with explicit DTB: $TMP_DTB"
        # Try with file-based syscall first (newer method)
        if /sbin/kexec -s -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga --dtb="$TMP_DTB" 2>/tmp/kexec_dtb_error.log; then
            echo "[TEST3] Successfully loaded with DTB support (file-based syscall)"
        # Try with preserve context and file-based syscall
        elif /sbin/kexec -s -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga --dtb="$TMP_DTB" --load-preserve-context 2>/tmp/kexec_dtb_error2.log; then
            echo "[TEST3] Successfully loaded with DTB support and preserve-context (file-based)"
        # Fall back to regular kexec_load syscall
        elif /sbin/kexec -c -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga --dtb="$TMP_DTB" 2>/tmp/kexec_dtb_error3.log; then
            echo "[TEST3] Successfully loaded with DTB support (compatibility syscall)"
        else
            echo "[TEST3] All DTB load attempts failed, trying without --dtb:"
            cat /tmp/kexec_dtb_error.log >&2
            cat /tmp/kexec_dtb_error2.log >&2  
            cat /tmp/kexec_dtb_error3.log >&2
            /sbin/kexec -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga || {
                echo "[TEST3] Failed to load kernel even without DTB"
                dmesg | tail -n 20
                exit 1
            }
        fi
    else
        echo "[TEST3] kexec doesn't support --dtb for bzImage, loading without explicit DTB"
        /sbin/kexec -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga || {
            echo "[TEST3] Failed to load kernel"
            dmesg | tail -n 20
            exit 1
        }
    fi
else
    echo "[TEST3] No DTB available, loading without DTB support"
    /sbin/kexec -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga || {
        echo "[TEST3] Failed to load kernel"
        dmesg | tail -n 20
        exit 1
    }
fi

echo "[TEST3] Executing kexec..."
sync
sleep 1
dmesg > /tmp/dmesg.log 2>/dev/null || true
exec /sbin/kexec -e
