DTB changes explaination:

## Kernel Changes (arch/x86/kernel/kexec-bzimage64.c)

### 1. Added Required Headers
```c
#include <linux/libfdt.h>
#include <linux/of_fdt.h>
```
These provide the FDT (Flattened Device Tree) functions and `initial_boot_params` declaration.

### 2. DTB Discovery and Preservation Logic
Added automatic DTB preservation right after purgatory loading:

```c
/* DTB support - preserve current system DTB for acpi=off compatibility */
void *dtb_data = NULL;
unsigned long dtb_size = 0;

#ifdef CONFIG_OF_EARLY_FLATTREE
if (initial_boot_params) {
    /* Validate and preserve the current DTB */
    if (fdt_check_header(initial_boot_params) == 0) {
        unsigned long total = fdt_totalsize(initial_boot_params);
        if (total > 0 && total < SZ_1M) { /* sanity check */
            dtb_data = kmalloc(total, GFP_KERNEL);
            if (dtb_data) {
                memcpy(dtb_data, initial_boot_params, total);
                dtb_size = total;
                pr_info("kexec: preserving current DTB (size=%lu bytes)\n", dtb_size);
            }
        }
    }
}
#endif
```

**What this does:**
- Checks if `initial_boot_params` (current kernel's DTB) exists
- Validates the DTB header using `fdt_check_header()`
- Gets the total DTB size using `fdt_totalsize()`
- Makes a copy of the DTB data to preserve it

### 3. Buffer Space Allocation
Added space reservation for DTB in the kexec buffer:

```c
#ifdef CONFIG_OF_EARLY_FLATTREE
unsigned int dtb_setup_data_offset = 0;
if (dtb_size) {
    /* Reserve space for DTB setup_data (header + blob) */
    dtb_setup_data_offset = kbuf.bufsz;
    kbuf.bufsz += sizeof(struct setup_data) + dtb_size;
    pr_info("kexec: reserving %lu bytes for DTB setup_data entry\n", dtb_size);
}
#endif
```

### 4. Modified Function Signature
Extended `setup_boot_parameters()` to accept DTB parameters:

```c
setup_boot_parameters(struct kimage *image, struct boot_params *params,
                     unsigned long params_load_addr,
                     unsigned int efi_map_offset, unsigned int efi_map_sz,
                     unsigned int setup_data_offset,
                     void *dtb_data, unsigned long dtb_size, 
                     unsigned int dtb_setup_data_offset)
```

### 5. DTB Setup Data Creation
Added DTB to the setup_data chain in `setup_boot_parameters()`:

```c
#ifdef CONFIG_OF_EARLY_FLATTREE
/* Setup DTB */
if (dtb_data && dtb_size) {
    struct setup_data *sd = (void *)params + dtb_setup_data_offset;
    unsigned long phys = params_load_addr + dtb_setup_data_offset;
    sd->type = SETUP_DTB;
    sd->len = dtb_size;
    memcpy(sd->data, dtb_data, dtb_size);
    /* Prepend to existing chain */
    sd->next = params->hdr.setup_data;
    params->hdr.setup_data = phys;
    pr_info("kexec: inserted DTB setup_data entry phys=0x%lx len=%lu\n", phys, dtb_size);
    
    /* Free the temporary DTB copy */
    kfree(dtb_data);
}
#endif
```

**What this does:**
- Creates a `setup_data` structure with `SETUP_DTB` type
- Copies the preserved DTB data into the setup_data payload
- Links it to the existing setup_data chain
- The new kernel will receive this DTB via the same mechanism as the original boot

## Script Changes (kexec_test.sh)

The script changes were actually a **simplification** - I removed the complex DTB extraction and `--dtb` flag attempts:

### Before (complex, non-working):
```bash
# Try to pass DTB if available - use file-based kexec
DTB_ARG=""
if [ -r /sys/firmware/fdt ]; then
    cp /sys/firmware/fdt /tmp/kexec.dtb 2>/dev/null && DTB_ARG="--dtb=/tmp/kexec.dtb"
    echo "[KEXEC] Extracted DTB from /sys/firmware/fdt (size $(stat -c%s /tmp/kexec.dtb))"
fi

if [ -n "$DTB_ARG" ]; then
    /sbin/kexec -l -s /boot/bzImage $DTB_ARG --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga
else
    /sbin/kexec -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga
fi
```

### After (simple, working):
```bash
echo "[KEXEC] Loading kernel with cmdline: $CMDLINE"
/sbin/kexec -l /boot/bzImage --initrd="$IMG_PATH" --command-line="$CMDLINE" --reset-vga
echo "[KEXEC] Executing kexec"
exec /sbin/kexec -e
```

**Why this works:**
- The kernel now automatically preserves the DTB without needing userspace `--dtb` flag
- Uses the standard syscall-based kexec path (not file-based)
- No need for DTB extraction to `/tmp/kexec.dtb`

## How DTB Preservation Works

1. **First Kernel Boot:** DTB passed via bootloader → stored in `initial_boot_params`
2. **Kexec Load:** My kernel code automatically copies DTB from `initial_boot_params` → creates `SETUP_DTB` entry
3. **Second Kernel Boot:** New kernel receives DTB via setup_data → processes it in `add_dtb()` → stores in `initial_dtb` → unflattenizes to `initial_boot_params`
4. **VMBus Init:** With `acpi=off`, VMBus uses DeviceTree path → finds VMBus nodes in DTB → initializes successfully
