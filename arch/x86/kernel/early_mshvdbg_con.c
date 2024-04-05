#include <linux/console.h>
#include <linux/init.h>
#include <linux/version.h>

#include <asm/mshyperv.h>

#include <asm/tdx.h>

#define HVCALL_OUTPUT_DEBUG_CHAR 0x0071

static int connected_to_hv = 0;

static void __naked __aligned(4096)
early_hvcall_pg(void)
{
    asm (".skip 4096, 0xf1");
}

static u8 early_hvcall_pg_input[4096]  __attribute__((aligned(4096)));
static u8 __maybe_unused early_hvcall_pg_output[4096] __attribute__((aligned(4096)));

static void early_connect_to_hv(void)
{
    union hv_x64_msr_hypercall_contents hypercall_msr;
    u64 guest_id;

    if (connected_to_hv)
        return;

    guest_id = hv_generate_guest_id(LINUX_VERSION_CODE);
    wrmsrl(HV_X64_MSR_GUEST_OS_ID, guest_id);

    rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
    hypercall_msr.enable = 1;
    hypercall_msr.guest_physical_address = __phys_to_pfn(virt_to_phys(early_hvcall_pg));
    wrmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
}

static u64 early_hypercall(u64 control, void* input, void* output)
{
    u64 input_address = input ? virt_to_phys(input) : 0;
    u64 output_address = output ? virt_to_phys(output) : 0;
    u64 hv_status;
    void* hvcall_pg = hv_hypercall_pg ? hv_hypercall_pg : early_hvcall_pg;

    __asm__ __volatile__("mov %4, %%r8\n"
                 CALL_NOSPEC
                 : "=a" (hv_status), ASM_CALL_CONSTRAINT,
                   "+c" (control), "+d" (input_address)
                 :  "r" (output_address),
                THUNK_TARGET(hvcall_pg)
                 : "cc", "memory", "r8", "r9", "r10", "r11");

    return hv_status;
}

static void early_log_to_mshvdbg_hvcall(const char* str, size_t len)
{
    size_t i;
    void *hvcall_in;
	unsigned long flags;

    if (!str)
        return;

    if (hyperv_pcpu_input_arg) {
		local_irq_save(flags);
		hvcall_in = *this_cpu_ptr(hyperv_pcpu_input_arg);
    } else
        hvcall_in = early_hvcall_pg_input;

    for (i = 0; i < len; ++i) {
        *(char*)hvcall_in = str[i];
        early_hypercall(HVCALL_OUTPUT_DEBUG_CHAR, hvcall_in, NULL);
    }

    if (hyperv_pcpu_input_arg)
		local_irq_restore(flags);
}

#define GHCB_INFO_SPECIAL_DBGPRINT 0xf03
#define GHCB_INFO_SPECIAL_SHUTDOWN 0x100

void early_log_to_mshvdbg_ghcb(const char *buf, unsigned len)
{
	int idx;
	u64 orig_val;
    u64 val;
	unsigned long flags;
    int uneven_head;

    if (hyperv_pcpu_input_arg)
		local_irq_save(flags);
	orig_val = __rdmsr(MSR_AMD64_SEV_ES_GHCB);

    uneven_head = len % 6;
    if (uneven_head) {
        val = GHCB_INFO_SPECIAL_DBGPRINT;
        memcpy(2 + (char*)&val, buf, uneven_head);
        native_wrmsrl(MSR_AMD64_SEV_ES_GHCB, val);
        asm volatile ("rep; vmmcall" : : : "cc", "memory");
    }

	for (idx = uneven_head; idx < len; idx += 6) {
        val = GHCB_INFO_SPECIAL_DBGPRINT;
        memcpy(2 + (char*)&val, buf + idx, 6);
        native_wrmsrl(MSR_AMD64_SEV_ES_GHCB, val);
		asm volatile ("rep; vmmcall" : : : "cc", "memory");
	}

	native_wrmsrl(MSR_AMD64_SEV_ES_GHCB, orig_val);
    if (hyperv_pcpu_input_arg)
		local_irq_restore(flags);
}

#define TDX_MSR_SPECIAL_DEBUG_PRINT 0x400000C1

static void tdx_write_msr(u32 index, u64 value)
{
	struct tdx_hypercall_args args = {
		.r10 = TDX_HYPERCALL_STANDARD,
		// .r11 = EXIT_REASON_MSR_WRITE,
        .r11 = 32,
		.r12 = index,
		.r13 = value,
	};

	/*
	 * Emulate the MSR write via hypercall. More info about ABI
	 * can be found in TDX Guest-Host-Communication Interface
	 * (GHCI) section titled "TDG.VP.VMCALL<Instruction.WRMSR>".
	 */
	__tdx_hypercall(&args);
}

void early_log_to_mshvdbg_tdx(const char *buf, unsigned len)
{
    int idx;
    u64 val;
    unsigned long flags;
    int uneven_head;

    if (hyperv_pcpu_input_arg)
        local_irq_save(flags);

    uneven_head = len % 6;
    if (uneven_head) {
        val = 0;
        memcpy((char*)&val, buf, uneven_head);
        tdx_write_msr(TDX_MSR_SPECIAL_DEBUG_PRINT, val);
    }

    for (idx = uneven_head; idx < len; idx += 6) {
        val = 0;
        memcpy((char*)&val, buf + idx, 6);
        tdx_write_msr(TDX_MSR_SPECIAL_DEBUG_PRINT, val);
    }

    if (hyperv_pcpu_input_arg)
        local_irq_restore(flags);
}

static void mshvdbg_write_hvcall(struct console *con, const char *str, unsigned n)
{
    if (!connected_to_hv) {
        // Best effort
        early_connect_to_hv();
        connected_to_hv = 1;
    }

    (void)con;
    early_log_to_mshvdbg_hvcall(str, n);
}

static void mshvdbg_write_ghcb(struct console *con, const char *str, unsigned n)
{
    (void)con;
    early_log_to_mshvdbg_ghcb(str, n);
}

static void mshvdbg_write_tdx(struct console *con, const char *str, unsigned n)
{
    (void)con;
    early_log_to_mshvdbg_tdx(str, n);
}

struct console mshvdbg_console = {
    .name = "mshvdbg",
    .write = mshvdbg_write_hvcall,
    .flags = CON_PRINTBUFFER,
    .index = -1,
};

struct console mshvdbg_console_snp = {
    .name = "mshvdbg_snp",
    .write = mshvdbg_write_ghcb,
    .flags = CON_PRINTBUFFER,
    .index = -1,
};

struct console mshvdbg_console_tdx = {
    .name = "mshvdbg_tdx",
    .write = mshvdbg_write_tdx,
    .flags = CON_PRINTBUFFER,
    .index = -1,
};
