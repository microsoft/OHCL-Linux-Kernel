#include <linux/console.h>
#include <linux/serial_core.h>
#include <linux/init.h>
#include <linux/version.h>

#include <asm/mshyperv.h>
#include <linux/hyperv.h>

#ifdef CONFIG_ARM64

#define HVCALL_OUTPUT_DEBUG_CHAR 0x0071

static void mshvdbg_write(struct console *con, const char *s, unsigned n)
{
    register u64 x0 asm("x0");
    register u64 x1 asm("x1");
    size_t i;    
    (void)con;

    for (i = 0; i < n; ++i) {
        x0 = HVCALL_OUTPUT_DEBUG_CHAR | HV_HYPERCALL_FAST_BIT;
        x1 = s[i];
        asm volatile("hvc #1\n" : "=r"(x0) : "r"(x0), "r"(x1)); 
    }
}

static void hv_connect(void)
{
    register u64 x0 asm("x0");
    register u64 x1 asm("x1");
    register u64 x2 asm("x2");
    register u64 x3 asm("x3");
    register u64 x4 asm("x4");
    register u64 x5 asm("x5");
    register u64 x6 asm("x6");

    union {
        struct {
            struct hv_input_set_vp_registers header;
            struct hv_register_assoc reg_assoc;
        } __packed hv_input;
        u64 x[6];
    } u;

    memset(&u.hv_input, 0, sizeof(u.hv_input));

    u.hv_input.header.partition_id = HV_PARTITION_ID_SELF;
	u.hv_input.header.vp_index = HV_VP_INDEX_SELF;
	u.hv_input.reg_assoc.name = HV_REGISTER_GUEST_OS_ID;
	u.hv_input.reg_assoc.value.reg64 = 1;

	x0 = HVCALL_SET_VP_REGISTERS | HV_HYPERCALL_FAST_BIT |
			HV_HYPERCALL_REP_COMP_1;
    x1 = u.x[0];
    x2 = u.x[1];
    x3 = u.x[2];
    x4 = u.x[3];
    x5 = u.x[4];
    x6 = u.x[5];
    asm volatile("hvc #1\n" : "=r"(x0) :
        "r"(x0),
        "r"(x1), "r"(x2), "r"(x3),
        "r"(x4), "r"(x5), "r"(x6));
}

static int __init mshvdbg_console_setup(struct earlycon_device *device,
					    const char *opt)
{
    hv_connect();
	device->con->write = mshvdbg_write;

	return 0;
}

OF_EARLYCON_DECLARE(mshvdbg, "arm,mshvdbg", mshvdbg_console_setup);

#endif
