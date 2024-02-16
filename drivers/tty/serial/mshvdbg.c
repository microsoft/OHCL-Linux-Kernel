#include <linux/console.h>
#include <linux/serial_core.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/of.h>

#include <asm/mshyperv.h>

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
	u64 guest_id = hv_generate_guest_id(LINUX_VERSION_CODE);
	hv_set_vpreg(HV_REGISTER_GUEST_OSID, guest_id);
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
