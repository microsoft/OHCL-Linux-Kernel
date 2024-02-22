// SPDX-License-Identifier: GPL-2.0-only
/*
 * Low-level idle sequences
 */

#include <linux/cpu.h>
#include <linux/irqflags.h>
#include <linux/static_call.h>

#include <asm/barrier.h>
#include <asm/cpuidle.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>

/*
 *	cpu_do_idle()
 *
 *	Idle the processor (wait for interrupt).
 *
 *	If the CPU supports priority masking we must do additional work to
 *	ensure that interrupts are not masked at the PMR (because the core will
 *	not wake up if we block the wake up signal in the interrupt controller).
 */
void noinstr cpu_do_idle(void)
{
	struct arm_cpuidle_irq_context context;

	arm_cpuidle_save_irq_context(&context);

	dsb(sy);
	wfi();

	arm_cpuidle_restore_irq_context(&context);
}

void noinstr default_idle(void)
{
	/*
	 * This should do all the clock switching and wait for interrupt
	 * tricks
	 */
	cpu_do_idle();
}

DEFINE_STATIC_CALL(arm64_idle, default_idle);

/*
 * This is our default idle handler.
 */
void noinstr arch_cpu_idle(void)
{
	static_call(arm64_idle)();
}

#ifdef CONFIG_MSHV_VTL
void mshv_vtl_set_idle(void (*idle)(void))
{
	static_call_update(arm64_idle, idle);
}
#endif
