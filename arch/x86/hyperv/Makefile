# SPDX-License-Identifier: GPL-2.0-only
obj-y			:= hv_init.o mmu.o nested.o irqdomain.o ivm.o
obj-$(CONFIG_X86_64)	+= hv_apic.o
obj-$(CONFIG_HYPERV_VTL_MODE)	+= hv_vtl.o mshv_vtl_asm.o

CFLAGS_hv_vtl.o			= -DHV_HYPERV_DEFS

$(obj)/mshv_vtl_asm.o: $(obj)/mshv-asm-offsets.h

$(obj)/mshv-asm-offsets.h: $(obj)/mshv-asm-offsets.s FORCE
	$(call filechk,offsets,__MSHV_ASM_OFFSETS_H__)

ifdef CONFIG_X86_64
obj-$(CONFIG_PARAVIRT_SPINLOCKS)	+= hv_spinlock.o
endif

targets += mshv-asm-offsets.s
clean-files += mshv-asm-offsets.h
