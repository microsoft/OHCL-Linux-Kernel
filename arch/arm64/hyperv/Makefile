# SPDX-License-Identifier: GPL-2.0
obj-y		:= hv_core.o mshyperv.o
obj-$(CONFIG_HYPERV_VTL_MODE)	+= hv_vtl.o

$(obj)/hv_vtl.o: $(obj)/mshv-asm-offsets.h

$(obj)/mshv-asm-offsets.h: $(obj)/mshv-asm-offsets.s FORCE
	$(call filechk,offsets,__MSHV_ASM_OFFSETS_H__)

targets += mshv-asm-offsets.s
clean-files += mshv-asm-offsets.h
