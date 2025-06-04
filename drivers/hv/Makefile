# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_HYPERV_VMBUS)	+= hv_vmbus.o
obj-$(CONFIG_HYPERV_UTILS)	+= hv_utils.o
obj-$(CONFIG_HYPERV_BALLOON)	+= hv_balloon.o
obj-$(CONFIG_MSHV_ROOT)		+= mshv_root.o
obj-$(CONFIG_MSHV_VTL)          += mshv_vtl.o


CFLAGS_mshv_tdx_asm_offsets.o  = -DHV_HYPERV_DEFS

CFLAGS_hv_trace.o = -I$(src)
CFLAGS_hv_balloon.o = -I$(src)

mshv_root-y			:= mshv_root_main.o mshv_synic.o mshv_portid_table.o \
						mshv_eventfd.o mshv_msi.o mshv_root_hv_call.o hv_call.o
mshv_vtl-y			:= mshv_vtl_main.o hv_call.o mshv_tdx.o

$(obj)/mshv_tdx.o: $(obj)/mshv_tdx_asm_offsets.h

$(obj)/mshv_tdx_asm_offsets.h: $(obj)/mshv_tdx_asm_offsets.s FORCE
	$(call filechk,offsets,__MSHV_TDX_ASM_OFFSETS_H__)

targets += mshv_tdx_asm_offsets.s
clean-files += mshv_tdx_asm_offsets.h

obj-$(CONFIG_MSHV_XFER_TO_GUEST_WORK) += xfer_to_guest.o

hv_vmbus-y := vmbus_drv.o \
		 hv.o connection.o channel.o \
		 channel_mgmt.o ring_buffer.o hv_trace.o
hv_vmbus-$(CONFIG_HYPERV_TESTING)	+= hv_debugfs.o
hv_utils-y := hv_util.o hv_kvp.o hv_snapshot.o hv_utils_transport.o
mshv_root-y := mshv_root_main.o mshv_synic.o mshv_eventfd.o mshv_irq.o \
	       mshv_root_hv_call.o mshv_portid_table.o
mshv_vtl-y := mshv_vtl_main.o
mshv_vtl-$(CONFIG_X86_64)       += mshv_vtl_sidecar.o mshv_tdx.o
mshv_vtl-$(CONFIG_SEV_GUEST)	+= mshv_vtl_local_maps.o

CFLAGS_mshv_vtl_local_maps.o = -DHV_HYPERV_DEFS

# Code that must be built-in
obj-$(CONFIG_HYPERV) += hv_common.o
obj-$(subst m,y,$(CONFIG_MSHV_ROOT)) += hv_proc.o
ifneq ($(CONFIG_MSHV_ROOT) $(CONFIG_MSHV_VTL),)
	obj-y += mshv_common.o
endif
