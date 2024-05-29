# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_HYPERV)		+= hv_vmbus.o
obj-$(CONFIG_HYPERV_UTILS)	+= hv_utils.o
obj-$(CONFIG_HYPERV_BALLOON)	+= hv_balloon.o
obj-$(CONFIG_MSHV)			+= mshv.o
obj-$(CONFIG_MSHV_VTL)		+= mshv_vtl.o
obj-$(CONFIG_MSHV_ROOT)		+= mshv_root.o

CFLAGS_hv_trace.o = -I$(src)
CFLAGS_hv_balloon.o = -I$(src)

CFLAGS_mshv_main.o			= -DHV_HYPERV_DEFS
CFLAGS_hv_call.o			= -DHV_HYPERV_DEFS
CFLAGS_mshv_root_main.o		= -DHV_HYPERV_DEFS
CFLAGS_mshv_root_hv_call.o	= -DHV_HYPERV_DEFS
CFLAGS_mshv_synic.o			= -DHV_HYPERV_DEFS
CFLAGS_mshv_portid_table.o	= -DHV_HYPERV_DEFS
CFLAGS_mshv_eventfd.o		= -DHV_HYPERV_DEFS
CFLAGS_mshv_msi.o			= -DHV_HYPERV_DEFS
CFLAGS_mshv_vtl_main.o		= -DHV_HYPERV_DEFS

mshv-y				+= mshv_main.o
mshv_root-y			:= mshv_root_main.o mshv_synic.o mshv_portid_table.o \
						mshv_eventfd.o mshv_msi.o mshv_root_hv_call.o hv_call.o
mshv_vtl-y			:= mshv_vtl_main.o hv_call.o
mshv_vtl-$(CONFIG_X86_64)	+= mshv_vtl_sidecar.o

obj-$(CONFIG_MSHV_XFER_TO_GUEST_WORK) += xfer_to_guest.o

hv_vmbus-y := vmbus_drv.o \
		 hv.o connection.o channel.o \
		 channel_mgmt.o ring_buffer.o hv_trace.o
hv_vmbus-$(CONFIG_HYPERV_TESTING)	+= hv_debugfs.o
hv_utils-y := hv_util.o hv_kvp.o hv_snapshot.o hv_fcopy.o hv_utils_transport.o

# Code that must be built-in
obj-$(subst m,y,$(CONFIG_HYPERV)) += hv_common.o
