// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Hypercall helper functions shared between mshv modules.
 *
 * Authors:
 *   Nuno Das Neves <nunodasneves@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/mshyperv.h>

#define HV_GET_REGISTER_BATCH_SIZE	\
	(HV_HYP_PAGE_SIZE / sizeof(union hv_register_value))
#define HV_SET_REGISTER_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_set_vp_registers)) \
		/ sizeof(struct hv_register_assoc))

int hv_call_get_vp_registers(u32 vp_index, u64 partition_id, u16 count,
			     union hv_input_vtl input_vtl,
			     struct hv_register_assoc *registers)
{
	struct hv_input_get_vp_registers *input_page;
	union hv_register_value *output_page;
	u16 completed = 0;
	unsigned long remaining = count;
	int rep_count, i;
	u64 status = HV_STATUS_SUCCESS;
	unsigned long flags;

	local_irq_save(flags);

	input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output_page = *this_cpu_ptr(hyperv_pcpu_output_arg);

	input_page->partition_id = partition_id;
	input_page->vp_index = vp_index;
	input_page->input_vtl.as_uint8 = input_vtl.as_uint8;
	input_page->rsvd_z8 = 0;
	input_page->rsvd_z16 = 0;

	while (remaining) {
		rep_count = min(remaining, HV_GET_REGISTER_BATCH_SIZE);
		for (i = 0; i < rep_count; ++i)
			input_page->names[i] = registers[i].name;

		status = hv_do_rep_hypercall(HVCALL_GET_VP_REGISTERS, rep_count,
					     0, input_page, output_page);
		if (!hv_result_success(status))
			break;
		completed = hv_repcomp(status);
		for (i = 0; i < completed; ++i)
			registers[i].value = output_page[i];

		registers += completed;
		remaining -= completed;
	}
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

int hv_call_set_vp_registers(u32 vp_index, u64 partition_id, u16 count,
			     union hv_input_vtl input_vtl,
			     struct hv_register_assoc *registers)
{
	struct hv_input_set_vp_registers *input_page;
	u16 completed = 0;
	unsigned long remaining = count;
	int rep_count;
	u64 status = HV_STATUS_SUCCESS;
	unsigned long flags;

	local_irq_save(flags);
	input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

	input_page->partition_id = partition_id;
	input_page->vp_index = vp_index;
	input_page->input_vtl.as_uint8 = input_vtl.as_uint8;
	input_page->rsvd_z8 = 0;
	input_page->rsvd_z16 = 0;

	while (remaining) {
		rep_count = min(remaining, HV_SET_REGISTER_BATCH_SIZE);
		memcpy(input_page->elements, registers,
		       sizeof(struct hv_register_assoc) * rep_count);

		status = hv_do_rep_hypercall(HVCALL_SET_VP_REGISTERS, rep_count,
					     0, input_page, NULL);
		if (!hv_result_success(status))
			break;
		completed = hv_repcomp(status);
		registers += completed;
		remaining -= completed;
	}

	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

int hv_call_install_intercept(
		u64 partition_id,
		u32 access_type,
		enum hv_intercept_type intercept_type,
		union hv_intercept_parameters intercept_parameter)
{
	struct hv_input_install_intercept *input;
	unsigned long flags;
	u64 status;
	int ret;

	do {
		local_irq_save(flags);
		input = (struct hv_input_install_intercept *)(*this_cpu_ptr(
					hyperv_pcpu_input_arg));
		input->partition_id = partition_id;
		input->access_type = access_type;
		input->intercept_type = intercept_type;
		input->intercept_parameter = intercept_parameter;
		status = hv_do_hypercall(
				HVCALL_INSTALL_INTERCEPT, input, NULL);

		local_irq_restore(flags);
		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_install_intercept);

int hv_call_assert_virtual_interrupt(
		u64 partition_id,
		u32 vector,
		u64 dest_addr,
		union hv_interrupt_control control)
{
	struct hv_input_assert_virtual_interrupt *input;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);
	input = (struct hv_input_assert_virtual_interrupt *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->vector = vector;
	input->dest_addr = dest_addr;
	input->control = control;
	status = hv_do_hypercall(HVCALL_ASSERT_VIRTUAL_INTERRUPT, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_assert_virtual_interrupt);

#ifdef HV_SUPPORTS_VP_STATE

int hv_call_get_vp_state(
		u32 vp_index,
		u64 partition_id,
		enum hv_get_set_vp_state_type type,
		struct hv_vp_state_data_xsave xsave,
		/* Choose between pages and ret_output */
		u64 page_count,
		struct page **pages,
		union hv_output_get_vp_state *ret_output)
{
	struct hv_input_get_vp_state *input;
	union hv_output_get_vp_state *output;
	u64 status;
	int i;
	u64 control;
	unsigned long flags;
	int ret = 0;

	if (page_count > HV_GET_VP_STATE_BATCH_SIZE)
		return -EINVAL;

	if (!page_count && !ret_output)
		return -EINVAL;

	do {
		local_irq_save(flags);
		input = (struct hv_input_get_vp_state *)
				(*this_cpu_ptr(hyperv_pcpu_input_arg));
		output = (union hv_output_get_vp_state *)
				(*this_cpu_ptr(hyperv_pcpu_output_arg));
		memset(input, 0, sizeof(*input));
		memset(output, 0, sizeof(*output));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->state_data.type = type;
		memcpy(&input->state_data.xsave, &xsave, sizeof(xsave));
		for (i = 0; i < page_count; i++)
			input->output_data_pfns[i] = page_to_pfn(pages[i]);

		control = (HVCALL_GET_VP_STATE) |
			  (page_count << HV_HYPERCALL_VARHEAD_OFFSET);

		status = hv_do_hypercall(control, input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			else if (ret_output)
				memcpy(ret_output, output, sizeof(*output));

			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    partition_id, 1);
	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_get_vp_state);

int hv_call_set_vp_state(
		u32 vp_index,
		u64 partition_id,
		enum hv_get_set_vp_state_type type,
		struct hv_vp_state_data_xsave xsave,
		/* Choose between pages and bytes */
		u64 page_count,
		struct page **pages,
		u32 num_bytes,
		u8 *bytes)
{
	struct hv_input_set_vp_state *input;
	u64 status;
	int i;
	u64 control;
	unsigned long flags;
	int ret = 0;
	u16 varhead_sz;

	if (page_count > HV_SET_VP_STATE_BATCH_SIZE)
		return -EINVAL;
	if (sizeof(*input) + num_bytes > HV_HYP_PAGE_SIZE)
		return -EINVAL;

	if (num_bytes)
		/* round up to 8 and divide by 8 */
		varhead_sz = (num_bytes + 7) >> 3;
	else if (page_count)
		varhead_sz =  page_count;
	else
		return -EINVAL;

	do {
		local_irq_save(flags);
		input = (struct hv_input_set_vp_state *)
				(*this_cpu_ptr(hyperv_pcpu_input_arg));
		memset(input, 0, sizeof(*input));

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->state_data.type = type;
		memcpy(&input->state_data.xsave, &xsave, sizeof(xsave));
		if (num_bytes) {
			memcpy((u8 *)input->data, bytes, num_bytes);
		} else {
			for (i = 0; i < page_count; i++)
				input->data[i].pfns = page_to_pfn(pages[i]);
		}

		control = (HVCALL_SET_VP_STATE) |
			  (varhead_sz << HV_HYPERCALL_VARHEAD_OFFSET);

		status = hv_do_hypercall(control, input, NULL);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (!hv_result_success(status))
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));

			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    partition_id, 1);
	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_set_vp_state);

#endif

int hv_call_map_vp_state_page(u64 partition_id, u32 vp_index, u32 type,
				struct page **state_page)
{
	struct hv_input_map_vp_state_page *input;
	struct hv_output_map_vp_state_page *output;
	u64 status;
	int ret;
	unsigned long flags;

	do {
		local_irq_save(flags);

		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input->partition_id = partition_id;
		input->vp_index = vp_index;
		input->type = type;

		status = hv_do_hypercall(HVCALL_MAP_VP_STATE_PAGE, input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (hv_result_success(status))
				*state_page = pfn_to_page(output->map_location);
			else
				pr_err("%s: %s\n", __func__,
				       hv_status_to_string(status));
			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}

		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_map_vp_state_page);

int hv_call_unmap_vp_state_page(u64 partition_id, u32 vp_index, u32 type)
{
	unsigned long flags;
	u64 status;
	struct hv_input_unmap_vp_state_page *input;

	local_irq_save(flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);

	memset(input, 0, sizeof(*input));

	input->partition_id = partition_id;
	input->vp_index = vp_index;
	input->type = type;

	status = hv_do_hypercall(HVCALL_UNMAP_VP_STATE_PAGE, input, NULL);

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_unmap_vp_state_page);

int hv_call_get_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 *property_value)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_partition_property *input;
	struct hv_output_get_partition_property *output;

	local_irq_save(flags);
	input = (struct hv_input_get_partition_property *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
	output = (struct hv_output_get_partition_property *)(*this_cpu_ptr(
			hyperv_pcpu_output_arg));
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	status = hv_do_hypercall(HVCALL_GET_PARTITION_PROPERTY, input,
			output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		local_irq_restore(flags);
		return hv_status_to_errno(status);
	}
	*property_value = output->property_value;

	local_irq_restore(flags);

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_get_partition_property);

int hv_call_set_partition_property(
		u64 partition_id,
		u64 property_code,
		u64 property_value,
		void (*completion_handler)(u64/* partition_id */, u64 */* status */))
{
	u64 status;
	unsigned long flags;
	struct hv_input_set_partition_property *input;

	local_irq_save(flags);
	input = (struct hv_input_set_partition_property *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	input->property_value = property_value;
	status = hv_do_hypercall(HVCALL_SET_PARTITION_PROPERTY, input, NULL);
	local_irq_restore(flags);

	if (unlikely(status == HV_STATUS_CALL_PENDING)) {
		if (completion_handler)
			completion_handler(partition_id, &status);
		else
			pr_err("%s: Missing completion handler for async set partition hypercall, property_code: %llu!\n",
			       __func__, property_code);
	}

	if (!hv_result_success(status))
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));

	return hv_status_to_errno(status);
}
EXPORT_SYMBOL_GPL(hv_call_set_partition_property);

int hv_call_translate_virtual_address(
		u32 vp_index,
		u64 partition_id,
		u64 flags,
		u64 gva,
		u64 *gpa,
		union hv_translate_gva_result *result)
{
	u64 status;
	unsigned long irq_flags;
	struct hv_input_translate_virtual_address *input;
	struct hv_output_translate_virtual_address *output;

	local_irq_save(irq_flags);

	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	memset(output, 0, sizeof(*output));

	input->partition_id = partition_id;
	input->vp_index = vp_index;
	input->control_flags = flags;
	input->gva_page = gva >> HV_HYP_PAGE_SHIFT;

	status = hv_do_hypercall(HVCALL_TRANSLATE_VIRTUAL_ADDRESS, input, output);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		goto out;
	}

	*result = output->translation_result;

	*gpa = (output->gpa_page << HV_HYP_PAGE_SHIFT) + /* pfn to gpa */
			((u64)gva & ~HV_HYP_PAGE_MASK);	 /* offset in gpa */

out:
	local_irq_restore(irq_flags);

	return hv_status_to_errno(status);
}
EXPORT_SYMBOL_GPL(hv_call_translate_virtual_address);

int
hv_call_clear_virtual_interrupt(u64 partition_id)
{
	unsigned long flags;
	int status;

	local_irq_save(flags);
	status = hv_do_fast_hypercall8(HVCALL_CLEAR_VIRTUAL_INTERRUPT,
				       partition_id) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_clear_virtual_interrupt);

int
hv_call_create_port(u64 port_partition_id, union hv_port_id port_id,
		    u64 connection_partition_id,
		    struct hv_port_info *port_info,
		    u8 port_vtl, u8 min_connection_vtl, int node)
{
	struct hv_input_create_port *input;
	unsigned long flags;
	int ret = 0;
	int status;

	do {
		local_irq_save(flags);
		input = (struct hv_input_create_port *)(*this_cpu_ptr(
				hyperv_pcpu_input_arg));
		memset(input, 0, sizeof(*input));

		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->port_info = *port_info;
		input->port_vtl = port_vtl;
		input->min_connection_vtl = min_connection_vtl;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CREATE_PORT, input,
					NULL) & HV_HYPERCALL_RESULT_MASK;
		local_irq_restore(flags);
		if (status == HV_STATUS_SUCCESS)
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				port_partition_id, 1);

	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_create_port);

int
hv_call_delete_port(u64 port_partition_id, union hv_port_id port_id)
{
	union hv_input_delete_port input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.port_partition_id = port_partition_id;
	input.port_id = port_id;
#ifdef CONFIG_X86_64
	status = hv_do_fast_hypercall16(HVCALL_DELETE_PORT,
					input.as_uint64[0],
					input.as_uint64[1]) &
			HV_HYPERCALL_RESULT_MASK;
#else
	panic("FIX ME\n");
#endif
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_delete_port);

int
hv_call_connect_port(u64 port_partition_id, union hv_port_id port_id,
		     u64 connection_partition_id,
		     union hv_connection_id connection_id,
		     struct hv_connection_info *connection_info,
		     u8 connection_vtl, int node)
{
	struct hv_input_connect_port *input;
	unsigned long flags;
	int ret = 0, status;

	do {
		local_irq_save(flags);
		input = (struct hv_input_connect_port *)(*this_cpu_ptr(
				hyperv_pcpu_input_arg));
		memset(input, 0, sizeof(*input));
		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->connection_id = connection_id;
		input->connection_info = *connection_info;
		input->connection_vtl = connection_vtl;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CONNECT_PORT, input,
					NULL) & HV_HYPERCALL_RESULT_MASK;

		local_irq_restore(flags);
		if (status == HV_STATUS_SUCCESS)
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				connection_partition_id, 1);
	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_connect_port);

int
hv_call_disconnect_port(u64 connection_partition_id,
			union hv_connection_id connection_id)
{
	union hv_input_disconnect_port input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.connection_partition_id = connection_partition_id;
	input.connection_id = connection_id;
	input.is_doorbell = 1;
#ifdef CONFIG_X86_64
	status = hv_do_fast_hypercall16(HVCALL_DISCONNECT_PORT,
					input.as_uint64[0],
					input.as_uint64[1]) &
			HV_HYPERCALL_RESULT_MASK;
#else
	panic("FIXME\n");
#endif
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_disconnect_port);

int
hv_call_notify_port_ring_empty(u32 sint_index)
{
	union hv_input_notify_port_ring_empty input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.sint_index = sint_index;
	status = hv_do_fast_hypercall8(HVCALL_NOTIFY_PORT_RING_EMPTY,
					input.as_uint64) &
			HV_HYPERCALL_RESULT_MASK;
	local_irq_restore(flags);

	if (status != HV_STATUS_SUCCESS) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_notify_port_ring_empty);

#ifdef HV_SUPPORTS_REGISTER_INTERCEPT

int hv_call_register_intercept_result(u32 vp_index,
				  u64 partition_id,
				  enum hv_intercept_type intercept_type,
				  union hv_register_intercept_result_parameters *params)
{
	u64 status;
	unsigned long flags;
	struct hv_input_register_intercept_result *in;
	int ret = 0;

	do {
		local_irq_save(flags);
		in = (struct hv_input_register_intercept_result *)(*this_cpu_ptr(
			hyperv_pcpu_input_arg));
		in->vp_index = vp_index;
		in->partition_id = partition_id;
		in->intercept_type = intercept_type;
		in->parameters = *params;

		status = hv_do_hypercall(HVCALL_REGISTER_INTERCEPT_RESULT, in, NULL);
		local_irq_restore(flags);

		if (hv_result_success(status))
			break;

		if (status != HV_STATUS_INSUFFICIENT_MEMORY) {
			pr_err("%s: %s\n",
			       __func__, hv_status_to_string(status));
			ret = hv_status_to_errno(status);
			break;
		}

		ret = hv_call_deposit_pages(NUMA_NO_NODE,
				partition_id, 1);
	} while (!ret);

	return ret;
}
EXPORT_SYMBOL_GPL(hv_call_register_intercept_result);

#endif

int hv_call_signal_event_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u8 sint,
				u16 flag_number,
				u8 *newly_signaled)
{
	u64 status;
	unsigned long flags;
	struct hv_input_signal_event_direct *in;
	struct hv_output_signal_event_direct *out;

	local_irq_save(flags);
	in = (struct hv_input_signal_event_direct *)(*this_cpu_ptr(
		hyperv_pcpu_input_arg));
	out = (struct hv_output_signal_event_direct *)(*this_cpu_ptr(
		hyperv_pcpu_output_arg));

	in->target_partition = partition_id;
	in->target_vp = vp_index;
	in->target_vtl = vtl;
	in->target_sint = sint;
	in->flag_number = flag_number;

	status = hv_do_hypercall(HVCALL_SIGNAL_EVENT_DIRECT, in, out);
	if (hv_result_success(status))
		*newly_signaled = out->newly_signaled;

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_signal_event_direct);

int hv_call_post_message_direct(u32 vp_index,
				u64 partition_id,
				u8 vtl,
				u32 sint_index,
				u8 *message)
{
	u64 status;
	unsigned long flags;
	struct hv_input_post_message_direct *in;

	local_irq_save(flags);
	in = (struct hv_input_post_message_direct *)(*this_cpu_ptr(
		hyperv_pcpu_input_arg));

	in->partition_id = partition_id;
	in->vp_index = vp_index;
	in->vtl = vtl;
	in->sint_index = sint_index;
	memcpy(&in->message, message, HV_MESSAGE_SIZE);

	status = hv_do_hypercall(HVCALL_POST_MESSAGE_DIRECT, in, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_post_message_direct);

int hv_call_get_vp_cpuid_values(u32 vp_index,
				u64 partition_id,
				union hv_get_vp_cpuid_values_flags values_flags,
				struct hv_cpuid_leaf_info *info,
				union hv_output_get_vp_cpuid_values *result)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_vp_cpuid_values *in;
	union hv_output_get_vp_cpuid_values *out;

	local_irq_save(flags);
	in = (struct hv_input_get_vp_cpuid_values *)(*this_cpu_ptr(
		hyperv_pcpu_input_arg));
	out = (union hv_output_get_vp_cpuid_values *)(*this_cpu_ptr(
		hyperv_pcpu_output_arg));

	memset(in, 0, sizeof(*in)+sizeof(*info));
	in->partition_id = partition_id;
	in->vp_index = vp_index;
	in->flags = values_flags;
	in->cpuid_leaf_info[0] = *info;

	status = hv_do_rep_hypercall(HVCALL_GET_VP_CPUID_VALUES, 1, 0, in, out);
	if (hv_result_success(status))
		*result = *out;

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_get_vp_cpuid_values);

int hv_call_map_stat_page(enum hv_stats_object_type type,
		const union hv_stats_object_identity *identity,
		void **addr)
{
	unsigned long flags;
	struct hv_input_map_stats_page *input;
	struct hv_output_map_stats_page *output;
	u64 status, pfn;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(input, 0, sizeof(*input));
	input->type = type;
	input->identity = *identity;

	status = hv_do_hypercall(HVCALL_MAP_STATS_PAGE, input, output);

	pfn = output->map_location;

	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	*addr = page_address(pfn_to_page(pfn));

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_map_stat_page);

int hv_call_unmap_stat_page(enum hv_stats_object_type type,
			    const union hv_stats_object_identity *identity)
{
	unsigned long flags;
	struct hv_input_unmap_stats_page *input;
	u64 status;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);

	memset(input, 0, sizeof(*input));
	input->type = type;
	input->identity = *identity;

	status = hv_do_hypercall(HVCALL_UNMAP_STATS_PAGE, input, NULL);
	local_irq_restore(flags);

	if (!hv_result_success(status)) {
		pr_err("%s: %s\n", __func__, hv_status_to_string(status));
		return hv_status_to_errno(status);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_unmap_stat_page);
