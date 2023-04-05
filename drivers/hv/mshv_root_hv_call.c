// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Microsoft Corporation.
 *
 * Hypercall helper functions used by the mshv_root module.
 *
 * Authors:
 *   Nuno Das Neves <nunodasneves@linux.microsoft.com>
 *   Wei Liu <wei.liu@kernel.org>
 *   Jinank Jain <jinankjain@microsoft.com>
 *   Vineeth Remanan Pillai <viremana@linux.microsoft.com>
 *   Asher Kariv <askariv@microsoft.com>
 *   Muminul Islam <Muminul.Islam@microsoft.com>
 *   Anatol Belski <anbelski@linux.microsoft.com>
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/mshyperv.h>

/* Determined empirically */
#define HV_INIT_PARTITION_DEPOSIT_PAGES 208
#define HV_MAP_GPA_DEPOSIT_PAGES	256

#define HV_WITHDRAW_BATCH_SIZE	(HV_HYP_PAGE_SIZE / sizeof(u64))
#define HV_MAP_GPA_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_map_gpa_pages)) \
		/ sizeof(u64))
#define HV_GET_VP_STATE_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_get_vp_state)) \
		/ sizeof(u64))
#define HV_SET_VP_STATE_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_set_vp_state)) \
		/ sizeof(u64))
#define HV_GET_GPA_ACCESS_STATES_BATCH_SIZE	\
	((HV_HYP_PAGE_SIZE - sizeof(union hv_gpa_page_access_state)) \
		/ sizeof(union hv_gpa_page_access_state))
#define HV_MODIFY_SPARSE_SPA_PAGE_HOST_ACCESS_MAX_PAGE_COUNT                   \
	((HV_HYP_PAGE_SIZE -                                                   \
	  sizeof(struct hv_input_modify_sparse_spa_page_host_access)) /        \
	 sizeof(u64))
#define HV_ISOLATED_PAGE_BATCH_SIZE                                            \
	((HV_HYP_PAGE_SIZE - sizeof(struct hv_input_import_isolated_pages)) /  \
	 sizeof(u64))

int hv_call_withdraw_memory(u64 count, int node, u64 partition_id)
{
	struct hv_input_withdraw_memory *input_page;
	struct hv_output_withdraw_memory *output_page;
	struct page *page;
	u16 completed;
	unsigned long remaining = count;
	u64 status;
	int i;
	unsigned long flags;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	output_page = page_address(page);

	while (remaining) {
		local_irq_save(flags);

		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

		input_page->partition_id = partition_id;
		input_page->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_rep_hypercall(HVCALL_WITHDRAW_MEMORY,
					     min(remaining, HV_WITHDRAW_BATCH_SIZE),
					     0, input_page, output_page);

		local_irq_restore(flags);

		completed = hv_repcomp(status);

		for (i = 0; i < completed; i++)
			__free_page(pfn_to_page(output_page->gpa_page_list[i]));

		if (!hv_result_success(status)) {
			if (hv_result(status) == HV_STATUS_NO_RESOURCES)
				status = HV_STATUS_SUCCESS;
			break;
		}

		remaining -= completed;
	}
	free_page((unsigned long)output_page);

	return hv_status_to_errno(status);
}

int hv_call_create_partition(u64 flags,
			     struct hv_partition_creation_properties creation_properties,
			     union hv_partition_isolation_properties isolation_properties,
			     u64 *partition_id)
{
	struct hv_input_create_partition *input;
	struct hv_output_create_partition *output;
	u64 status;
	int ret;
	unsigned long irq_flags;

	do {
		local_irq_save(irq_flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input->flags = flags;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(NUMA_NO_NODE);
		input->compatibility_version = HV_COMPATIBILITY_21_H2;

		memcpy(&input->partition_creation_properties, &creation_properties,
		       sizeof(creation_properties));

		memcpy(&input->isolation_properties, &isolation_properties,
		       sizeof(isolation_properties));

		status = hv_do_hypercall(HVCALL_CREATE_PARTITION,
					 input, output);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			if (hv_result_success(status))
				*partition_id = output->partition_id;
			local_irq_restore(irq_flags);
			ret = hv_status_to_errno(status);
			break;
		}
		local_irq_restore(irq_flags);
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    hv_current_partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_initialize_partition(u64 partition_id)
{
	struct hv_input_initialize_partition input;
	u64 status;
	int ret;

	input.partition_id = partition_id;

	ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id,
				    HV_INIT_PARTITION_DEPOSIT_PAGES);
	if (ret)
		return ret;

	do {
		status = hv_do_fast_hypercall8(HVCALL_INITIALIZE_PARTITION,
					       *(u64 *)&input);

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_finalize_partition(u64 partition_id)
{
	struct hv_input_finalize_partition input;
	u64 status;

	input.partition_id = partition_id;
	status = hv_do_fast_hypercall8(HVCALL_FINALIZE_PARTITION, *(u64 *)&input);

	return hv_status_to_errno(status);
}

int hv_call_delete_partition(u64 partition_id)
{
	struct hv_input_delete_partition input;
	u64 status;

	input.partition_id = partition_id;
	status = hv_do_fast_hypercall8(HVCALL_DELETE_PARTITION, *(u64 *)&input);

	return hv_status_to_errno(status);
}

int hv_call_map_gpa_pages(u64 partition_id, u64 gpa_target, u64 page_count,
			  u32 flags, struct page **pages)
{
	struct hv_input_map_gpa_pages *input_page;
	u64 status;
	int i;
	struct page **p;
	u32 completed = 0;
	unsigned long remaining = page_count;
	int rep_count;
	unsigned long irq_flags;
	int ret = 0;

	if (page_count == 0)
		return -EINVAL;

	while (remaining) {
		rep_count = min(remaining, HV_MAP_GPA_BATCH_SIZE);

		local_irq_save(irq_flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

		input_page->target_partition_id = partition_id;
		input_page->target_gpa_base = gpa_target;
		input_page->map_flags = flags;

		for (i = 0, p = pages; i < rep_count; i++, p++)
			input_page->source_gpa_page_list[i] = page_to_pfn(*p);
		status = hv_do_rep_hypercall(HVCALL_MAP_GPA_PAGES, rep_count,
					     0, input_page, NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);

		if (hv_result(status) == HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_call_deposit_pages(NUMA_NO_NODE,
						    partition_id,
						    HV_MAP_GPA_DEPOSIT_PAGES);
			if (ret)
				break;
		} else if (!hv_result_success(status)) {
			ret = hv_status_to_errno(status);
			break;
		}

		pages += completed;
		remaining -= completed;
		gpa_target += completed;
	}

	return ret;
}

int hv_call_unmap_gpa_pages(u64 partition_id, u64 gpa_target, u64 page_count,
			    u32 flags)
{
	struct hv_input_unmap_gpa_pages *input_page;
	u64 status;
	u32 completed = 0;
	unsigned long remaining = page_count;
	int rep_count;
	unsigned long irq_flags;

	if (page_count == 0)
		return -EINVAL;

	while (remaining) {
		local_irq_save(irq_flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);

		input_page->target_partition_id = partition_id;
		input_page->target_gpa_base = gpa_target;
		input_page->unmap_flags = flags;
		rep_count = min(remaining, HV_MAP_GPA_BATCH_SIZE);
		status = hv_do_rep_hypercall(HVCALL_UNMAP_GPA_PAGES, rep_count,
					     0, input_page, NULL);
		local_irq_restore(irq_flags);

		completed = hv_repcomp(status);
		if (!hv_result_success(status))
			return hv_status_to_errno(status);

		remaining -= completed;
		gpa_target += completed;
	}

	return 0;
}

int hv_call_get_gpa_access_states(u64 partition_id, u32 count,
				  u64 gpa_base_pfn, u64 state_flags,
				  int *written_total,
				  union hv_gpa_page_access_state *states)
{
	struct hv_input_get_gpa_pages_access_state *input_page;
	union hv_gpa_page_access_state *output_page;
	int completed = 0;
	unsigned long remaining = count;
	int rep_count, i;
	u64 status;
	unsigned long flags;

	*written_total = 0;
	while (remaining) {
		local_irq_save(flags);
		input_page = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output_page = *this_cpu_ptr(hyperv_pcpu_output_arg);

		input_page->partition_id = partition_id;
		input_page->hv_gpa_page_number = gpa_base_pfn + *written_total;
		input_page->flags.as_uint64 = state_flags;
		rep_count = min(remaining, HV_GET_GPA_ACCESS_STATES_BATCH_SIZE);

		status = hv_do_rep_hypercall(HVCALL_GET_GPA_PAGES_ACCESS_STATES, rep_count,
					     0, input_page, output_page);
		if (!hv_result_success(status)) {
			local_irq_restore(flags);
			break;
		}
		completed = hv_repcomp(status);
		for (i = 0; i < completed; ++i)
			states[i].as_uint8 = output_page[i].as_uint8;

		states += completed;
		*written_total += completed;
		remaining -= completed;
		local_irq_restore(flags);
	}

	return hv_status_to_errno(status);
}

int hv_call_install_intercept(u64 partition_id, u32 access_type,
			      enum hv_intercept_type intercept_type,
			      union hv_intercept_parameters intercept_parameter)
{
	struct hv_input_install_intercept *input;
	unsigned long flags;
	u64 status;
	int ret;

	do {
		local_irq_save(flags);
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		input->partition_id = partition_id;
		input->access_type = access_type;
		input->intercept_type = intercept_type;
		input->intercept_parameter = intercept_parameter;
		status = hv_do_hypercall(HVCALL_INSTALL_INTERCEPT, input, NULL);

		local_irq_restore(flags);
		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_status_to_errno(status);
			break;
		}

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

int hv_call_assert_virtual_interrupt(u64 partition_id, u32 vector, u64 dest_addr,
				     union hv_interrupt_control control)
{
	struct hv_input_assert_virtual_interrupt *input;
	unsigned long flags;
	u64 status;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->vector = vector;
	input->dest_addr = dest_addr;
	input->control = control;
	status = hv_do_hypercall(HVCALL_ASSERT_VIRTUAL_INTERRUPT, input, NULL);
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

#ifdef HV_SUPPORTS_VP_STATE

int hv_call_get_vp_state(u32 vp_index, u64 partition_id,
			 enum hv_get_set_vp_state_type type,
			 struct hv_vp_state_data_xsave xsave,
			 /* Choose between pages and ret_output */
			 u64 page_count, struct page **pages,
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
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		output = *this_cpu_ptr(hyperv_pcpu_output_arg);
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
			if (hv_result_success(status) && ret_output)
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

int hv_call_set_vp_state(u32 vp_index, u64 partition_id,
			 enum hv_get_set_vp_state_type type,
			 struct hv_vp_state_data_xsave xsave,
			 /* Choose between pages and bytes */
			 u64 page_count, struct page **pages,
			 u32 num_bytes, u8 *bytes)
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
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
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
			local_irq_restore(flags);
			ret = hv_status_to_errno(status);
			break;
		}

		local_irq_restore(flags);

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

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

	return hv_status_to_errno(status);
}

int hv_call_get_partition_property(u64 partition_id, u64 property_code,
				   u64 *property_value)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_partition_property *input;
	struct hv_output_get_partition_property *output;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	output = *this_cpu_ptr(hyperv_pcpu_output_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	status = hv_do_hypercall(HVCALL_GET_PARTITION_PROPERTY, input, output);

	if (!hv_result_success(status)) {
		local_irq_restore(flags);
		return hv_status_to_errno(status);
	}
	*property_value = output->property_value;

	local_irq_restore(flags);

	return 0;
}

int hv_call_set_partition_property(u64 partition_id, u64 property_code,
				   u64 property_value,
				   void (*completion_handler)(void * /* data */,
							      u64 * /* status */),
				   void *completion_data)
{
	u64 status;
	unsigned long flags;
	struct hv_input_set_partition_property *input;

	if (!completion_handler)
		return -EINVAL;

	local_irq_save(flags);
	input = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(input, 0, sizeof(*input));
	input->partition_id = partition_id;
	input->property_code = property_code;
	input->property_value = property_value;
	status = hv_do_hypercall(HVCALL_SET_PARTITION_PROPERTY, input, NULL);
	local_irq_restore(flags);

	if (unlikely(hv_result(status) == HV_STATUS_CALL_PENDING))
		completion_handler(completion_data, &status);

	return hv_status_to_errno(status);
}

int hv_call_translate_virtual_address(u32 vp_index, u64 partition_id, u64 flags,
				      u64 gva, u64 *gpa,
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

	if (!hv_result_success(status))
		goto out;

	*result = output->translation_result;

	*gpa = (output->gpa_page << HV_HYP_PAGE_SHIFT) + /* pfn to gpa */
			((u64)gva & ~HV_HYP_PAGE_MASK);	 /* offset in gpa */

out:
	local_irq_restore(irq_flags);

	return hv_status_to_errno(status);
}

int
hv_call_clear_virtual_interrupt(u64 partition_id)
{
	unsigned long flags;
	int status;

	local_irq_save(flags);
	status = hv_do_fast_hypercall8(HVCALL_CLEAR_VIRTUAL_INTERRUPT,
				       partition_id);
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

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
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		memset(input, 0, sizeof(*input));

		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->port_info = *port_info;
		input->port_vtl = port_vtl;
		input->min_connection_vtl = min_connection_vtl;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CREATE_PORT, input, NULL);
		local_irq_restore(flags);

		if (hv_result_success(status))
			break;

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE, port_partition_id, 1);

	} while (!ret);

	return ret;
}

int
hv_call_delete_port(u64 port_partition_id, union hv_port_id port_id)
{
	union hv_input_delete_port input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.port_partition_id = port_partition_id;
	input.port_id = port_id;
	status = hv_do_fast_hypercall16(HVCALL_DELETE_PORT,
					input.as_uint64[0],
					input.as_uint64[1]);
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

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
		input = *this_cpu_ptr(hyperv_pcpu_input_arg);
		memset(input, 0, sizeof(*input));
		input->port_partition_id = port_partition_id;
		input->port_id = port_id;
		input->connection_partition_id = connection_partition_id;
		input->connection_id = connection_id;
		input->connection_info = *connection_info;
		input->connection_vtl = connection_vtl;
		input->proximity_domain_info =
			numa_node_to_proximity_domain_info(node);
		status = hv_do_hypercall(HVCALL_CONNECT_PORT, input, NULL);

		local_irq_restore(flags);
		if (hv_result_success(status))
			break;

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_status_to_errno(status);
			break;
		}
		ret = hv_call_deposit_pages(NUMA_NO_NODE,
					    connection_partition_id, 1);
	} while (!ret);

	return ret;
}

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
	status = hv_do_fast_hypercall16(HVCALL_DISCONNECT_PORT,
					input.as_uint64[0],
					input.as_uint64[1]);
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

int
hv_call_notify_port_ring_empty(u32 sint_index)
{
	union hv_input_notify_port_ring_empty input = { 0 };
	unsigned long flags;
	int status;

	local_irq_save(flags);
	input.sint_index = sint_index;
	status = hv_do_fast_hypercall8(HVCALL_NOTIFY_PORT_RING_EMPTY,
				       input.as_uint64);
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

#ifdef HV_SUPPORTS_REGISTER_INTERCEPT

int hv_call_register_intercept_result(u32 vp_index, u64 partition_id,
				      enum hv_intercept_type intercept_type,
				      union hv_register_intercept_result_parameters *params)
{
	u64 status;
	unsigned long flags;
	struct hv_input_register_intercept_result *in;
	int ret = 0;

	do {
		local_irq_save(flags);
		in = *this_cpu_ptr(hyperv_pcpu_input_arg);
		in->vp_index = vp_index;
		in->partition_id = partition_id;
		in->intercept_type = intercept_type;
		in->parameters = *params;

		status = hv_do_hypercall(HVCALL_REGISTER_INTERCEPT_RESULT, in, NULL);
		local_irq_restore(flags);

		if (hv_result_success(status))
			break;

		if (hv_result(status) != HV_STATUS_INSUFFICIENT_MEMORY) {
			ret = hv_status_to_errno(status);
			break;
		}

		ret = hv_call_deposit_pages(NUMA_NO_NODE, partition_id, 1);
	} while (!ret);

	return ret;
}

#endif

int hv_call_signal_event_direct(u32 vp_index, u64 partition_id, u8 vtl,
				u8 sint, u16 flag_number, u8 *newly_signaled)
{
	u64 status;
	unsigned long flags;
	struct hv_input_signal_event_direct *in;
	struct hv_output_signal_event_direct *out;

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);
	out = *this_cpu_ptr(hyperv_pcpu_output_arg);

	in->target_partition = partition_id;
	in->target_vp = vp_index;
	in->target_vtl = vtl;
	in->target_sint = sint;
	in->flag_number = flag_number;

	status = hv_do_hypercall(HVCALL_SIGNAL_EVENT_DIRECT, in, out);
	if (hv_result_success(status))
		*newly_signaled = out->newly_signaled;

	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

int hv_call_post_message_direct(u32 vp_index, u64 partition_id, u8 vtl,
				u32 sint_index, u8 *message)
{
	u64 status;
	unsigned long flags;
	struct hv_input_post_message_direct *in;

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);

	in->partition_id = partition_id;
	in->vp_index = vp_index;
	in->vtl = vtl;
	in->sint_index = sint_index;
	memcpy(&in->message, message, HV_MESSAGE_SIZE);

	status = hv_do_hypercall(HVCALL_POST_MESSAGE_DIRECT, in, NULL);
	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

int hv_call_get_vp_cpuid_values(u32 vp_index, u64 partition_id,
				union hv_get_vp_cpuid_values_flags values_flags,
				struct hv_cpuid_leaf_info *info,
				union hv_output_get_vp_cpuid_values *result)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_vp_cpuid_values *in;
	union hv_output_get_vp_cpuid_values *out;

	local_irq_save(flags);
	in = *this_cpu_ptr(hyperv_pcpu_input_arg);
	out = *this_cpu_ptr(hyperv_pcpu_output_arg);

	memset(in, 0, sizeof(*in) + sizeof(*info));
	in->partition_id = partition_id;
	in->vp_index = vp_index;
	in->flags = values_flags;
	in->cpuid_leaf_info[0] = *info;

	status = hv_do_rep_hypercall(HVCALL_GET_VP_CPUID_VALUES, 1, 0, in, out);
	if (hv_result_success(status))
		*result = *out;

	local_irq_restore(flags);

	return hv_status_to_errno(status);
}

