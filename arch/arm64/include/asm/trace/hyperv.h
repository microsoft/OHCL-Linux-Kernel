#undef TRACE_SYSTEM
#define TRACE_SYSTEM hyperv

#if !defined(_TRACE_HYPERV_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HYPERV_H

#include <linux/tracepoint.h>

#if IS_ENABLED(CONFIG_HYPERV)

TRACE_EVENT(hyperv_send_ipi_mask,
	    TP_PROTO(const struct cpumask *cpus,
		     int vector),
	    TP_ARGS(cpus, vector),
	    TP_STRUCT__entry(
		    __field(unsigned int, ncpus)
		    __field(int, vector)
		    ),
	    TP_fast_assign(__entry->ncpus = cpumask_weight(cpus);
			   __entry->vector = vector;
		    ),
	    TP_printk("ncpus %d vector %x",
		      __entry->ncpus, __entry->vector)
	);

TRACE_EVENT(hyperv_send_ipi_one,
	    TP_PROTO(int cpu,
		     int vector),
	    TP_ARGS(cpu, vector),
	    TP_STRUCT__entry(
		    __field(int, cpu)
		    __field(int, vector)
		    ),
	    TP_fast_assign(__entry->cpu = cpu;
			   __entry->vector = vector;
		    ),
	    TP_printk("cpu %d vector %x",
		      __entry->cpu, __entry->vector)
	);

#if IS_ENABLED(CONFIG_MSHV_VTL)
TRACE_EVENT(mshv_vtl_exit_vtl0,
	    TP_PROTO(u32 vtl_entry_reason, void *ctx),
	    TP_ARGS(vtl_entry_reason, ctx),
	    TP_STRUCT__entry(
		    __field(u32, vtl_entry_reason)
		    __field(void*, ctx)
		    ),
	    TP_fast_assign(__entry->vtl_entry_reason = vtl_entry_reason;
			   __entry->ctx = ctx;
		    ),
	    TP_printk("vtl2 entry reason %u, cpu_ctx=%p",
		      __entry->vtl_entry_reason, __entry->ctx)
	   );

TRACE_EVENT(mshv_vtl_enter_vtl0,
	    TP_PROTO(void *ctx),
	    TP_ARGS(ctx),
	    TP_STRUCT__entry(
		    __field(void*, ctx)
		    ),
	    TP_fast_assign(__entry->ctx = ctx;
		    ),
	    TP_printk("cpu_ctx=%p", __entry->ctx)
	   );
#endif /* CONFIG_MSHV_VTL */

#endif /* CONFIG_HYPERV */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH asm/trace/
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE hyperv
#endif /* _TRACE_HYPERV_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
