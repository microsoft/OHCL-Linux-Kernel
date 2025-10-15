# ARM64 Secondary CPU Bringup Performance Instrumentation

## Overview
Added detailed timing instrumentation to investigate the ~655ms delay in secondary CPU bringup on ARM64 systems with 128 CPUs when comparing kernel 6.12 vs 6.6.

## Problem Statement
- **Issue**: Kernel 6.12.9 takes ~690ms longer to boot compared to 6.6.63 on GB200 (ARM64, 128 CPUs)
- **Primary bottleneck**: Secondary CPU bringup (655ms of the 690ms difference)
- **Symptom**: Some CPUs (especially CPU24-43 and CPU80+) show long delays in "Detected PIPT I-cache" messages
  - Example: 20ms delay for CPU26, 10ms for CPU27, 16ms for CPU81

## Root Cause Hypotheses
1. **PIPT I-cache detection delay**: Long gaps between "Booted secondary processor" and "Detected PIPT I-cache"
2. **cpuinfo_store_cpu() slowdown**: Possible new CPU feature detection code in 6.12
3. **check_local_cpu_capabilities() overhead**: New capability checks added in recent kernels
4. **2023 DPISA extensions**: New ARM64 data processing extensions enabled in 6.12 (Mark Brown's patch series)

## Changes Made

### 1. arch/arm64/kernel/smp.c - secondary_start_kernel()
Added microsecond-level timing measurements at each major step:

```c
- Added ktime_t t_start, t_now variables
- Measures time for:
  1. mmgrab + active_mm setup
  2. cpu_uninstall_idmap()
  3. Pre-check_local_cpu_capabilities baseline
  4. check_local_cpu_capabilities() *** KEY SUSPECT ***
  5. cpu_postboot()
  6. cpuinfo_store_cpu() *** KEY SUSPECT ***
  7. store_cpu_topology()
  8. notify_cpu_starting()
  9. ipi_setup()
  10. numa_add_cpu()
  11. TOTAL time for entire function
```

### 2. arch/arm64/kernel/cpuinfo.c - cpuinfo_store_cpu()
Added timing breakdown inside this function:

```c
- Measures time for:
  1. __cpuinfo_store_cpu() - reads all CPU ID registers
  2. update_cpu_features() - updates system capabilities *** KEY SUSPECT ***
```

## What to Look For in Logs

### Expected Output Pattern
```
[X.XXXXXX] CPU24: [TIMING] mmgrab+active_mm: YY us
[X.XXXXXX] CPU24: [TIMING] cpu_uninstall_idmap: YY us
[X.XXXXXX] CPU24: [TIMING] pre-check_local_cpu_capabilities: YY us
[X.XXXXXX] CPU24: [TIMING] check_local_cpu_capabilities: YY us    <-- Watch this
[X.XXXXXX] CPU24: [TIMING] cpu_postboot: YY us
[X.XXXXXX] CPU24: [CPUINFO] __cpuinfo_store_cpu: YY us            <-- Watch this
[X.XXXXXX] CPU24: [CPUINFO] update_cpu_features: YY us            <-- Watch this
[X.XXXXXX] Detected PIPT I-cache on CPU24
[X.XXXXXX] CPU24: [TIMING] cpuinfo_store_cpu: YY us               <-- Watch this
[X.XXXXXX] CPU24: [TIMING] store_cpu_topology: YY us
[X.XXXXXX] CPU24: [TIMING] notify_cpu_starting: YY us
[X.XXXXXX] CPU24: [TIMING] ipi_setup: YY us
[X.XXXXXX] CPU24: [TIMING] numa_add_cpu: YY us
[X.XXXXXX] CPU24: Booted secondary processor 0x0000000108 [0x410fd4f0]
[X.XXXXXX] CPU24: [TIMING] TOTAL secondary_start_kernel: YYYY us
```

### Analysis Focus Points

1. **Compare problematic CPUs (24-43, 80+) vs fast CPUs (0-23)**
   - Look for which timing measurement shows the largest delta
   - Fast CPUs should complete in ~500-2000us total
   - Slow CPUs are showing 10,000-20,000us delays

2. **check_local_cpu_capabilities()**
   - This validates CPU features against boot CPU
   - New capability checks in 6.12 might be expensive
   - Related commit: https://lore.kernel.org/r/20231017052322.1211099-3-jeremy.linton@arm.com

3. **update_cpu_features()**
   - This function updates system-wide capability bits
   - May involve cross-CPU synchronization
   - Could be affected by 2023 DPISA extensions support

4. **CPU-specific patterns**
   - Are delays CPU-number related? (e.g., every Nth CPU)
   - Are delays NUMA-domain related?
   - Are delays socket/cluster related? (CPU 24-43 = second cluster? CPU 80+ = different socket?)

## Building and Testing

### Build the kernel
```bash
cd /home/hargar/underhill/OHCL-Linux-Kernel
make -j$(nproc)
```

### Boot and collect logs
```bash
# Boot with increased log buffer to capture all timing data
# Ensure console captures all messages or use:
dmesg | grep -E '\[TIMING\]|\[CPUINFO\]|Detected.*I-cache|Booted secondary' > cpu_bringup_timing.log
```

### Parse results
```bash
# Extract timing data for analysis
grep '\[TIMING\]' cpu_bringup_timing.log | awk '{print $2, $3, $5}' | sort -k1 -n

# Find slowest CPUs
grep 'TOTAL secondary_start_kernel' cpu_bringup_timing.log | sort -t: -k2 -n | tail -20

# Compare specific function timings
grep 'check_local_cpu_capabilities' cpu_bringup_timing.log | awk '{sum+=$5; count++} END {print "Avg:", sum/count, "us"}'
grep 'cpuinfo_store_cpu' cpu_bringup_timing.log | grep -v CPUINFO | awk '{sum+=$5; count++} END {print "Avg:", sum/count, "us"}'
```

## Next Steps

Based on timing results:

### If check_local_cpu_capabilities() is slow:
- Investigate arch/arm64/kernel/cpufeature.c:verify_local_cpu_capabilities()
- Look for new capability checks added between 6.6 and 6.12
- Consider: dirt bit detection, DPISA features, SVE2/SME validation

### If update_cpu_features() is slow:
- May need to instrument cpufeature.c:update_cpu_capabilities()
- Look for expensive cross-CPU operations or locking
- Check if certain feature bits trigger expensive validation

### If __cpuinfo_store_cpu() is slow:
- The many read_cpuid() calls might be hitting slow paths
- New registers in 6.12: ID_AA64MMFR3_EL1, ID_AA64MMFR4_EL1, ID_AA64FPFR0_EL1
- Could be trapped/emulated on certain CPUs

### If delay is between specific timing points:
- Add more granular instrumentation in that region
- May need to instrument sub-functions

## Related Commits to Investigate

1. **Dirt bit and capability detection**: https://lore.kernel.org/r/20231017052322.1211099-3-jeremy.linton@arm.com
2. **2023 DPISA extensions**: "arm64: Support for 2023 DPISA extensions" - Mark Brown (v5 series)
3. **New ID registers**: Search for commits adding ID_AA64MMFR3_EL1, ID_AA64MMFR4_EL1, ID_AA64FPFR0_EL1

## Files Modified

- `arch/arm64/kernel/smp.c` - Added timing instrumentation to secondary_start_kernel()
- `arch/arm64/kernel/cpuinfo.c` - Added timing instrumentation to cpuinfo_store_cpu()
