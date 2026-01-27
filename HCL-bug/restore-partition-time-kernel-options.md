.. SPDX-License-Identifier: GPL-2.0

Kernel-level handling options for HvCallRestorePartitionTime
===========================================================

Context
-------
When OpenHCL (VTL2) reissues ``HvCallRestorePartitionTime``, Hyper-V updates the
TSC→reference-time mapping for the whole partition. Linux must apply a coherent
bias/offset adjustment so time remains monotonic and consistent across CPUs.

This doc enumerates kernel-level handling options, with pros and cons.

Option A: stop_machine() (global stop-the-world)
-----------------------------------------------
**Summary**: Use ``stop_machine()`` to run a single callback while all other CPUs
are paused. Inside the callback, read TSC, issue the hypercall, read TSC again,
update the Hyper-V bias/offset, then resume CPUs.

**Pros**
- Closest to legacy HCL behavior (pause all processors).
- Strong correctness guarantees: no concurrent readers during update.
- Simple to reason about and implement.

**Cons**
- Adds noticeable latency (global pause).
- Potential upstream pushback if the call is frequent or long-running.
- Risk/unknown: resetting the time mapping "under" the OS is inherently
  sensitive; correctness depends on all time read paths consistently applying
  the bias/offset.

**Best fit**
- Rare events (restore/migration/resume) where correctness matters most.


Option B: cross-CPU rendezvous + barriers
-----------------------------------------
**Summary**: Use ``smp_call_function_many()`` (or equivalent) to park CPUs at a
barrier, apply the bias/offset update, then release the CPUs.

**Pros**
- Lower latency than ``stop_machine()``.
- More control over which CPUs participate.

**Cons**
- More complex: must prevent time readers (including vDSO) from observing
  half-updated state.
- Requires careful ordering and memory barriers.

**Best fit**
- Moderate-frequency events where ``stop_machine()`` is too heavy.


Option C: timekeeping-seqlock integration
-----------------------------------------
**Summary**: Hook into timekeeping’s sequencing (seqlocks) and update Hyper-V
clocksource/sched_clock state under the same serialization as other clock
adjustments.

**Pros**
- Aligns with existing kernel timekeeping model.
- Potentially lowest disruption to the system.

**Cons**
- Requires deeper integration with timekeeping internals.
- Harder to prove cross-CPU correctness without careful analysis.

**Best fit**
- Long-term upstream-quality solution once the semantics are fully understood.


Option D: dedicated Hyper-V bias layer + RCU-style update
---------------------------------------------------------
**Summary**: Maintain a Hyper-V specific bias struct published via RCU or a
sequence counter; readers retry if they see an in-flight update.

**Pros**
- Avoids full stop-the-world pauses.
- Can be optimized for very low latency.

**Cons**
- Requires new reader-side retry logic in clocksource/vDSO paths.
- More invasive changes across kernel/user-facing time read paths.

**Best fit**
- Very latency-sensitive systems where restore-time events are not rare.


Recommendation (pragmatic path)
-------------------------------
1. Start with **Option A** for correctness and simplicity if the event is rare.
2. Collect latency data to justify or replace the approach.
3. If needed, move to **Option B** or **Option C** for upstream acceptance.

Open questions
--------------
- How often will ``HvCallRestorePartitionTime`` occur in real workloads?
- What maximum pause time is acceptable for upstream?
- Which time read paths must be covered (clocksource, sched_clock, vDSO)?
