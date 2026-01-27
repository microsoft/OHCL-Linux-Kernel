.. SPDX-License-Identifier: GPL-2.0

HvCallRestorePartitionTime and time-base shifts
==============================================

Problem summary
---------------
Hyper-V provides a hypercall, ``HvCallRestorePartitionTime``, that allows a
guest to restore/reset the partition time mapping so time can remain synchronized
without keeping a permanent software bias.

Terminology
-----------
**TSC (Time Stamp Counter)**
  A hardware counter on x86/x64 that increments as the CPU runs and can be read
  very cheaply (e.g. via RDTSC/RDTSCP). By itself it is not “time of day”; it is
  just a counter value.

**Reference time / partition time mapping**
  Hyper-V exposes a monotonic “reference time” to guests. In the fast path the
  guest derives this reference time from the TSC using hypervisor-provided scale
  and offset values (conceptually: ``ref_time = f(tsc, scale, offset)``). When
  ``HvCallRestorePartitionTime`` is invoked, Hyper-V updates this mapping.

**Software bias**
  A guest-side offset applied in software to compensate for a change in the
  underlying time mapping. Conceptually: ``corrected_time = raw_time + bias``.
  A bias can avoid needing to change the mapping at the source, but it requires
  careful coordination so all CPUs/userspace time readers observe a coherent,
  monotonic time.

The complication is that the underlying time base (TSC-to-reference-time mapping)
impacts **all Virtual Trust Levels (VTLs)** in the partition because the TSC is a
shared resource across VTLs.  As a result, Hyper-V only permits
``HvCallRestorePartitionTime`` to be invoked from the **highest VTL**.

When OpenHCL is running in VTL2, OpenHCL is the highest VTL and therefore must
be the component that ultimately issues the hypercall.

Intended call path
------------------
The intended behavior is:

1. A VTL0 guest (normal Linux guest context) issues ``HvCallRestorePartitionTime``
   when it needs to re-synchronize time.
2. OpenHCL intercepts the hypercall from VTL0.
3. OpenHCL reissues the hypercall from VTL2 (where it is permitted).

This preserves the VTL0 programming model while still enforcing the Hyper-V
security requirement that only the highest VTL can shift the partition time.

What goes wrong with nested hypervisors and VSM/secure kernel
------------------------------------------------------------
In practice, the only caller of ``HvCallRestorePartitionTime`` may be a nested
hypervisor layer running in VTL0.  This can happen because:

* The guest is actually running nested VMs.
* Or the guest enables VSM / secure kernel functionality that includes a
  hypervisor-like component that expects to manage time.

In these cases, the nested hypervisor expects to be able to restore partition
time as part of its own synchronization/management logic.  But because the call
is restricted to the highest VTL, a VTL0 invocation will fail unless OpenHCL
intercepts and reissues it.

Why reissuing the hypercall is not sufficient
---------------------------------------------
Reissuing ``HvCallRestorePartitionTime`` from OpenHCL in VTL2 changes the
partition's time mapping.  This effectively shifts the guest-observable
reference time derived from Hyper-V's synthetic clock mechanisms.

Linux consumes Hyper-V time via the Hyper-V clocksource and sched_clock plumbing
(see ``drivers/clocksource/hyperv_timer.c``).  Linux already contains support for
adjusting a software offset/bias in some situations (for example, the
``hv_adj_sched_clock_offset()`` helper and the ``hv_sched_clock_offset`` field).

More detail: what changes "underneath" Linux
--------------------------------------------
The important point is that ``HvCallRestorePartitionTime`` changes the
*hypervisor-provided conversion parameters* used to turn the fast counter
(TSC) into Hyper-V "reference time". The guest typically does not read a
separate hardware time register that the hypervisor overwrites; instead, the
guest reads TSC and applies a mapping (scale/offset) provided by Hyper-V.

Once the mapping changes, Linux can observe an apparent time jump even though it
did not change any Linux state. This affects multiple Linux time read paths:

* Hyper-V clocksource read path
    - ``read_hv_clock_tsc()`` reads the Hyper-V TSC reference page when
      available and falls back to the MSR-based reference time if not.
    - If Hyper-V updates the mapping (scale/offset) due to
      ``HvCallRestorePartitionTime``, the value returned by
      ``read_hv_clock_tsc()`` changes immediately.

* sched_clock on non-invariant-TSC paths
    - ``read_hv_sched_clock_tsc()`` derives sched_clock from Hyper-V reference
      time, but rebases it using ``hv_sched_clock_offset`` before converting to
      nanoseconds.
    - ``hv_sched_clock_offset`` is initialized once when Hyper-V registers
      sched_clock, and ``hv_adj_sched_clock_offset()`` exists to adjust that
      offset after events like resume/hibernate.
    - If Hyper-V changes the underlying reference-time mapping without Linux
      updating ``hv_sched_clock_offset`` (or an equivalent bias), sched_clock can
      jump.

Why CPU coordination matters
----------------------------
Applying a time-base correction is not only about the magnitude of the shift,
it is also about applying it *atomically enough* across CPUs.

If one CPU observes the new Hyper-V mapping while another CPU is still using the
old mapping (or one CPU has observed an updated Linux bias/offset while another
has not), the system can see "torn" time state:

* apparent one-CPU-ahead/one-CPU-behind behavior in timestamps
* transient non-monotonicity when comparing timestamps across CPUs
* jitter or mis-ordering in time-based logic that assumes a coherent clock

This is the motivation behind the legacy HCL approach of pausing CPUs during the
update: it creates a window where no CPU is concurrently sampling time while the
mapping/bias transition is being applied.

However, a restore-partition-time event is fundamentally a **time-base
transition** that can occur while CPUs are running.  If different CPUs observe a
mix of "old" and "new" time mapping (or old/new bias values) during the
transition, the system can see "torn" time state, such as:

* A CPU observing time moving backwards relative to another CPU.
* Inconsistencies in scheduler timestamps.
* Timer misfires or jitter.

Legacy HCL behavior (high level)
--------------------------------
Legacy HCL addresses the torn-state risk by:

1. Pausing all processors.
2. Updating the bias/offset to account for the time mapping change.
3. Resuming all processors.

This creates a global point where time reads are effectively quiesced while the
transition is applied.

Legacy HCL handling sequence (more detail)
-----------------------------------------
The legacy flow is intentionally simple and relies on the ability of the
paravisor to pause VPs directly:

1. Intercept ``HvCallRestorePartitionTime`` from the lower VTL.
2. Pause other processors (VPs) to prevent inconsistent reads.
3. Read current TSC (``prev_tsc``).
4. Forward the hypercall to the hypervisor with the original parameters.
5. Read TSC again (``cur_tsc``).
6. Update the bias based on ``prev_tsc`` and ``cur_tsc``.
7. Resume other processors.

The pause step is purely to ensure a consistent, global transition. The goal is
to reset the reference time underneath the OS without breaking monotonicity or
cross-CPU consistency. The Linux kernel already has support for a bias/offset
mechanism in the Hyper-V clocksource path, but it needs a safe, kernel-native
coordination mechanism to apply it coherently.

Open question for Linux
-----------------------
Linux does not have a single, universal "pause all processors" primitive as a
public API in the way legacy HCL describes.  Linux does have mechanisms to run
callbacks on other CPUs (e.g. SMP call helpers), but we need a well-defined
kernel-side strategy to ensure that:

* CPUs cannot observe a partially-applied time shift.
* The clocksource/sched_clock/vDSO-visible time remains monotonic and coherent.

A follow-on design task is to define the Linux-side synchronization and the
interfaces between:

* the OpenHCL intercept/reissue path (VTL2), and
* the Linux timekeeping/clocksource logic that must absorb the shift.

Notes
-----
* Hyper-V feature discovery includes a bit indicating support for
  ``HvCallRestorePartitionTime`` (see ``include/uapi/hyperv/hvhdk.h``).
