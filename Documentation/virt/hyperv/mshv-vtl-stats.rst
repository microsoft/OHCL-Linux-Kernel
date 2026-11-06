.. SPDX-License-Identifier: GPL-2.0

MSHV VTL transition statistics
==============================

``MSHV_VTL_GET_STATS`` returns a ``struct mshv_vtl_stats`` snapshot on a VTL
file descriptor obtained through ``MSHV_CREATE_VTL``. Set ``cpu`` to the
Linux CPU number to query; all other fields are output. Possible CPUs are
accepted even when offline. These are driver-wide per-CPU statistics, not
statistics specific to the file descriptor or current task.

Accounting is always enabled and independent of ftrace. Each explicit
Hyper-V, SNP, or TDX lower-VTL switch call increments ``entry_count`` before
the call and ``exit_count`` after it returns. Halt-only waits, cancellation,
and message-only processing do not add transitions. The legacy sysfs
counter is unchanged and retains its existing coverage limitations.

All timestamps and durations are CLOCK_MONOTONIC nanoseconds. Totals and
maxima contain completed intervals only:

* ``lower_vtl_total_ns`` and ``lower_vtl_max_ns`` measure entry to return.
* ``vtl2_total_ns`` and ``vtl2_max_ns`` measure return to the next entry.
  The initial VTL2 interval before the first recorded entry is omitted.

``state`` is the last observed software state: UNKNOWN (0) before the first
switch, VTL2 (1) after a return, or LOWER_VTL (2) after an entry.
For VTL2, ``snapshot_ns - last_exit_ns`` gives the current interval age.
For LOWER_VTL, use ``snapshot_ns - last_entry_ns``. This does not prove that
the VP is physically executing in the indicated VTL.

Snapshots do not send an IPI to the target CPU. The per-CPU lock is never
held across lower-VTL execution. A busy snapshot returns ``EAGAIN`` without
waiting; the caller can retry later. Invalid CPU numbers return ``EINVAL``
and inaccessible userspace memory returns ``EFAULT``.

These are elapsed switch-call intervals, not exclusive CPU execution
times. They include context-switch overhead and descheduling. Entry counts
include attempts that return without executing the lower VTL, such as a
rejected TDX entry. Lower-VTL intervals can refer to VTL0 or another lower
VTL; they are not split by target. CCA plane switches and sidecar execution
are not implemented by these paths.

There is no reset, histogram, or transition-history buffer. Accounting
adds two clock reads and short per-CPU critical sections to each switch.

Example, using an existing VTL file descriptor::

    struct mshv_vtl_stats stats = { .cpu = 0 };

    if (ioctl(vtl_fd, MSHV_VTL_GET_STATS, &stats) == -1) {
        perror("MSHV_VTL_GET_STATS"); /* Retry later on EAGAIN. */
        return -1;
    }

    printf("cpu=%u state=%u\n"
           "entry_count=%llu exit_count=%llu\n"
           "last_entry_ns=%llu last_exit_ns=%llu\n"
           "lower_vtl_total_ns=%llu lower_vtl_max_ns=%llu\n"
           "vtl2_total_ns=%llu vtl2_max_ns=%llu\n"
           "snapshot_ns=%llu\n",
           stats.cpu, stats.state,
           (unsigned long long)stats.entry_count,
           (unsigned long long)stats.exit_count,
           (unsigned long long)stats.last_entry_ns,
           (unsigned long long)stats.last_exit_ns,
           (unsigned long long)stats.lower_vtl_total_ns,
           (unsigned long long)stats.lower_vtl_max_ns,
           (unsigned long long)stats.vtl2_total_ns,
           (unsigned long long)stats.vtl2_max_ns,
           (unsigned long long)stats.snapshot_ns);
