Focusing on why the kexec run dies with “unexpected cpu status 2” while the original (cold) boot proceeds into normal device state transitions.

## What the warning means

From `sidecar_defs::CpuStatus`:
- 0 REMOVED
- 1 IDLE
- 2 RUN
- 3 STOP
- 4 REMOVE

The kernel warning is emitted inside the (out‑of‑tree) Linux sidecar driver (`sidecar_start+0x85/0x90`), not from the Rust sidecar code. It’s complaining that a CPU slot in the sidecar control page had status 2 (RUN) when it expected some other value (very likely REMOVED or IDLE) during the bring‑up handshake.

In the Rust sidecar initialization (init.rs):

1. When the control page is initialized:
   - `cpu_status[0]` (the base VP per node) is set to REMOVED (0).
   - `cpu_status[1..vp_count]` are set to RUN (2) as placeholders until each AP actually starts and transitions itself to IDLE (1) inside `ap_entry`.
2. AP startup:
   - Each non‑base VP is started via `start_aps`.
   - In `ap_entry`, the AP swaps its status from RUN → IDLE.
3. After launching all APs, the BSP waits until no `cpu_status[..]` entries are RUN:
   ```
   while status.load() == RUN { spin_loop(); }
   ```
   So if initialization completes successfully, there should be:
   - cpu 0: REMOVED
   - cpus 1..N: IDLE
   when control returns to the caller.

Therefore, if the Linux driver later sees cpu 0 (or any expected-idle slot) still showing RUN (2), it means one of:
A. The AP(s) never actually executed `ap_entry` (startup failed silently).
B. The control page contents are stale / not reinitialized (memory reuse issue under kexec).
C. The driver is reading a different physical page than the sidecar initialized (address mismatch).
D. The memory got clobbered after sidecar init (overlap with another allocator, or not reserved properly in the kexec path).
E. Sidecar init returned early but reported success (logical bug causing statuses to remain RUN). (Less likely because the code would panic on VP start errors.)

Because the panic happens before the cascade of `state_unit` device start logs (which appear in the original run shortly after sidecar boot completes), it strongly suggests sidecar never reached a stable post-init state from the kernel driver’s perspective.

## Key delta in logs

At similar timestamps:

Kexec (failing):
- We see Underhill loader message about loading UEFI, VP context dump (0 registers), then quickly the kernel warning.
- No `state_unit` device start logs appear before the warning.
- No vmbus offer emission sequence (the offers logged are only the initial host → guest offers, not the later “sending offer to guest” wave from the original run).

Cold boot (healthy):
- Sidecar is fully up; `state_unit` orchestrates a long chain: ioapic, rtc, pm, serials, chipset, partition, etc.
- Then a flood of vmbus offer sends, synthetic interrupt traffic, watchdog and UEFI NVRAM flushes, etc.

So the entire VM/device orchestration layer never engages in the kexec scenario because the kernel aborted in the sidecar driver path first.

## Why kexec makes this fragile

Under kexec:
- Physical memory isn’t fully power‑on reset. Pages previously used for sidecar (control page + per‑VP pages) may still contain old contents.
- The mechanism that identifies free VTL2 memory (`partition_info.vtl2_ram` minus `vtl2_used_ranges`) may not reflect new kernel allocations made during the first boot, causing sidecar to pick a region now partially in use or not fully clean.
- If the region reused already has cpu_status entries still set to RUN (2) for cpu 0 (unexpected in a fresh init), and for some reason the sidecar init code didn’t overwrite them (e.g., misaligned mapping, wrong physical base, or struct layout mismatch), the Linux driver will complain.

The absence of any panic from sidecar Rust code (“failed to start VP …”) reduces likelihood of genuine hypercall failures and increases suspicion of address / memory reuse issues.

## VP context absence is probably not the root cause

The “measured VTL0 VP context dump … total_registers=0” difference is observable but:
- The sidecar bring‑up doesn’t depend on the measured VP context page—it performs hypercalls directly to retrieve VSM offsets and capabilities.
- A zeroed VP context page shouldn’t impact the control page handshake between sidecar and the kernel driver.

Still, you should regenerate a correct VP context later for parity, but it’s probably orthogonal to this warning.

## Most likely causes (ranked)

1. Control page memory reuse / stale contents (not fully rewritten under kexec).
2. Sidecar reserved memory colliding with something else post-kexec (so writes are lost or overlapped).
3. Sidecar node memory base miscomputed due to differences in partition info gathering on kexec path.
4. AP startup not attempted because `node_count` ended up 0 or some early return condition (would need to confirm, but logs show sidecar_start invoked).
5. Extremely early clobber by another component mapping the same physical page into a different domain.

## Concrete next steps to pinpoint

1. Instrument sidecar init (Rust) right after the control page is initialized (inside that block in init.rs) to log:
   - Control page physical address
   - First, say, 16 CPU statuses (or `min(vp_count, 16)`)
   - Values of key fields (index/base_cpu/cpu_count/request_vector)
2. Instrument right after AP wait loop finishes (just before `Ok(())`) to log those statuses again.
3. Add a one-time dump in the kernel (or a small helper in userspace using mem) immediately before the kernel invokes the sidecar driver start IOCTL in the kexec boot to confirm what the driver sees in the control page (verifying whether sidecar’s writes “stuck”).
4. Verify the physical address passed back via `SidecarOutput.nodes[0].control_page` matches what the driver maps (log both).
5. In kexec path, before launching underhill/sidecar:
   - Zero (memset) the chosen sidecar node memory ranges (especially the first page). This will eliminate “stale content” ambiguity (you can do this cautiously with mem once you’ve confirmed the planned ranges).
6. Cross-check that `memory_base` is page aligned and `memory_size` is a multiple of 4096 (should be, but log it explicitly).
7. Compare the chosen sidecar node layout (base_vp, vp_count) between cold boot and kexec (log from `start_sidecar`).
8. If statuses are written correctly initially but later become RUN again, add a watchpoint/logging (periodic CRC) over the control page to detect external clobber.

## Quick code instrumentation sketch (Rust sidecar)

Inside init.rs, in the control page initialization block:

```
if enable_logging && node_index == 0 {
    let show = core::cmp::min(vp_count as usize, 16);
    for i in 0..show {
        log!("sidecar init: initial cpu_status[{i}]={}", control.cpu_status[i].load(Relaxed));
    }
    log!("sidecar init: control_page_pa={:#x} base_vp={base_vp} vp_count={vp_count}", control_page_range.start());
}
```

And just after the AP wait loop:

```
if enable_logging {
    let show = core::cmp::min(nodes[0].vp_count as usize, 16);
    let output0 = &output.nodes[0];
    let cp = unsafe { mapper.map::<ControlPage>(output0.control_page) };
    for i in 0..show {
        log!("sidecar post-wait: cpu_status[{i}]={}", cp.cpu_status[i].load(Relaxed));
    }
}
```

(Guard with logging flag to avoid noisy production output.)

## Validation path after adding instrumentation

1. Cold boot: capture those new logs (baseline expected: cpu_status[0]=0, others 1 after wait).
2. Kexec boot: compare; if cpu_status[0] already 2 before AP wait loop, initialization didn’t overwrite that location ⇒ memory mismatch or stale mapping.
3. If initialization shows correct values but the driver still reports status 2 later, something mutated the page in between: look for overlapping allocator usage.

## Interim workaround (if you need progress)

If the failure blocks further investigation and sidecar is optional for your current functional testing:
- Temporarily disable sidecar in the kexec path (e.g., strip `boot_cpus=` injection or force `partition_info.boot_options.sidecar = false`).
- Proceed with other VP context regeneration tasks.
Document this as a temporary deviation.

## VP context regeneration (still pending)

When you circle back:
1. Build a small helper (in-tree) that uses `igvm_defs` to serialize a `VbsVpContextHeader` + register array exactly as loader expects.
2. Replace base64 blob generation with an on-demand call to that helper in the kexec script (avoid stale artifacts).
3. Re-enable VP context synthesis and confirm that `parse_vtl0_vp_context` logs a non-zero `total_registers` and no unsupported register IDs.

## Summary of likely root cause

The “unexpected cpu status 2” warning nearly certainly indicates the sidecar control page at the moment the kernel driver inspected it had an unexpected RUN (2) where it expected REMOVED or IDLE. Given the initialization code’s logic, the most plausible explanation under kexec is stale or mis-mapped memory: the control page the driver sees was not freshly reinitialized, or the sidecar wrote a different physical page than the driver later read. Instrumentation and forced zeroing of the reserved sidecar region before start will quickly confirm this.

## Action checklist (succinct)

- Add logging instrumentation (control page initial + post-wait snapshots).
- Log chosen node memory ranges and control page PA.
- Zero node memory before sidecar_start in kexec flow for a test run.
- Compare cold vs kexec snapshots.
- If mismatch: investigate address selection (PartitionInfo, vtl2_ram enumeration).
- After resolving: proceed to VP context page regeneration.

Let me know if you’d like me to apply the instrumentation patch directly or craft a helper to dump the control page from userspace—I can do that next.