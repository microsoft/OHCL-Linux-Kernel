## Save-state blob details

#### What “save” does (sequence)
1. **Stop graph / quiesce**: VPs are stopped and the state-unit graph is halted so no device or subsystem is mutating while we snapshot. The transition is driven by `state_units.stop()` inside the servicing path. See [openhcl/underhill_core/src/dispatch/mod.rs](openhcl/underhill_core/src/dispatch/mod.rs#L786-L835).
2. **Collect subsystem saves**: Underhill gathers snapshots from subsystems and the state-unit graph. This yields a `ServicingState` struct that is then encoded into a byte payload. See [openhcl/underhill_core/src/dispatch/mod.rs](openhcl/underhill_core/src/dispatch/mod.rs#L868-L966).
3. **Encode to blob**: The full `ServicingState` is serialized into a binary payload using `mesh::payload::encode`. See [openhcl/underhill_core/src/dispatch/mod.rs](openhcl/underhill_core/src/dispatch/mod.rs#L552-L575).

#### What is in the servicing-state blob
The blob is a serialized `ServicingState` (not a DTB). It has two major parts: `init_state` and `units`. The type definition is in [openhcl/underhill_core/src/servicing.rs](openhcl/underhill_core/src/servicing.rs#L14-L104).

**A) `init_state` (boot/restore setup + subsystem state)**
Captured fields:
- `firmware_type`: which firmware mode VTL0 booted with (UEFI/PCAT/None).
- `vm_stop_reference_time`: hypervisor reference time when VPs/state units were stopped.
- `correlation_id`: tracing correlation for the servicing event.
- `emuplat`: saved state for emuplat glue:
   - `rtc_local_clock`
   - `get_backed_adjust_gpa_range` (optional)
   - `netvsp_state` (vector)
- `flush_logs_result`: timing + error (if any) from the log‑flush call done near the end of save.
- `vmgs`: optional VMGS saved state plus disk metadata.
- `overlay_shutdown_device`: whether the host shutdown IC is intercepted/overlaid.
- `nvme_state`: optional NVMe manager saved state (only saved when controllers exist and keepalive is enabled).
- `dma_manager_state`: optional DMA manager saved state (only saved when keepalive is enabled).
- `vmbus_client`: optional VMBus client saved state.
- `mana_state`: optional MANA saved state (only when keepalive is enabled).

Where these are gathered:
- `emuplat`, `dma_manager_state`, `nvme_state`, `units`, `mana_state`, `vmgs`, `vmbus_client`, etc. are assembled in `save()` when building `ServicingState`. See [openhcl/underhill_core/src/dispatch/mod.rs](openhcl/underhill_core/src/dispatch/mod.rs#L856-L953).

**B) `units` (state-unit graph snapshots)**
`units` is a list of `SavedStateUnit { name, state }`, where `state` is an opaque `SavedStateBlob` from each state unit. The type is defined in [vmm_core/state_unit/src/lib.rs](vmm_core/state_unit/src/lib.rs#L346-L356).

The exact contents of each unit blob depend on the unit implementation, but they are all collected by `state_units.save()` during the save step. See [openhcl/underhill_core/src/dispatch/mod.rs](openhcl/underhill_core/src/dispatch/mod.rs#L956-L966).

#### Compatibility fixups included in the blob
Before sending, Underhill runs `ServicingState::fix_pre_save()` to add legacy compatibility data (notably around `vmbus_relay` vs `vmbus_client` state) so older paravisors can restore. See [openhcl/underhill_core/src/servicing.rs](openhcl/underhill_core/src/servicing.rs#L114-L148).