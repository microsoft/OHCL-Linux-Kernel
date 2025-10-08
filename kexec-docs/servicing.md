GitHub Copilot: Got it. We should stop treating kexec as a special “debug override” and instead align it with the servicing (restore) code path so we don’t need ad‑hoc flags like OPENHCL_FORCE_SERVICING or manual skips that diverge from intended behavior.

## What “servicing” currently means in code

Servicing behavior in worker.rs is enabled when:
- `dps.general.is_servicing_scenario` (host tells us) OR
- We injected `OPENHCL_FORCE_SERVICING=1`, which forces `load_kind = LoadKind::None` (no firmware reload, no VP context generation).

During servicing:
- Firmware load is skipped.
- State units may be restored.
- Certain intercepted channels (like shutdown IC) may disconnect/reconnect.
- Some initialization (e.g. VP context synthesis, UEFI dynamic config) is intentionally bypassed.

For kexec we want exactly those semantics: don’t try to (re)load UEFI, don’t require measured UEFI VP context, treat already-applied VTL2 protections as normal, and avoid failing on missing “cold boot” assumptions.

## Why current approach still feels “bolted on”

Right now:
- `OPENHCL_FORCE_SERVICING` is a manual manual trigger—not automatic.
- We rely on logs like “VTL2 protections already applied (likely kexec scenario)” later in initialization rather than making an early servicing decision.
- Some subsystems (like sidecar and VMBus logic) still assume cold boot ordering unless explicitly told otherwise.

## Recommended direction

### Phase 1 (Minimal / Fast)

Introduce a clearer alias: `OPENHCL_KEXEC_SERVICING=1` that maps to the same force_servicing behavior. Keep the existing one for backward compatibility. Update the log to reflect which path triggered it (force vs kexec).

Logic change (safe, small):
- In worker.rs, compute `force_servicing` as:
  - `OPENHCL_FORCE_SERVICING=1` OR
  - `OPENHCL_KEXEC_SERVICING=1`

This leaves your current experiments intact but makes intent explicit.

### Phase 2 (Heuristic Auto-Detect)

Automatically infer servicing (without env vars) if all of the following hold early:
1. Measured VTL0 page reads successfully but lacks both UEFI and Linux support descriptors.
2. A “probe” hypercall (or early memory protection apply) indicates VTL2 protections are already active (we already log this later).
3. No saved servicing state came from the host.

If those conditions hold: treat as servicing. (We’d add a tracing WARN making the heuristic explicit.)

Because we only know about already-applied VTL2 protections inside `underhill_mem::init`, which happens after worker sets `load_kind`, we would either:
- (a) add a lightweight early probe hypercall just for detection, or
- (b) defer final classification until just before firmware load and downgrade load_kind then (slightly refactors loader entry call).

Option (a) is cleaner (does not introduce mutable state after partial init); option (b) touches fewer layers but needs a conditional patch point.

### Phase 3 (Refinement)

Once stable:
- Remove (or hide behind debug cfg) the skip flags (`OPENHCL_SKIP_VTL0_UEFI`, forced synthetic VP context) you no longer need in steady-state servicing flows.
- Add a structured “boot mode” enum to diagnostics: Cold, ServicingHostState, ServicingHeuristic(Kexec), Forced(Debug).

### Sidecar Consideration

Sidecar AP states stuck in RUN (2) are likely a downstream symptom of skipping firmware + not restoring any saved VP context/register programming normally expected before Linux driver attaches. Under true servicing, the host would have provided saved state so the AP trampoline logic may differ minimally.

Once we classify kexec as servicing:
- If we still see RUN statuses, we can safely auto-demote lingering RUN -> IDLE for diagnostic progression (env gated) because servicing semantics assume prior state continuity rather than fresh rendezvous requirements.

### Immediate Small Patch (if you want me to apply now)

Add in worker.rs near existing force_servicing code:

```rust
let force_servicing = {
    let env_force = std::env::var("OPENHCL_FORCE_SERVICING").map(|v| v == "1").unwrap_or(false);
    let env_kexec  = std::env::var("OPENHCL_KEXEC_SERVICING").map(|v| v == "1").unwrap_or(false);
    if env_kexec {
        tracing::warn!(CVM_ALLOWED, "treating boot as servicing (kexec) via OPENHCL_KEXEC_SERVICING=1");
    }
    env_force || env_kexec
};
```

And adjust the existing log so it doesn’t always say “forcing servicing …” unless actually forced.

Let me know if you want:
- Just Phase 1 patch now
- Phase 1 + a TODO scaffold for Phase 2
- Or proceed straight to adding the heuristic probe

I can implement whichever you choose in the next turn. Just tell me “Phase 1”, “Phase 2 plan”, or “Both now”.
