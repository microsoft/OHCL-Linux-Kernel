# Hostless servicing state across kexec (KHO/LUO concept)

## Goal
Reduce servicing blackout time by removing the **stream servicing-state blob to host + ACK/COMMIT** step, while still enabling the next VTL2 kernel/userspace instance to restore the unit/device graph.

This doc proposes **guest-only** alternatives using upstream kernel concepts:
- **KHO (Kernel Handover)**: kexec handover metadata (commonly via a handover FDT / device-tree payload)
- **LUO (Live Update Orchestrator)**: a control-plane that coordinates the update/restart boundary

> Note: This repo does not currently implement KHO/LUO. This doc is a design target and can be mapped onto whichever upstream interfaces we decide to consume.

## Background (what we do today)
Current design intent is to keep servicing semantics end-to-end:
- Stop VPs + stop graph
- Save graph into a serialized `ServicingState` blob
- Stream blob to host (GET/GED) and await durable **ACK/COMMIT**
- Cross restart boundary (reload or guest kexec)
- New VTL2 fetches blob from host, restores, starts graph, resumes VM

See [kexec-design/kexec-servicing.md](kexec-design/kexec-servicing.md) and blob contents in [kexec-design/save-state.md](kexec-design/save-state.md).

## What state must survive the boundary
Underhill already defines the "what" as one serialized payload:
- `ServicingState` = `init_state` + `units` (state-unit graph blobs)

Details: [kexec-design/save-state.md](kexec-design/save-state.md)

The key question is *where that payload lives* across the kexec boundary.

## Constraints and requirements
### Hard requirements (functional)
- VPs must be stopped while the save is taken (quiescence requirement).
- Saved state must be available to the **new** VTL2 instance early enough to restore graph before resuming.
- Versioning and compatibility: saved state format must be versioned; restore must safely reject unknown/invalid blobs.

### Nice-to-have requirements (operational)
- Reduce blackout time by removing host roundtrips.
- Preserve a recovery story when the update fails (rollback / retry).

### Non-requirements (explicitly out of scope)
- Full VM memory snapshot/restore. This design is about **Underhill servicing state**, not dumping RAM.

## Candidate solutions

### Solution A (recommended): KHO carries a descriptor; blob lives in reserved RAM
**Summary**: Save the existing `ServicingState` blob into a reserved physical memory region. KHO passes a small handover FDT node that points to that region. The new kernel reads, validates, restores, then wipes/releases.

**Why this fits**
- Keeps the existing `ServicingState` format (no need to stuff the whole blob into DT properties).
- Handover DT stays small and stable.

**High-level flow**
1. Stop VPs + stop graph
2. Save graph to `ServicingState` bytes
3. Allocate a *handover-safe* reserved memory region and copy the bytes there
4. Populate KHO handover DT with `{paddr, size, hash, version, correlation_id}`
5. `kexec` into new kernel
6. Early boot/userspace reads descriptor, maps reserved memory, validates hash/version
7. Restore graph, then wipe + free the region

**Block diagram**

```text
                         +----------------------------------+
                         | Hostless servicing via KHO (A)    |
                         +----------------+-----------------+
                                          |
                                          v
+--------------------------------------------------------------------------------+
|                         Blackout window (VPs paused)                           |
|                                                                                |
|  +---------------------------+                                                 |
|  | Stop graph                |  stop VPs + stop unit/device graph              |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Save graph                |  build ServicingState bytes                     |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Place blob in RAM         |  copy into reserved-memory handover region      |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | KHO handover FDT          |  (paddr,size,hash,version,correlation_id)       |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +===========================+                                                 |
|  || Restart boundary (kexec) ||                                                |
|  +=============+=============+                                                 |
|                |                                                               |
+----------------+---------------------------------------------------------------+
                 |
                 v
+--------------------------------------------------------------------------------+
| New VTL2 boots                                                                  |
|  +---------------------------+                                                 |
|  | Read KHO handover FDT     |  locate reserved-memory region                  |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Validate + restore graph  |  verify hash/version, apply ServicingState      |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Start graph + resume      |  wipe blob region, resume VPs                   |
|  +---------------------------+                                                 |
+--------------------------------------------------------------------------------+
```

**Handover DT contract (sketch)**
- Node name: `/chosen/openhcl,kho-servicing-state`
- Properties:
  - `openhcl,servicing-state-version` (u32)
  - `openhcl,servicing-state-paddr` (u64)
  - `openhcl,servicing-state-size` (u32 or u64)
  - `openhcl,servicing-state-sha256` (32 bytes)
  - `openhcl,servicing-correlation-id` (string or 16-byte UUID)
  - `openhcl,save-flags` (bitmask: optional subsystems present)

**Memory reservation options**
- Prefer a **reserved-memory** entry in the handover FDT so the new kernel won’t allocate over it.
- Alternatively, use a kexec "preserve" mechanism if the platform provides one; still document the region in the handover DT.

**Pros**
- Fast path: eliminates host streaming + ACK latency.
- Minimal schema surface: DT carries only a descriptor.
- Reuses existing `ServicingState` blob format and fixups.

**Cons / risks**
- Not durable across hard reset / host-initiated reload; only survives kexec.
- If the new kernel crashes before restore, you may be stuck in blackout until recovery logic runs.
- Requires careful memory lifetime handling (don’t leak reserved RAM; wipe sensitive state).

---

### Solution B: Put the whole blob into the handover FDT
**Summary**: Encode `ServicingState` bytes directly as a DT property.

**Pros**
- Simplest mental model: everything is "in the DT".

**Cons**
- DT size can grow; parsing/alloc overhead in early boot.
- DT becomes a heavy ABI for opaque runtime state.
- Harder to do streaming/incremental validation.

**Recommendation**: Avoid unless blob is proven to stay small and we accept DT-as-runtime-state ABI.

---

### Solution C: Guest-only persistence (write blob to guest storage)
**Summary**: Save `ServicingState` to a guest-visible persistent store (filesystem, block device) before kexec.

**Pros**
- Durable across crashes/reboots (depending on storage guarantees).
- Can support rollback/retry.

**Cons**
- Usually slower than RAM handover; may increase blackout.
- Requires choosing a storage location available in blackout and early boot.

**When to use**
- When durability is mandatory and hostless is required.

---

### Solution D: Hybrid: RAM handover + optional host commit (policy-based)
**Summary**: Default to Solution A for speed, but optionally stream to host (or persist to disk) when policy requires durability.

**Pros**
- Fast common case, safe critical case.

**Cons**
- More complexity and branching.

## Semantics: what you lose by removing host streaming
If we remove "send saved state to host" entirely, we typically lose:
- **Durability barrier**: host ACK/COMMIT guarantees the state survived the boundary.
- **Host-coordinated recovery**: host can keep state even if guest fails mid-update.

You can partially recover these semantics with Solution C (guest persistence) or D (hybrid).

## Validation and safety checks (regardless of solution)
- Version field + strict compatibility checks.
- Cryptographic hash (at minimum) to detect corruption.
- Wipe-on-success and wipe-on-failure policy to avoid leaking sensitive state across boots.
- Upper bound on blob size (to avoid pathological DT/memory usage).

## Measurement plan (what to benchmark)
- Blackout time components:
  - stop graph/VPs
  - save graph
  - host streaming + ack (baseline only)
  - kexec time
  - restore graph
- Compare baseline vs Solution A on identical configurations.

## Open questions
- Where is the best integration point for KHO handover DT construction (kernel vs userspace)?
- What is the required failure behavior if restore fails (retry kexec? fallback to host? reboot)?
- Do any subsystems require host participation to re-establish state even if the blob is carried locally?
