# Servicing vs. Kexec — Design Doc

## Primary goal
Replace the host-triggered VTL2 reload boundary with a guest-driven Linux kexec boundary, while preserving servicing semantics end-to-end: enter the same blackout window, stop and save the unit/device graph, then carry the saved state across the boundary either by streaming it to the host (with an explicit host ACK/COMMIT before kexec) or by passing it directly to the new kernel via KHO kexec as FTD. After the boundary, the new VTL2 instance restores state, starts the graph, and resumes the VM.

---

## A. Original servicing flow (baseline)

Servicing logs: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments)

### A.1 Block diagram (baseline)

<details>
<summary>Block diagram (baseline)</summary>

```text
                         +---------------------------+
                         | Current Servicing Flow   |
                         +-------------+-------------+
                                       |
                                       v
+--------------------------------------------------------------------------------+
|                         Blackout window (VPs paused)                            |
|                                                                                |
|  +---------------------------+                                                 |
|  | Stop graph (quiesce VM)   |  Stop VPs + stop unit/device graph              |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Save graph                |  Serialize unit/device state                    |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Stream blob to host       |  GET/GED write + await host response            |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Restart boundary          |  Host reloads VTL2 (new kernel/userspace)       |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | New VTL2 boots            |  Detect servicing restore mode                   |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Fetch blob from host      |  New VTL2 requests saved state                   |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Restore graph             |  Apply blob to rebuild unit/device state         |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Start graph               |  Start units/devices                             |
|  +-------------+-------------+                                                 |
+--------------------------------------------------------------------------------+
                                       |
                                       v
                          +--------------------------+
                          | Resume VM (end blackout) |
                          +--------------------------+
```

</details>

### A.2 Different stages in servicing

- Stop VPs: stop all virtual processors
- Save VTL2 state as a blob: Underhill produces one serialized payload called ServicingState and sends it to the host (via GET/
GED)
- Blob sent to host (not a dtb): VTL2 finished streaming the saved-state blob to the host. Host sends an ACK after receiving the blob
- Restart boundary + new kernel boot
- New VTL2 fetches blob: The new Underhill instance is up far enough to establish transport and request the saved blob
- Restore complete
- Start complete

### 1) Stop VPs (stop graph finished)

Anchor: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments) Line no.: 91

Meaning:
- Underhill has finished dependency-ordered stopping of its unit/device graph.
- VPs are stopped during this window (you’ll see many `stopping VP` lines earlier).

Snapshot:
```text
<31>[   64.551034] state_unit: DEBUG servicing_save_vtl2{ correlation_id=aa6fc41c-851d-4c4c-afb0-596ac365d2c3}:state_change{ operation="stop"}:device_state_change{ device="vmbus_relay"}:  device state change complete duration=382.850418ms
<31>[   64.562337] vmm_core::partition_unit::vp_set: DEBUG run_vp{ vp_index=0x0}:  stopping VP
<31>[   64.567376] vmm_core::partition_unit::vp_set: DEBUG run_vp{ vp_index=0x0}:  VP stopped on request
```

### 2) Save graph (save graph finished)

Anchor: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments) : Line no. 148

Meaning:
- Units/devices finished serializing their saveable state into the servicing-state payload.

Snapshot:
```text
<30>[   65.199232] state_unit:  INFO servicing_save_vtl2{ correlation_id=aa6fc41c-851d-4c4c-afb0-596ac365d2c3}:save_units:state_change{ operation="save"}:  state change complete duration=314.640888ms
```

For more details, please check [save-state.md](https://github.com/microsoft/OHCL-Linux-Kernel/blob/user/hargar/kexec-2026/kexec-design/save-state.md)

### 3) Blob sent to host (GET/GED stream complete)

Anchor: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments) : Line no. 174

Meaning:
- VTL2 finished streaming the saved-state blob to the host.
- The old VTL2 instance now waits for the host to proceed (typically: perform the VTL2 reload boundary).

Snapshot:
```text
<31>[   65.400587] guest_emulation_transport::process_loop: DEBUG  More data? SUCCESS saved_state_bytes_written 65536 saved_state_size 67324, payload_len 1788
<31>[   65.407720] guest_emulation_transport::process_loop: DEBUG  Done writing saved state, awaiting host response
```

### 4) Restart boundary + new kernel

Anchor: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments) : Line no. 177

Meaning:
- Servicing crosses the reboot boundary for VTL2.
- In this log, the transition is visible as the “jump to kernel” line followed by a fresh kernel boot at timestamp 0.0.

Snapshot:
```text
uninitializing hypercalls, about to jump to kernel
<5>[    0.000000] Linux version 6.12.36-microsoft-hcl+
```

### 5) Fetch blob (new VTL2 gets servicing state from host)

Anchor: Anchor: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments) : Line no. 414

Meaning:
- The new Underhill instance is up far enough to establish transport and request the saved blob.

Snapshot:
```text
<30>[    1.280999] underhill_core::worker:  INFO worker_new{ name="UnderhillWorker" action="new"}:init:  VTL2 restart, getting servicing state from the host
<30>[    1.288084] underhill_core::worker:  INFO worker_new{ name="UnderhillWorker" action="new"}:init:  received servicing state from host saved_state_len=0x106fc
```

### 6) Restore complete (restore graph finished)

Anchor: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments) : Line no. 600

Meaning:
- The new Underhill instance has applied the saved blob to rebuild internal/device state.

Snapshot:
```text
<30>[    3.811745] state_unit:  INFO worker_new{ name="UnderhillWorker" action="new"}:init:init/restore{ correlation_id=aa6fc41c-851d-4c4c-afb0-596ac365d2c3}:restore_units:state_change{ operation="restore"}:  state change complete duration=1.15248739s
```

### 7) Start complete (start graph finished)

Anchor: [servicing_logs](https://onedrive.cloud.microsoft/my?id=%2Fa%40ru7a88zu%2FDocuments%2Fservicing%2Dlogs%2Etxt&parent=%2Fa%40ru7a88zu%2FDocuments) : Line no. 658

Meaning:
- Units/devices have been started and the system is ready to resume execution.

Snapshot:
```text
<30>[    4.414129] state_unit:  INFO state_change{ operation="start"}:  state change complete duration=586.932644ms
```

### 8) Resume + blackout time

Anchor: [kexec/servicing_logs](kexec/servicing_logs#L799)

Meaning:
- Underhill resumes the VM (VPs run again).
- `blackout_time` is the end-to-end pause duration as tracked by Underhill, spanning more than just the 4 state graphs.

Snapshot:
```text
<30>[    4.420856] underhill_core::dispatch:  INFO  resuming VM correlation_id=aa6fc41c-851d-4c4c-afb0-596ac365d2c3 blackout_time_ms=0x1873 blackout_time="6.2598526s"
```

---

## B. Kexec-based approach (current)

Replace the **restart boundary mechanism** (host-triggered reload) with **guest-triggered Linux kexec** inside VTL2.

kexec-servicing logs (with current state of the prototype): [logs](https://github.com/microsoft/OHCL-Linux-Kernel/blob/user/hargar/kexec-2026/kexec-design/logs/kexec-servicing-logs.txt)

### B.1 Block diagram (current state of prototype: servicing with kexec)

<details>
<summary>Block diagram (kexec parity)</summary>

```text
                         +----------------------------------+
                         | Servicing flow with Kexec        |
                         +----------------+-----------------+
                                          |
                                          v
+--------------------------------------------------------------------------------+
|                         Blackout window (VPs paused)                            |
|                                                                                |
|  +---------------------------+                                                 |
|  | Stop graph                |                                                 |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | Save graph                |                                                 |
|  +-------------+-------------+                                                 |
|                |                                                               |
|                v                                                               |                                                                                |
|  +===========================+                                                 |
|  || Restart boundary (kexec) ||  <-- REPLACES: "Host reloads VTL2" boundary    |
|  +=============+=============+  VTL2 runs Linux kexec into new VTL2 kernel     |
|                |                                                               |
|                v                                                               |
|  +---------------------------+                                                 |
|  | New VTL2 boots            |                                                 |
|  +-------------+-------------+                                                 |
|                                                                                 |
+--------------------------------------------------------------------------------+
```

</details>

### B.2 Current state (prototype)

Current behavior:
- A guest-side kexec hook is integrated into the servicing-save path.
- The prototype can effectively do: **Stop VPs/graph → Save graph → kexec → (later) request saved state**.

Why this is not yet servicing-parity:
- The servicing-state blob must be **fully streamed to the host and durably stored** before the restart boundary.
- Today, kexec can happen **before** `send_servicing_state()` finishes, so the host may not have a committed blob and the new VTL2 cannot reliably restore.

What we need to figure out:
- Audit what data is captured in the save stage (“saved state”).
- Determine what subset can be passed directly to the new kernel via KHO kexec as FTD, and what (if anything) must still be sent to the host.

---

## D. Next steps / open questions

Host + protocol:
- Update host behavior to support guest-driven restart:
    - If any data is required by the host from the save stage, kexec should happen only after the host ACK (i.e. after the “awaiting host response” ACK is received).
      Ensure the post-kexec boot path reliably fetches the saved blob and reports restore success/failure back to the host.
    - If no data is required to be sent to the host, pass the required data via KHO kexec as FTD and notify the host once kexec is complete.

Measurement:
- Do a fair latency/perf comparison only after the host changes exist (otherwise the flow is not equivalent).

Packaging ownership:
- Decide how we provide `kexec` + kernel binary (current approach: include in rootfs; increases Underhill binary size by ~ 4mb).
- Confirm who owns/implements the host-side changes.
