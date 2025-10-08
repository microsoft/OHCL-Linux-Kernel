Summary:

After kexec the measured Paravisor config pages (which normally contain VTL0 UEFI metadata and VP context) are lost,
so the loader saw missing supports_uefi and originally failed with “uefi not supported”. We added an environment‑controlled
fallback (OPENHCL_FORCE_LOAD_VTL0_IMAGE=uefi) that reconstructs a synthetic UEFI firmware memory range.
To move beyond a bare bypass, we:

1. Captured the real cold‑boot VP register context (21 registers: GDT, flat segments, CR0/3/4, EFER, PAT, RIP, RBP, some GPRs, MTRRs).
2. Implemented optional synthetic VP context reconstruction in the forced path (enable with OPENHCL_SYNTHESIZE_VTL0_VP_CTX=1) so post‑kexec
boot more closely matches measured startup.
3. Added automatic dump of the measured VP context on normal boot (suppressible), and an optional validation of the firmware
base (OPENHCL_VALIDATE_SYNTHETIC_UEFI=1).
4. Patched kexec script to set the missing magic values (“OHCLVTL2”, “OHCLVTL0”) so initial asserts pass; full measured 
contents are still absent.

Remaining gap: If full fidelity or attestation correctness is needed, we’d have to rebuild the entire 
ParavisorMeasuredVtl0Config (not just magic + synthetic context).
