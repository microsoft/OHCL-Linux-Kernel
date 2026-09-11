.. SPDX-License-Identifier: GPL-2.0

========================
Loading an x86-64 kernel
========================

The ``kexec_file_load()`` system call asks the kernel to parse a kernel image,
place its segments, and prepare the architecture-specific boot state. On
x86-64, the in-kernel loader accepts either a boot protocol ``bzImage`` or an
uncompressed ELF ``vmlinux``.

Loading ELF vmlinux
===================

An ELF image is loaded by passing its file descriptor to
``kexec_file_load()``. A version of kexec-tools with x86 ELF file-syscall
support can provide that interface::

  kexec --kexec-file-syscall --load /path/to/vmlinux \
        --initrd=/path/to/initrd --command-line="..."

Some kexec-tools versions only implement the legacy userspace ELF loader;
``--kexec-file-syscall`` alone does not add the required userspace support.
The selftest below invokes the syscall directly and does not need kexec-tools.

The supported ELF input is the little-endian, ELF64, ``ET_EXEC`` image for
``EM_X86_64`` produced by an x86 kernel build, with the Linux ``startup_64``
entry accepting a physical ``boot_params`` pointer in RSI and the target boot
note described below. The target must be rebuilt with the note producer;
older images without this contract are rejected. The loader uses the
``PT_LOAD`` and ``PT_NOTE`` program headers and does not require section
headers or debugging information. An omitted command line is accepted,
including when the target uses a built-in command line.

The uncompressed x86-64 startup code fixes up its physical mappings while
retaining the linked virtual addresses. This does not depend on the running
kernel's ``CONFIG_RELOCATABLE`` option. The loader does not perform arbitrary
ELF relocations: the target must implement this Linux startup contract.

Each loadable segment must have a valid file and memory size, a page-aligned
physical address, and a power-of-two alignment of at least 2 MiB respected by
that address.
Loadable physical ranges must not overlap. The ELF entry point may identify
either a virtual or physical address within file-backed loadable data, and
must resolve to the same physical address as the target-declared entry.
The executable program-header flag is not required: the kernel linker places
``.init.text``, including ``startup_64``, in a writable load segment.
Entry points in zero-filled memory, or mapping to more than one physical
address, are rejected.

The loader preserves the relative physical layout of all loadable segments and
relocates the complete span as one kexec segment. Images with a sparse physical
span larger than half of system RAM are rejected. Both normal kexec and
crash-kexec images are supported subject to the target contract.

Provisional target boot note
============================

This is an RFC implementation, not an upstream-assigned or stable ABI. The
owner ``Linux.x86.elfboot.rfc`` and type 1 are local proposal identifiers and
may change following review. Production compatibility must not depend on them.

The note is emitted for x86-64 targets independently of ``CONFIG_KEXEC_FILE``.
Its descriptor is little-endian, with the following byte offsets::

  Offset  Size  Meaning
       0     4  Version (1)
       4     4  Required flags
       8     4  Maximum command-line characters, excluding the NUL
      12     4  Minimum physical relocation alignment in bytes
      16     4  Physical address bits for inherited four-level paging
      20     4  Physical address bits for inherited five-level paging
      24     8  Linked startup_64 virtual address
      32     N  Built-in command line, including exactly one final NUL

Flag bit 0 permits physical rebasing while preserving segment offsets and
linked virtual addresses; it does not permit virtual KASLR. If clear, the
image must fit at its specified physical addresses. Flag bit 1 means the
built-in command line overrides the loader-provided command line. Otherwise
the target prepends its nonempty built-in string and a space. The effective
command line, including any crash parameters, must fit the advertised limit.
Crash loading with an override is rejected because it would discard the
loader's crash parameters.

An address width of zero rejects that incoming paging mode. Nonzero widths
apply uniformly to the kernel, boot parameters, command line, initrd, and
prepared kexec segments. The current target advertises 46 bits in four-level
mode and 52 bits in five-level mode. Allocation is additionally constrained
by the running CPU, kernel mappings, available RAM and crash/KHO reservations.
The descriptor is not permission to access addresses outside those constraints.

Version 1 requires a complete descriptor and rejects unknown versions, flags,
types in this owner namespace, and duplicate descriptors. Unrelated ELF notes
are ignored. Notes are bounded by their program header and the kernel payload,
excluding an appended signature. The descriptor is read from the same file
whose signature or IMA policy is checked before loading. Stripping debug or
symbol sections must retain the note, and signing must follow final packaging.

Targets using ``CONFIG_CMDLINE_FROM_BOOTCONFIG`` do not emit this version of
the note, because it does not describe their additional embedded command line.

Boot compatibility and security
===============================

ELF images have no x86 setup header advertising target boot capabilities.
The provisional note instead describes direct entry with the running kernel's
paging mode preserved. Four-level to four-level and five-level to five-level
entry are accepted only when the target advertises the corresponding mode.
There is no automatic upgrade to five-level paging. An effective ``no5lvl``
argument on a five-level host is rejected with ``EOPNOTSUPP``, because direct
entry cannot perform that transition. A paging-mode switch requires a separate
target entry path; the decompressor's switching code is not executed here.

Active 32-bit EFI runtime services remain unsupported. The running kernel's
encrypted-memory environments (including SME and SEV/TDX guests) are also
rejected by this contract. Its configuration is never used as proof of target
capabilities. A successful load
only confirms staging; boot, firmware and crash behavior still need testing
on the intended source/target combination.

.. warning::

  Direct ELF boot bypasses the decompressor's KASLR implementation. Kernel
  text virtual addresses are not randomized, and memory-layout randomization
  (``CONFIG_RANDOMIZE_MEMORY``) is also disabled. This applies even when the
  target was built with ``CONFIG_RANDOMIZE_BASE=y`` and ``nokaslr`` was not
  specified. A kernel warning is emitted when an ELF image is staged.
  Use ``bzImage`` when address randomization is required. Signature
  verification authenticates the image but does not restore this hardening.

Image authentication
====================

The x86 ``bzImage`` loader can verify a PE/Authenticode signature. With
``CONFIG_KEXEC_ELF_VERIFY_SIG=y``, the ELF loader verifies an appended PKCS#7
signature in the same format used for signed kernel modules. For example::

  scripts/sign-file sha256 key.pem cert.pem vmlinux kernel.signed

The signing certificate must be available through the secondary trusted
keyring, or through the platform keyring when
``CONFIG_INTEGRITY_PLATFORM_KEYRING=y``. An ELF image can alternatively be
authenticated by an IMA appraisal policy for ``KEXEC_KERNEL_CHECK``.

When forced kexec signature verification is enabled, the ELF signature option
and a valid appended signature are required. Under kernel lockdown, an unsigned
ELF image requires an IMA policy that guarantees appraisal of the kexec image.

Selftests
=========

The kexec selftests include an opt-in direct-syscall test for this path.
Build and run only the ELF test, as root, with a known bootable image::

  make -C tools/testing/selftests/kexec
  cd tools/testing/selftests/kexec
  KEXEC_VMLINUX=/path/to/vmlinux ./test_kexec_file_load_vmlinux.sh

The test never executes the image and refuses to replace an already staged
normal kexec image. Do not run it concurrently with another kexec loader.
It requires successful load and unload of the valid image, tests omitted,
empty and boundary-length command lines, and checks malformed ELF headers,
alignment, sizes, overlapping segments and entry addresses. Negative image
tests use private copies, leaving the supplied image unchanged. Signature
or IMA policy rejections of modified images are reported as SKIP, not PASS;
run on a system permitting unsigned images for parser coverage. Unsupported
platforms and policy-denied initial loads also report SKIP. Unexpected load
or unload failures report FAIL. Crash boot and boot-time behavior still require
separate testing on a disposable machine.

Performance evaluation
======================

Direct ELF entry avoids kernel decompression, but the larger input file and
the contiguous staging buffer can increase load-time I/O and memory use.
Measure ``kexec_file_load()`` time separately from the transition to the next
kernel and from application availability. Use the same kernel source,
configuration, initrd and command line when comparing formats, and include
the fastest practical supported ``bzImage`` compression as a baseline.

Keep Kexec Handover (KHO) and CMA settings consistent between the two formats.
For non-crash images, the common kexec code skips segment checksum verification
when KHO is enabled or all segments use CMA. Crash images retain verification.
This optimization applies to both loaders and does not bypass image signature
verification; its benefit must not be attributed to direct ELF entry.

For a comparison that isolates decompression costs, disable KASLR for the
``bzImage`` baseline as well. Report the production ``bzImage`` baseline with
its normal hardening separately; disabling randomization is a security
tradeoff, not solely a performance optimization. Record image sizes, whether
debug sections were stripped before signing, peak staging memory, and the
distribution of timings across repeated boots. Load/unload selftests do not
measure transition latency or validate crash capture.
