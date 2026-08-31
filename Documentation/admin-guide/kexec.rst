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
entry accepting a physical ``boot_params`` pointer in RSI. The loader uses
the ``PT_LOAD`` program headers; debugging, BTF, and other non-loadable
sections are ignored. An omitted command line is accepted, including when
the target uses a built-in command line.

The uncompressed x86-64 startup code fixes up its physical mappings while
retaining the linked virtual addresses. This does not depend on the running
kernel's ``CONFIG_RELOCATABLE`` option. The loader does not perform arbitrary
ELF relocations: the target must implement this Linux startup contract.

Each loadable segment must have a valid file and memory size, a page-aligned
physical address, and a power-of-two alignment of at least 2 MiB respected by
that address.
Loadable physical ranges must not overlap. The ELF entry point may identify
either a virtual or physical address within a loadable segment.

The loader preserves the relative physical layout of all loadable segments and
relocates the complete span as one kexec segment. Images with a sparse physical
span larger than half of system RAM are rejected. Both normal kexec and
crash-kexec images are supported.

Boot compatibility and security
===============================

ELF images have no x86 setup header advertising target boot capabilities.
The loader therefore rejects ELF images with ``EOPNOTSUPP`` when five-level
paging (LA57) is active, even if the target supports it, or when 32-bit EFI
runtime services are active. Use ``bzImage`` in these environments. Supporting
ELF on an LA57 host requires a future target-capability contract; the running
kernel's configuration cannot establish the target's capabilities.

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
