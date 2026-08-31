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

An ELF image can be loaded with kexec-tools by selecting the file system call::

  kexec --kexec-file-syscall --load /path/to/vmlinux \
        --initrd=/path/to/initrd --command-line="..."

The supported ELF input is the little-endian, ELF64, ``ET_EXEC`` image for
``EM_X86_64`` produced by an x86 kernel build. The loaded kernel must have
``CONFIG_RELOCATABLE=y``. The loader uses the ``PT_LOAD`` program headers;
debugging, BTF, and other non-loadable sections are ignored.

Each loadable segment must have a valid file and memory size, a page-aligned
physical address, and a power-of-two alignment respected by that address.
Loadable physical ranges must not overlap. The ELF entry point may identify
either a virtual or physical address within a loadable segment.

The loader preserves the relative physical layout of all loadable segments and
relocates the complete span as one kexec segment. Images with a sparse physical
span larger than half of system RAM are rejected. Both normal kexec and
crash-kexec images are supported.

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

The kexec selftests include an opt-in load-and-unload test for this path. It
does not execute the loaded image::

  KEXEC_VMLINUX=/path/to/vmlinux \
    make -C tools/testing/selftests TARGETS=kexec run_tests
