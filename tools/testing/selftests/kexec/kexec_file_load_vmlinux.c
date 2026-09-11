// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kexec.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../kselftest.h"
#include "../../../../arch/x86/include/asm/elfboot.h"

static bool image_loaded;

static void unload_image(void)
{
	if (image_loaded &&
	    !syscall(__NR_kexec_file_load, -1, -1, 0UL, NULL, KEXEC_FILE_UNLOAD))
		image_loaded = false;
}

static int load_image(int image_fd, const char *command, size_t length)
{
	if (syscall(__NR_kexec_file_load, image_fd, -1, length, command,
		    KEXEC_FILE_NO_INITRAMFS))
		return errno;

	image_loaded = true;
	unload_image();
	if (image_loaded)
		ksft_exit_fail_msg("cannot unload test image: %s\n", strerror(errno));
	return 0;
}

static bool policy_error(int error)
{
	return error == EPERM || error == EACCES || error == EKEYREJECTED ||
	       error == ENOKEY;
}

static void expect_result(int image_fd, const char *command, size_t length,
			  int expected, bool modified, const char *name)
{
	int error = load_image(image_fd, command, length);

	if (modified && policy_error(error)) {
		ksft_test_result_skip("%s: policy rejected modified image (%s)\n",
				      name, strerror(error));
		return;
	}
	ksft_test_result(error == expected, "%s: got %d, expected %d\n",
			 name, error, expected);
}

static void test_modified_error(const void *buffer, size_t length, int expected,
				const char *name)
{
	const char *cursor = buffer;
	int image_fd = memfd_create("kexec-elf-test", MFD_CLOEXEC);

	if (image_fd < 0)
		ksft_exit_fail_msg("memfd_create: %s\n", strerror(errno));
	while (length) {
		ssize_t written = write(image_fd, cursor, length);

		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			ksft_exit_fail_msg("write test image: %s\n", strerror(errno));
		cursor += written;
		length -= written;
	}
	expect_result(image_fd, "", 1, expected, true, name);
	close(image_fd);
}

static void test_modified(const void *buffer, size_t length, const char *name)
{
	test_modified_error(buffer, length, ENOEXEC, name);
}

static size_t find_boot_note(const char *buffer, size_t length,
			     const Elf64_Ehdr *header, size_t *phdr_offset)
{
	size_t found = 0;

	for (unsigned int index = 0; index < header->e_phnum; index++) {
		size_t offset = header->e_phoff + index * sizeof(Elf64_Phdr);
		Elf64_Phdr phdr;
		size_t cursor, end;

		memcpy(&phdr, buffer + offset, sizeof(phdr));
		if (phdr.p_type != PT_NOTE)
			continue;
		if (phdr.p_offset > length || phdr.p_filesz > length - phdr.p_offset)
			ksft_exit_fail_msg("fixture note segment is out of bounds\n");
		cursor = phdr.p_offset;
		end = cursor + phdr.p_filesz;
		while (cursor < end) {
			Elf64_Nhdr note;
			size_t namesz, descsz, start = cursor;

			if (end - cursor < sizeof(note))
				ksft_exit_fail_msg("truncated fixture note header\n");
			memcpy(&note, buffer + cursor, sizeof(note));
			cursor += sizeof(note);
			namesz = ((size_t)note.n_namesz + 3) & ~3UL;
			descsz = ((size_t)note.n_descsz + 3) & ~3UL;
			if (namesz > end - cursor || descsz > end - cursor - namesz)
				ksft_exit_fail_msg("truncated fixture note payload\n");
			if (note.n_namesz == sizeof(X86_ELFBOOT_NOTE_NAME) &&
			    !memcmp(buffer + cursor, X86_ELFBOOT_NOTE_NAME, note.n_namesz)) {
				if (found || note.n_type != X86_ELFBOOT_NOTE_TYPE)
					ksft_exit_fail_msg("duplicate or unsupported boot note\n");
				found = start;
				*phdr_offset = offset;
			}
			cursor += namesz + descsz;
		}
	}
	if (!found)
		ksft_exit_fail_msg("fixture requires a target ELF boot note\n");
	return found;
}

int main(int argc, char **argv)
{
	char *command;
	Elf64_Phdr first_load, second_load, changed;
	Elf64_Phdr entry_load;
	Elf64_Nhdr note, changed_note;
	struct x86_elfboot boot, changed_boot;
	size_t note_offset, note_phdr_offset = 0, desc_offset, builtin_size;
	size_t command_size, maximum_text;
	size_t first_offset = 0, second_offset = 0;
	size_t entry_phdr_offset = 0;
	uint64_t entry_offset = 0;
	struct stat image_stat;
	Elf64_Ehdr header;
	FILE *status;
	char *buffer;
	int image_fd, loaded, error;
	unsigned int index;

	ksft_print_header();
	if (argc != 2)
		ksft_exit_skip("provide a bootable x86-64 vmlinux image\n");
	if (geteuid())
		ksft_exit_skip("root privileges are required\n");
	status = fopen("/sys/kernel/kexec_loaded", "r");
	if (!status)
		ksft_exit_skip("cannot check for an existing kexec image\n");
	if (fscanf(status, "%d", &loaded) != 1 || loaded)
		ksft_exit_skip("refusing to replace an existing or unknown kexec image\n");
	fclose(status);
	if (atexit(unload_image))
		ksft_exit_fail_msg("cannot register image cleanup\n");

	image_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (image_fd < 0)
		ksft_exit_fail_msg("open image: %s\n", strerror(errno));
	if (fstat(image_fd, &image_stat) || image_stat.st_size < (off_t)sizeof(header))
		ksft_exit_fail_msg("image is too short or cannot be read\n");
	buffer = mmap(NULL, image_stat.st_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, image_fd, 0);
	if (buffer == MAP_FAILED)
		ksft_exit_fail_msg("mmap image: %s\n", strerror(errno));
	memcpy(&header, buffer, sizeof(header));
	if (memcmp(header.e_ident, ELFMAG, SELFMAG) ||
	    header.e_ident[EI_CLASS] != ELFCLASS64 ||
	    header.e_ident[EI_DATA] != ELFDATA2LSB ||
	    header.e_machine != EM_X86_64 || header.e_type != ET_EXEC ||
	    header.e_phentsize != sizeof(Elf64_Phdr) ||
	    header.e_phoff > (uint64_t)image_stat.st_size ||
	    header.e_phnum > (image_stat.st_size - header.e_phoff) / sizeof(Elf64_Phdr))
		ksft_exit_fail_msg("invalid x86-64 ELF test fixture\n");
	for (index = 0; index < header.e_phnum; index++) {
		size_t offset = header.e_phoff + index * sizeof(Elf64_Phdr);

		memcpy(&changed, buffer + offset, sizeof(changed));
		if (changed.p_type != PT_LOAD)
			continue;
		if (!entry_phdr_offset) {
			if (header.e_entry >= changed.p_vaddr &&
			    header.e_entry - changed.p_vaddr < changed.p_filesz) {
				entry_phdr_offset = offset;
				entry_offset = header.e_entry - changed.p_vaddr;
			} else if (header.e_entry >= changed.p_paddr &&
				   header.e_entry - changed.p_paddr < changed.p_filesz) {
				entry_phdr_offset = offset;
				entry_offset = header.e_entry - changed.p_paddr;
			}
			if (entry_phdr_offset)
				entry_load = changed;
		}
		if (!first_offset) {
			first_offset = offset;
			first_load = changed;
		} else if (!second_offset) {
			second_offset = offset;
			second_load = changed;
		}
	}
	if (!first_offset)
		ksft_exit_fail_msg("test fixture has no PT_LOAD\n");
	if (!entry_phdr_offset)
		ksft_exit_fail_msg("test fixture has no file-backed entry\n");

	note_offset = find_boot_note(buffer, image_stat.st_size, &header, &note_phdr_offset);
	memcpy(&note, buffer + note_offset, sizeof(note));
	desc_offset = note_offset + sizeof(note) + ((note.n_namesz + 3UL) & ~3UL);
	if (note.n_descsz <= sizeof(boot))
		ksft_exit_fail_msg("fixture boot descriptor is too short\n");
	memcpy(&boot, buffer + desc_offset, sizeof(boot));
	builtin_size = note.n_descsz - sizeof(boot);
	if (boot.version != X86_ELFBOOT_VERSION || boot.flags & ~X86_ELFBOOT_FLAGS ||
	    !boot.cmdline_size || boot.cmdline_size > 16 * 1024 * 1024 ||
	    builtin_size - 1 > boot.cmdline_size ||
	    memchr(buffer + desc_offset + sizeof(boot), 0, builtin_size) !=
		buffer + desc_offset + note.n_descsz - 1)
		ksft_exit_fail_msg("unsupported fixture boot descriptor\n");
	maximum_text = boot.cmdline_size;
	if (!(boot.flags & X86_ELFBOOT_CMDLINE_OVERRIDE) && builtin_size > 1) {
		if (builtin_size > maximum_text)
			ksft_exit_fail_msg("fixture has no room to append boot arguments\n");
		maximum_text -= builtin_size;
	}
	command_size = (size_t)boot.cmdline_size + 2;
	command = malloc(command_size);
	if (!command)
		ksft_exit_fail_msg("allocate command line: %s\n", strerror(errno));

	error = load_image(image_fd, "nokaslr", sizeof("nokaslr"));
	if (error == ENOSYS || error == EOPNOTSUPP || policy_error(error))
		ksft_exit_skip("ELF load unavailable or denied by policy: %s\n",
			       strerror(error));
	ksft_set_plan(35);
	ksft_test_result(!error, "valid image load and unload: %s\n", strerror(error));
	if (error)
		ksft_exit_fail_msg("valid fixture must load before negative tests\n");

	expect_result(image_fd, NULL, 0, 0, false, "omitted command line");
	expect_result(image_fd, "", 1, 0, false, "empty command line");
	memset(command, ' ', command_size);
	command[maximum_text] = '\0';
	expect_result(image_fd, command, maximum_text + 1, 0, false,
		      "maximum command line");
	command[maximum_text] = ' ';
	command[command_size - 1] = '\0';
	expect_result(image_fd, command, command_size, EINVAL, false,
		      "oversized command line");
	expect_result(image_fd, command, command_size - 1, EINVAL, false,
		      "unterminated command line");

	buffer[note_offset + sizeof(note)] = 'X';
	test_modified(buffer, image_stat.st_size, "missing boot contract");
	buffer[note_offset + sizeof(note)] = X86_ELFBOOT_NOTE_NAME[0];
	changed_boot = boot;
	changed_boot.version++;
	memcpy(buffer + desc_offset, &changed_boot, sizeof(changed_boot));
	test_modified_error(buffer, image_stat.st_size, EOPNOTSUPP, "unknown boot version");
	changed_boot = boot;
	changed_boot.flags |= 1U << 31;
	memcpy(buffer + desc_offset, &changed_boot, sizeof(changed_boot));
	test_modified_error(buffer, image_stat.st_size, EOPNOTSUPP, "unknown required boot flag");
	changed_boot = boot;
	changed_boot.cmdline_size = 0;
	memcpy(buffer + desc_offset, &changed_boot, sizeof(changed_boot));
	test_modified(buffer, image_stat.st_size, "zero target command-line capacity");
	changed_boot = boot;
	changed_boot.alignment = 4096;
	memcpy(buffer + desc_offset, &changed_boot, sizeof(changed_boot));
	test_modified(buffer, image_stat.st_size, "invalid target alignment");
	changed_boot = boot;
	changed_boot.phys_bits_4 = 64;
	memcpy(buffer + desc_offset, &changed_boot, sizeof(changed_boot));
	test_modified(buffer, image_stat.st_size, "invalid target address width");
	changed_boot = boot;
	changed_boot.phys_bits_4 = 0;
	changed_boot.phys_bits_5 = 0;
	memcpy(buffer + desc_offset, &changed_boot, sizeof(changed_boot));
	test_modified(buffer, image_stat.st_size, "no supported paging mode");
	changed_boot = boot;
	changed_boot.entry = UINT64_MAX;
	memcpy(buffer + desc_offset, &changed_boot, sizeof(changed_boot));
	test_modified(buffer, image_stat.st_size, "invalid declared target entry");
	memcpy(buffer + desc_offset, &boot, sizeof(boot));
	changed_note = note;
	changed_note.n_type++;
	memcpy(buffer + note_offset, &changed_note, sizeof(changed_note));
	test_modified_error(buffer, image_stat.st_size, EOPNOTSUPP, "unknown boot note type");
	changed_note = note;
	changed_note.n_namesz = UINT32_MAX;
	memcpy(buffer + note_offset, &changed_note, sizeof(changed_note));
	test_modified(buffer, image_stat.st_size, "note name exceeds segment");
	changed_note = note;
	changed_note.n_descsz = UINT32_MAX;
	memcpy(buffer + note_offset, &changed_note, sizeof(changed_note));
	test_modified(buffer, image_stat.st_size, "note descriptor exceeds segment");
	changed_note = note;
	changed_note.n_descsz = sizeof(boot);
	memcpy(buffer + note_offset, &changed_note, sizeof(changed_note));
	test_modified(buffer, image_stat.st_size, "truncated boot descriptor");
	memcpy(buffer + note_offset, &note, sizeof(note));
	buffer[desc_offset + note.n_descsz - 1] = 'X';
	test_modified(buffer, image_stat.st_size, "unterminated target command line");
	buffer[desc_offset + note.n_descsz - 1] = '\0';
	memcpy(&changed, buffer + note_phdr_offset, sizeof(changed));
	memcpy(buffer + first_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "duplicate boot descriptor");
	memcpy(buffer + first_offset, &first_load, sizeof(first_load));

	buffer[EI_MAG0] = 0;
	test_modified(buffer, image_stat.st_size, "invalid ELF magic");
	buffer[EI_MAG0] = ELFMAG0;
	test_modified(buffer, sizeof(header) - 1, "truncated ELF header");
	changed = first_load;
	changed.p_align = 0x1000;
	memcpy(buffer + first_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "4 KiB segment alignment");
	changed = first_load;
	changed.p_memsz = 0;
	memcpy(buffer + first_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "zero segment memory size");
	changed = first_load;
	changed.p_memsz = changed.p_filesz ? changed.p_filesz - 1 : 0;
	memcpy(buffer + first_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "file size exceeds memory size");
	changed = first_load;
	changed.p_offset = image_stat.st_size;
	changed.p_filesz = 1;
	memcpy(buffer + first_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "segment data beyond end of file");
	changed = first_load;
	changed.p_offset = UINT64_MAX;
	changed.p_filesz = 2;
	memcpy(buffer + first_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "segment file range wraps around");
	changed = first_load;
	changed.p_paddr = UINT64_MAX - changed.p_memsz + 1;
	memcpy(buffer + first_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "segment physical range wraps around");
	memcpy(buffer + first_offset, &first_load, sizeof(first_load));
	if (second_offset) {
		changed = second_load;
		changed.p_paddr = first_load.p_paddr;
		memcpy(buffer + second_offset, &changed, sizeof(changed));
		test_modified(buffer, image_stat.st_size, "overlapping PT_LOAD ranges");
		memcpy(buffer + second_offset, &second_load, sizeof(second_load));
	} else {
		ksft_test_result_skip("overlap test requires two PT_LOAD segments\n");
	}
	header.e_entry = UINT64_MAX;
	memcpy(buffer, &header, sizeof(header));
	test_modified(buffer, image_stat.st_size, "entry outside PT_LOAD ranges");

	header.e_entry = entry_load.p_vaddr + entry_offset + 1;
	memcpy(buffer, &header, sizeof(header));
	test_modified(buffer, image_stat.st_size, "virtual entry differs from target contract");
	header.e_entry = entry_load.p_paddr + entry_offset + 1;
	memcpy(buffer, &header, sizeof(header));
	test_modified(buffer, image_stat.st_size, "physical entry differs from target contract");
	header.e_entry = entry_load.p_paddr + entry_offset;
	memcpy(buffer, &header, sizeof(header));
	changed = entry_load;
	changed.p_filesz = entry_offset;
	memcpy(buffer + entry_phdr_offset, &changed, sizeof(changed));
	test_modified(buffer, image_stat.st_size, "physical entry in zero-filled data");
	header.e_entry = entry_load.p_vaddr + entry_offset;
	memcpy(buffer, &header, sizeof(header));
	test_modified(buffer, image_stat.st_size, "virtual entry in zero-filled data");
	memcpy(buffer + entry_phdr_offset, &entry_load, sizeof(entry_load));
	if (second_offset && entry_phdr_offset != second_offset &&
	    entry_offset < second_load.p_filesz) {
		changed = second_load;
		changed.p_flags |= PF_X;
		changed.p_vaddr = entry_load.p_vaddr;
		memcpy(buffer + second_offset, &changed, sizeof(changed));
		test_modified(buffer, image_stat.st_size, "ambiguous virtual entry");
	} else {
		ksft_test_result_skip("ambiguous entry requires another file-backed PT_LOAD\n");
	}

	free(command);
	munmap(buffer, image_stat.st_size);
	close(image_fd);
	ksft_finished();
}
