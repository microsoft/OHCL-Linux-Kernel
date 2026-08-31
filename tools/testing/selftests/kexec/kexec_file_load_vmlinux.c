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

#define X86_COMMAND_LINE_SIZE 2048

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

static void test_modified(const void *buffer, size_t length, const char *name)
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
	expect_result(image_fd, "", 1, ENOEXEC, true, name);
	close(image_fd);
}

int main(int argc, char **argv)
{
	char command[X86_COMMAND_LINE_SIZE + 1];
	Elf64_Phdr first_load, second_load, changed;
	size_t first_offset = 0, second_offset = 0;
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

	error = load_image(image_fd, "nokaslr", sizeof("nokaslr"));
	if (error == ENOSYS || error == EOPNOTSUPP || policy_error(error))
		ksft_exit_skip("ELF load unavailable or denied by policy: %s\n",
			       strerror(error));
	ksft_set_plan(13);
	ksft_test_result(!error, "valid image load and unload: %s\n", strerror(error));
	if (error)
		ksft_exit_fail_msg("valid fixture must load before negative tests\n");

	expect_result(image_fd, NULL, 0, 0, false, "omitted command line");
	expect_result(image_fd, "", 1, 0, false, "empty command line");
	memset(command, ' ', sizeof(command));
	command[X86_COMMAND_LINE_SIZE - 1] = '\0';
	expect_result(image_fd, command, X86_COMMAND_LINE_SIZE, 0, false,
		      "maximum command line");
	command[X86_COMMAND_LINE_SIZE - 1] = ' ';
	command[X86_COMMAND_LINE_SIZE] = '\0';
	expect_result(image_fd, command, sizeof(command), EINVAL, false,
		      "oversized command line");
	expect_result(image_fd, command, X86_COMMAND_LINE_SIZE, EINVAL, false,
		      "unterminated command line");

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

	munmap(buffer, image_stat.st_size);
	close(image_fd);
	ksft_finished();
}
