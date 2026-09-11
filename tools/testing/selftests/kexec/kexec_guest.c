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
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static char token[65];

static void finish(bool success, const char *reason)
{
	printf("KEXEC_VM %s %s %s\n", token, success ? "PASS" : "FAIL", reason);
	fflush(stdout);
	sync();
	reboot(RB_POWER_OFF);
	_exit(success ? 0 : 1);
}

static int read_text(const char *path, char *buffer, size_t size)
{
	int fd = open(path, O_RDONLY);
	ssize_t length;

	if (fd < 0)
		return -1;
	length = read(fd, buffer, size - 1);
	close(fd);
	if (length < 0 || (size_t)length == size - 1)
		return -1;
	buffer[length] = '\0';
	if (length && buffer[length - 1] == '\n')
		buffer[length - 1] = '\0';
	return 0;
}

static bool has_token(char *command)
{
	char expected[96], *argument, *save;

	snprintf(expected, sizeof(expected), "kexec_vm_token=%s", token);
	for (argument = strtok_r(command, " \t\n", &save); argument;
	     argument = strtok_r(NULL, " \t\n", &save)) {
		if (!strcmp(argument, expected))
			return true;
	}
	return false;
}

static void save_vmcore(void)
{
	unsigned char buffer[65536];
	Elf64_Ehdr header;
	struct stat status;
	uint64_t total = 0;
	ssize_t count;
	int input = open("/proc/vmcore", O_RDONLY);
	int output;

	if (input < 0 || fstat(input, &status) ||
	    pread(input, &header, sizeof(header), 0) != sizeof(header) ||
	    memcmp(header.e_ident, ELFMAG, SELFMAG) ||
	    header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_type != ET_CORE)
		finish(false, "invalid-vmcore");
	output = open("/dev/vda", O_WRONLY);
	if (output < 0)
		finish(false, "open-dump-disk");
	while ((count = read(input, buffer, sizeof(buffer))) > 0) {
		ssize_t offset = 0;

		while (offset < count) {
			ssize_t written = write(output, buffer + offset, count - offset);

			if (written < 0 && errno == EINTR)
				continue;
			if (written <= 0)
				finish(false, "write-vmcore");
			offset += written;
		}
		total += count;
	}
	if (count < 0 || total != (uint64_t)status.st_size || fsync(output))
		finish(false, "incomplete-vmcore");
	close(output);
	close(input);
	printf("KEXEC_VM %s VMCORE_BYTES %llu\n", token, (unsigned long long)total);
}

int main(void)
{
	char command[8192], stage[32], mode[32], expected_text[32];
	char marker[192], expected_release[256];
	struct utsname identity;
	unsigned long flags = 0;
	int kernel_fd, initrd_fd, error, expected;

	if (getpid() != 1) {
		fprintf(stderr, "Refusing to run outside an opt-in guest init\n");
		return 1;
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	if (read_text("/token", token, sizeof(token)) || strlen(token) != 32)
		return 1;
	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    read_text("/proc/cmdline", command, sizeof(command)) || !has_token(command))
		return 1;
	if (mount("sysfs", "/sys", "sysfs", 0, NULL) ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) ||
	    read_text("/stage", stage, sizeof(stage)) ||
	    read_text("/mode", mode, sizeof(mode)) || uname(&identity))
		finish(false, "guest-initialization");
	printf("KEXEC_VM %s IDENTITY %s %s\n", token, stage, identity.release);
	if (strcmp(mode, "normal") && strcmp(mode, "crash") && strcmp(mode, "load"))
		finish(false, "invalid-mode");
	if (!strcmp(stage, "target")) {
		if (read_text("/expected-release", expected_release, sizeof(expected_release)) ||
		    strcmp(identity.release, expected_release))
			finish(false, "unexpected-target-release");
		printf("KEXEC_VM %s TARGET_READY\n", token);
		if (!strcmp(mode, "crash"))
			save_vmcore();
		finish(true, "target-userspace");
	}
	if (strcmp(stage, "source"))
		finish(false, "invalid-stage");
	printf("KEXEC_VM %s SOURCE_READY\n", token);
	if (read_text("/target-command", command, sizeof(command)) ||
	    read_text("/expected-errno", expected_text, sizeof(expected_text)))
		finish(false, "missing-request");
	expected = atoi(expected_text);
	if (!strcmp(mode, "crash"))
		flags |= KEXEC_FILE_ON_CRASH;
	kernel_fd = open("/kernel", O_RDONLY);
	initrd_fd = open("/target-initrd", O_RDONLY);
	if (kernel_fd < 0 || initrd_fd < 0)
		finish(false, "open-input");
	printf("KEXEC_VM %s LOAD_BEGIN\n", token);
	error = syscall(__NR_kexec_file_load, kernel_fd, initrd_fd,
			strlen(command) + 1, command, flags) ? errno : 0;
	close(kernel_fd);
	close(initrd_fd);
	printf("KEXEC_VM %s LOAD_RESULT %d\n", token, error);
	if (error != expected)
		finish(false, "unexpected-load-result");
	if (!strcmp(mode, "load")) {
		if (!error && syscall(__NR_kexec_file_load, -1, -1, 0UL, NULL,
				      KEXEC_FILE_UNLOAD))
			finish(false, "unload");
		finish(true, "load-policy");
	}
	if (error)
		finish(false, "cannot-execute-rejected-image");
	printf("KEXEC_VM %s HANDOFF\n", token);
	if (flags & KEXEC_FILE_ON_CRASH) {
		int panic_fd;

		snprintf(marker, sizeof(marker), "KEXEC_VM %s PANIC_SOURCE\n", token);
		panic_fd = open("/dev/kmsg", O_WRONLY);
		if (panic_fd >= 0) {
			if (write(panic_fd, marker, strlen(marker)) < 0)
				finish(false, "panic-marker");
			close(panic_fd);
		}
		panic_fd = open("/proc/sysrq-trigger", O_WRONLY);
		if (panic_fd < 0 || write(panic_fd, "c", 1) != 1)
			finish(false, "panic-trigger");
	} else {
		reboot(RB_KEXEC);
	}
	finish(false, "handoff-returned");
}
