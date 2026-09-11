#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

script_dir=$(dirname "$(realpath "$0")")
kernel_dir=$(realpath "$script_dir/../../../..")
source_build= target= target_release= output=
mode=normal accel=tcg cpu=max memory=2048 limit=300 expected=0 action=
source_args=no5lvl target_args=no5lvl
qemu=${QEMU:-qemu-system-x86_64}

usage()
{
	printf '%s\n' "Usage: $0 --run|--prepare-only --source-build DIR --target FILE" \
		"  --target-release RELEASE [--mode normal|crash|load] [--expect-errno N]" \
		"  [--accel tcg|kvm] [--cpu CPU] [--memory MiB] [--timeout SECONDS]" \
		"  [--source-args STRING] [--target-args STRING] [--output DIR]" \
		"No host kernel is loaded. TCG results are correctness tests, not benchmarks."
}

while (($#)); do
	case "$1" in
	--help) usage; exit 0 ;;
	--run|--prepare-only) action=$1; shift ;;
	--source-build|--target|--target-release|--mode|--expect-errno|--accel|--cpu|\
	--memory|--timeout|--source-args|--target-args|--output)
		(($# >= 2)) || { usage >&2; exit 1; }
		option=${1#--}
		option=${option//-/_}
		case "$option" in
		expect_errno) expected=$2 ;;
		timeout) limit=$2 ;;
		*) printf -v "$option" '%s' "$2" ;;
		esac
		shift 2 ;;
	*) usage >&2; exit 1 ;;
	esac
done

[[ -n "$action" && -n "$source_build" && -n "$target" && -n "$target_release" ]] || {
	usage >&2; exit 1;
}
[[ "$mode" =~ ^(normal|crash|load)$ && "$accel" =~ ^(tcg|kvm)$ &&
	"$memory" =~ ^[1-9][0-9]{0,5}$ && "$limit" =~ ^[1-9][0-9]{0,5}$ &&
	"$expected" =~ ^[0-9]{1,3}$ ]] || { printf 'Invalid mode or numeric option\n' >&2; exit 1; }
[[ "$mode" == load || "$expected" == 0 ]] || {
	printf 'Rejection tests require --mode load\n' >&2; exit 1;
}
if [[ "$action" == --run ]] && ! command -v "$qemu" >/dev/null; then
	printf 'SKIP: QEMU unavailable; install it or set QEMU to its path\n'
	exit 4
fi
if [[ "$action" == --run && "$accel" == kvm && (! -r /dev/kvm || ! -w /dev/kvm) ]]; then
	printf 'SKIP: KVM is not accessible; use --accel tcg for functional tests\n'
	exit 4
fi

source_build=$(realpath "$source_build")
target=$(realpath "$target")
source_image=$source_build/arch/x86/boot/bzImage
cpio_tool=$source_build/usr/gen_init_cpio
[[ -r "$source_image" && -r "$target" && -x "$cpio_tool" ]] || {
	printf 'Need built source bzImage, gen_init_cpio, and target image\n' >&2; exit 1;
}
for path in "$source_build" "$target" "$script_dir"; do
	[[ "$path" != *[[:space:]]* ]] || {
		printf 'Initramfs input paths must not contain whitespace\n' >&2; exit 1;
	}
done
if [[ -n "$output" ]]; then
	mkdir -p "$output"
	work=$(mktemp -d "$(realpath "$output")/kexec-vm.XXXXXXXX")
else
	work=$(mktemp -d /tmp/kexec-vm.XXXXXXXX)
fi
[[ "$work" != *[[:space:]]* ]] || {
	printf 'Output path must not contain whitespace\n' >&2; exit 1;
}
chmod 700 "$work"
printf 'Artifacts: %s\n' "$work"
token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" > "$work/token"
printf '%s\n' "$mode" > "$work/mode"
printf '%s\n' "$expected" > "$work/expected-errno"
printf '%s\n' "$target_release" > "$work/expected-release"
printf 'source\n' > "$work/stage-source"
printf 'target\n' > "$work/stage-target"
target_command="console=ttyS0 panic=-1 $target_args kexec_vm_token=$token"
source_command="console=ttyS0 panic=-1 $source_args kexec_vm_token=$token"
if [[ "$mode" == crash ]]; then
	source_command+=" crashkernel=256M"
fi
printf '%s\n' "$target_command" > "$work/target-command"
${CC:-gcc} -static -O2 -Wall -Wextra -Werror "$script_dir/kexec_guest.c" -o "$work/init"

common_list()
{
	printf 'dir /dev 0755 0 0\ndir /proc 0755 0 0\ndir /sys 0755 0 0\n'
	printf 'nod /dev/console 0600 0 0 c 5 1\n'
	for name in init token mode expected-release expected-errno target-command; do
		printf 'file /%s %s/%s 0700 0 0\n' "$name" "$work" "$name"
	done
}
{
	common_list
	printf 'file /stage %s/stage-target 0400 0 0\n' "$work"
} > "$work/target.cpio-list"
"$cpio_tool" "$work/target.cpio-list" > "$work/target.cpio"
{
	common_list
	printf 'file /stage %s/stage-source 0400 0 0\n' "$work"
	printf 'file /kernel %s 0400 0 0\n' "$target"
	printf 'file /target-initrd %s/target.cpio 0400 0 0\n' "$work"
} > "$work/source.cpio-list"
"$cpio_tool" "$work/source.cpio-list" > "$work/source.cpio"

{
	printf 'base=%s\n' "$(git -C "$kernel_dir" rev-parse HEAD)"
	printf 'mode=%s\naccel=%s\ncpu=%s\nmemory_mib=%s\n' "$mode" "$accel" "$cpu" "$memory"
	printf 'source_cmdline=%s\ntarget_cmdline=%s\n' "$source_command" "$target_command"
	printf 'expected_errno=%s\ntarget_release=%s\n' "$expected" "$target_release"
	git -C "$kernel_dir" diff HEAD | sha256sum
	sha256sum "$source_image" "$source_build/.config" "$target" "$work/init" \
		"$script_dir/vmtest.sh"
} > "$work/manifest.txt"
cp "$source_build/.config" "$work/source.config"

if [[ "$action" == --prepare-only ]]; then
	printf 'Prepared guest artifacts; no QEMU launched\n'
	exit 0
fi
"$qemu" --version >> "$work/manifest.txt"
qemu_args=(-machine q35 -accel "$accel" -cpu "$cpu" -m "$memory" -smp 2
	-no-reboot -display none -monitor none -serial "file:$work/serial.log"
	-nic none -kernel "$source_image" -initrd "$work/source.cpio" -append "$source_command")
if [[ "$mode" == crash ]]; then
	truncate -s "$((memory * 2))M" "$work/vmcore.elf"
	qemu_args+=(-drive "file=$work/vmcore.elf,format=raw,if=virtio")
fi
printf '%q ' "$qemu" "${qemu_args[@]}" > "$work/qemu-command.txt"
printf '\n' >> "$work/qemu-command.txt"
status=0
timeout --kill-after=10 "$limit" "$qemu" "${qemu_args[@]}" > "$work/qemu.log" 2>&1 || status=$?
if [[ "$status" != 0 ]] || grep -Fq "KEXEC_VM $token FAIL " "$work/serial.log" ||
	! grep -Fq "KEXEC_VM $token SOURCE_READY" "$work/serial.log" ||
	! grep -Fq "KEXEC_VM $token PASS " "$work/serial.log"; then
	printf 'FAIL: guest test (QEMU status %s); see %s\n' "$status" "$work"
	exit 1
fi
if [[ "$mode" != load ]] && ! grep -Fq "KEXEC_VM $token TARGET_READY" "$work/serial.log"; then
	printf 'FAIL: target did not reach userspace; see %s\n' "$work"
	exit 1
fi
if [[ "$mode" == crash ]]; then
	bytes=$(awk -v token="$token" '
		$1 == "KEXEC_VM" && $2 == token && $3 == "VMCORE_BYTES" { print $4 }
	' "$work/serial.log")
	[[ "$bytes" =~ ^[1-9][0-9]*$ ]] || { printf 'FAIL: no complete vmcore\n'; exit 1; }
	truncate -s "$bytes" "$work/vmcore.elf"
	readelf -hW -lW "$work/vmcore.elf" > "$work/vmcore-headers.txt"
	printf 'Vmcore saved: %s/vmcore.elf (symbol-aware analysis still required)\n' "$work"
fi
printf 'PASS: %s guest test; artifacts %s\n' "$mode" "$work"
