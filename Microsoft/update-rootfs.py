#!/usr/bin/python3

import os
import sys
import gzip
import shutil
import struct
import subprocess
import tempfile
import time

from gen_init_ramfs import create_cpio
from typing import List

package_id = "Microsoft.HyperV.Internal.HCL.x64"

class Config:
    VERBOSE = False
    CPIO = "cpio"
    STRIP = "strip"
    EXECSTACK = "execstack"
    GZIP = "gzip"
    BINWALK = "binwalk"
    LSINITRAMFS = "lsinitramfs"
    REQUIRED_TOOLS = [
        CPIO,
        STRIP,
        EXECSTACK,
        GZIP,
        BINWALK,
        LSINITRAMFS
    ] if VERBOSE else [
        STRIP,
        EXECSTACK,
    ]


def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))


def run_inside_shell_and_check(command: str):
    if Config.VERBOSE: print(f'Running "{command}"...')
    subprocess.run(
        command,
        shell=True,
        check=True)


def append_to_rootfs(initial_dir: str, file_to_append: str, existing_cpio_gz_path: str):
    command = f'cd {initial_dir}; ' + \
              f'echo {file_to_append} | ' + \
              f'{Config.CPIO} -o -H newc | {Config.GZIP} >> {existing_cpio_gz_path}'
    run_inside_shell_and_check(command)


def prepare_executable(path: str, preserve_debuginfo: bool):
    strip = "" if preserve_debuginfo else f"{Config.STRIP} {path} && "
    command = f"{strip}{Config.EXECSTACK} -c {path} && chmod a+x {path}"
    run_inside_shell_and_check(command)


def append_file(path: str, append: str):
    command = f"cat {append} >> {path}"
    run_inside_shell_and_check(command)


def process(temp_dir: str, underhill_path: str,
            rootfs_config_path: str,
            updated_initramfs_path: str, additional_layers: List[str],
            preserve_debuginfo: bool):
    align = lambda x, boundary: (x + boundary-1) & ~(boundary-1)

    print("Building the initial root fs")

    underhill_cpio_gz_file_name = os.path.join(temp_dir, 'underhill.cpio.gz')

    final_underhill_path = os.path.join(temp_dir, 'underhill')
    shutil.copy(underhill_path, final_underhill_path)
    prepare_executable(final_underhill_path, preserve_debuginfo)

    os.environ["UNDERHILL"] = final_underhill_path

    create_cpio(rootfs_config_path, underhill_cpio_gz_file_name, 'gzip')

    for layer in additional_layers:
        append_file(underhill_cpio_gz_file_name, layer)

    if Config.VERBOSE: subprocess.run(f'binwalk -eM {underhill_cpio_gz_file_name}', shell=True, check=True)
    if Config.VERBOSE: subprocess.run(f'lsinitramfs -l {underhill_cpio_gz_file_name}', shell=True, check=True)

    initgz_file_data = bytes()

    with open(underhill_cpio_gz_file_name, 'rb') as cpiogz_file:
        initgz_file_data = cpiogz_file.read()
        print(f'Size of the updated initial RAM FS {len(initgz_file_data)} bytes')

    shutil.move(underhill_cpio_gz_file_name, updated_initramfs_path)

class PackageLayer:
    name = ""
    def __init__(self, name):
        self.name = name


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Updates the initial RAM FS')

    parser.add_argument('underhill_path', help='Path to underhill')
    parser.add_argument('updated_initramfs_path', help='The path to the updated initramfs')
    parser.add_argument('--package-root', default=os.path.join(get_script_path(), "../.packages", package_id), help='HCL package root containing extra cpio.gz files')
    parser.add_argument('--debuginfo', action='store_true', help='Preserve debugging information in the binaries.')
    parser.add_argument('--rootfs-config', default=os.path.join(get_script_path(), "../underhill/rootfs.config"),
                                            help='Configuration file for the root filesystem')
    parser.add_argument('--socat', action='append_const', dest='layer', const=PackageLayer('socat'), help='Include socat.')
    parser.add_argument('--dump', action='append_const', dest='layer', const=PackageLayer('uh-dump'), help='Adds a core dumping utility, uhdump.')
    parser.add_argument('--debug', action='append_const', dest='layer', const=PackageLayer('gdbserver'), help='Adds gdbserver.')
    parser.add_argument('--tests', action='append_const', dest='layer', const=PackageLayer('tests'), help='Adds the driver test package.')
    parser.add_argument('--perf', action='append_const', dest='layer', const=PackageLayer('perf'), help='Adds the perf tool.')
    parser.add_argument('--layer', action='append', help='Adds a custom layer file.')
    parser.set_defaults(layer=[])

    args = parser.parse_args()

    for required_tool in Config.REQUIRED_TOOLS:
        if shutil.which(required_tool) is None:
            raise Exception(f"Can't find {required_tool}")

    underhill_path = os.path.realpath(args.underhill_path)
    rootfs_config_path = os.path.realpath(args.rootfs_config)
    updated_initramfs_path = args.updated_initramfs_path
    preserve_debuginfo = args.debuginfo

    additional_layers = []
    for layer in args.layer:
        if isinstance(layer, PackageLayer):
            additional_layers.append(os.path.join(args.package_root, f'{layer.name}.cpio.gz'))
        elif os.path.exists(layer):
            additional_layers.append(layer)
        else:
            raise Exception(f"Can't find layer file {layer}")

    with tempfile.TemporaryDirectory() as temp_dir:
        process(
            str(temp_dir),
            underhill_path, rootfs_config_path,
            updated_initramfs_path, additional_layers, preserve_debuginfo)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
        exit(-1)
