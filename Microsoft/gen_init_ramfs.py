#!/usr/bin/python3

#
# There is a similar tool implemented in C inside the Linux kernel source tree.
# The goal for this one has been to be independent of the kernel source tree,
# and be able to create the intial RAM FS files without running as root.
#
# The format for the configuration file lines:
#
# "file <name> <location> <mode> <uid> <gid> [<hard links>]\n"
# "dir <name> <mode> <uid> <gid>\n"
# "nod <name> <mode> <uid> <gid> <dev_type> <maj> <min>\n"
# "slink <name> <target> <mode> <uid> <gid>\n"
# "pipe <name> <mode> <uid> <gid>\n"
# "sock <name> <mode> <uid> <gid>\n"
#
# Empty lines and lines starting with '#' are skipped over.
# For the location of a file, environment varibles may be used, i.e.: ${MY_INIT}
# The mode is expected to be in octal.
#

import io
import os
import stat
import time

from typing import BinaryIO


class CpioEntry(object):
    def __init__(self, name: str, mode: int, uid: int,
                gid: int, nlink: int, mtime: int, major: int, minor: int, rmajor: int, rminor: int,
                chksum: int, content: BinaryIO) -> None:
        if len(name) > 255:
            raise Exception(f"The entry name '{name}' is too long")

        if name.startswith('/'):
            name = name[1:]

        filesize = content.seek(0, io.SEEK_END);

        self.name = name
        self.inode = 721
        self.mode = int(mode)
        self.uid = int(uid)
        self.gid = int(gid)
        self.nlink = int(nlink)
        self.mtime = int(mtime)
        self.filesize = filesize
        self.major = int(major)
        self.minor = int(minor)
        self.rmajor = int(rmajor)
        self.rminor = int(rminor)
        self.namesize = len(name)+1
        self.chksum = int(chksum)
        self.content = content

    def __repr__(self) -> str:
        return None

    def write(self, buffer: BinaryIO) -> None:
        def align_on_dword(buffer):
            while buffer.tell() & 3 != 0:
                buffer.write(b'\x00')

        name_bytes = bytearray(self.name, 'ascii')
        name_bytes.append(0)

        if self.filesize > 0 and self.nlink > 1:
            # Create entries for hardlinks. They all share the same inode

            header_bytes = bytes(
                f'070701{self.inode:08X}{self.mode:08X}{self.uid:08X}{self.gid:08X}{self.nlink:08X}{self.mtime:08X}' + \
                f'{0:08X}{self.major:08X}{self.minor:08X}{self.rmajor:08X}{self.rminor:08X}' + \
                f'{self.namesize:08X}{self.chksum:08X}',
                'ascii')

            assert(len(header_bytes) == 110)

            for i in range(self.nlink - 1):
                buffer.write(header_bytes)
                buffer.write(name_bytes)
                align_on_dword(buffer)

        # After the hard link entries are written (if any) write the file itself

        header_bytes = bytes(
            f'070701{self.inode:08X}{self.mode:08X}{self.uid:08X}{self.gid:08X}{self.nlink:08X}{self.mtime:08X}' + \
            f'{self.filesize:08X}{self.major:08X}{self.minor:08X}{self.rmajor:08X}{self.rminor:08X}' + \
            f'{self.namesize:08X}{self.chksum:08X}',
            'ascii')

        assert(len(header_bytes) == 110)

        buffer.write(header_bytes)
        buffer.write(name_bytes)
        align_on_dword(buffer)

        self.content.seek(0);
        while True:
            data = self.content.read(0x10000)
            if len(data) == 0:
                break
            buffer.write(data)

        align_on_dword(buffer)

        self.inode += 1


class FileEntry(CpioEntry):
    def __init__(self, name, location, mode, uid, gid, hard_links) -> None:
        if location.startswith('${') and location.endswith('}'):
            location = os.environ[location[2:-1]]

        self.location = location
        self.hard_links = hard_links

        parameters = {
            'name': name,
            'mode': int(mode) | stat.S_IFREG,
            'uid': uid,
            'gid': gid,
            'nlink': 1 + len(hard_links),
            'mtime': int(os.path.getmtime(location)),
            'major': 3,
            'minor': 1,
            'rmajor': 0,
            'rminor': 0,
            'chksum': 0,
            'content': open(location, 'rb')
        }

        super(FileEntry, self).__init__(**parameters)

    def __repr__(self) -> str:
        return f"file {self.name} {self.location} {self.mode:06o} {self.uid} {self.gid} {' '.join(self.hard_links)}"


class DirEntry(CpioEntry):
    def __init__(self, name, mode, uid, gid) -> None:
        parameters = {
            'name': name,
            'mode': int(mode) | stat.S_IFDIR,
            'uid': uid,
            'gid': gid,
            'nlink': 2,
            'mtime': int(time.time()),
            'major': 3,
            'minor': 1,
            'rmajor': 0,
            'rminor': 0,
            'chksum': 0,
            'content': io.BytesIO(b"")
        }

        super(DirEntry, self).__init__(**parameters)

    def __repr__(self) -> str:
        return f"dir {self.name} {self.mode:06o} {self.uid} {self.gid}"


class DeviceNodeEntry(CpioEntry):
    def __init__(self, name, mode, uid, gid, dev_type, dev_maj, dev_min) -> None:
        if dev_type == 'c':
            mode = int(mode) | stat.S_IFCHR
        elif dev_type == 'b':
            mode = int(mode) | stat.S_IFBLK
        else:
            raise Exception("Invalid device type")

        parameters = {
            'name': name,
            'mode': mode,
            'uid': uid,
            'gid': gid,
            'nlink': 1,
            'mtime': int(time.time()),
            'major': 3,
            'minor': 1,
            'rmajor': dev_maj,
            'rminor': dev_min,
            'chksum': 0,
            'content': io.BytesIO(b"")
        }

        super(DeviceNodeEntry, self).__init__(**parameters)

    def __repr__(self) -> str:
        return f"nod {self.name} {self.mode:06o} {self.uid} {self.gid} {self.rmajor} {self.rminor}"


class SymLinkEntry(CpioEntry):
    def __init__(self, name, target, mode, uid, gid) -> None:
        content = bytearray(target, 'ascii')
        content.append(0)

        parameters = {
            'name': name,
            'mode': int(mode) | stat.S_IFLNK,
            'uid': uid,
            'gid': gid,
            'nlink': 1,
            'mtime': int(time.time()),
            'major': 3,
            'minor': 1,
            'rmajor': 0,
            'rminor': 0,
            'chksum': 0,
            'content': io.BytesIO(content)
        }

        super(SymLinkEntry, self).__init__(**parameters)

    def __repr__(self) -> str:
        return f"slink {self.name} {self.target} {self.mode:06o} {self.uid} {self.gid}"


class PipeEntry(CpioEntry):
    def __init__(self, name, mode, uid, gid) -> None:
        parameters = {
            'name': name,
            'mode': int(mode) | stat.S_IFIFO,
            'uid': uid,
            'gid': gid,
            'nlink': 2,
            'mtime': int(time.time()),
            'major': 3,
            'minor': 1,
            'rmajor': 0,
            'rminor': 0,
            'chksum': 0,
            'content': io.BytesIO(b"")
        }

        super(PipeEntry, self).__init__(**parameters)

    def __repr__(self) -> str:
        return f"pipe {self.name} {self.mode:06o} {self.uid} {self.gid}"


class SocketEntry(CpioEntry):
    def __init__(self, name, mode, uid, gid) -> None:
        parameters = {
            'name': name,
            'mode': int(mode) | stat.S_IFSOCK,
            'uid': uid,
            'gid': gid,
            'nlink': 2,
            'mtime': int(time.time()),
            'major': 3,
            'minor': 1,
            'rmajor': 0,
            'rminor': 0,
            'chksum': 0,
            'content': io.BytesIO(b"")
        }

        super(SocketEntry, self).__init__(**parameters)

    def __repr__(self) -> str:
        return f"sock {self.name} {self.mode:06o} {self.uid} {self.gid}"


class TrailerEntry(CpioEntry):
    def __init__(self) -> None:
        parameters = {
            'name': 'TRAILER!!!',
            'mode': 0,
            'uid': 0,
            'gid': 0,
            'nlink': 1,
            'mtime': 0,
            'major': 0,
            'minor': 0,
            'rmajor': 0,
            'rminor': 0,
            'chksum': 0,
            'content': io.BytesIO(b""),
        }

        super(TrailerEntry, self).__init__(**parameters)

    def __repr__(self) -> str:
        return f"{self.name}"


class CpioRamFs:
    def __init__(self, buffer_obj: BinaryIO):
        self.buffer_obj = buffer_obj
        self.opened = False

    def __enter__(self):
        self.opened = True
        return self

    def write(self, cpio_entry: CpioEntry):
        assert(self.opened)
        cpio_entry.write(self.buffer_obj)

    def __exit__(self, type, value, traceback):
        trailer = TrailerEntry()
        trailer.write(self.buffer_obj)

        while self.buffer_obj.tell() & 511 != 0:
            self.buffer_obj.write(b'\x00')

        self.buffer_obj.close()
        self.opened = False


class InitRamFsConfig:
    def __init__(self, file_name) -> None:
        self.cpio_entries = []

        with open(file_name, 'rt') as f:
            for line in f:
                line = line.strip()

                if line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) == 0:
                    continue

                cpio_entry = None

                try:
                    if parts[0] == "file":
                        name, location, mode, uid, gid, *hard_links = parts[1:]
                        mode = int(mode, 8)
                        cpio_entry = FileEntry(name, location, mode, uid, gid, hard_links)
                    elif parts[0] == "dir":
                        name, mode, uid, gid = parts[1:]
                        mode = int(mode, 8)
                        cpio_entry = DirEntry(name, mode, uid, gid)
                    elif parts[0] == "nod":
                        name, mode, uid, gid, dev_type, dev_maj, dev_min = parts[1:]
                        mode = int(mode, 8)
                        cpio_entry = DeviceNodeEntry(name, mode, uid, gid, dev_type, dev_maj, dev_min)
                    elif parts[0] == "slink":
                        name, target, mode, uid, gid = parts[1:]
                        mode = int(mode, 8)
                        cpio_entry = SymLinkEntry(name, target, mode, uid, gid)
                    elif parts[0] == "pipe":
                        name, mode, uid, gid = parts[1:]
                        mode = int(mode, 8)
                        cpio_entry = PipeEntry(name, mode, uid, gid)
                    elif parts[0] == "sock":
                        name, mode, uid, gid = parts[1:]
                        mode = int(mode, 8)
                        cpio_entry = SocketEntry(name, mode, uid, gid)
                    else:
                        raise Exception(f"Can't parse: {line}")
                except ValueError:
                    raise Exception(f"Can't parse: {line}")

                self.cpio_entries.append(cpio_entry)
                # print(cpio_entry)

    def entries(self):
        return self.cpio_entries


def __open_output_stream(file_name: str, compression: str):
    mode = 'xb'
    if compression == 'none':
        return open(file_name, mode)
    elif compression == 'bz2':
        import bz2
        return bz2.open(file_name, mode)
    elif compression == 'gzip':
        import gzip
        return gzip.open(file_name, mode, compresslevel=6)
    elif compression == 'lzma':
        import lzma
        return lzma.open(file_name, mode)
    else:
        raise Exception("Unknown compression algorithm")


def create_cpio(config_file: str, output_file: str, compression: str):
    with __open_output_stream(output_file, compression) as ostream:
        with CpioRamFs(ostream) as cpio:
            config = InitRamFsConfig(config_file)
            for entry in config.entries():
                cpio.write(entry)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('config_file', help='Initial RAM FS configiration file')
    parser.add_argument('output_file', help='Output file that contains the initial RAM FS')
    parser.add_argument('--compression', required=False, help='Compression to use, default is gzip',
        choices=('gzip', 'bz2', 'lzma', 'none'), default='gzip')

    args = parser.parse_args()

    create_cpio(args.config_file, args.output_file, args.compression)
