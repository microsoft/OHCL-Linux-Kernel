
import re
import subprocess

# TODO check dependencies at startup
# - make


def get_tarball_format():
    # This probably should come from some config, but keep hardcoded for now
    return "tar"


def build_tarball_prefix(version):
    return "kernel-mshv-{}".format(version)


def build_tar_name(version):
    tarball_format = "tar"
    return "{}.{}".format(build_tarball_prefix(version), tarball_format)


def build_tgz_name(version):
    tarball_name = "{}.gz".format(build_tar_name(version))
    return tarball_name


def get_version_local():
    # TODO try/except
    res = subprocess.run(["make", "kernelversion"], stdout=subprocess.PIPE)
    return res.stdout.decode("ascii").strip()


def get_version_from_tag(ref):
    parts = ref.split("/")
    return parts[len(parts)-1]


def is_version_valid(version):
    ver_ptr = re.compile(r"\d+\.\d+\.\d+\.mshv\d+$")
    return ver_ptr.match(version) is not None
