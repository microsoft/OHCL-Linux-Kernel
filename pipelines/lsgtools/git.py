
import subprocess

from . import log


def deepen(source_branch, depth):
    log.debug(f"Fetch {source_branch} with depth {depth}")
    result = subprocess.run(["git", "fetch", f"--depth={depth}", "origin", source_branch], capture_output=True)
    if result.returncode == 0:
        return True

    log.err(result.stdout.decode("ascii"))
    log.err(result.stderr.decode("ascii"))
    log.fatal(f"git fetch failed with exit code: {result.returncode}")
    return False


def is_merge_commit(commit_id):
    result = subprocess.run([f"git show --summary {commit_id} | grep -q ^Merge:"], shell=True)
    if result.returncode == 0:
        return True

    return False
