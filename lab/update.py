"""Updates of the lab from GitHub: whether the branch it runs has new
commits there, and taking them, so that a server needs no shell for it.

An update only fast-forwards: local changes or commits GitHub does not have
stop it, nothing is overwritten. Results keep the commit they ran.
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from .config import ROOT


class UpdateError(Exception):
    pass


def git(*args: str, root: Path = ROOT, timeout: float = 60) -> str:
    try:
        out = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise UpdateError(f"git {args[0]}: {e}") from None
    if out.returncode:
        raise UpdateError((out.stderr or out.stdout).strip().splitlines()[-1] if (out.stderr or out.stdout).strip() else f"git {args[0]} failed")
    return out.stdout.strip()


def status(fetch: bool = True, root: Path = ROOT) -> dict:
    """The branch and commit the lab runs, and what GitHub has beyond it:
    new commits (behind), commits only here (ahead), local changes."""
    out = {"branch": None, "commit": None, "date": None, "behind": 0, "ahead": 0, "new": [], "dirty": [],
           "problem": None, "checked": datetime.now() if fetch else None}  # without a fetch, nothing was checked
    try:
        branch = git("rev-parse", "--abbrev-ref", "HEAD", root=root)
        out.update(commit=git("rev-parse", "--short", "HEAD", root=root), date=git("log", "-1", "--format=%cs", root=root))
        if branch == "HEAD":
            return {**out, "problem": "The lab runs a commit, not a branch."}
        out["branch"] = branch
        remote = _remote(branch, root)
        if fetch:
            git("fetch", "--quiet", remote, branch, root=root, timeout=120)
        upstream = f"{remote}/{branch}"
        try:
            git("rev-parse", "--verify", "--quiet", upstream, root=root)
        except UpdateError:
            if not fetch:  # never fetched yet: not known, not a problem
                return out
            raise
        out.update(behind=int(git("rev-list", "--count", f"HEAD..{upstream}", root=root)),
                   ahead=int(git("rev-list", "--count", f"{upstream}..HEAD", root=root)),
                   new=git("log", "--format=%h %s", "-n", "10", f"HEAD..{upstream}", root=root).splitlines(),
                   dirty=git("status", "--porcelain", "--untracked-files=no", root=root).splitlines())
    except UpdateError as e:
        out["problem"] = f"GitHub is not reachable or does not have the branch: {e}" if fetch else str(e)
    return out


def _remote(branch: str, root: Path) -> str:
    try:
        return git("config", f"branch.{branch}.remote", root=root) or "origin"
    except UpdateError:
        return "origin"  # no upstream set: the clone's origin


def update(root: Path = ROOT, sync: bool = True) -> str:
    """Takes the new commits of the branch and the dependencies they need;
    returns the commit the lab is at then. UpdateError says why not."""
    s = status(fetch=True, root=root)
    if s["problem"]:
        raise UpdateError(s["problem"])
    if s["dirty"]:
        raise UpdateError(f"The lab has local changes, in {', '.join(line.split(maxsplit=1)[-1] for line in s['dirty'][:3])}. Commit or discard them on the server first.")
    if s["ahead"]:
        raise UpdateError(f"The lab has {s['ahead']} commits GitHub does not have. Push them, or reset the server to GitHub.")
    if not s["behind"]:
        raise UpdateError("The lab is up to date.")
    git("merge", "--ff-only", f"{_remote(s['branch'], root)}/{s['branch']}", root=root)
    if sync and shutil.which("uv"):
        done = subprocess.run(["uv", "sync"], cwd=root, capture_output=True, text=True, timeout=600)
        if done.returncode:
            raise UpdateError(f"The code is updated, but uv sync failed: {done.stderr.strip().splitlines()[-1:]}")
    return git("rev-parse", "--short", "HEAD", root=root)


def restart() -> None:
    """Starts the web server again, as it was started, in this process: it
    reads the new code. Workers of results run on in their own sessions."""
    os.execv(sys.executable, [sys.executable, *sys.argv])
