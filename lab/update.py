"""Updates of the lab from GitHub: whether the branch it runs has new
commits there, and taking them, so that a server needs no shell for it.

An update only fast-forwards: local changes or commits GitHub does not have
stop it, nothing is overwritten. Results keep the commit they ran. When the
branch is gone on GitHub or its history was rewritten, or another branch is
wanted, a switch moves the lab to a branch on GitHub and keeps the old commit
as a backup branch.
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
    new commits (behind), commits only here (ahead), local changes, the
    branches on GitHub, and whether a switch is the way out (resettable)."""
    out = {"branch": None, "commit": None, "date": None, "behind": 0, "ahead": 0, "new": [], "dirty": [], "branches": [],
           "problem": None, "resettable": False, "checked": datetime.now() if fetch else None}  # without a fetch, nothing was checked
    try:
        branch = git("rev-parse", "--abbrev-ref", "HEAD", root=root)
        out.update(commit=git("rev-parse", "--short", "HEAD", root=root), date=git("log", "-1", "--format=%cs", root=root),
                   dirty=git("status", "--porcelain", "--untracked-files=no", root=root).splitlines())
        remote = _remote(branch, root)
        if fetch:
            try:
                git("fetch", "--quiet", "--prune", remote, root=root, timeout=120)
                git("remote", "set-head", remote, "--auto", root=root, timeout=120)
            except UpdateError as e:
                return {**out, "problem": f"GitHub is not reachable: {e}"}
        out["branches"] = branches(remote, root)
        if branch == "HEAD":
            return {**out, "problem": "The lab runs a commit, not a branch.", "resettable": True}
        out["branch"] = branch
        upstream = f"{remote}/{branch}"
        try:
            git("rev-parse", "--verify", "--quiet", upstream, root=root)
        except UpdateError:
            if not fetch:  # never fetched yet: not known, not a problem
                return out
            return {**out, "problem": f"GitHub no longer has the branch {branch}.", "resettable": True}
        out.update(behind=int(git("rev-list", "--count", f"HEAD..{upstream}", root=root)),
                   ahead=int(git("rev-list", "--count", f"{upstream}..HEAD", root=root)),
                   new=git("log", "--format=%h %s", "-n", "10", f"HEAD..{upstream}", root=root).splitlines())
        if out["ahead"] and out["behind"] and _was_published(upstream, root):
            out.update(problem=f"The history of {branch} on GitHub was rewritten.", resettable=True)
    except UpdateError as e:
        out["problem"] = str(e)
    return out


def branches(remote: str = "origin", root: Path = ROOT) -> list[dict]:
    """The branches on GitHub as of the last fetch, the default one first."""
    try:
        default = git("symbolic-ref", "--short", f"refs/remotes/{remote}/HEAD", root=root).removeprefix(f"{remote}/")
    except UpdateError:
        default = None
    found = []
    for line in git("for-each-ref", "--sort=-committerdate", "--format=%(refname:short)|%(objectname:short)|%(committerdate:short)|%(subject)",
                    f"refs/remotes/{remote}", root=root).splitlines():
        ref, commit, date, subject = line.split("|", 3)
        name = ref.removeprefix(f"{remote}/")
        if name not in ("HEAD", remote):
            found.append({"name": name, "commit": commit, "date": date, "subject": subject, "default": name == default,
                          "switch": _has_switch(f"{remote}/{name}", root)})
    return sorted(found, key=lambda b: not b["default"])


def _was_published(upstream: str, root: Path) -> bool:
    """Whether GitHub once had this commit on the branch: then a force push
    dropped it, and the commits ahead are not work done only here."""
    for seen in dict.fromkeys(git("log", "-g", "-n", "100", "--format=%H", upstream, root=root).splitlines()):
        try:
            git("merge-base", "--is-ancestor", "HEAD", seen, root=root)
            return True
        except UpdateError:
            continue
    return False


def _remote(branch: str, root: Path) -> str:
    try:
        return git("config", f"branch.{branch}.remote", root=root) or "origin"
    except UpdateError:
        return "origin"  # no upstream set: the clone's origin


def update(root: Path = ROOT, sync: bool = True, allow_current: bool = False) -> str:
    """Takes the new commits of the branch and the dependencies they need;
    returns the commit the lab is at then. UpdateError says why not."""
    s = status(fetch=True, root=root)
    if s["problem"]:
        raise UpdateError(s["problem"] + (" Switch to a branch on GitHub to continue." if s["resettable"] else ""))
    if s["dirty"]:
        raise UpdateError(f"The lab has local changes, in {', '.join(line.split(maxsplit=1)[-1] for line in s['dirty'][:3])}. Commit or discard them on the server first.")
    if s["ahead"]:
        raise UpdateError(f"The lab has {s['ahead']} commits GitHub does not have. Push them, or switch to a branch on GitHub.")
    if not s["behind"] and not allow_current:
        raise UpdateError("The lab is up to date.")
    git("merge", "--ff-only", f"{_remote(s['branch'], root)}/{s['branch']}", root=root)
    _sync(root, sync)
    return git("rev-parse", "--short", "HEAD", root=root)


def _has_switch(ref: str, root: Path) -> bool:
    """Whether the lab on that branch can switch branches itself, or needs the shell to come back."""
    try:
        return "def switch(" in git("show", f"{ref}:lab/update.py", root=root)
    except UpdateError:
        return False


def switch(branch: str | None = None, root: Path = ROOT, sync: bool = True) -> str:
    """Moves the lab to a branch on GitHub, the default one without a name,
    only without local changes. The old commit stays as a branch
    lab-backup-<commit>, results and settings are not in Git and stay.
    Returns the new commit."""
    s = status(fetch=True, root=root)
    if s["problem"] and not s["resettable"]:
        raise UpdateError(s["problem"])
    if s["dirty"]:
        raise UpdateError(f"The lab has local changes, in {', '.join(line.split(maxsplit=1)[-1] for line in s['dirty'][:3])}. Commit or discard them on the server first.")
    remote = _remote(s["branch"] or "HEAD", root)
    names = {b["name"]: b for b in s["branches"]}
    branch = branch or next((b["name"] for b in s["branches"] if b["default"]), None)
    if not branch:
        raise UpdateError("GitHub does not say which branch is its default.")
    if branch not in names:
        raise UpdateError(f"GitHub has no branch {branch}.")
    old = git("rev-parse", "--short", "HEAD", root=root)
    git("branch", "--force", f"lab-backup-{old}", "HEAD", root=root)
    git("checkout", "--quiet", "-B", branch, "--track", f"{remote}/{branch}", root=root)
    _sync(root, sync)
    return git("rev-parse", "--short", "HEAD", root=root)


def _sync(root: Path, sync: bool) -> None:
    if sync and shutil.which("uv"):
        done = subprocess.run(["uv", "sync"], cwd=root, capture_output=True, text=True, timeout=600)
        if done.returncode:
            raise UpdateError(f"The code is updated, but uv sync failed: {done.stderr.strip().splitlines()[-1:]}")


def restart() -> None:
    """Starts the web server again, as it was started, in this process: it
    reads the new code. Workers of results run on in their own sessions."""
    os.execv(sys.executable, [sys.executable, "-m", "lab.cli", *sys.argv[1:]])
