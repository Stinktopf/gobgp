"""Remove recorded installation changes, preserving unowned or modified resources."""

import argparse
import fcntl
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS = {"minikube", "kubectl", "helm", "uv", "uvx"}
SETTINGS_FILES = {
    "host.yaml", "lifecycle.json", "web.json", "initial-password", "tls.crt", "tls.key",
    "notify.json", "cluster-policy.json", "serve.json", "serve.log", "serve.lock", "lifecycle.lock",
}
SYSCTL = Path("/etc/sysctl.d/90-obgp-lab.conf")
SYSTEMD = Path("/etc/systemd/system/obgp-lab.service.d/lifecycle.conf")


def inventory(base):
    try:
        return (base / "installed.txt").read_text().splitlines()
    except FileNotFoundError:
        return []


def record(base, line):
    base.mkdir(parents=True, exist_ok=True)
    if line not in inventory(base):
        with (base / "installed.txt").open("a") as file:
            file.write(line + "\n")


def before_service_change(base):
    if any(line.startswith("systemd-before ") for line in inventory(base)):
        return
    if SYSTEMD.exists():
        base.mkdir(parents=True, exist_ok=True)
        backup = base / "systemd.before"
        backup.write_bytes(SYSTEMD.read_bytes())
        record(base, f"sha256 {digest(backup)} {backup}")
        record(base, "systemd-before existing")
    else:
        record(base, "systemd-before absent")


def undo_service(lines, base, privileged, kept):
    before = next((line for line in lines if line.startswith("systemd-before ")), None)
    if before is None:
        return
    hashes = {line.split(" ", 2)[2]: line.split(" ", 2)[1] for line in lines if line.startswith("sha256 ")}
    if not SYSTEMD.exists() and before == "systemd-before absent":
        return
    if not SYSTEMD.is_file() or hashes.get(str(SYSTEMD)) != digest(SYSTEMD):
        kept.append("systemd configuration (changed since setup)")
        return
    if before == "systemd-before existing":
        backup = base / "systemd.before"
        if not backup.is_file() or hashes.get(str(backup)) != digest(backup):
            raise RuntimeError("The original systemd configuration backup is missing or changed")
        privileged(["cp", "--", str(backup), str(SYSTEMD)])
    else:
        privileged(["rm", "--", str(SYSTEMD)])
        privileged(["rmdir", "--ignore-fail-on-non-empty", str(SYSTEMD.parent)])
    privileged(["systemctl", "daemon-reload"])


def preflight(root, base):
    """Do not remove shared user tools if another recorded checkout still exists."""
    if base.is_symlink() or (base / "bin").is_symlink():
        raise RuntimeError(f"Installation directory is a symlink: {base}")
    for line in inventory(base):
        if line.startswith("dir "):
            path = Path(line[4:])
            if path.name == ".venv" and path != root / ".venv" and path.exists():
                raise RuntimeError(f"Another checkout uses this installation: {path.parent}")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"Cannot check {command[0]}: {result.stderr.strip()}")
    return result.stdout.strip()


def remove_packages(packages, privileged, kept):
    """APT may only remove recorded, unchanged packages, without extra dependents."""
    candidates = []
    for name, version in packages:
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.:\-]*", name):
            raise RuntimeError("Invalid package name in installation inventory")
        check = subprocess.run(["dpkg-query", "-W", "-f=${Status}\n${Version}\n${Conffiles}", name],
                               capture_output=True, text=True, timeout=30)
        lines = check.stdout.splitlines()
        if check.returncode or not lines or lines[0] != "install ok installed":
            continue
        changed = len(lines) < 2 or lines[1] != version
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("/"):
                file = Path(parts[0])
                if not file.exists() or hashlib.md5(file.read_bytes()).hexdigest() != parts[1]:
                    changed = True
        if changed:
            kept.append(f"package {name} (changed since setup)")
        else:
            candidates.append(name)
    if not candidates:
        return
    plan = output(["apt-get", "--simulate", "purge", "--no-auto-remove", *candidates])
    removals = {line.split()[1].split(":")[0] for line in plan.splitlines() if line.startswith(("Remv ", "Purg "))}
    allowed = {name.split(":")[0] for name in candidates}
    if not removals <= allowed or any(line.startswith("Inst ") for line in plan.splitlines()):
        kept.append("system packages (APT would change other packages)")
        return
    privileged(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "purge", "--no-auto-remove", "-y", *candidates])


def undo_host(lines, base, privileged, kept):
    packages = [tuple(line.split()[1:]) for line in lines if line.startswith("package ")]
    changes = any(line.startswith(("package ", "docker-group ", "inotify-before ", "docker-started ")) for line in lines)
    if not changes:
        return
    # Other Docker workloads, including stopped containers, may rely on these changes.
    if shutil.which("docker"):
        try:
            if output(["docker", "ps", "-aq"]):
                kept.append("host changes (other Docker containers exist)")
                return
        except RuntimeError:
            kept.append("host changes (Docker usage could not be checked)")
            return
    before = next((line.split()[1:] for line in lines if line.startswith("inotify-before ")), None)
    after = next((line.split()[1:] for line in reversed(lines) if line.startswith("inotify-after ")), None)
    hashes = {line.split(" ", 2)[2]: line.split(" ", 2)[1] for line in lines if line.startswith("sha256 ")}
    if before:
        names = ("max_user_instances", "max_user_watches")
        current = [Path("/proc/sys/fs/inotify", name).read_text().strip() for name in names]
        if (not after or not all(v.isdigit() for v in before + after)
                or len(before) != 2 or current != after or not SYSCTL.is_file()
                or hashes.get(str(SYSCTL)) != digest(SYSCTL)):
            kept.append("inotify settings (changed or incomplete installation record)")
        else:
            if "inotify-existing" in lines:
                backup = base / "inotify.before"
                if not backup.is_file() or hashes.get(str(backup)) != digest(backup):
                    raise RuntimeError("The original inotify configuration backup is missing")
                privileged(["cp", "--", str(backup), str(SYSCTL)])
            else:
                privileged(["rm", "--", str(SYSCTL)])
            privileged(["sysctl", "-w", *(f"fs.inotify.{name}={value}" for name, value in zip(names, before))])
    # Remove the membership only if setup added it for this user.
    import pwd
    user = pwd.getpwuid(os.getuid()).pw_name
    if f"docker-group {user}" in lines:
        import grp
        try:
            members = grp.getgrnam("docker").gr_mem
        except KeyError:
            members = []
        if user in members:
            privileged(["gpasswd", "-d", user, "docker"])
    started = next((line.split()[1] for line in reversed(lines) if line.startswith("docker-started ")), None)
    if started:
        stamp = output(["systemctl", "show", "docker", "--property=ActiveEnterTimestampMonotonic", "--value"])
        if stamp == started:
            privileged(["systemctl", "stop", "docker"])
        else:
            kept.append("Docker service state (changed since setup)")
    remove_packages(packages, privileged, kept)


def cleanup(root, settings, base, privileged):
    """Called after teardown, while the shared cluster claim is still held."""
    preflight(root, base)
    lines = inventory(base)
    kept = []
    undo_service(lines, base, privileged, kept)
    undo_host(lines, base, privileged, kept)
    hashes = {line.split(" ", 2)[2]: line.split(" ", 2)[1] for line in lines if line.startswith("sha256 ")}
    directories = []
    for line in lines:
        kind, _, raw = line.partition(" ")
        path = Path(raw)
        if kind == "file" and path.parent == base / "bin" and path.name in TOOLS:
            if path.exists() or path.is_symlink():
                if path.is_symlink() or (str(path) in hashes and digest(path) != hashes[str(path)]):
                    kept.append(f"{path} (changed since setup)")
                else:
                    path.unlink()
        elif kind == "dir" and path in (root / ".venv", base / "cache", base / "python"):
            if path.is_symlink():
                kept.append(f"{path} (symlink)")
            elif path.exists():
                directories.append(path)
    # Keep unknown files rather than recursively deleting a possibly shared directory.
    if settings.is_symlink():
        kept.append(f"{settings} (symlink)")
    else:
        for name in SETTINGS_FILES:
            path = settings / name
            if path.is_file() or path.is_symlink():
                path.unlink()
        if settings.exists():
            if any(settings.iterdir()):
                kept.append(f"{settings} (unrecognized files)")
            else:
                settings.rmdir()
    # The environment/interpreter is removed last, once cleanup imports are loaded.
    if not kept:
        for path in directories:
            shutil.rmtree(path)
    if not kept:
        (base / "installed.txt").unlink(missing_ok=True)
        (base / "inotify.before").unlink(missing_ok=True)
        (base / "systemd.before").unlink(missing_ok=True)
    for path in (base / "bin", base):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    return kept


def main():
    """Allow a harmless repeated uninstall after the Python environment is gone."""
    root = Path(__file__).resolve().parents[1]
    python = root / ".venv/bin/python"
    if python.exists():
        os.execv(str(python), [str(python), "-m", "lab.lifecycle", "uninstall", *sys.argv[1:]])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--purge", action="store_true", help="also delete this checkout's private results")
    parser.add_argument("--non-interactive", action="store_true")
    args = parser.parse_args()
    base = Path.home() / "obgp-lab"
    settings = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "obgp-lab"
    minikube = Path(os.environ.get("MINIKUBE_HOME", Path.home() / ".minikube"))
    if inventory(base) or settings.exists() or (minikube / "profiles/obgp-lab").exists():
        print("The Python environment is missing but installation state remains. Run setup.sh to repair it before uninstalling.", file=sys.stderr)
        return 1
    if args.purge:
        # Keep the same stable lock inode used by runners, even after uninstall.
        minikube.mkdir(parents=True, exist_ok=True)
        with (minikube / "obgp-lab.lab.lock").open("a+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("An experiment or cluster operation is active. Nothing removed.", file=sys.stderr)
                return 75
            private = root / "results/private"
            if private.is_symlink() or not private.resolve().is_relative_to(root):
                print("Private results are a symlink. Nothing removed.", file=sys.stderr)
                return 1
            if private.exists():
                shutil.rmtree(private)
        print("No lab installation remains. Private results removed. Repository and public results kept.")
        return 0
    print("No lab installation remains. Repository and results kept.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
