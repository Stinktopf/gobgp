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
    "gpu-seen", "web-stopped", "watch.log", "watch.json", "serve.log.1", "watch.log.1", "watch.path",
    "tokens.json", "agents.json", "agents.log", "groups.json", "pending.json", "cluster-busy",
    "host-history.jsonl", "host-history.tmp", "marks.lock",
}
SETTINGS_DIRS = {"analysing", "served-static"}  # locks of analyses, the copy of the pages a started server serves
SEARCHES = "simulation"  # the searches of the simulator: kept as results are, unless purged
KEPT = {SEARCHES, "marks.json"}  # and the stars and notes on results, searches and cases
SYSCTL = Path("/etc/sysctl.d/90-obgp-lab.conf")
PROC = Path("/proc/sys")
NEIGH_SYSCTL = Path("/etc/sysctl.d/90-obgp-lab-neigh.conf")
# What setup may raise: the record's name, its file, the sysctl prefix and the limits, in the record's order.
SYSCTLS = (("inotify", SYSCTL, "fs.inotify", ("max_user_instances", "max_user_watches")),
           ("neigh", NEIGH_SYSCTL, "net.ipv4.neigh.default", ("gc_thresh1", "gc_thresh2", "gc_thresh3")))
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


KICBASE = "gcr.io/k8s-minikube/kicbase"  # the image of the minikube node, pulled for the lab


def restore_sysctl(lines, base, privileged, kept, hashes, kind, sysctl, prefix, names):
    """Sets kernel limits back to what they were before setup, if setup changed them and nobody since."""
    before = next((line.split()[1:] for line in lines if line.startswith(f"{kind}-before ")), None)
    after = next((line.split()[1:] for line in reversed(lines) if line.startswith(f"{kind}-after ")), None)
    if not before:
        return
    current = [PROC.joinpath(*prefix.split("."), name).read_text().strip() for name in names]
    if (not after or not all(v.isdigit() for v in before + after)
            or len(before) != len(names) or current != after or not sysctl.is_file()
            or hashes.get(str(sysctl)) != digest(sysctl)):
        kept.append(f"{kind} settings (changed or incomplete installation record)")
        return
    if f"{kind}-existing" in lines:
        backup = base / f"{kind}.before"
        if not backup.is_file() or hashes.get(str(backup)) != digest(backup):
            raise RuntimeError(f"The original {kind} configuration backup is missing")
        privileged(["cp", "--", str(backup), str(sysctl)])
    else:
        privileged(["rm", "--", str(sysctl)])
    privileged(["sysctl", "-w", *(f"{prefix}.{name}={value}" for name, value in zip(names, before))])


def undo_host(lines, base, privileged, kept):
    packages = [tuple(line.split()[1:]) for line in lines if line.startswith("package ")]
    changes = any(line.startswith(("package ", "docker-group ", "inotify-before ", "neigh-before ", "docker-started ")) for line in lines)
    if not changes:
        return
    # Other Docker workloads, including stopped containers and images of others, may rely on these changes.
    if shutil.which("docker"):
        try:
            if output(["docker", "ps", "-aq"]):
                kept.append("host changes (other Docker containers exist)")
                return
            own = {raw for kind, _, raw in (line.partition(" ") for line in lines) if kind == "docker-image"}
            images = output(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]).split()
            if [i for i in images if i not in own and not i.startswith(KICBASE)]:
                kept.append("host changes (other Docker images exist)")
                return
        except RuntimeError:
            kept.append("host changes (Docker usage could not be checked)")
            return
    hashes = {line.split(" ", 2)[2]: line.split(" ", 2)[1] for line in lines if line.startswith("sha256 ")}
    for kind, sysctl, prefix, names in SYSCTLS:
        restore_sysctl(lines, base, privileged, kept, hashes, kind, sysctl, prefix, names)
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


def cleanup(root, settings, base, privileged, purge=False):
    """Called after teardown, while the shared cluster claim is still held.
    The searches of the simulator stay, as results do, unless purge."""
    preflight(root, base)
    lines = inventory(base)
    kept = []
    undo_service(lines, base, privileged, kept)
    undo_host(lines, base, privileged, kept)
    if f"crontab {root}" in lines:
        from .service import remove_watchdog
        try:
            remove_watchdog(root)
        except (OSError, subprocess.SubprocessError):
            kept.append("the watchdog lines in the crontab (crontab -e to remove them)")
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
        elif kind == "file" and path == base / "no-sudo":
            if path.is_file() and not path.is_symlink():
                path.unlink()
        elif kind == "docker-image":
            # Pulled by lab simulate where Go was missing: gone unless a container still uses it.
            if shutil.which("docker") and subprocess.run(["docker", "image", "inspect", raw], capture_output=True, timeout=120).returncode == 0:
                if subprocess.run(["docker", "image", "rm", raw], capture_output=True, timeout=600).returncode:
                    kept.append(f"Docker image {raw} (still in use)")
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
        for name in SETTINGS_DIRS | (KEPT if purge else set()):
            path = settings / name
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.is_file():
                path.unlink()
        if settings.exists():
            if any(p.name not in KEPT for p in settings.iterdir()):
                kept.append(f"{settings} (unrecognized files)")
            elif not any((settings / name).exists() for name in KEPT):
                settings.rmdir()
    # The environment/interpreter is removed last, once cleanup imports are loaded.
    if not kept:
        for path in directories:
            shutil.rmtree(path)
    if not kept:
        (base / "installed.txt").unlink(missing_ok=True)
        (base / "inotify.before").unlink(missing_ok=True)
        (base / "neigh.before").unlink(missing_ok=True)
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
