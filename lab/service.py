"""One web server per user configuration, with verified Linux process ownership.

The registry is also written by manual `lab serve` starts. Old detached and
systemd starts are discovered by UID, checkout and exact command arguments.
PID reuse is checked with /proc start time. signals use pidfds, never groups.
"""

import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import requests

from . import config
from . import terminal as ui


def state_file() -> Path:
    return config.SETTINGS / "serve.json"


def identity(pid: int) -> dict | None:
    try:
        proc = Path(f"/proc/{pid}")
        if proc.stat().st_uid != os.getuid():
            return None
        stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        if stat[0] == "Z":
            return None
        return {"pid": pid, "start": stat[19], "root": str((proc / "cwd").resolve(strict=True)),
                "command": (proc / "cmdline").read_bytes().decode().strip("\0").split("\0")}
    except (OSError, ValueError):
        return None


def matches(state: dict) -> bool:
    return identity(state["pid"]) == {k: state[k] for k in ("pid", "start", "root", "command")}


def save(state: dict) -> None:
    config.SETTINGS.mkdir(parents=True, exist_ok=True)
    temp = state_file().with_suffix(".tmp")
    temp.write_text(json.dumps(state))
    temp.chmod(0o600)
    temp.replace(state_file())


def discover() -> dict | None:
    try:
        saved = json.loads(state_file().read_text())
        if matches(saved):
            if saved["root"] != str(config.ROOT):
                raise RuntimeError(f"The web server belongs to another checkout: {saved['root']}")
            return saved
    except (FileNotFoundError, ValueError, KeyError, TypeError):
        pass
    found = []
    for proc in Path("/proc").glob("[0-9]*"):
        ident = identity(int(proc.name))
        if not ident or ident["root"] != str(config.ROOT):
            continue
        try:
            argv = (proc / "cmdline").read_bytes().decode().strip("\0").split("\0")
        except (OSError, UnicodeError):
            continue
        # Exclude uv/nohup/shell parents: only the Python entry point owns the listener.
        if not argv or not Path(argv[0]).name.startswith("python"):
            continue
        if len(argv) > 3 and argv[1:3] == ["-m", "lab.cli"] and argv[3] == "serve":
            args = argv[4:]
        elif len(argv) > 2 and Path(argv[1]).name == "lab" and argv[2] == "serve":
            args = argv[3:]
        else:
            continue
        def option(name, default, args=args):
            for i, arg in enumerate(args):
                if arg.startswith(name + "="):
                    return arg.split("=", 1)[1]
                if arg == name and i + 1 < len(args):
                    return args[i + 1]
            return default
        found.append({**ident, "port": int(option("--port", 8443)), "host": option("--host", "0.0.0.0"), "http": "--http" in args})
    if len(found) > 1:
        raise RuntimeError("Multiple lab web servers exist in this checkout. Stop the extra manual services first.")
    if found:
        save(found[0])
        return found[0]
    return None


@contextmanager
def register(args):
    config.SETTINGS.mkdir(parents=True, exist_ok=True)
    with (config.SETTINGS / "serve.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("The lab web server is already running.") from None
        existing = discover()
        if existing and existing["pid"] != os.getpid():
            raise RuntimeError("The lab web server is already running.")
        state = {**identity(os.getpid()), "port": args.port, "host": args.host, "http": args.http}
        save(state)
        try:
            yield
        finally:
            if state_file().exists() and json.loads(state_file().read_text()).get("pid") == os.getpid():
                state_file().unlink()


def unit() -> dict:
    """Recognize the old host installer service only for this user and checkout."""
    try:
        result = subprocess.run(["systemctl", "show", "obgp-lab.service", "--property=User,WorkingDirectory,MainPID,LoadState,ExecStart"],
                                capture_output=True, text=True, timeout=10)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        import pwd
        if (values.get("LoadState") == "loaded" and values.get("User") == pwd.getpwuid(os.getuid()).pw_name
                and values.get("WorkingDirectory") == str(config.ROOT)
                and any(command in values.get("ExecStart", "") for command in ("lab serve", "lab.cli serve"))):
            return values
    except (OSError, subprocess.SubprocessError):
        pass
    return {}


def privileged(command: list[str], interactive: bool) -> None:
    if os.getuid() != 0:
        command = ["sudo", *([] if interactive else ["-n"]), *command]
    subprocess.run(command, check=True, timeout=90)


def control_unit(action: str, interactive: bool) -> None:
    privileged(["systemctl", action, "obgp-lab.service"], interactive)


def configure_unit(settings: dict, interactive: bool) -> None:
    """Carry saved configuration into a recognized legacy systemd service."""
    if not unit():
        return
    host = "127.0.0.1" if settings.get("http", True) else settings.get("host", "0.0.0.0")
    args = [sys.executable, "-m", "lab.cli", "serve", "--host", host, "--port", str(settings.get("port", 8443))]
    if settings.get("http", True):
        args.append("--http")
    # systemd escaping, not shell quoting (ExecStart does not use a shell).
    def quote(value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
    directory = "/etc/systemd/system/obgp-lab.service.d"
    path = f"{Path.home()}/obgp-lab/bin:/usr/local/bin:/usr/bin:/bin"
    content = "[Service]\nExecStart=\nExecStart=" + " ".join(quote(a) for a in args) + "\nEnvironment=" + quote("PATH=" + path) + "\n"
    from . import uninstall
    base = Path.home() / "obgp-lab"
    uninstall.before_service_change(base)
    with tempfile.NamedTemporaryFile("w") as file:
        file.write(content)
        file.flush()
        privileged(["install", "-d", directory], interactive)
        privileged(["install", "-m", "644", file.name, directory + "/lifecycle.conf"], interactive)
    uninstall.record(base, f"sha256 {uninstall.digest(uninstall.SYSTEMD)} {uninstall.SYSTEMD}")
    privileged(["systemctl", "daemon-reload"], interactive)


def stop(interactive: bool = False) -> None:
    state = discover()
    managed = unit()
    if managed and managed.get("MainPID", "0") != "0":
        ui.info("Stopping the existing systemd web service.")
        control_unit("stop", interactive)
    elif state:
        ui.info("Stopping the existing lab web server.")
        # Open the handle before checking identity, closing the PID-reuse race.
        try:
            fd = os.pidfd_open(state["pid"])
        except ProcessLookupError:
            return
        try:
            if matches(state):
                signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)
    if state:
        until = time.monotonic() + 30
        while matches(state):
            if time.monotonic() > until:
                raise RuntimeError("The lab web server did not stop. No process was force-killed.")
            time.sleep(0.2)
    state_file().unlink(missing_ok=True)


def ready(state: dict) -> bool:
    host = "127.0.0.1" if state["http"] or state["host"] in ("0.0.0.0", "::") else state["host"]
    try:
        with requests.Session() as session:
            session.trust_env = False
            # A self-signed localhost certificate is expected.
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                response = session.get(f"{'http' if state['http'] else 'https'}://{host}:{state['port']}/login", verify=False, timeout=1)
            return response.status_code == 200
    except requests.RequestException:
        return False


def start(settings: dict, interactive: bool = False) -> dict:
    state = discover()
    ui.info(f"Web server log: {config.SETTINGS / 'serve.log'} (systemd: journalctl -u obgp-lab)")
    if state and not ready(state):
        # A dead listener with a live Python process is not a healthy service.
        until = time.monotonic() + 5
        while matches(state) and time.monotonic() < until and not ready(state):
            time.sleep(0.2)
        if not ready(state):
            ui.warning("Existing web server is not responding. Restarting it.")
            stop(interactive)
            state = None
    process = None
    if not state:
        if unit():
            ui.info("Starting the existing systemd web service.")
            control_unit("start", interactive)
        else:
            port = settings.get("port", 8443)
            host = "127.0.0.1" if settings.get("http", True) else settings.get("host", "0.0.0.0")
            # Never mistake an unrelated listener for our server or kill it.
            while True:
                try:
                    with socket.socket() as sock:
                        sock.bind((host, port))
                    break
                except OSError:
                    if settings.get("port") or port >= 8543:
                        raise RuntimeError(f"Cannot bind {host}:{port}. Choose --port in setup.") from None
                    port += 1
            ui.info(f"Starting web server on {host}:{port}. Waiting for HTTP readiness (up to 45s).")
            args = [sys.executable, "-m", "lab.cli", "serve", "--host", host, "--port", str(port)]
            if settings.get("http", True):
                args.append("--http")
            with (config.SETTINGS / "serve.log").open("a") as log:
                process = subprocess.Popen(args, cwd=config.ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
    else:
        ui.info("Reusing the running web server.")
    until = time.monotonic() + 45
    while time.monotonic() < until:
        state = discover()
        if state and ready(state):
            host = "localhost" if state["http"] or state["host"] in ("0.0.0.0", "::") else state["host"]
            host = f"[{host}]" if ":" in host else host
            ui.success(f"Web interface: {'http' if state['http'] else 'https'}://{host}:{state['port']}")
            return state
        if process and process.poll() is not None:
            break
        time.sleep(0.2)
    raise RuntimeError(f"Web server is not ready. See {config.SETTINGS / 'serve.log'} (or journalctl -u obgp-lab).")
