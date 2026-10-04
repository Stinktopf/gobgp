"""Shared setup/start/update/stop/teardown policy. scripts only dispatch here."""

import argparse
import fcntl
import getpass
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import cluster, config, service, update
from . import terminal as ui
from .web import auth


@contextmanager
def step(description: str):
    """Keep long, otherwise silent operations visible, including in piped logs."""
    ui.heading(description)
    started, finished = time.monotonic(), threading.Event()
    def heartbeat():
        while not finished.wait(10):
            ui.waiting(f"{description} · {time.monotonic() - started:.0f}s elapsed")
    reporter = threading.Thread(target=heartbeat, daemon=True)
    reporter.start()
    try:
        yield
    except BaseException:
        ui.error(f"{description} failed after {time.monotonic() - started:.1f}s")
        raise
    else:
        ui.success(f"Done in {time.monotonic() - started:.1f}s")
    finally:
        finished.set()
        reporter.join()


def options_file() -> Path:
    return config.SETTINGS / "lifecycle.json"


def load_options() -> dict:
    try:
        return json.loads(options_file().read_text())
    except FileNotFoundError:
        return {}


def configure(args, interactive: bool) -> dict:
    values = config.host_settings()
    first = not (config.SETTINGS / "host.yaml").exists()
    reconfigure = args.action == "reconfigure"
    for key, value in (("cpus", args.cpus), ("memory_mb", args.memory_gb),
                       ("keep_cpus", args.keep_cpus), ("keep_mb", args.keep_memory_gb)):
        if value is not None:
            values[key] = round(value * 1024) if key.endswith("mb") else value
    have = cluster.host()
    ui.info(f"Host capacity: {have['cpus']} CPU threads, {have['memory_mb'] / 1024:.1f} GB RAM")
    if not first:
        ui.info("Enter keeps each saved value. Type all to use the whole host budget." if reconfigure
                else f"Reusing saved settings from {config.SETTINGS / 'host.yaml'}. Applying any supplied flags.")
    if (first or reconfigure) and interactive:
        ui.info("Choose the total CPU/RAM budget for the lab. Host reserves are subtracted next.")
        for key, supplied, label, scale, minimum in (
            ("cpus", args.cpus, "Total CPU budget, threads", 1, 2),
            ("memory_mb", args.memory_gb, "Total RAM budget, GB", 1024, 2048),
        ):
            if supplied is None:
                default = f"{values[key] / scale:g}" if key in values else f"all ({have[key] / scale:g})"
                answer = input(ui.prompt(f"{label} [{default}]: ")).strip()
                if answer.lower() == "all":
                    values.pop(key, None)
                elif answer:
                    value = int(answer) if scale == 1 else round(float(answer) * scale)
                    if not minimum <= value <= have[key]:
                        raise ValueError(f"{label}: choose between {minimum / scale:g} and {have[key] / scale:g}.")
                    values[key] = value
    # Keep the established defaults where they fit. make unattended laptop
    # setup viable without silently exceeding its saved budget later.
    if first:
        if args.keep_cpus is None:
            values["keep_cpus"] = min(values["keep_cpus"], max(0, min(values.get("cpus", have["cpus"]), have["cpus"]) - 2))
        if args.keep_memory_gb is None:
            values["keep_mb"] = min(values["keep_mb"], max(0, min(values.get("memory_mb", have["memory_mb"]), have["memory_mb"]) - 2048))
    if (first or reconfigure) and interactive:
        for key, supplied, label, scale in (("keep_cpus", args.keep_cpus, "CPU threads to leave for the host", 1),
                                            ("keep_mb", args.keep_memory_gb, "GB RAM to leave for the host", 1024)):
            if supplied is None:
                default = values[key] / scale
                answer = input(ui.prompt(f"{label} [{default:g}]: ")).strip()
                if answer:
                    values[key] = round(float(answer) * scale)
    cpus = min(values.get("cpus", have["cpus"]), have["cpus"])
    memory = min(values.get("memory_mb", have["memory_mb"]), have["memory_mb"])
    if not 0 <= values["keep_cpus"] <= cpus - 2 or not 0 <= values["keep_mb"] <= memory - 2048:
        raise ValueError("Headroom must leave at least 2 CPUs and 2048 MB for minikube. "
                         "Use --keep-cpus and --keep-memory-gb to choose smaller reserves on a laptop.")
    if values.get("routers_per_cpu", 4) < 1:
        raise ValueError("routers_per_cpu must be positive")
    settings = load_options()
    if interactive and (reconfigure or not settings.get("web_access_configured")) and args.http is None and args.host is None:
        ui.info("HTTPS uses a self-signed certificate. HTTP stays on localhost.")
        ui.info(f"HTTPS listen address: {settings.get('host', '0.0.0.0')} (0.0.0.0 means all network interfaces).")
        default_http = settings.get("http", True)
        choice = "y/N" if default_http else "Y/n"
        while True:
            answer = input(ui.prompt(f"Set up HTTPS? [{choice}]: ")).strip().lower()
            if answer in ("", "n", "no", "y", "yes"):
                settings["http"] = (answer not in ("y", "yes")) if answer else default_http
                settings["web_access_configured"] = True
                break
            ui.info("Enter y or n.")
    for key in ("host", "port", "http"):
        if getattr(args, key) is not None:
            settings[key] = getattr(args, key)
    if args.host is not None and args.http is None:
        settings["http"] = False
    if args.http is not None or args.host is not None:
        settings["web_access_configured"] = True
    if settings.get("port") is not None and not 1 <= settings["port"] <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    if any(c in settings.get("host", "") for c in "\n\r\0"):
        raise ValueError("Invalid bind address")
    config.save_host(values)
    options_file().write_text(json.dumps(settings, indent=2))
    ui.resources(cpus, memory, values["keep_cpus"], values["keep_mb"])
    ui.info(f"Settings saved in {config.SETTINGS}.")
    reset_password = reconfigure and bool(args.password_file)
    if reconfigure and interactive and auth.load() and not args.password_file:
        while True:
            answer = input(ui.prompt("Set a new web password? [y/N]: ")).strip().lower()
            if answer in ("", "n", "no", "y", "yes"):
                reset_password = answer in ("y", "yes")
                break
            ui.info("Enter y or n.")
    if auth.load() and not reset_password:
        ui.info("Web password: keeping the existing password.")
    else:
        ui.info("Web password input is hidden.")
        if args.password_file:
            password = Path(args.password_file).read_text().rstrip("\r\n")
        elif interactive:
            label = "New web password (at least 10 characters): " if reset_password else "Web UI password (at least 10 characters, empty generates one): "
            password = getpass.getpass(ui.prompt(label))
            if password and password != getpass.getpass(ui.prompt("Repeat password: ")):
                raise ValueError("Passwords differ")
        else:
            password = ""
        if reset_password and not password:
            raise ValueError("The new password must have at least 10 characters")
        if password:
            if len(password) < 10:
                raise ValueError("Use at least 10 characters for the web password")
            auth.set_password(password)
            ui.info("Web password saved.")
        else:
            auth.initialize()
    if auth.initial_file().exists():
        ui.info(f"Initial web password is in {auth.initial_file()}. Change it at first sign-in.")
    return settings


def desired_cluster() -> cluster.Cluster:
    experiments = [config.Experiment.load(config.path(n)) for n in config.names()]
    have, (keep_cpus, keep_mb) = cluster.capacity(), cluster.keep()
    if have["cpus"] - keep_cpus < 2 or have["memory_mb"] - keep_mb < 2048:
        raise ValueError("Saved headroom leaves less than 2 CPUs / 2048 MB for minikube. Run setup with smaller reserves.")
    return cluster.Cluster(cluster.size_for(experiments, have))


def ensure_cluster(c: cluster.Cluster) -> dict:
    """Called with the experiment lock held. Only incompatibility permits deletion."""
    ui.info(f"Checking minikube profile {cluster.PROFILE}. Target: {c.resources.cpus} CPU threads, "
          f"{c.resources.memory_mb / 1024:.1f} GB RAM.")
    profile = c._profile()
    if not profile:
        # Profile state is per-user. Docker names are shared across all users.
        other = subprocess.run(["docker", "container", "inspect", cluster.PROFILE], capture_output=True)
        if other.returncode == 0:
            raise RuntimeError("A Docker container named obgp-lab exists without this user's minikube profile. "
                               "It may belong to another user. Nothing was changed.")
        ui.info("No existing profile: creating the cluster. First startup may download images and take several minutes.")
    else:
        cfg, have = profile["Config"], cluster.capacity()
        keep_cpus, keep_mb = cluster.keep()
        if cfg["CPUs"] > have["cpus"] - keep_cpus or cfg["Memory"] > have["memory_mb"] - keep_mb:
            ui.warning("Existing cluster exceeds the saved budget: recreating it. Results are kept. Cluster images must be rebuilt.")
            c.delete()  # apply reduced limits too, not only increases
        else:
            ui.info("Checking the existing cluster for reuse. Starting it if stopped.")
    try:
        have = c.start()
    except cluster.Incompatible as problem:
        ui.warning(f"Existing cluster is incompatible: {problem}\nRecreating it automatically. Results are kept.")
        c.delete()
        have = c.start()
    cluster.set_manually_stopped(False)
    return have


def stop_cluster(manual: bool = True) -> None:
    """Stop only the cluster, under an existing claim. Keep the web server alive."""
    if manual:
        cluster.set_manually_stopped(True)
    c = cluster.Cluster(config.Cluster())
    profile = c._profile()
    if profile and profile.get("Status") != "Stopped":
        cluster.sh("minikube", "stop", "-p", cluster.PROFILE, timeout=300)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["setup", "reconfigure", "update", "start", "stop", "teardown", "uninstall"])
    p.add_argument("--non-interactive", action="store_true", help="use saved settings/defaults. Sudo never prompts")
    p.add_argument("--keep-cpus", type=int, help="CPU threads reserved for the host (default: 4)")
    p.add_argument("--keep-memory-gb", type=float, help="GB RAM reserved for the host (default: 4)")
    p.add_argument("--cpus", type=int, help="total CPU allowance before headroom on a shared server")
    p.add_argument("--memory-gb", type=float, help="total RAM allowance before headroom on a shared server")
    p.add_argument("--host", help="HTTPS bind address. Default is localhost HTTP")
    p.add_argument("--port", type=int, help="fixed port. Otherwise find a free port starting at 8443")
    protocol = p.add_mutually_exclusive_group()
    protocol.add_argument("--http", action="store_true", default=None, help="localhost HTTP")
    protocol.add_argument("--https", dest="http", action="store_false", help="HTTPS with a self-signed certificate")
    p.add_argument("--password-file", help="read initial password from a file, or reset it with reconfigure")
    p.add_argument("--purge", action="store_true", help="teardown/uninstall: also delete this checkout's private results")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    interactive = sys.stdin.isatty() and not args.non_interactive
    if args.purge and args.action not in ("teardown", "uninstall"):
        parser().error("--purge is only valid with teardown or uninstall")
    if not interactive:
        os.environ["GIT_TERMINAL_PROMPT"] = "0"
        os.environ["GIT_SSH_COMMAND"] = os.environ.get("GIT_SSH_COMMAND", "ssh") + " -oBatchMode=yes"
    config.SETTINGS.mkdir(parents=True, exist_ok=True)
    try:
        with (config.SETTINGS / "lifecycle.lock").open("a+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise cluster.Busy("Another lifecycle command is running") from None
            # Atomic exclusion with runners, not a check followed by a destructive action.
            with cluster.claim("__maintenance__"):
                if args.purge:
                    from .results import PRIVATE
                    if PRIVATE.is_symlink() or not PRIVATE.resolve().is_relative_to(config.ROOT.resolve()):
                        raise RuntimeError("Private results point outside this checkout. Nothing removed.")
                existing = service.discover()
                if existing and not options_file().exists():
                    options_file().write_text(json.dumps({k: existing[k] for k in ("host", "port", "http")}))
                if args.action in ("setup", "reconfigure"):
                    for key, env, convert in (("cpus", "LAB_CPUS", int), ("memory_gb", "LAB_MEMORY_GB", float)):
                        if getattr(args, key) is None and os.environ.get(env):
                            setattr(args, key, convert(os.environ[env]))
                    ui.heading("Resources and web access")
                    settings = configure(args, interactive)
                    with step("Apply web server configuration"):
                        service.stop(interactive)
                        service.configure_unit(settings, interactive)
                    with step("Synchronize Python dependencies"):
                        subprocess.run(["uv", "sync"], cwd=config.ROOT, check=True, timeout=600)
                    with step("Prepare the minikube cluster"):
                        have = ensure_cluster(desired_cluster())
                        ui.info(f"Cluster ready: {have['cpus']} CPU threads, {have['memory_mb'] / 1024:.1f} GB RAM.")
                    with step("Start the web interface and wait for readiness"):
                        service.start(settings, interactive)
                    ui.success("Configuration applied. Open the web interface shown above." if args.action == "reconfigure"
                               else "Setup complete. Open the web interface shown above.")
                elif args.action == "start":
                    auth.initialize()
                    with step("Prepare the minikube cluster"):
                        ensure_cluster(desired_cluster())
                    with step("Start the web interface and wait for readiness"):
                        service.start(load_options(), interactive)
                elif args.action == "update":
                    # Keep Git's fast-forward and local-change safeguards, including when current.
                    with step("Fetch updates and fast-forward the checkout"):
                        update.update(sync=False, allow_current=True)
                    with step("Stop the web server for the update"):
                        service.stop(interactive)
                    with step("Synchronize Python dependencies"):
                        subprocess.run(["uv", "sync"], cwd=config.ROOT, check=True, timeout=600)
                    with step("Restart the web interface and wait for readiness"):
                        service.start(load_options(), interactive)
                else:
                    if args.action == "uninstall":
                        from . import uninstall
                        uninstall.preflight(config.ROOT, Path.home() / "obgp-lab")
                        if config.SETTINGS.is_symlink():
                            raise RuntimeError("Settings directory is a symlink. Uninstall cannot establish ownership.")
                    with step("Stop the web interface"):
                        if args.action in ("teardown", "uninstall") and service.unit():
                            service.control_unit("disable", interactive)
                        service.stop(interactive)
                    if args.action == "stop":
                        with step("Stop the minikube cluster"):
                            stop_cluster()
                    else:
                        cluster.set_manually_stopped(True)
                        c = cluster.Cluster(config.Cluster())
                        missing_tool = args.action == "uninstall" and not shutil.which("minikube")
                        if missing_tool and (cluster.lock_file().parent / "profiles" / cluster.PROFILE).exists():
                            raise RuntimeError("minikube is missing but its profile remains. Run setup to repair before uninstalling.")
                        if not missing_tool and c._profile():
                            with step("Remove the minikube cluster"):
                                c.delete()
                    if args.purge:
                        from .results import PRIVATE
                        if PRIVATE.exists():
                            shutil.rmtree(PRIVATE)
                    if args.action == "uninstall":
                        with step("Remove recorded installation changes"):
                            kept = uninstall.cleanup(config.ROOT, config.SETTINGS, Path.home() / "obgp-lab",
                                                     lambda command: service.privileged(command, interactive))
                        cluster.set_manually_stopped(False)
                        for item in kept:
                            ui.warning(f"Kept {item}")
                        ui.info("Repository and results kept." if not args.purge else "Repository and public results kept.")
                        if kept:
                            ui.warning("Some installation changes could not safely be removed. Their inventory is retained.")
                            return 1
                        ui.success("Recorded installation removed. Pre-existing tools and unrecorded host settings kept.")
                        return 0
                    ui.info("Runtime stopped." if args.action == "stop" else "Runtime removed. Settings and tools kept." +
                          (" Private results deleted." if args.purge else " Results kept."))
        return 0
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError, update.UpdateError) as e:
        ui.error(str(e))
        return cluster.BUSY if isinstance(e, cluster.Busy) else 1


if __name__ == "__main__":
    raise SystemExit(main())
