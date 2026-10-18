"""Cluster-only operations in the background. The web server stays available."""

import json
import logging
import threading
import time

from .. import cluster, config, host, lifecycle
from ..results import write_atomic

log = logging.getLogger(__name__)


def _policy() -> dict:
    return json.loads((config.SETTINGS / "cluster-policy.json").read_text())


def _save_policy(key: str, minutes: int) -> None:
    try:
        policy = _policy()
        policy = policy if isinstance(policy, dict) else {}
    except (OSError, ValueError):
        policy = {}
    config.SETTINGS.mkdir(parents=True, exist_ok=True)
    write_atomic(config.SETTINGS / "cluster-policy.json", json.dumps({**policy, key: minutes}))


def idle_minutes() -> int:
    try:
        minutes = int(_policy()["idle_minutes"])
        return minutes if 0 <= minutes <= 10080 else 0
    except (FileNotFoundError, KeyError):
        return 30
    except (ValueError, TypeError):
        return 0  # malformed policy must never cause an unexpected shutdown


def save_idle(minutes: int) -> None:
    if not 0 <= minutes <= 10080:
        raise ValueError("Idle timeout must be between 0 and 10080 minutes. Use 0 to disable it.")
    _save_policy("idle_minutes", minutes)


def busy_file():
    return config.SETTINGS / "cluster-busy"


def busy_seen() -> float | None:
    """When the cluster last had work, as wall time, kept across restarts of
    the web server: otherwise every restart would begin the idle time anew."""
    try:
        return float(busy_file().read_text())
    except (OSError, ValueError):
        return None


def gpu_quiet_minutes() -> int:
    """How long a GPU used by others must be idle before the next result starts, 0 for not waiting."""
    try:
        minutes = int(_policy()["gpu_quiet_minutes"])
        return minutes if 0 <= minutes <= 1440 else 15
    except (OSError, KeyError, ValueError, TypeError):
        return 15  # waiting is the polite default on a shared server


def save_gpu_quiet(minutes: int) -> None:
    if not 0 <= minutes <= 1440:
        raise ValueError("The GPU wait must be between 0 and 1440 minutes. Use 0 to disable it.")
    _save_policy("gpu_quiet_minutes", minutes)


PROFILE_S = 60  # how long an answer of minikube holds


class ClusterControl:
    def __init__(self, jobs):
        self.jobs = jobs
        self.lock = threading.Lock()
        self.busy = False
        self.action = ""
        self.message = ""
        self.error = ""
        seen = busy_seen()
        self.idle_since = time.monotonic() - max(0.0, time.time() - seen) if seen else time.monotonic()
        self.thread = None
        self.profile: tuple[float, dict | None, str] | None = None  # when, the profile, the error
        self.asking = False

    def _ask(self) -> None:
        try:
            answer = (time.monotonic(), cluster.Cluster(config.Cluster())._profile(), "")
        except Exception as e:
            answer = (time.monotonic(), None, str(e) or type(e).__name__)
        with self.lock:
            self.profile, self.asking = answer, False

    def prime(self) -> None:
        """Asks minikube once at startup, so that the first page need not wait."""
        with self.lock:
            if self.profile is not None or self.asking:
                return
            self.asking = True
        threading.Thread(target=self._ask, daemon=True).start()

    def _profile(self) -> tuple[dict | None, str]:
        """The minikube profile and why it could not be read, asked in the
        background at most every minute: minikube takes seconds, under WSL
        about six and two of CPU, and pages ask every few. Changes through
        the web interface ask at once. Only the first answer waits."""
        with self.lock:
            known, stale = self.profile, self.profile is None or time.monotonic() - self.profile[0] > PROFILE_S
            ask = stale and not self.asking and known is not None
            self.asking |= ask
        while known is None and self.asking:  # asked at startup: wait for that answer
            time.sleep(0.1)
            known = self.profile
        if known is None:
            self._ask()
            known = self.profile
        elif ask:
            threading.Thread(target=self._ask, daemon=True).start()
        return known[1], known[2]

    def snapshot(self) -> dict:
        with self.lock:
            state = {"busy": self.busy, "action": self.action, "message": self.message, "error": self.error}
        state.update(manual_off=cluster.manually_stopped(), idle_minutes=idle_minutes(), gpu_quiet_minutes=gpu_quiet_minutes(), status="Checking", cpus=None, memory_mb=None,
                     docker=host.docker_running())
        if not state["busy"]:
            profile, error = self._profile()
            if error:
                state.update(status="Unknown", error=state["error"] or error)
            else:
                status = profile.get("Status", "Unknown") if profile else "Not created"
                state["status"] = "Running" if status == "OK" else status
                if ((state["action"] in ("stop", "idle-stop") and state["status"] == "Running")
                        or (state["action"] in ("start", "apply") and state["status"] == "Stopped")):
                    state["message"] = ""
                if profile:
                    state.update(cpus=profile["Config"]["CPUs"], memory_mb=profile["Config"]["Memory"])
        state.update(idle_seconds=None, stop_in_seconds=None)
        if not state["busy"] and state["status"] == "Running" and not self.jobs.active() and (not self.jobs.queue() or self.jobs.held_back()):
            state["idle_seconds"] = max(0, time.monotonic() - self.idle_since)
            if state["idle_minutes"] and not state["manual_off"]:
                state["stop_in_seconds"] = max(0, state["idle_minutes"] * 60 - state["idle_seconds"])
        return state

    def request(self, action: str, values: dict | None = None) -> None:
        if action not in ("start", "stop", "apply", "idle-stop", "save"):
            raise ValueError("Unknown cluster action")
        if action in ("start", "apply") and not host.docker_running():
            raise cluster.Busy("Docker does not run. Start Docker first, then the cluster.")
        # Exclude a worker which was launched but has not claimed the cluster yet.
        with self.jobs.lock:
            if self.jobs.active():
                raise cluster.Busy("An experiment is active. Pause it and wait for it to stop first.")
            if action == "idle-stop" and self.jobs.queue() and not self.jobs.held_back():
                raise cluster.Busy("Jobs are waiting. Let them finish or remove them from the queue before using Idle.")
            claim = cluster.claim("__maintenance__")
            try:
                if values is not None:
                    config.save_host(values)
                if action == "save":
                    return
                with self.lock:
                    self.busy, self.action, self.message, self.error = True, action, "", ""
                self.thread = threading.Thread(target=self._work, args=(action, claim), daemon=True)
                try:
                    self.thread.start()
                except Exception:
                    with self.lock:
                        self.busy = False
                    raise
                claim = None  # ownership passes to the worker, including on failures
            finally:
                if claim is not None:
                    claim.close()

    def _work(self, action, claim):
        try:
            if action in ("stop", "idle-stop"):
                lifecycle.stop_cluster(manual=action == "stop")
                if action == "idle-stop":
                    cluster.set_manually_stopped(False)
                message = ("Cluster stopped. The web interface stays available. Start the cluster to run queued jobs."
                           if action == "stop" else "Cluster idle. A new queued job starts it automatically.")
            else:
                # A failed recreation must not trigger repeated starts from the queue.
                cluster.set_manually_stopped(True)
                have = lifecycle.ensure_cluster(lifecycle.desired_cluster())
                message = f"Cluster ready with {have['cpus']} CPU threads and {have['memory_mb'] / 1024:.1f} GB RAM."
            with self.lock:
                self.message = message
        except Exception as e:
            log.exception("Cluster operation failed")
            with self.lock:
                self.error = str(e)
        finally:
            self._ask()  # the cluster changed: the page shows it as it is now
            with self.lock:
                self.busy = False
                self._busy()
            claim.close()

    def _busy(self) -> None:
        """The cluster has work now: its idle time begins anew, on disk at most every 30 s."""
        self.idle_since = time.monotonic()
        if (busy_seen() or 0) < time.time() - 30:
            config.SETTINGS.mkdir(parents=True, exist_ok=True)
            write_atomic(busy_file(), str(time.time()))

    def idle(self) -> None:
        """Called by the queue supervisor, even without an open browser."""
        now = time.monotonic()
        with self.jobs.lock:
            if self.jobs.active() or cluster.holder() or (self.jobs.queue() and not self.jobs.held_back()):
                self._busy()
                return
            minutes = idle_minutes()
            if cluster.manually_stopped() or not minutes or now - self.idle_since < minutes * 60:
                return
        try:
            self.request("idle-stop")  # rechecks the queue and claims the cluster atomically
        except cluster.Busy:
            pass
        finally:
            self._busy()
