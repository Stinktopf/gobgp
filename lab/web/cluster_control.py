"""Cluster-only operations in the background. The web server stays available."""

import json
import logging
import threading
import time

from .. import cluster, config, lifecycle
from ..results import write_atomic

log = logging.getLogger(__name__)


def idle_minutes() -> int:
    try:
        minutes = int(json.loads((config.SETTINGS / "cluster-policy.json").read_text())["idle_minutes"])
        return minutes if 0 <= minutes <= 10080 else 0
    except FileNotFoundError:
        return 30
    except (ValueError, TypeError, KeyError):
        return 0  # malformed policy must never cause an unexpected shutdown


def save_idle(minutes: int) -> None:
    if not 0 <= minutes <= 10080:
        raise ValueError("Idle timeout must be between 0 and 10080 minutes. Use 0 to disable it.")
    config.SETTINGS.mkdir(parents=True, exist_ok=True)
    write_atomic(config.SETTINGS / "cluster-policy.json", json.dumps({"idle_minutes": minutes}))


class ClusterControl:
    def __init__(self, jobs):
        self.jobs = jobs
        self.lock = threading.Lock()
        self.busy = False
        self.action = ""
        self.message = ""
        self.error = ""
        self.idle_since = time.monotonic()
        self.thread = None

    def snapshot(self) -> dict:
        with self.lock:
            state = {"busy": self.busy, "action": self.action, "message": self.message, "error": self.error}
        state.update(manual_off=cluster.manually_stopped(), idle_minutes=idle_minutes(), status="Checking", cpus=None, memory_mb=None)
        if not state["busy"]:
            try:
                profile = cluster.Cluster(config.Cluster())._profile()
                status = profile.get("Status", "Unknown") if profile else "Not created"
                state["status"] = "Running" if status == "OK" else status
                if ((state["action"] in ("stop", "idle-stop") and state["status"] == "Running")
                        or (state["action"] in ("start", "apply") and state["status"] == "Stopped")):
                    state["message"] = ""
                if profile:
                    state.update(cpus=profile["Config"]["CPUs"], memory_mb=profile["Config"]["Memory"])
            except Exception as e:
                state.update(status="Unknown", error=state["error"] or str(e))
        state.update(idle_seconds=None, stop_in_seconds=None)
        if not state["busy"] and state["status"] == "Running" and not self.jobs.active() and not self.jobs.queue():
            state["idle_seconds"] = max(0, time.monotonic() - self.idle_since)
            if state["idle_minutes"] and not state["manual_off"]:
                state["stop_in_seconds"] = max(0, state["idle_minutes"] * 60 - state["idle_seconds"])
        return state

    def request(self, action: str, values: dict | None = None) -> None:
        if action not in ("start", "stop", "apply", "idle-stop", "save"):
            raise ValueError("Unknown cluster action")
        # Exclude a worker which was launched but has not claimed the cluster yet.
        with self.jobs.lock:
            if self.jobs.active():
                raise cluster.Busy("An experiment is active. Pause it and wait for it to stop first.")
            if action == "idle-stop" and self.jobs.queue():
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
            with self.lock:
                self.busy = False
                self.idle_since = time.monotonic()
            claim.close()

    def idle(self) -> None:
        """Called by the queue supervisor, even without an open browser."""
        now = time.monotonic()
        with self.jobs.lock:
            if self.jobs.active() or self.jobs.queue() or cluster.holder():
                self.idle_since = now
                return
            minutes = idle_minutes()
            if cluster.manually_stopped() or not minutes or now - self.idle_since < minutes * 60:
                return
        try:
            self.request("idle-stop")  # rechecks the queue and claims the cluster atomically
        except cluster.Busy:
            pass
        finally:
            self.idle_since = now
