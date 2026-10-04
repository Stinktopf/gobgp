"""The queue of results, run one at a time by a supervised worker process.

The worker is `lab resume <result>` in its own session, so it keeps
running when the web server restarts. A result whose worker vanished
while running, e.g. after a reboot, is resumed automatically; one whose
worker fails before it starts is marked failed instead of retried.
Whether a result runs is told by the cluster lock, which its runner holds.
"""

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time

from .. import cluster
from ..results import Dataset, pause_file, queue_file, queued, write_atomic

log = logging.getLogger("lab")


class Jobs:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.worker: subprocess.Popen | None = None
        self.cluster_control = None

    def queue(self) -> list[str]:
        return queued()  # a damaged file counts as empty

    def _save(self, names: list[str]) -> None:
        queue_file().parent.mkdir(parents=True, exist_ok=True)
        write_atomic(queue_file(), json.dumps(names))

    def enqueue(self, name: str) -> None:
        with self.lock:
            dataset = Dataset.find(name)
            dataset.write_status({**dataset.status, "state": "queued"})
            if name not in (queue := self.queue()):
                self._save(queue + [name])

    def reorder(self, names: list[str]) -> None:
        """Puts the waiting datasets in the given order; the running one stays first."""
        with self.lock:
            queue = self.queue()
            active = self.active()
            first = [queue[0]] if active and queue and queue[0] == active.name else []
            waiting = [n for n in queue if n not in first]
            ordered = [n for n in names if n in waiting] + [n for n in waiting if n not in names]
            self._save(first + ordered)

    def paused(self) -> bool:
        return pause_file().exists()

    def pause(self) -> None:
        """Pauses the queue: the running result stops after its phase and
        stays first, and nothing new starts until the queue resumes."""
        with self.lock:
            pause_file().parent.mkdir(parents=True, exist_ok=True)
            pause_file().touch()
            if running := cluster.holding():
                if running[0] == "__maintenance__":
                    return
                if running[0] not in (queue := self.queue()):  # started on the command line
                    self._save([running[0]] + queue)
                os.kill(running[1], signal.SIGTERM)  # the runner stops and writes "stopped"
            elif self.worker and self.worker.poll() is None:
                self.worker.terminate()  # started, but not yet running; it stays queued
                self.worker.wait(timeout=10)

    def resume_queue(self) -> None:
        """Goes on in the same order, with the runs the paused result still misses."""
        with self.lock:
            if self.active():  # still stopping
                return
            for name in self.queue():
                if (dataset := Dataset.find(name)) and dataset.status.get("state") == "stopped":
                    dataset.write_status({**dataset.status, "state": "queued"})
            pause_file().unlink(missing_ok=True)

    def stop_all(self) -> None:
        """Cancels every result of the queue and stops the running one. Their runs are kept."""
        names = self.queue()
        active = self.active()
        if active and active.name not in names:
            names = [active.name] + names
        for name in reversed(names):  # the running one last, so that none of the others starts
            self.stop(name)
        pause_file().unlink(missing_ok=True)

    def active(self) -> Dataset | None:
        """The dataset that is running right now, started here or on the command line."""
        if self.worker and self.worker.poll() is None:
            return Dataset.find(self.worker.args[-1])
        name = cluster.holder()
        return Dataset.find(name) if name else None

    def stop(self, name: str) -> None:
        """Stops a result; it finishes the current phase and can be resumed later."""
        with self.lock:
            self._save([n for n in self.queue() if n != name])
            dataset = Dataset.find(name)
            if not dataset:
                return
            state, running = dataset.status.get("state"), cluster.holding()
            if running and running[0] == name:
                os.kill(running[1], signal.SIGTERM)  # the runner stops and writes "stopped"
                return
            if self.worker and self.worker.poll() is None and self.worker.args[-1] == name:
                self.worker.terminate()  # started, but not yet running
                self.worker.wait(timeout=10)
            if state in ("queued", "running"):  # never started, or its worker is gone
                dataset.write_status({**dataset.status, "state": "stopped"})

    def supervise(self) -> None:
        while True:
            try:
                with self.lock:
                    self._step()
                if self.cluster_control:
                    self.cluster_control.idle()
            except Exception:  # the queue must go on; the next step may succeed
                log.exception("supervising the queue")
            time.sleep(2)

    def _step(self) -> None:
        if self.active() or cluster.holder():
            return
        self._ended()
        if cluster.manually_stopped():
            return
        if self.paused() and not self.queue():  # nothing left to hold back
            pause_file().unlink(missing_ok=True)
        if self.paused():
            return
        for name in self.queue():
            dataset = Dataset.find(name)
            if not dataset or dataset.status["state"] in ("finished", "failed", "stopped"):
                # Done, or ended for a reason that needs attention.
                self._save([n for n in self.queue() if n != name])
                continue
            # Queued, or running without a worker, e.g. after a reboot.
            with open(dataset.path / "worker.log", "a") as out:  # the worker keeps its own copy
                self.worker = subprocess.Popen(
                    [sys.executable, "-m", "lab.cli", "resume", name],
                    stdout=out, stderr=subprocess.STDOUT, start_new_session=True,
                )
            return

    def _ended(self) -> None:
        """Marks the result of a worker that failed before its runner took over as failed."""
        worker, self.worker = self.worker, None
        if not worker or worker.poll() is None or worker.returncode in (0, cluster.BUSY):
            return
        dataset = Dataset.find(worker.args[-1])
        if dataset and dataset.status.get("state") == "queued":
            error = f"the worker ended with code {worker.returncode} before it started; see worker.log"
            dataset.write_status({**dataset.status, "state": "failed", "error": error})
            log.error("%s: %s", dataset.name, error)
