"""Tests that write work on copies in a temporary directory, never on the
files of the repository."""

import shutil
from collections import deque

import pytest

from lab import cluster, config, host, results, scenario, topology
from lab.config import ROOT

SOURCES = (("topologies", topology, ROOT / "gobgp-lab" / "topologies"),
           ("scenarios", scenario, ROOT / "scenarios"),
           ("experiments", config, ROOT / "experiments"))


@pytest.fixture(autouse=True)
def own_crontab(tmp_path, monkeypatch):
    """A crontab of the test's own: no test touches the user's real one."""
    fake = tmp_path / "bin" / "crontab"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\nf="$(dirname "$0")/crontab.txt"\n'
                    'case "$1" in\n-l) [ -f "$f" ] && exec cat "$f"; echo "no crontab for test" >&2; exit 1 ;;\n-) cat > "$f" ;;\nesac\n')
    fake.chmod(0o755)
    monkeypatch.setenv("OBGP_CRONTAB", str(fake))
    return fake.parent / "crontab.txt"


@pytest.fixture(autouse=True)
def quiet_host(monkeypatch):
    """No test asks the real disk or Docker how full they are or whether
    Docker runs, nor starts the thread that watches the host: a host without
    a GPU, whose Docker runs."""
    monkeypatch.setattr(host, "docker_root", lambda: config.ROOT)
    monkeypatch.setattr(host, "docker_running", lambda: True)
    # The charts of the host read its watch: one without a thread, which would
    # ask Docker every second for the rest of the tests.
    monkeypatch.setattr(host, "_watching", lambda: type("Watch", (), {"state": {}, "history": deque()})())
    monkeypatch.setattr(host.shutil, "disk_usage", lambda path: shutil._ntuple_diskusage(1000 * 2**30, 0, 1000 * 2**30))
    monkeypatch.setattr(host, "now", lambda: {"busy": 0.1, "lab": 0.0, "others": 0.1, "threads": 16, "load": 1.0, "memory_mb": 4096.0,
                                              "total_mb": 32768.0, "lab_mb": 0.0, "gpus": [], "gpu_error": False})


@pytest.fixture(scope="session")
def public(tmp_path_factory):
    """A copy of the public results, which analysis writes caches into."""
    path = tmp_path_factory.mktemp("public")
    shutil.copytree(results.PUBLIC, path, dirs_exist_ok=True)
    return path


@pytest.fixture
def lab_files(tmp_path, monkeypatch, public):
    """Copies of the topologies, scenarios and experiments, the public
    results, empty private results, and settings of their own."""
    for name, module, source in SOURCES:
        shutil.copytree(source, tmp_path / name)
        monkeypatch.setattr(module, "DIRECTORY", tmp_path / name)
    monkeypatch.setattr(results, "PUBLIC", public)
    monkeypatch.setattr(results, "PRIVATE", tmp_path / "results" / "private")
    monkeypatch.setattr(config, "SETTINGS", tmp_path / "settings")
    monkeypatch.setattr(cluster, "lock_file", lambda: tmp_path / "cluster.lock")
    return tmp_path


@pytest.fixture
def app(lab_files, monkeypatch):
    from lab.web import app as web

    monkeypatch.setattr("lab.web.context.EXPERIMENTS", lab_files / "experiments")
    monkeypatch.setattr(web.jobs, "supervise", lambda: None)  # never start experiments
    monkeypatch.setattr(web, "warm_up", lambda: None)  # analyses on demand only
    monkeypatch.setattr(web, "watch_updates", lambda: None)  # no GitHub in the tests
    monkeypatch.setattr(cluster.Cluster, "_profile", lambda self: None)  # no minikube either: no cluster yet
    return web.create_app()


@pytest.fixture
def client(app):
    """A signed-in client of the web interface."""
    from fastapi.testclient import TestClient

    from lab.web import auth

    auth.set_password("test-password")
    c = TestClient(app)
    c.cookies.set(auth.COOKIE, auth.issue(auth.load()))
    return c
