"""Tests that write work on copies in a temporary directory, never on the
files of the repository."""

import shutil

import pytest

from lab import cluster, config, results, scenario, topology
from lab.config import ROOT

SOURCES = (("topologies", topology, ROOT / "gobgp-lab" / "topologies"),
           ("scenarios", scenario, ROOT / "scenarios"),
           ("experiments", config, ROOT / "experiments"))


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

    monkeypatch.setattr(web, "EXPERIMENTS", lab_files / "experiments")
    monkeypatch.setattr(web.jobs, "supervise", lambda: None)  # never start experiments
    monkeypatch.setattr(web, "warm_up", lambda: None)  # analyses on demand only
    monkeypatch.setattr(web, "watch_updates", lambda: None)  # no GitHub in the tests
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
