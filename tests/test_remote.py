"""The MCP tool download and lab pull: a result or a search of another lab, fetched with a token that only
downloads."""

import io
import json
import shutil
import tarfile

import pytest

from lab import config, remote, results, simulation
from lab.config import Experiment
from lab.web import agent, tokens

MCP = {"accept": "application/json, text/event-stream", "content-type": "application/json"}
SEARCH = "20260101000000000001"


def bearer(token):
    return {"authorization": f"Bearer {token}"}


@pytest.fixture
def lab(app, lab_files, monkeypatch):
    """This process as the other lab, reached over a test client, with a result and a search."""
    from fastapi.testclient import TestClient

    c = TestClient(app)
    results.Dataset.create(Experiment.load(config.path("lab-smoke")), "t-pull")
    simulation.folder().mkdir(parents=True, exist_ok=True)
    (simulation.folder() / f"{SEARCH}.json").write_text(json.dumps({"id": SEARCH, "state": "done", "findings": []}))
    owner, entry = tokens.create("claude", "read", 0)

    class Answer:
        def __init__(self, r):
            self.r, self.status_code, self.content = r, r.status_code, r.content

        def json(self):
            return self.r.json()

        def raise_for_status(self):
            assert self.status_code == 200, self.r.text

        def iter_content(self, size):
            yield self.content

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(remote, "_get", lambda url, token, fingerprint: Answer(
        c.get(url.removeprefix("http://lab.test"), headers=bearer(token))))
    return c, owner, entry


def download(entry, name):
    """The MCP tool, as the agent of entry reached the lab at http://lab.test."""
    who, where = tokens.caller.set(entry), agent.origin.set("http://lab.test")
    try:
        return agent.download(name)
    finally:
        tokens.caller.reset(who)
        agent.origin.reset(where)


def test_a_download_token_fetches_files_and_nothing_else(lab):
    c, owner, entry = lab
    got = download(entry, "t-pull")
    assert got["url"] == "http://lab.test/api/v1/results/t-pull/archive" and got["fingerprint"] is None
    token = got["token"]
    assert c.get("/api/v1/results/t-pull/archive", headers=bearer(token)).status_code == 200
    assert c.get(f"/api/v1/simulation/searches/{SEARCH}/file", headers=bearer(token)).status_code == 200
    assert c.get("/api/v1/results/t-pull/archive").status_code == 401
    assert c.get("/api/v1/results", headers=bearer(token)).status_code == 403
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    assert c.post("/mcp", json=call, headers={**MCP, **bearer(token)}).status_code == 403


def test_each_download_replaces_the_token_before_and_goes_with_its_owner(lab):
    c, owner, entry = lab
    first = download(entry, "t-pull")["token"]
    second = download(entry, SEARCH)["token"]
    assert tokens.check(f"Bearer {first}") is None and tokens.check(f"Bearer {second}")["scope"] == tokens.DOWNLOAD
    tokens.revoke(entry["id"])
    assert tokens.check(f"Bearer {second}") is None


def test_download_names_only_what_there_is(lab):
    c, owner, entry = lab
    for name in ("nothing", "99", "../t-pull"):
        with pytest.raises(LookupError):
            download(entry, name)


def test_mcp_offers_download_to_a_read_token(app, lab):
    from fastapi.testclient import TestClient

    c, owner, entry = lab
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    with TestClient(app) as running:
        listed = running.post("/mcp", json=call, headers={**MCP, **bearer(owner)}).json()["result"]["tools"]
    assert "download" in {t["name"] for t in listed}


def test_a_result_and_a_search_come_back_whole(lab):
    c, owner, entry = lab
    got = download(entry, "t-pull")
    with pytest.raises(FileExistsError):
        remote.pull(got["url"], got["token"])
    kept = results.PRIVATE.parent / "kept"
    shutil.copytree(results.PRIVATE / "t-pull", kept)
    assert remote.pull(got["url"], got["token"], force=True) == results.PRIVATE / "t-pull"
    assert results.Dataset.find("t-pull").experiment.name == "lab-smoke"
    assert sorted(p.name for p in (results.PRIVATE / "t-pull").iterdir()) == sorted(p.name for p in kept.iterdir())
    got = download(entry, SEARCH)
    stored = (simulation.folder() / f"{SEARCH}.json").read_text()
    assert remote.pull(got["url"], got["token"], force=True).read_text() == stored


def test_pull_takes_only_download_addresses_of_the_lab(lab_files):
    for url in ("lab.test/api/v1/results/x/archive", "http://lab.test/api/v1/results", "http://lab.test/api/v1/results/../archive",
                "http://lab.test/api/v1/simulation/searches/x/file"):
        with pytest.raises(ValueError):
            remote.target(url)
    assert remote.target("https://lab.test/api/v1/simulation/searches/7/file") == ("search", "7")
    with pytest.raises(ValueError):
        remote.pull("https://lab.test/api/v1/results/x/archive", "obgp_x")  # over HTTPS only with the fingerprint


def test_an_archive_with_more_than_the_result_is_refused(lab_files, monkeypatch):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        info = tarfile.TarInfo("../evil")
        info.size = 2
        tar.addfile(info, io.BytesIO(b"{}"))

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def iter_content(self, size):
            yield out.getvalue()

    monkeypatch.setattr(remote, "_get", lambda url, token, fingerprint: Answer())
    with pytest.raises(ValueError):
        remote.pull("http://lab.test/api/v1/results/t-evil/archive", "obgp_x")
    assert not (results.PRIVATE.parent / "evil").exists()
