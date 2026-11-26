import gzip
import hashlib
import io
import json
import lzma
import shutil
import tarfile

import pytest

from lab import analysis, archive
from lab.results import Dataset


def finished(lab_files, name="r"):
    """A finished private result of one run, with gzip samples and caches."""
    from lab import results
    path = results.PRIVATE / name
    run = path / "t" / "v" / "s" / "1"
    run.mkdir(parents=True)
    (run / "samples.csv.gz").write_bytes(gzip.compress(CSV))
    (run / "run.json").write_text("{}")
    (run / "series.json").write_text("{}")
    (path / "analysis.json").write_text("{}")
    (path / "dataset.json").write_text(json.dumps({"commits": {"v": "abc"}}))
    d = Dataset(path)
    d.__class__ = type("D", (Dataset,), {"status": {"state": "finished"}, "experiment": type("E", (), {"model_dump": lambda self, mode=None: {"name": "e"}})(),
                                          "keys": lambda self: [type("K", (), {"path": "t/v/s/1"})()], "is_done": lambda self, k: True})
    return d


CSV = b"t,router,destinations\n0.0,a,1\n1.0,a,2\n" * 50


def test_an_archived_result_keeps_every_sample_in_xz_with_a_manifest_and_stays_as_it_is(lab_files, monkeypatch):
    monkeypatch.setattr(analysis, "summary", lambda d: [{"variant": "v"}])
    monkeypatch.setattr("lab.problems.verdict", lambda d: {"passed": True})
    d = finished(lab_files)
    assert d.state == "private" and d.kept() is None
    m = archive.freeze(d)
    run = d.path / "t/v/s/1"
    assert d.state == "archived" and not (run / "samples.csv.gz").exists() and lzma.decompress((run / "samples.csv.xz").read_bytes()) == CSV
    assert not (run / "series.json").exists() and not (d.path / "analysis.json").exists()
    assert m["commits"] == {"v": "abc"} and "t/v/s/1/samples.csv.xz" in m["files"] and archive.check(d.path) == []
    (d.path / "analysis.json").write_text("{}")  # a cache the lab makes again is no change
    assert archive.check(d.path) == []
    with pytest.raises(ValueError, match="Unarchive"):
        d.update(verdict="changed")
    with pytest.raises(ValueError, match="Unarchive"):
        d.delete()
    with pytest.raises(ValueError, match="only a private result"):
        archive.freeze(d)
    (run / "run.json").write_text('{"changed": 1}')
    (run / "extra").write_text("")
    assert archive.check(d.path) == ["t/v/s/1/run.json changed", "t/v/s/1/extra was added"]
    (run / "run.json").write_text("{}")
    (run / "extra").unlink()
    archive.unfreeze(d)
    assert d.state == "private" and d.kept() is None
    archive.freeze(d)  # again, with the samples xz already
    d.set_zenodo({"id": 7})
    with pytest.raises(ValueError, match="stays archived"):
        archive.unfreeze(d)
    assert "on Zenodo" in d.kept()


def test_the_lab_fetches_an_archived_result_of_the_index_checked_against_the_index_and_its_manifest(lab_files, monkeypatch):
    from lab import results, zenodo
    monkeypatch.setattr(analysis, "summary", lambda d: [])
    monkeypatch.setattr("lab.problems.verdict", lambda d: {"passed": True})
    d = finished(lab_files)
    archive.freeze(d)
    tar = archive.pack(d)
    blob = tar.read_bytes()
    line = {"name": "r", "doi": "10.5281/zenodo.7", "use": "real", "record": 7, "file": "r.tar", "bytes": len(blob), "sha256": archive.digest(tar)}
    d.set_zenodo({"id": 7, "use": "real", "doi": line["doi"], "file": "r.tar", "bytes": len(blob), "sha256": line["sha256"]})
    assert archive.entry(d) == line
    results.INDEX.parent.mkdir(parents=True, exist_ok=True)
    results.INDEX.write_text(json.dumps([line]))
    assert archive.index() == [line]
    with pytest.raises(ValueError, match="in this lab already"):
        archive.fetch(line)
    shutil.rmtree(d.path)
    asked = []
    monkeypatch.setattr(zenodo, "download", lambda line, to: asked.append(line["record"]) or to.write_bytes(blob))
    got = archive.fetch(line)
    assert asked == [7] and got.state == "archived" and got.zenodo["doi"] == line["doi"] and archive.check(got.path) == []
    assert got.zenodo["url"] == "https://zenodo.org/records/7"
    shutil.rmtree(got.path)
    monkeypatch.setattr(zenodo, "download", lambda line, to: to.write_bytes(changed(blob)))  # a sample changed on the way
    with pytest.raises(ValueError, match="does not match its manifest"):
        archive.fetch(line)
    assert results.Dataset.find("r") is None


def changed(blob: bytes) -> bytes:
    """The same archive with one sample changed."""
    src, out = io.BytesIO(blob), io.BytesIO()
    with tarfile.open(fileobj=src) as old, tarfile.open(fileobj=out, mode="w") as new:
        for m in old.getmembers():
            data = old.extractfile(m).read() if m.isfile() else None
            if m.name.endswith("samples.csv.xz"):
                data = lzma.compress(b"t,router,destinations\n0.0,a,9\n")
                m.size = len(data)
            new.addfile(m, io.BytesIO(data) if data is not None else None)
    return out.getvalue()


def test_zenodo_downloads_only_what_the_index_names(tmp_path, monkeypatch):
    from lab import zenodo
    line = {"name": "r", "use": "real", "record": 7, "file": "r.tar", "bytes": 3, "sha256": hashlib.sha256(b"tar").hexdigest()}
    urls = []

    class Answer:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def raise_for_status(self):
            pass

        def iter_content(self, n):
            yield self.body
    monkeypatch.setattr(zenodo.requests, "get", lambda url, stream, timeout: urls.append(url) or Answer(body))
    body = b"tar"
    zenodo.download(line, tmp_path / "a")
    assert urls == ["https://zenodo.org/api/records/7/files/r.tar/content"] and (tmp_path / "a").read_bytes() == b"tar"
    body = b"tan"
    with pytest.raises(ValueError, match="differs from the index"):
        zenodo.download(line, tmp_path / "b")
    with pytest.raises(ValueError, match="no file name"):
        zenodo.download({**line, "file": "../x"}, tmp_path / "c")
    with pytest.raises(ValueError, match="sandbox or real"):
        zenodo.download({**line, "use": "elsewhere"}, tmp_path / "d")


def test_the_lab_reads_the_samples_of_an_archived_run(tmp_path):
    from lab.results import RunKey
    key = RunKey("t", "v", "s", 1)
    folder = tmp_path / key.path
    folder.mkdir(parents=True)
    (folder / "samples.csv.xz").write_bytes(lzma.compress(b"t,router,destinations\n0.5,a,3\n"))
    d = object.__new__(Dataset)
    d.path = tmp_path
    assert d.samples(key) == [{"t": 0.5, "router": "a", "destinations": 3.0}]


def test_zenodo_tokens_are_kept_private_never_shown_and_one_of_them_is_used(tmp_path, monkeypatch):
    import stat
    from lab import config, zenodo
    monkeypatch.setattr(config, "SETTINGS", tmp_path)
    zenodo.save({"sandbox": "s3cret"})
    assert stat.S_IMODE((tmp_path / "zenodo.json").stat().st_mode) == 0o600
    assert zenodo.state() == {"sandbox": True, "real": False} and "s3cret" not in str(zenodo.state())
    sent = []

    class Answer:
        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            pass

        def json(self):
            return self.data
    monkeypatch.setattr(zenodo.requests, "post", lambda url, json, headers, timeout: sent.append(("post", url, headers)) or
                        Answer({"id": 7, "links": {"bucket": "https://b/7", "html": "https://sandbox.zenodo.org/deposit/7"}}))
    monkeypatch.setattr(zenodo.requests, "put", lambda url, headers, timeout, data=None, json=None: sent.append(("put", url, json)) or Answer({}))
    tar = tmp_path / "r.tar"
    tar.write_bytes(b"tar")
    out = zenodo.draft(tar, "R", "about R", ["BGP"], "sandbox")
    assert out == {"id": 7, "url": "https://sandbox.zenodo.org/deposit/7", "use": "sandbox", "file": "r.tar", "bytes": 3,
                   "sha256": hashlib.sha256(b"tar").hexdigest()}
    assert sent[0][1] == "https://sandbox.zenodo.org/api/deposit/depositions" and sent[0][2] == {"Authorization": "Bearer s3cret"}
    assert sent[1][1] == "https://b/7/r.tar" and sent[2][2]["metadata"]["upload_type"] == "dataset"
    with pytest.raises(ValueError, match="No Zenodo token for real"):
        zenodo.draft(tar, "R", "", [], "real")
