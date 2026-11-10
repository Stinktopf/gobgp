"""lab pull: a result or a search of another lab on this machine, so that the local web interface and the
figures of a paper see the real data. The address, a token that only downloads and the fingerprint of the
lab's certificate come from the MCP tool download of that lab. Nothing of them is kept."""

import io
import json
import shutil
import tarfile
import tempfile
import warnings
from pathlib import Path
from urllib.parse import unquote, urlsplit

import requests
from requests.adapters import HTTPAdapter

from . import results, simulation

RESULT, SEARCH = "/api/v1/results/", "/api/v1/simulation/searches/"


class Pinned(HTTPAdapter):
    """Trusts exactly the certificate of this fingerprint, as the lab signs its own."""

    def __init__(self, fingerprint: str):
        self.fingerprint = fingerprint.replace(":", "").lower()
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self.fingerprint
        super().init_poolmanager(*args, **kwargs)


def target(url: str) -> tuple[str, str]:
    """What a download address of the lab fetches: ("result", name) or ("search", id)."""
    path = unquote(urlsplit(url).path)
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("The address needs http:// or https://.")
    if path.startswith(RESULT) and path.endswith("/archive"):
        kind, name = "result", path[len(RESULT):-len("/archive")]
    elif path.startswith(SEARCH) and path.endswith("/file"):
        kind, name = "search", path[len(SEARCH):-len("/file")]
    else:
        raise ValueError("This is no download address of the lab. The MCP tool download gives one.")
    if not name or name.startswith(".") or Path(name).name != name or (kind == "search" and not name.isdigit()):
        raise ValueError(f"No {kind} is called {name!r}.")
    return kind, name


def _get(url: str, token: str, fingerprint: str | None) -> requests.Response:
    session = requests.Session()
    if url.startswith("https"):
        if not fingerprint:
            raise ValueError("Over HTTPS the fingerprint of the lab's certificate is needed.")
        session.mount("https://", Pinned(fingerprint))
        session.verify = False  # the fingerprint stands in for a signature
    with warnings.catch_warnings():  # unverified only in name: the adapter checks the fingerprint
        warnings.simplefilter("ignore")
        answer = session.get(url, headers={"authorization": f"Bearer {token}"}, timeout=600, stream=True)
    if answer.status_code == 404:
        raise LookupError(answer.json().get("detail", "Not found."))
    answer.raise_for_status()
    return answer


def pull(url: str, token: str, fingerprint: str | None = None, force: bool = False) -> Path:
    """Fetches what the address names into this lab and returns where it went. One of the same name is
    replaced only with force."""
    kind, name = target(url)
    if kind == "search":
        where = simulation.folder() / f"{name}.json"
        if where.exists() and not force:
            raise FileExistsError(f"Search {name} is here already. --force replaces it.")
        with _get(url, token, fingerprint) as answer:
            content = answer.content
        json.loads(content)  # whole, or not at all
        where.parent.mkdir(parents=True, exist_ok=True)
        where.write_bytes(content)
        return where
    where = results.PRIVATE / name
    if (where.exists() or results.Dataset.find(name)) and not force:
        raise FileExistsError(f"Result {name} is here already. --force replaces it.")
    with tempfile.TemporaryDirectory(prefix="obgp-pull-") as tmp:
        archive = Path(tmp) / "result.tar.gz"
        with _get(url, token, fingerprint) as answer, archive.open("wb") as out:
            for chunk in answer.iter_content(1 << 20):
                out.write(chunk)
        with tarfile.open(archive) as tar:
            if any(Path(m.name).parts[:1] != (name,) for m in tar.getmembers()):
                raise ValueError("The archive holds more than the result.")
            tar.extractall(tmp, filter="data")
        if not (Path(tmp) / name / "dataset.json").exists():
            raise ValueError("The archive holds no result.")
        shutil.rmtree(where, ignore_errors=True)
        where.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(Path(tmp) / name, where)
    return where


def archive(path: Path) -> io.BufferedRandom:
    """A result folder as a gzipped tar, in a temporary file at its start."""
    out = tempfile.TemporaryFile()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        tar.add(path, arcname=path.name)
    out.seek(0)
    return out
