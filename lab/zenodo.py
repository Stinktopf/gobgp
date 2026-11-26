"""Archived results on Zenodo: uploads as drafts, which a person completes and
publishes on zenodo.org since a DOI cannot be taken back, and downloads of
published records, which need no token.

Two tokens, kept in the settings of this installation readable by its owner
only: one of sandbox.zenodo.org to try, one of zenodo.org. Each upload names
which it uses. A token needs the scopes deposit:write and deposit:actions.
Tokens are never shown, logged or sent anywhere but to Zenodo.
"""

import hashlib
import json
from pathlib import Path

import requests

from . import config
from .archive import digest

HOSTS = {"sandbox": "https://sandbox.zenodo.org", "real": "https://zenodo.org"}


def file() -> Path:
    return config.SETTINGS / "zenodo.json"


def load() -> dict:
    try:
        return json.loads(file().read_text())
    except (OSError, ValueError):
        return {}


def save(settings: dict) -> None:
    file().parent.mkdir(parents=True, exist_ok=True)
    file().touch(mode=0o600)
    file().chmod(0o600)
    file().write_text(json.dumps(settings, indent=2))


def state() -> dict:
    """Which tokens are set, never a token."""
    s = load()
    return {use: bool(s.get(use)) for use in HOSTS}


def draft(archive: Path, title: str, description: str, keywords: list[str], use: str) -> dict:
    """A new draft on Zenodo, sandbox or real, with the archive in it: its id, the page to complete
    and publish it on, and which Zenodo. Raises ValueError with Zenodo's answer."""
    if use not in HOSTS:
        raise ValueError("Zenodo is sandbox or real.")
    if not (token := load().get(use)):
        raise ValueError(f"No Zenodo token for {use}: set it in the settings.")
    host = HOSTS[use]
    auth = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.post(f"{host}/api/deposit/depositions", json={}, headers=auth, timeout=60)
        r.raise_for_status()
        deposition = r.json()
        with archive.open("rb") as f:
            up = requests.put(f"{deposition['links']['bucket']}/{archive.name}", data=f, headers=auth, timeout=3600)
        up.raise_for_status()
        meta = {"metadata": {"title": title, "upload_type": "dataset", "description": description, "keywords": keywords}}
        m = requests.put(f"{host}/api/deposit/depositions/{deposition['id']}", json=meta, headers=auth, timeout=60)
        m.raise_for_status()
    except requests.RequestException as e:
        answer = getattr(getattr(e, "response", None), "text", "") or str(e)
        raise ValueError(f"Zenodo ({use}): {answer[:300]}") from None
    return {"id": deposition["id"], "url": deposition["links"]["html"], "use": use, "file": archive.name,
            "bytes": archive.stat().st_size, "sha256": digest(archive)}


def record_url(line: dict) -> str:
    return f"{HOSTS[line['use']]}/records/{int(line['record'])}"


def download(line: dict, to: Path) -> None:
    """The archive of a published record into a file, checked against the size and
    digest the index names. Raises ValueError when it differs or Zenodo fails."""
    if line.get("use") not in HOSTS:
        raise ValueError("Zenodo is sandbox or real.")
    if Path(line["file"]).name != line["file"]:
        raise ValueError(f"{line['file']} is no file name")
    url = f"{HOSTS[line['use']]}/api/records/{int(line['record'])}/files/{line['file']}/content"
    h, size = hashlib.sha256(), 0
    try:
        with requests.get(url, stream=True, timeout=60) as r, to.open("wb") as f:
            r.raise_for_status()
            for block in r.iter_content(1 << 20):
                size += len(block)
                if size > line["bytes"]:
                    raise ValueError(f"{line['file']} on Zenodo is larger than the index says")
                h.update(block)
                f.write(block)
    except requests.RequestException as e:
        raise ValueError(f"Zenodo ({line['use']}): {e}") from None
    if size != line["bytes"] or h.hexdigest() != line["sha256"]:
        raise ValueError(f"{line['file']} on Zenodo differs from the index")


def status(deposition: int, use: str) -> dict:
    """Whether a draft was published, and its DOI once it was."""
    token = load().get(use)
    if not token:
        raise ValueError(f"No Zenodo token for {use}.")
    try:
        r = requests.get(f"{HOSTS[use]}/api/deposit/depositions/{deposition}", headers={"Authorization": f"Bearer {token}"}, timeout=60)
        r.raise_for_status()
    except requests.RequestException as e:
        raise ValueError(f"Zenodo ({use}): {e}") from None
    d = r.json()
    return {"submitted": bool(d.get("submitted")), "doi": d.get("doi") or None, "url": d["links"].get("html")}
