"""Actions that wait for a person: with a token that asks first, an agent's
control action only proposes itself, and runs once it is approved in the
settings. Kept in ~/.config/obgp-lab/pending.json, decided ones for a week."""

import json
import os
import secrets
import time

from .. import config

KEPT_S = 7 * 86400


def file():
    return config.SETTINGS / "pending.json"


def load() -> list[dict]:
    try:
        return json.loads(file().read_text())
    except (OSError, ValueError):
        return []


def _save(entries: list[dict]) -> None:
    now = time.time()
    entries = [e for e in entries if e["state"] == "waiting" or now - e.get("decided", now) < KEPT_S]
    file().parent.mkdir(parents=True, exist_ok=True)
    tmp = file().with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(file())


def propose(token: dict, call: str, args: dict, text: str, details: str = "", why: str = "", fingerprint: str | None = None) -> dict:
    """A new action that waits, of the agent with this token: details tell its extent, why it waits
    though the token acts at once, fingerprint the file it acts on, so that a change of the file since
    makes the approval fail."""
    entry = {"id": secrets.token_hex(4), "token": token["id"], "by": token["name"], "call": call, "args": args,
             "text": text, "details": details, "why": why, "fingerprint": fingerprint, "created": int(time.time()), "state": "waiting"}
    _save([*load(), entry])
    return entry


def get(action_id: str) -> dict | None:
    return next((e for e in load() if e["id"] == action_id), None)


def head() -> str | None:
    """The commit the lab runs, which an update binds to."""
    from .. import update

    try:
        return update.git("rev-parse", "HEAD")
    except update.UpdateError:
        return None


def waiting() -> list[dict]:
    """The actions that wait. An update asked for before the lab moved to another commit is obsolete:
    it is closed, not shown."""
    entries = [e for e in load() if e["state"] == "waiting"]
    if stale := [e for e in entries if e["call"] == "update_lab" and e.get("fingerprint") != head()]:
        for e in stale:
            settle(e["id"], "obsolete", "the lab moved to another commit since")
        entries = [e for e in entries if e not in stale]
    return entries


def settle(action_id: str, state: str, outcome: str) -> None:
    """Notes how an action ended: done, failed or rejected."""
    entries = load()
    for e in entries:
        if e["id"] == action_id:
            e.update(state=state, outcome=outcome, decided=int(time.time()))
    _save(entries)
