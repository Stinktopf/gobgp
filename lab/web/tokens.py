"""Tokens for agents, e.g. an AI assistant over MCP or a script over the
API: made in the settings, shown once, kept only as a hash in
~/.config/obgp-lab/tokens.json. A token reads, or also controls the lab:
experiments, scenarios, the queue and updates, at once or after a person
approved each action. None deletes results or changes settings."""

import hashlib
import hmac
import json
import os
import secrets
import time
from contextvars import ContextVar

from .. import config

SCOPES = {"read": "Read results and status", "control": "Also change experiments and scenarios, run the queue, update"}
PREFIX = "obgp_"
USED_EVERY_S = 60  # how often the last use is written, at most
KEPT = 200  # lines of the activity log
caller: ContextVar[dict | None] = ContextVar("caller", default=None)  # the token of the request, set by the API and MCP


def file():
    return config.SETTINGS / "tokens.json"


def load() -> list[dict]:
    try:
        return json.loads(file().read_text())
    except (OSError, ValueError):
        return []


def _save(tokens: list[dict]) -> None:
    file().parent.mkdir(parents=True, exist_ok=True)
    tmp = file().with_suffix(".tmp")
    tmp.write_text(json.dumps(tokens, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(file())


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create(name: str, scope: str, days: int, approval: bool = False) -> tuple[str, dict]:
    """A new token and its record. days 0 never expires. With approval, each
    control action waits for a person, see approvals."""
    name = name.strip()
    if not name or len(name) > 60:
        raise ValueError("Give the token a name of up to 60 characters.")
    if scope not in SCOPES:
        raise ValueError("Choose read or control.")
    if not 0 <= days <= 365:
        raise ValueError("Choose 0 to 365 days.")
    token = PREFIX + secrets.token_urlsafe(32)
    now = int(time.time())
    entry = {"id": secrets.token_hex(4), "name": name, "scope": scope, "hash": _hash(token),
             "created": now, "expires": now + days * 86400 if days else None, "used": None, "approval": approval and scope == "control"}
    _save([*load(), entry])
    return token, entry


LIMITS = {"queue_h": 24}  # hours of estimated runs an agent may queue without a person


def limits() -> dict:
    """What agents may do without a person, from ~/.config/obgp-lab/agents.json."""
    try:
        return {**LIMITS, **json.loads((config.SETTINGS / "agents.json").read_text())}
    except (OSError, ValueError):
        return dict(LIMITS)


def save_limits(queue_h: float) -> None:
    if not 0 <= queue_h <= 24 * 30:
        raise ValueError("Choose 0 to 720 hours.")
    (config.SETTINGS / "agents.json").parent.mkdir(parents=True, exist_ok=True)
    (config.SETTINGS / "agents.json").write_text(json.dumps({"queue_h": queue_h}))


def activity_file():
    return config.SETTINGS / "agents.log"


def record(action: str) -> None:
    """Notes what the agent of this request did, the newest last."""
    token = caller.get()
    line = json.dumps({"t": int(time.time()), "token": token["name"] if token else None, "action": action})
    try:
        lines = activity_file().read_text().splitlines()[-(KEPT - 1):]
    except OSError:
        lines = []
    activity_file().parent.mkdir(parents=True, exist_ok=True)
    activity_file().write_text("\n".join([*lines, line]) + "\n")


def activity(n: int = 8) -> list[dict]:
    """The last things agents did, the newest first."""
    try:
        lines = activity_file().read_text().splitlines()
    except OSError:
        return []
    return [json.loads(line) for line in reversed(lines[-n:])]


def revoke(token_id: str) -> None:
    _save([t for t in load() if t["id"] != token_id])


def check(authorization: str | None) -> dict | None:
    """The record of a valid bearer token, None otherwise."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.startswith(PREFIX):
        return None
    digest, now = _hash(token), int(time.time())
    tokens = load()
    for entry in tokens:
        if hmac.compare_digest(entry["hash"], digest):
            if entry["expires"] and entry["expires"] < now:
                return None
            if not entry["used"] or now - entry["used"] > USED_EVERY_S:
                entry["used"] = now
                _save(tokens)
            return entry
    return None
