"""Password login with a signed session cookie.

The password hash and the signing secret are stored in
~/.config/obgp-lab/web.json. Without one, the first start sets a random
initial password and writes it to initial-password next to it, readable
only by the lab's user; it has to be changed at the first sign-in, in
the settings or with `lab passwd`. Changing the password invalidates all
sessions.
"""

import hashlib
import hmac
import json
import os
import secrets
import time

from .. import config

COOKIE = "lab_session"
MAX_AGE = 7 * 24 * 3600


def file():
    return config.SETTINGS / "web.json"


def initial_file():
    return config.SETTINGS / "initial-password"


def set_password(password: str, initial: bool = False) -> None:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    settings = load() or {}
    settings.update(password=f"scrypt${salt.hex()}${digest.hex()}", secret=settings.get("secret") or secrets.token_hex(32),
                    initial=initial)
    file().parent.mkdir(parents=True, exist_ok=True)
    file().touch(mode=0o600)
    file().write_text(json.dumps(settings, indent=2))
    if not initial:
        initial_file().unlink(missing_ok=True)


def initialize() -> str | None:
    """Sets a random initial password if there is none; its file, or None."""
    if load() is not None:
        return None
    password = secrets.token_urlsafe(12)
    set_password(password, initial=True)
    file = initial_file()
    file.touch(mode=0o600)
    file.chmod(0o600)
    file.write_text(password + "\n")
    return str(file)


def must_change(settings: dict | None) -> bool:
    return bool(settings and settings.get("initial"))


def load() -> dict | None:
    try:
        return json.loads(file().read_text())
    except FileNotFoundError:
        return None


def check_password(password: str, settings: dict) -> bool:
    _, salt, digest = settings["password"].split("$")
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate.hex(), digest)


def _sign(expires: int, settings: dict) -> str:
    message = f"{expires}.{settings['password']}".encode()
    return hmac.new(bytes.fromhex(settings["secret"]), message, hashlib.sha256).hexdigest()


def issue(settings: dict) -> str:
    expires = int(time.time()) + MAX_AGE
    return f"{expires}.{_sign(expires, settings)}"


def valid(token: str | None, settings: dict) -> bool:
    try:
        expires, signature = token.split(".")
        return int(expires) > time.time() and hmac.compare_digest(signature, _sign(int(expires), settings))
    except (AttributeError, ValueError):
        return False


class Throttle:
    """Slows down password guessing: failed attempts lock a client out for a growing time."""

    def __init__(self) -> None:
        self.failures: dict[str, tuple[int, float]] = {}

    def locked(self, client: str) -> float:
        _, until = self.failures.get(client, (0, 0))
        return max(0.0, until - time.time())

    def failed(self, client: str) -> None:
        now = time.time()
        # Forget clients whose lock ran out long ago.
        self.failures = {c: f for c, f in self.failures.items() if f[1] > now - 3600}
        count, _ = self.failures.get(client, (0, 0))
        self.failures[client] = (count + 1, now + min(2 ** count, 300))

    def succeeded(self, client: str) -> None:
        self.failures.pop(client, None)
