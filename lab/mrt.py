"""What the Internet did to prefixes in a window of time, from the MRT
update files of RIPE RIS (data.ris.ripe.net), as seen by one peer of a
collector, the vantage point: when a prefix became reachable from an
origin AS, and when it stopped to be.

Only BGP4MP messages with four-byte ASNs and IPv4 prefixes outside of
MP_REACH are read, which is how RIS records IPv4. The vantage point is
the IPv4 peer that sent the most messages in the first file, usually one
with a full table. While its session is down, nothing is known; prefixes then
keep their state.
"""

import gzip
import json
import os
import re
import struct
import urllib.request
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

BASE_URL = "https://data.ris.ripe.net/"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "obgp-lab" / "ris"
STEP = timedelta(minutes=5)  # RIS writes a file every five minutes
BGP4MP, MESSAGE_AS4, STATE_CHANGE_AS4 = 16, 4, 5
UPDATE, AS_PATH, AS_SEQUENCE = 2, 2, 2


def window(start: str, minutes: int) -> tuple[datetime, list[datetime]]:
    """The start in UTC, rounded down to five minutes, and the times of its files."""
    try:
        t = datetime.fromisoformat(start.strip().replace("T", " ")).replace(tzinfo=UTC, second=0, microsecond=0)
    except ValueError:
        raise ValueError(f"not a time: {start!r}, e.g. 2026-09-01 12:00") from None
    t -= timedelta(minutes=t.minute % 5)
    if t + timedelta(minutes=minutes) > datetime.now(UTC) - timedelta(minutes=15):
        raise ValueError("RIS has no data of that window yet: choose one that ended a while ago.")
    return t, [t + i * STEP for i in range((minutes + 4) // 5)]


def download(collector: str, t: datetime) -> Path:
    """An update file of a collector, downloaded once."""
    if not re.fullmatch(r"rrc\d\d", collector):
        raise ValueError(f"no RIS collector {collector!r}, e.g. rrc00")
    name = f"updates.{t:%Y%m%d.%H%M}.gz"
    path = CACHE / collector / name
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(f"{BASE_URL}{collector}/{t:%Y.%m}/{name}", timeout=120) as response:
            part = path.with_suffix(".part")
            part.write_bytes(response.read(300_000_000))
            part.replace(path)
    return path


def records(path: Path):
    """The BGP4MP records of a file with four-byte ASNs: time, subtype, peer and the rest."""
    try:
        data = gzip.open(path).read()
    except (OSError, EOFError) as e:
        raise ValueError(f"{path.name} is damaged: {e}") from None
    i = 0
    while i + 12 <= len(data):
        ts, kind, subtype, length = struct.unpack_from("!IHHI", data, i)
        body = data[i + 12:i + 12 + length]
        i += 12 + length
        if kind != BGP4MP or subtype not in (MESSAGE_AS4, STATE_CHANGE_AS4) or len(body) < 12:
            continue
        afi = struct.unpack_from("!H", body, 10)[0]
        size = 4 if afi == 1 else 16
        peer = bytes(body[12:12 + size])
        yield ts, subtype, peer, body[12 + 2 * size:]


def prefixes(data: bytes, i: int, end: int) -> list[str]:
    out = []
    while i < end:
        length = data[i]
        n = (length + 7) // 8
        raw = data[i + 1:i + 1 + n] + bytes(4 - n)
        out.append(f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}/{length}")
        i += 1 + n
    return out


def update(message: bytes) -> tuple[list[str], list[str], int | None]:
    """The withdrawn prefixes, the announced ones and their origin of a BGP UPDATE."""
    if len(message) < 23 or message[18] != UPDATE:
        return [], [], None
    withdrawn_len = struct.unpack_from("!H", message, 19)[0]
    withdrawn = prefixes(message, 21, 21 + withdrawn_len)
    i = 21 + withdrawn_len
    attrs_len = struct.unpack_from("!H", message, i)[0]
    i, end = i + 2, i + 2 + attrs_len
    origin = None
    while i < end:
        flags, kind = message[i], message[i + 1]
        if flags & 0x10:
            length, i = struct.unpack_from("!H", message, i + 2)[0], i + 4
        else:
            length, i = message[i + 2], i + 3
        if kind == AS_PATH:
            j, last = i, None
            while j < i + length:
                segment, count = message[j], message[j + 1]
                asns = struct.unpack_from(f"!{count}I", message, j + 2)
                last = asns[-1] if segment == AS_SEQUENCE and asns else None
                j += 2 + 4 * count
            origin = last
        i += length
    return withdrawn, prefixes(message, end, len(message)), origin


def events(collector: str, start: str, minutes: int) -> dict:
    """Seconds into the window, prefix and origin (0 for gone) of every change
    the vantage point saw, cached once read."""
    t0, times = window(start, minutes)
    cache = CACHE / collector / f"events-{t0:%Y%m%d-%H%M}-{minutes}.json"
    if cache.exists():
        return json.loads(cache.read_text())
    files = [download(collector, t) for t in times]
    # IPv4 peers only: the others send IPv4 in MP_REACH, if at all.
    counts = Counter(peer for _, subtype, peer, _ in records(files[0]) if subtype == MESSAGE_AS4 and len(peer) == 4)
    if not counts:
        raise ValueError(f"{collector} recorded no updates at {t0:%Y-%m-%d %H:%M}")
    vantage = counts.most_common(1)[0][0]
    state: dict[str, int] = {}
    changes = []
    end = t0.timestamp() + minutes * 60
    for f in files:
        for ts, subtype, peer, message in records(f):
            if peer != vantage or not t0.timestamp() <= ts < end or subtype != MESSAGE_AS4:
                continue
            withdrawn, announced, origin = update(message)
            for p in withdrawn:
                if state.get(p, 0):
                    state[p] = 0
                    changes.append([round(ts - t0.timestamp()), p, 0])
            for p in announced:
                if origin and state.get(p) != origin:
                    state[p] = origin
                    changes.append([round(ts - t0.timestamp()), p, origin])
    out = {"collector": collector, "vantage": ".".join(map(str, vantage)),
           "start": f"{t0:%Y-%m-%d %H:%M}", "minutes": minutes, "changes": changes}
    cache.write_text(json.dumps(out))
    return out
