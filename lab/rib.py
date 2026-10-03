"""Full tables of the Internet, the default-free zone, from the RIB dumps of
RIPE RIS (bview files, every eight hours): the IPv4 routes each peer of a
collector had, with their AS paths.

A router of a topology injects the table of the RIS peer with its AS, as
if it learned the Internet from beyond the topology. Only paths of
AS_SEQUENCE are kept: the order of OBGP is defined for those alone.
"""

import gzip
import hashlib
import json
import re
import shutil
import struct
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .mrt import BASE_URL, CACHE

TABLE_DUMP_V2, PEER_INDEX_TABLE, RIB_IPV4_UNICAST = 13, 1, 2
ORIGIN, AS_PATH, AS_SEQUENCE = 1, 2, 2
EVERY = timedelta(hours=8)  # RIS writes a bview at 00:00, 08:00 and 16:00 UTC


def snapshot(at: str) -> datetime:
    """The bview at or before a time in UTC."""
    try:
        t = datetime.fromisoformat(at.strip().replace("T", " ")).replace(tzinfo=UTC, minute=0, second=0, microsecond=0)
    except ValueError:
        raise ValueError(f"not a time: {at!r}, e.g. 2026-09-01 08:00") from None
    t -= timedelta(hours=t.hour % 8)
    if t > datetime.now(UTC) - timedelta(hours=1):
        raise ValueError("RIS has no table of that time yet: choose one a few hours ago or earlier.")
    return t


def download(collector: str, t: datetime) -> Path:
    """The bview of a collector at a time, downloaded once: some 500 MB."""
    if not re.fullmatch(r"rrc\d\d", collector):
        raise ValueError(f"no RIS collector {collector!r}, e.g. rrc00")
    name = f"bview.{t:%Y%m%d.%H%M}.gz"
    path = CACHE / collector / name
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        part = path.with_suffix(".part")
        with urllib.request.urlopen(f"{BASE_URL}{collector}/{t:%Y.%m}/{name}", timeout=120) as response, open(part, "wb") as f:
            shutil.copyfileobj(response, f, 1 << 20)
        part.replace(path)
    return path


def records(path: Path):
    """The TABLE_DUMP_V2 records of a dump, one at a time: subtype and body."""
    try:
        with gzip.open(path) as f:
            while len(head := f.read(12)) == 12:
                _, kind, subtype, length = struct.unpack("!IHHI", head)
                body = f.read(length)
                if kind == TABLE_DUMP_V2:
                    yield subtype, body
    except (OSError, EOFError, struct.error) as e:
        raise ValueError(f"{path.name} is damaged: {e}") from None


def peer_index(body: bytes) -> list[int]:
    """The ASN of every peer of a PEER_INDEX_TABLE, by index."""
    i = 4
    i += 2 + struct.unpack_from("!H", body, i)[0]  # the name of the view
    count = struct.unpack_from("!H", body, i)[0]
    i += 2
    asns = []
    for _ in range(count):
        kind = body[i]
        i += 1 + 4 + (16 if kind & 1 else 4)
        size = 4 if kind & 2 else 2
        asns.append(int.from_bytes(body[i:i + size], "big"))
        i += size
    return asns


def path_of(attrs: bytes) -> tuple[int, list[int]] | None:
    """The origin and the AS path of a route; None for paths with an AS_SET."""
    origin, path, i = 0, [], 0
    while i + 3 <= len(attrs):
        flags, kind = attrs[i], attrs[i + 1]
        if flags & 0x10:
            length, i = struct.unpack_from("!H", attrs, i + 2)[0], i + 4
        else:
            length, i = attrs[i + 2], i + 3
        value = attrs[i:i + length]
        i += length
        if kind == ORIGIN and value:
            origin = value[0]
        elif kind == AS_PATH:
            j = 0
            while j + 2 <= len(value):
                segment, count = value[j], value[j + 1]
                if segment != AS_SEQUENCE:
                    return None
                path += struct.unpack_from(f"!{count}I", value, j + 2)
                j += 2 + 4 * count
    return origin, path


def routes(body: bytes):
    """The prefix of a RIB_IPV4_UNICAST record and its entries: the index of
    the peer and its attributes."""
    bits = body[4]
    size = (bits + 7) // 8
    address = body[5:5 + size] + bytes(4 - size)
    prefix = f"{'.'.join(map(str, address))}/{bits}"
    i = 5 + size
    count = struct.unpack_from("!H", body, i)[0]
    i += 2
    entries = []
    for _ in range(count):
        peer, _, length = struct.unpack_from("!HIH", body, i)
        entries.append((peer, body[i + 8:i + 8 + length]))
        i += 8 + length
    return prefix, entries


def tables(collector: str, at: str, asns: set[int]) -> tuple[datetime, dict[int, Path]]:
    """The time of the bview, and for every AS among asns that peers with the
    collector, a file of its routes: "prefix origin AS…" a line, without the
    AS itself at the start. Of several sessions of an AS, the one with the
    most routes counts. Read from the bview once, then kept."""
    t = snapshot(at)
    folder = CACHE / collector / f"rib.{t:%Y%m%d.%H%M}"
    done = folder / "peers.json"
    if not done.exists():
        _extract(download(collector, t), folder)
    known = json.loads(done.read_text())
    return t, {a: folder / f"as{a}.gz" for a in sorted(asns) if str(a) in known}


def _extract(bview: Path, folder: Path) -> None:
    """Writes the table of every peer AS of a bview into folder, and the
    number of routes of each into peers.json."""
    folder.mkdir(parents=True, exist_ok=True)
    asns: list[int] = []
    files: dict[int, gzip.GzipFile] = {}
    counts: dict[int, int] = {}
    try:
        for subtype, body in records(bview):
            if subtype == PEER_INDEX_TABLE:
                asns = peer_index(body)
            elif subtype == RIB_IPV4_UNICAST and asns:
                prefix, entries = routes(body)
                for peer, attrs in entries:
                    if (route := path_of(attrs)) is None:
                        continue
                    origin, path = route
                    own = asns[peer]
                    while path and path[0] == own:
                        path = path[1:]
                    if not path:
                        continue
                    if peer not in files:
                        files[peer] = gzip.open(folder / f"peer{peer}.gz", "wt", compresslevel=3)
                    files[peer].write(f"{prefix} {origin} {' '.join(map(str, path))}\n")
                    counts[peer] = counts.get(peer, 0) + 1
    finally:
        for f in files.values():
            f.close()
    best: dict[int, int] = {}
    for peer, n in counts.items():
        if n > counts.get(best.get(asns[peer], -1), -1):
            best[asns[peer]] = peer
    for asn, peer in best.items():
        (folder / f"peer{peer}.gz").replace(folder / f"as{asn}.gz")
    for stale in folder.glob("peer*.gz"):
        stale.unlink()
    (folder / "peers.json").write_text(json.dumps({str(a): counts[p] for a, p in best.items()}))


def read(path: Path) -> dict[str, tuple[int, list[int]]]:
    """A table written by tables(): its routes by prefix."""
    out = {}
    with gzip.open(path, "rt") as f:
        for line in f:
            prefix, origin, *path = line.split()
            out[prefix] = (int(origin), [int(a) for a in path])
    return out


def pick(prefixes: set[str], most: int | None, seed: int) -> set[str]:
    """At most `most` of the prefixes, the same for every router, drawn by the seed."""
    if most is None or len(prefixes) <= most:
        return prefixes
    rank = lambda p: hashlib.sha1(f"{seed}/{p}".encode()).digest()
    return set(sorted(prefixes, key=rank)[:most])
