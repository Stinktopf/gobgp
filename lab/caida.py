"""Imports parts of the Internet from the AS relationships of CAIDA
(publicdata.caida.org/datasets/as-relationships/serial-1) as topologies.

A part is chosen by one rule, without a choice of ours: the core, the N
ASes with the largest customer cones as CAIDA's AS Rank orders them; an AS
and all of its customers; or all ASes of a country. Each keeps what of it
is connected. Every AS becomes a router with its real ASN,
every relation between two chosen ASes a session that follows Gao-Rexford.
Roles name the clique of CAIDA, the transit ASes and the stubs, e.g. to run
OBGP on some of them. The routers are placed in tiers, providers above
their customers. ASes are found by name with the AS-to-organization data
of CAIDA (publicdata.caida.org/datasets/as-organizations).
"""

import bz2
import gzip
import os
import re
import threading
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

from . import topology

BASE_URL = "https://publicdata.caida.org/datasets/as-relationships/serial-1/"
ORGS_URL = "https://publicdata.caida.org/datasets/as-organizations/"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "obgp-lab" / "caida"
# The graph view: at most ROW routers side by side, GAP pixels apart, rows
# of a tier ROW_GAP apart and tiers TIER.
ROW, GAP, ROW_GAP, TIER = 16, 70, 60, 140
FILE = re.compile(r"(\d{8})\.as-rel\.txt\.bz2")
PARTS = ("core", "cone", "country")
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
ORGS_FILE = re.compile(r"(\d{8})\.as-org2info\.txt\.gz")


class Relations:
    """Who provides whom and who peers with whom, among all ASes."""

    def __init__(self, text: str, source: str) -> None:
        self.source = source
        self.customers: dict[int, set[int]] = defaultdict(set)
        self.providers: dict[int, set[int]] = defaultdict(set)
        self.peers: dict[int, set[int]] = defaultdict(set)
        self.clique: set[int] = set()
        self.names: dict[int, tuple[str, str, str]] = {}  # AS name, organization, country
        for line in text.splitlines():
            if line.startswith("# input clique:"):
                self.clique = {int(a) for a in line.split(":", 1)[1].split()}
            if not line or line.startswith("#"):
                continue
            try:
                a, b, rel = line.split("|")[:3]
                a, b, rel = int(a), int(b), int(rel)
            except ValueError:
                raise ValueError(f"not a CAIDA AS relationship file: {line[:60]!r}") from None
            if a == b:
                continue
            if rel == -1:
                self.customers[a].add(b)
                self.providers[b].add(a)
            elif rel == 0:
                self.peers[a].add(b)
                self.peers[b].add(a)
        if not self.customers and not self.peers:
            raise ValueError("not a CAIDA AS relationship file: no relations")

    def label(self, asn: int) -> dict:
        name, org, country = self.names.get(asn, ("", "", ""))
        return {"asn": asn, "name": name, "org": org, "country": country}

    def cone_size(self, asn: int, limit: int = 200_000) -> int:
        """How many ASes the customer cone of an AS holds, itself included."""
        seen, todo = {asn}, [asn]
        while todo and len(seen) < limit:
            for c in self.customers.get(todo.pop(), ()):
                if c not in seen:
                    seen.add(c)
                    todo.append(c)
        return len(seen)

    def search(self, query: str, limit: int = 8) -> list[dict]:
        """ASes by number or by words of their name or organization, the
        largest first."""
        query = query.strip().lower().removeprefix("as")
        if not query:
            return []
        if query.isdigit():
            hits = [a for a in (int(query),) if self.known(a)]
            hits += sorted((a for a in self.names if str(a).startswith(query) and a != int(query) and self.known(a)),
                           key=lambda a: -len(self.customers.get(a, ())))
        else:
            words = query.split()
            hits = [a for a, (name, org, _) in self.names.items()
                    if self.known(a) and all(w in f"{name} {org}".lower() for w in words)]
            hits.sort(key=lambda a: -len(self.customers.get(a, ())))
        return [{**self.label(a), "cone": self.cone_size(a)} for a in hits[:limit]]

    def known(self, asn: int) -> bool:
        return asn in self.customers or asn in self.providers or asn in self.peers

    def whole_cone(self, asn: int) -> list[int]:
        """The AS and all of its customers, theirs and so on, nearest first."""
        if not self.known(asn):
            raise ValueError(f"AS{asn} is not in the CAIDA data{' of ' + month_name(self.source[6:]) if self.source else ''}.")
        chosen, seen = [asn], {asn}
        for a in chosen:
            for c in sorted(self.customers.get(a, ())):
                if c not in seen:
                    seen.add(c)
                    chosen.append(c)
        if len(chosen) < 2:
            raise ValueError(f"AS{asn} has no customers. Choose a transit AS, the core or a country.")
        return chosen

    def rank(self) -> list[int]:
        """The ASes with customers by the size of their customer cone, the
        largest first, as CAIDA's AS Rank orders them."""
        if not hasattr(self, "_rank"):
            sizes = self._cone_sizes()
            self._rank = sorted(self.customers, key=lambda a: (-sizes[a], a))
        return self._rank

    def _cone_sizes(self) -> dict[int, int]:
        """The size of the customer cone of every AS with customers, at once:
        each cone a set of bits, merged from the customers up. A customer
        still open, in the rare cycles of the data, counts as itself only."""
        index: dict[int, int] = {}
        bit = lambda a: 1 << index.setdefault(a, len(index))
        cones: dict[int, int] = {}
        for root in self.customers:
            if root in cones:
                continue
            open_, stack = {root}, [(root, iter(self.customers[root]))]
            while stack:
                a, rest = stack[-1]
                for c in rest:
                    if c in self.customers and c not in cones and c not in open_:
                        open_.add(c)
                        stack.append((c, iter(self.customers[c])))
                        break
                else:
                    stack.pop()
                    open_.discard(a)
                    cone = bit(a)
                    for c in self.customers[a]:
                        cone |= cones.get(c) or bit(c)
                    cones[a] = cone
        return {a: cone.bit_count() for a, cone in cones.items()}

    def core(self, size: int) -> list[int]:
        """The `size` ASes with the largest customer cones that connect to
        the largest, in the order of their rank."""
        chosen: list[int] = []
        inside: set[int] = set()
        for a in self.rank():
            if len(chosen) == size:
                break
            if not chosen or self.neighbors(a) & inside:
                chosen.append(a)
                inside.add(a)
        return chosen

    def country(self, code: str) -> list[int]:
        """The ASes of a country, as their organization is registered, that
        connect with the most of them, the largest first."""
        code = code.strip().upper()
        ases = [a for a, (_, _, cc) in self.names.items() if cc == code and self.known(a)]
        if not ases:
            raise ValueError(f"CAIDA knows no AS of the country {code!r}.")
        return self.largest_part(ases)

    def countries(self) -> list[tuple[str, int]]:
        """Every country and how many of its ASes connect, the most first."""
        if not hasattr(self, "_countries"):
            by: dict[str, list[int]] = defaultdict(list)
            for a, (_, _, cc) in self.names.items():
                if cc and self.known(a):
                    by[cc].append(a)
            self._countries = sorted(((cc, len(self.largest_part(ases))) for cc, ases in by.items()), key=lambda x: (-x[1], x[0]))
        return self._countries

    def neighbors(self, a: int) -> set[int]:
        return self.customers.get(a, set()) | self.providers.get(a, set()) | self.peers.get(a, set())

    def largest_part(self, ases: list[int]) -> list[int]:
        """Those of the ASes that connect with the most of them, the AS with
        the most customers first."""
        left, best = set(ases), set()
        while len(left) > len(best):
            start = left.pop()
            part, todo = {start}, [start]
            while todo:
                for b in self.neighbors(todo.pop()) & left:
                    left.discard(b)
                    part.add(b)
                    todo.append(b)
            best = max(best, part, key=len)
        return sorted(best, key=lambda a: (-len(self.customers.get(a, ())), a))

    def multihomed_share(self) -> float:
        """The share of ASes with providers that have more than one, in all of the Internet."""
        if not hasattr(self, "_multihomed"):
            self._multihomed = sum(len(p) > 1 for p in self.providers.values()) / max(1, len(self.providers))
        return self._multihomed

    def multihomed(self, ases: list[int]) -> int:
        """How many of the ASes have more than one provider among them."""
        chosen = set(ases)
        return sum(len(self.providers.get(a, set()) & chosen) > 1 for a in ases)


_listings: dict[str, tuple[float, list[str]]] = {}


def _listing(url: str, pattern: re.Pattern) -> list[str]:
    """The dates of the files in a folder of CAIDA, newest first, asked once an hour."""
    if (hit := _listings.get(url)) and time.monotonic() - hit[0] < 3600:
        return hit[1]
    with urllib.request.urlopen(url, timeout=30) as response:
        dates = sorted(set(pattern.findall(response.read(2_000_000).decode(errors="replace"))), reverse=True)
    _listings[url] = (time.monotonic(), dates)
    return dates


def months() -> list[str]:
    """The months of the CAIDA files, newest first, e.g. 20260901."""
    return _listing(BASE_URL, FILE)


def nearest(month: str) -> tuple[str, bool]:
    """The available month nearest to a month as YYYY-MM or YYYYMMDD, the
    newest if none is given, and whether CAIDA was reachable."""
    try:
        have, online = months(), True
    except OSError:
        have, online = cached(), False
    if not have:
        raise OSError("CAIDA is not reachable, and nothing was downloaded before.")
    digits = re.sub(r"\D", "", month)[:6]
    if len(digits) != 6:
        return have[0], online
    return min(have, key=lambda m: (abs((int(m[:4]) * 12 + int(m[4:6])) - (int(digits[:4]) * 12 + int(digits[4:6]))), m)), online


def _orgs(month: str) -> dict[int, tuple[str, str, str]]:
    """AS name, organization and country by ASN, from the data nearest before the month."""
    try:
        dates = _listing(ORGS_URL, ORGS_FILE)
    except OSError:
        dates = sorted((m.group(1) for p in CACHE.glob("orgs-*.txt.gz") if (m := re.fullmatch(r"orgs-(\d{8})\.txt\.gz", p.name))), reverse=True)
    if not dates:
        return {}
    day = next((d for d in dates if d <= month), dates[-1])
    path = CACHE / f"orgs-{day}.txt.gz"
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(f"{ORGS_URL}{day}.as-org2info.txt.gz", timeout=120) as response:
            part = path.with_suffix(".part")
            part.write_bytes(response.read(100_000_000))
            part.replace(path)
    orgs, out, section = {}, {}, ""
    with gzip.open(path, "rt", errors="replace") as f:
        for line in f:
            if line.startswith("# format:"):
                section = line.split(":", 1)[1].split("|", 1)[0]
                continue
            fields = line.rstrip("\n").split("|")
            if section == "org_id" and len(fields) >= 4:
                orgs[fields[0]] = (fields[2], fields[3])
            elif section == "aut" and len(fields) >= 4 and fields[0].isdigit():
                org, country = orgs.get(fields[3], ("", ""))
                out[int(fields[0])] = (fields[2], org, country)
    return out


_names: dict[str, dict] = {}


def names(source: str, asns) -> dict[int, dict]:
    """The names of ASes of a topology imported from CAIDA, as of its month."""
    month = source.removeprefix("caida/")
    if month not in _names:
        try:
            _names[month] = _orgs(month)
        except (OSError, EOFError, gzip.BadGzipFile):
            return {}
    orgs = _names[month]
    return {a: {"name": orgs[a][0], "org": orgs[a][1], "country": orgs[a][2]} for a in asns if a in orgs}


def cached() -> list[str]:
    """The months downloaded before, newest first."""
    return sorted((m.group(1) for p in CACHE.glob("*.as-rel.txt.bz2") if (m := FILE.fullmatch(p.name))), reverse=True)


def download(month: str) -> Path:
    """The file of a month, downloaded once."""
    if not re.fullmatch(r"\d{8}", month):
        raise ValueError(f"no CAIDA month {month}")
    path = CACHE / f"{month}.as-rel.txt.bz2"
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(f"{BASE_URL}{path.name}", timeout=120) as response:
            part = path.with_suffix(".part")
            part.write_bytes(response.read(50_000_000))
            part.replace(path)
    return path


# One month at a time, for a while after its last use: it takes some
# 160 MB, too much to keep in the web server for good.
_loaded: dict[str, Relations] = {}
_lock = threading.Lock()
_forget: threading.Timer | None = None
KEEP_S = 600


def relations(month: str = "") -> Relations:
    """The relations of a month, the newest one cached or online if none is given."""
    global _forget
    month = month or next(iter(cached()), "") or months()[0]
    with _lock:
        if month not in _loaded:
            try:
                text = bz2.decompress(download(month).read_bytes()).decode(errors="replace")
            except (OSError, EOFError) as e:
                raise ValueError(f"the CAIDA file of {month} is damaged: {e}") from None
            _loaded.clear()
            rels = Relations(text, f"caida/{month}")
            try:
                rels.names = _orgs(month)
            except (OSError, EOFError, gzip.BadGzipFile):
                rels.names = {}  # found by number only
            _loaded[month] = rels
        if _forget:
            _forget.cancel()
        _forget = threading.Timer(KEEP_S, _loaded.clear)
        _forget.daemon = True
        _forget.start()
        return _loaded[month]


def max_routers() -> int:
    """How many routers this host runs well."""
    from . import cluster

    return cluster.max_routers()


def choose(rels: Relations, part: str, key: str | int | None, fits: bool = True) -> list[int]:
    """The ASes of a part: the core of `key` ASes, the cone of AS `key`, or the country `key`."""
    if part == "core":
        if not isinstance(key, int) or key < 3:
            raise ValueError("Choose 3 routers or more: fewer give no alternative.")
        ases = rels.core(key)
    elif part == "cone":
        ases = rels.whole_cone(int(key))
    elif part == "country":
        ases = rels.country(str(key))
    else:
        raise ValueError(f"no part {part!r}, only {', '.join(PARTS)}")
    if fits and len(ases) > (most := max_routers()):
        raise ValueError(f"{len(ases):,} routers do not fit this host, at most {most}.")
    return ases


def convert(rels: Relations, ases: list[int], root: int | None = None) -> dict:
    """The topology of some ASes, as lab.topology works with it. The origin
    is the AS of a cone, or else the AS with the most sessions."""
    chosen = set(ases)
    name = {a: f"as{a}" for a in ases}
    routers = {name[a]: {"asn": a, "routerId": f"10.{(i + 1) >> 16 & 255}.{(i + 1) >> 8 & 255}.{(i + 1) & 255}", "neighbors": []}
               for i, a in enumerate(ases)}
    for a in ases:
        r = routers[name[a]]
        for kind, others in (("customer", rels.customers), ("peer", rels.peers), ("provider", rels.providers)):
            for b in sorted(others.get(a, set()) & chosen):
                r["neighbors"].append({"name": name[b], "peerAs": b, "relation": kind})
    tiers = _tiers(rels, ases)
    _place(routers, rels, ases, tiers)
    customers = {a: rels.customers.get(a, set()) & chosen for a in ases}
    origin = root if root in chosen else max(ases, key=lambda a: (len(routers[name[a]]["neighbors"]), -a))
    roles = {"origins": [name[origin]],
             "clique": [name[a] for a in ases if a in rels.clique],
             "transit": [name[a] for a in ases if customers[a]],
             "stubs": [name[a] for a in ases if not customers[a]]}
    return {"source": rels.source, "roles": {k: v for k, v in roles.items() if v}, "routers": routers}


def _tiers(rels: Relations, ases: list[int]) -> dict[int, int]:
    """Per AS the longest chain of providers above it among the ASes."""
    chosen, tier = set(ases), {}

    def depth(a: int, path: frozenset) -> int:
        if a not in tier:
            above = [b for b in rels.providers.get(a, set()) & chosen if b not in path]
            tier[a] = 1 + max((depth(b, path | {a}) for b in above), default=-1)
        return tier[a]

    for a in ases:
        depth(a, frozenset())
    return tier


def _place(routers: dict, rels: Relations, ases: list[int], tiers: dict[int, int]) -> None:
    """Tiers from top to bottom, each sorted by where its providers are; a
    wide tier wraps into rows, so that the names stay apart."""
    x: dict[int, float] = {}
    width = min(ROW, max(sum(1 for a in ases if tiers[a] == t) for t in set(tiers.values()))) * GAP
    y = 0.0
    for t in sorted(set(tiers.values())):
        tier = [a for a in ases if tiers[a] == t]
        above = lambda a: [x[b] for b in rels.providers.get(a, set()) if b in x]
        tier.sort(key=lambda a: (sum(above(a)) / len(above(a)) if above(a) else width / 2, a))
        rows = [tier[i:i + ROW] for i in range(0, len(tier), ROW)]
        for row in rows:
            for i, a in enumerate(row):
                x[a] = (i + 0.5) * width / len(row)
                routers[f"as{a}"]["position"] = {"x": x[a], "y": y}
            y += ROW_GAP
        y += TIER - ROW_GAP


def read_form(part: str, asn: str, country: str, size: str) -> tuple[str, str | int]:
    """The part and its key from the import form."""
    try:
        return part, {"core": lambda: int(size), "cone": lambda: int(asn), "country": lambda: country.strip().upper()}[part]()
    except (ValueError, KeyError):
        raise ValueError("Give how many routers, an AS or a country.") from None


def default_name(part: str, key: str | int) -> str:
    return {"core": f"core-{key}", "cone": f"cone-as{key}", "country": f"country-{str(key).lower()}"}[part]


def month_name(day: str) -> str:
    """E.g. September 2026 for 20260901."""
    return f"{MONTHS[int(day[4:6]) - 1]} {day[:4]}" if re.fullmatch(r"\d{4}(0[1-9]|1[0-2])\d\d", day) else day


def preview(part: str, key: str | int, month: str = "") -> dict:
    """What an import would give: its routers, sessions and memory, how many
    ASes are multihomed against all of the Internet, its ASes, the month."""
    from .config import Cluster

    day, _ = nearest(month)
    rels = relations(day)
    ases = choose(rels, part, key, fits=False)
    root = key if part == "cone" else None
    t = convert(rels, ases, root) if len(ases) <= max_routers() else None
    sessions = sum(len(rels.neighbors(a) & set(ases)) for a in ases) // 2
    asked = re.sub(r"\D", "", month)[:6]
    return {"part": part, "key": key, "routers": len(ases), "sessions": sessions, "source": f"caida/{day}",
            "per_router": 2 * sessions / len(ases), "multihomed": rels.multihomed(ases) / len(ases),
            "internet": rels.multihomed_share(), "memory_mb": Cluster.SYSTEM_MB + len(ases) * Cluster.ROUTER_MB,
            "fits": t is not None, "most": max_routers(),
            "roles": {k: len(v) for k, v in t["roles"].items() if k != "origins"} if t else {},
            "root": rels.label(root) if root else None, "month": month_name(day), "name": default_name(part, key),
            "asked": f"{asked[:4]}-{asked[4:]}" if len(asked) == 6 and asked != day[:6] else ""}


_parts: dict[tuple, list[dict]] = {}


def members(part: str, key: str | int, month: str = "", query: str = "", offset: int = 0, limit: int = 50) -> tuple[list[dict], int]:
    """A page of the ASes of a part, those that match the query, and how
    many match. The members of a part are kept for the next page."""
    day, _ = nearest(month)
    if (day, part, key) not in _parts:
        rels = relations(day)
        if len(_parts) > 8:
            _parts.clear()
        _parts[(day, part, key)] = _members(rels, choose(rels, part, key, fits=False), key if part == "cone" else None)
    found = _parts[(day, part, key)]
    if words := query.strip().lower().removeprefix("as").split():
        found = [m for m in found if all(w in f"{m['asn']} {m['name']} {m['org']} {m['country']}".lower() for w in words)]
    return found[offset:offset + limit], len(found)


def _members(rels: Relations, ases: list[int], root: int | None) -> list[dict]:
    """The ASes of a part, the root first, then Tier-1, transit and stubs,
    each by its sessions in the part."""
    chosen = set(ases)
    out = []
    for a in ases:
        neighbors = (rels.customers.get(a, set()) | rels.peers.get(a, set()) | rels.providers.get(a, set())) & chosen
        role = "Tier-1" if a in rels.clique else "Transit" if rels.customers.get(a, set()) & chosen else "Stub"
        out.append({**rels.label(a), "role": role, "sessions": len(neighbors), "root": a == root})
    order = {"Tier-1": 0, "Transit": 1, "Stub": 2}
    return sorted(out, key=lambda x: (not x["root"], order[x["role"]], -x["sessions"], x["asn"]))


def import_part(part: str, key: str | int, name: str = "", month: str = "", text: str | None = None, fits: bool = True) -> str:
    """Imports a part of the Internet, from CAIDA or a file in its format, and returns the topology name."""
    rels = Relations(text, "") if text is not None else relations(nearest(month)[0])
    name = name or default_name(part, key)
    if topology.path(name).exists():
        raise FileExistsError(f"A topology named {name} exists already.")
    t = convert(rels, choose(rels, part, key, fits), key if part == "cone" else None)
    topology.save(name, t["routers"], t["roles"], t["source"] or None)
    return name
