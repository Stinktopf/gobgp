"""The CPU profiles routers keep beside a run (cpu-<router>-<t>.pb.gz, pprof),
read without Go: where a router spent its CPU, by bucket and by function.

A bucket is a part of the router, decided by the frames of each sample's
stack, function and source file, in the order of BUCKETS: the first bucket
any frame matches takes the sample, so the same function falls in the same
bucket in every mode. The garbage collector comes first, its assists
included, then what the lab reads through the API (not the routes its
controller injects), policy, the export filter, the decision process
wherever it is called, the tables per neighbor (NS-BGP's and OBGP's alike,
OBGP's code they call included), OBGP outside the decision process and those tables, the rest of the RIB, sending and
receiving. A sample no bucket matches is other.
"""

import gzip
import re
from collections import defaultdict
from pathlib import Path

BUCKETS = [  # bucket, the frames that put a sample in it: "function file"
    ("gc", re.compile(r"^runtime\.(gcBgMarkWorker|gcAssistAlloc|bgsweep|bgscavenge|gcDrain|markroot|scanobject|gcMarkDone)")),
    # What the lab reads, not the routes its controller injects (AddPath), which take the router's own way.
    ("api", re.compile(r"pkg/server\.\(\*(server|BgpServer)\)\.(List|Get|Watch|Monitor|getRibInfo|getAdjRib|getRib)|^google\.golang\.org/grpc/internal/transport"
                       r"|^net/http\.\(\*conn\)\.serve |^github\.com/prometheus/")),
    ("policy", re.compile(r"\(\*RoutingPolicy\)\.ApplyPolicy ")),
    ("export", re.compile(r"table\.UpdatePathAttrs |server\.\(\*BgpServer\)\.(filterpath|operaFilter) |^github\.com/osrg/gobgp/v4/pkg/server\.filterpath ")),
    # The decision process of every mode, OBGP's admission inside it included, whatever calls it.
    ("decision", re.compile(r"internal/pkg/table\.\(\*Destination\)\.Calculate ")),
    # A table per neighbor, NS-BGP's and OBGP's alike, by its file.
    ("tables", re.compile(r" \S*internal/pkg/table/opera_neighbor\.go$| \S*pkg/server/opera_neighbor\.go$")),
    # OBGP outside the decision process: pruning, setting aside, refreshes.
    ("obgp", re.compile(r" \S*internal/pkg/table/opera\.go$| \S*pkg/server/opera(_refresh)?\.go$")),
    ("rib", re.compile(r"server\.\(\*BgpServer\)\.(propagateUpdate|handleFSMMessage|processOutgoingPaths) ")),
    ("send", re.compile(r"server\.\(\*fsmHandler\)\.(sendMessageloop|send)")),
    ("receive", re.compile(r"server\.\(\*fsmHandler\)\.(recvMessage|handlingError|recvMessageloop)|packet/bgp\.ParseBGP")),
]
NAMES = [b for b, _ in BUCKETS] + ["other"]


def _varint(data: bytes, i: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, i
        shift += 7


def _fields(data: bytes):
    """The fields of a protobuf message: (number, wire type, value), a length-delimited value as bytes."""
    i = 0
    while i < len(data):
        key, i = _varint(data, i)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _varint(data, i)
        elif wire == 1:
            value, i = int.from_bytes(data[i:i + 8], "little"), i + 8
        elif wire == 2:
            size, i = _varint(data, i)
            value, i = data[i:i + size], i + size
        elif wire == 5:
            value, i = int.from_bytes(data[i:i + 4], "little"), i + 4
        else:
            raise ValueError(f"protobuf wire type {wire}")
        yield number, wire, value


def _ints(wire: int, value) -> list[int]:
    """A repeated integer field, packed or not."""
    if wire != 2:
        return [value]
    out, i = [], 0
    while i < len(value):
        v, i = _varint(value, i)
        out.append(v)
    return out


def read(path: Path) -> dict:
    """A pprof profile: its sample types, and its samples as (stack of
    function names from the leaf to the root, the same frames as "function
    file", values)."""
    raw = path.read_bytes()
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    strings, types, samples, locations, functions = [], [], [], {}, {}
    for number, _, value in _fields(data):
        if number == 6:
            strings.append(value.decode(errors="replace"))
        elif number == 1:
            types.append({n: v for n, _, v in _fields(value)})
        elif number == 2:
            ids, values = [], []
            for n, w, v in _fields(value):
                if n == 1:
                    ids += _ints(w, v)
                elif n == 2:
                    values += [x - (1 << 64) if x >= 1 << 63 else x for x in _ints(w, v)]
            samples.append((ids, values))
        elif number == 4:
            loc, lines = 0, []
            for n, _, v in _fields(value):
                if n == 1:
                    loc = v
                elif n == 4:
                    lines.append(next((x for m, _, x in _fields(v) if m == 1), 0))
            locations[loc] = lines  # inlined functions first, as pprof keeps them
        elif number == 5:
            fields = {n: v for n, _, v in _fields(value)}
            functions[fields.get(1, 0)] = (fields.get(2, 0), fields.get(4, 0))
    text = lambda i: strings[i] if i < len(strings) else "?"  # noqa: E731
    frame = lambda f: (text(functions.get(f, (0, 0))[0]), text(functions.get(f, (0, 0))[1]))  # noqa: E731
    stacks = {loc: [frame(f) for f in lines] for loc, lines in locations.items()}
    out = []
    for ids, values in samples:
        frames = [fr for loc in ids for fr in stacks.get(loc, [])]
        out.append(([n for n, _ in frames], [f"{n} {f}" for n, f in frames], values))
    return {"types": [strings[t.get(1, 0)] for t in types], "samples": out}


def bucket(stack: list[str]) -> str:
    """The bucket of a sample by the frames of its stack, each "function file"."""
    for name, pattern in BUCKETS:
        if any(pattern.search(frame) for frame in stack):
            return name
    return "other"


def cpu(paths: list[Path]) -> dict:
    """The CPU seconds of profiles together: in all, per bucket, and per
    function flat (at the leaf) and cumulative (anywhere on the stack)."""
    total, buckets = 0.0, dict.fromkeys(NAMES, 0.0)
    flat, cum = defaultdict(float), defaultdict(float)
    for path in paths:
        p = read(path)
        at = p["types"].index("cpu") if "cpu" in p["types"] else len(p["types"]) - 1
        for stack, frames, values in p["samples"]:
            s = values[at] / 1e9
            total += s
            buckets[bucket(frames)] += s
            if stack:
                flat[stack[0]] += s
            for fn in set(stack):
                cum[fn] += s
    return {"seconds": total, "buckets": buckets, "flat": dict(flat), "cum": dict(cum)}


def tree(paths: list[Path]) -> dict:
    """The call tree of profiles together, from the root down: each node the
    CPU seconds of the samples through it, {"s": seconds, "c": {function: node}}."""
    root: dict = {"s": 0.0, "c": {}}
    for path in paths:
        p = read(path)
        at = p["types"].index("cpu") if "cpu" in p["types"] else len(p["types"]) - 1
        for stack, _, values in p["samples"]:
            s = values[at] / 1e9
            node = root
            node["s"] += s
            for fn in reversed(stack):
                node = node["c"].setdefault(fn, {"s": 0.0, "c": {}})
                node["s"] += s
    return root


def allocated(start: Path, end: Path) -> dict:
    """The bytes allocated between two allocation profiles, per function at the leaf."""
    def space(path: Path) -> dict[tuple, int]:
        p = read(path)
        at = p["types"].index("alloc_space") if "alloc_space" in p["types"] else 1
        out = defaultdict(int)
        for stack, _, values in p["samples"]:
            out[tuple(stack)] += values[at]
        return out
    before, after = space(start), space(end)
    flat = defaultdict(float)
    for stack, b in after.items():
        if (d := b - before.get(stack, 0)) > 0 and stack:
            flat[stack[0]] += d / 2**20
    return {"mb": sum(flat.values()), "flat": dict(flat)}


def of_run(folder: Path) -> dict | None:
    """The CPU of the profiles of one run, all its profiled routers together, None without any."""
    paths = sorted(folder.glob("cpu-*.pb.gz"))
    return cpu(paths) if paths else None


def top(seconds: dict[str, float], n: int = 15) -> list[list]:
    """The n functions with the most seconds, as [name, seconds]."""
    return [[f, round(s, 3)] for f, s in sorted(seconds.items(), key=lambda x: -x[1])[:n]]
