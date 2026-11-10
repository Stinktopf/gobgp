import gzip
import struct

from lab import mrt


def prefix(text):
    address, length = text.split("/")
    length = int(length)
    return bytes([length]) + bytes(int(x) for x in address.split("."))[:(length + 7) // 8]


def message(withdrawn=(), announced=(), path=()):
    w = b"".join(prefix(p) for p in withdrawn)
    attrs = b""
    if path:
        segment = bytes([2, len(path)]) + struct.pack(f"!{len(path)}I", *path)
        attrs = bytes([0x40, 2, len(segment)]) + segment
    body = struct.pack("!H", len(w)) + w + struct.pack("!H", len(attrs)) + attrs + b"".join(prefix(p) for p in announced)
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 2) + body


def record(ts, peer, bgp):
    body = struct.pack("!IIHH", 64500, 12654, 0, 1) + bytes(peer) + bytes(4) + bgp
    return struct.pack("!IHHI", ts, 16, 4, len(body)) + body


def test_updates_are_read():
    w, a, origin = mrt.update(message(["10.0.0.0/8"], ["192.0.2.0/24", "198.51.100.0/22"], [64500, 3320]))
    assert w == ["10.0.0.0/8"] and a == ["192.0.2.0/24", "198.51.100.0/22"] and origin == 3320


def test_the_vantage_point_tells_when_prefixes_come_and_go(tmp_path, monkeypatch):
    start = 1577880000  # 2020-01-01 12:00 UTC
    busy, quiet = (192, 0, 2, 1), (192, 0, 2, 2)
    data = b"".join([
        record(start + 1, busy, message([], ["192.0.2.0/24"], [64500, 3320])),
        record(start + 2, quiet, message(["192.0.2.0/24"])),             # another peer: not the vantage point
        record(start + 3, busy, message([], ["192.0.2.0/24"], [64500, 3320])),  # the same origin again
        record(start + 30, busy, message(["192.0.2.0/24"])),
        record(start + 40, busy, message([], ["192.0.2.0/24"], [64500, 64501, 13335])),
        record(start + 50, busy, message([], ["203.0.113.0/24"], [64500, 3320])),
    ])
    path = tmp_path / "updates.gz"
    path.write_bytes(gzip.compress(data))
    monkeypatch.setattr(mrt, "CACHE", tmp_path)
    monkeypatch.setattr(mrt, "download", lambda collector, t: path)
    (tmp_path / "rrc00").mkdir()
    events = mrt.events("rrc00", "2020-01-01 12:02", 5)
    assert events["vantage"] == "192.0.2.1" and events["start"] == "2020-01-01 12:00"
    assert events["changes"] == [[1, "192.0.2.0/24", 3320], [30, "192.0.2.0/24", 0], [40, "192.0.2.0/24", 13335], [50, "203.0.113.0/24", 3320]]
    assert mrt.events("rrc00", "2020-01-01 12:00", 5) == events  # cached


def test_a_window_must_lie_in_the_past():
    import pytest
    with pytest.raises(ValueError, match="no data of that window yet"):
        mrt.window("2999-01-01 00:00", 30)
    with pytest.raises(ValueError, match="not a time"):
        mrt.window("yesterday", 30)
