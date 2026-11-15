import gzip
import struct

from lab import rib


def record(subtype: int, body: bytes) -> bytes:
    return struct.pack("!IHHI", 0, rib.TABLE_DUMP_V2, subtype, len(body)) + body


def peers(*asns: int) -> bytes:
    body = bytes(4) + struct.pack("!H", 0) + struct.pack("!H", len(asns))
    for asn in asns:
        body += bytes([2]) + bytes(4) + bytes(4) + struct.pack("!I", asn)  # IPv4 peer, four-byte ASN
    return record(rib.PEER_INDEX_TABLE, body)


def attrs(path: list[int], segment: int = 2) -> bytes:
    seg = bytes([segment, len(path)]) + struct.pack(f"!{len(path)}I", *path)
    return bytes([0x40, 1, 1, 0]) + bytes([0x40, 2, len(seg)]) + seg


def prefix(seq: int, net: str, entries: list[tuple[int, bytes]]) -> bytes:
    address, bits = net.split("/")
    bits = int(bits)
    body = struct.pack("!I", seq) + bytes([bits]) + bytes(map(int, address.split(".")))[:(bits + 7) // 8]
    body += struct.pack("!H", len(entries))
    for peer, a in entries:
        body += struct.pack("!HIH", peer, 0, len(a)) + a
    return record(rib.RIB_IPV4_UNICAST, body)


def test_the_table_of_each_peer_as_is_extracted_without_the_as_itself(tmp_path):
    dump = tmp_path / "bview.gz"
    dump.write_bytes(gzip.compress(
        peers(3320, 1299, 3320)
        + prefix(0, "10.0.0.0/8", [(0, attrs([3320, 174, 65001])), (1, attrs([1299, 65001]))])
        + prefix(1, "192.0.2.0/24", [(1, attrs([1299, 1299, 65002])), (2, attrs([3320, 65003], segment=1))])
        + prefix(2, "198.51.100.0/24", [(0, attrs([3320, 65004]))])))
    rib._extract(dump, tmp_path / "out")
    assert rib.read(tmp_path / "out" / "as3320.gz") == {"10.0.0.0/8": (0, [174, 65001]), "198.51.100.0/24": (0, [65004])}
    # Its own ASN at the start goes, also when prepended; paths with an AS_SET do not count.
    assert rib.read(tmp_path / "out" / "as1299.gz") == {"10.0.0.0/8": (0, [65001]), "192.0.2.0/24": (0, [65002])}


def test_the_same_prefixes_are_picked_for_every_router():
    all_ = {f"10.{i}.0.0/16" for i in range(100)}
    picked = rib.pick(all_, 10, seed=7)
    assert len(picked) == 10 and picked == rib.pick(all_, 10, seed=7) and picked != rib.pick(all_, 10, seed=8)
    assert rib.pick(all_, None, seed=7) == all_


def test_tables_are_taken_every_eight_hours():
    assert rib.snapshot("2026-09-01 13:30").strftime("%H:%M") == "08:00"
