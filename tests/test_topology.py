import pytest

from lab import sndlib, topology

NATIVE = """?SNDlib native format; type: network; version: 1.0
NODES (
  Berlin ( 13.40 52.52 )
  Hamburg ( 9.99 53.55 )
  Frankfurt ( 8.68 50.11 )
)
LINKS (
  L1 ( Berlin Hamburg ) 0 0 0 0 ( )
  L2 ( Hamburg Frankfurt ) 0 0 0 0 ( )
  L3 ( Frankfurt Berlin ) 0 0 0 0 ( )
  L4 ( Berlin Hamburg ) 0 0 0 0 ( )
)
"""


@pytest.mark.parametrize("name", topology.names())
def test_topologies_are_valid(name):
    t = topology.load(name)
    assert topology.validate(t["routers"], t["roles"]) == []


@pytest.mark.parametrize("name", topology.names())
def test_topologies_round_trip(name):
    t = topology.load(name)
    assert topology.parse(topology.dump(t["routers"], t["roles"], t["source"])) == t


def test_validation_finds_problems():
    routers = {"a": {"asn": 1, "routerId": "10.0.0.1", "neighbors": [{"name": "b", "peerAs": 3}]},
               "b": {"asn": 1, "routerId": "10.0.0.1", "neighbors": []}}
    problems = " ".join(topology.validate(routers, {"origins": ["z"]}))
    for expected in ("unknown routers z", "ASN 1 is used", "router ID", "peerAs", "does not list"):
        assert expected in problems


def test_sndlib_native_format():
    t = sndlib.convert("mini", NATIVE)
    assert set(t["routers"]) == {"berlin", "hamburg", "frankfurt"}
    assert sum(len(r["neighbors"]) for r in t["routers"].values()) == 6  # parallel links count once
    assert all("location" in r for r in t["routers"].values())
    assert t["source"] == "sndlib/mini" and len(t["roles"]["origins"]) == 1
    assert topology.validate(t["routers"], t["roles"]) == []


def test_sndlib_grid_coordinates_are_no_locations():
    grid = NATIVE.replace("13.40 52.52", "1 2").replace("9.99 53.55", "3 4").replace("8.68 50.11", "5 6")
    assert not any("location" in r for r in sndlib.convert("grid", grid)["routers"].values())


def test_sndlib_rejects_other_files():
    with pytest.raises(ValueError):
        sndlib.convert("x", "hello")


def test_sndlib_archive_imports_record_their_source(lab_files, monkeypatch):
    monkeypatch.setattr(sndlib, "networks", lambda: {"mini": NATIVE})
    name = sndlib.import_network("mini")
    assert topology.load(name)["source"] == "sndlib/mini"
    assert topology.sources()["sndlib/mini"] == [name]
    own = sndlib.import_network("mine", text=NATIVE)
    assert topology.load(own)["source"] is None


def chain(relations: dict[tuple[str, str], str]) -> dict:
    """Routers a, b, c with sessions whose relation is given from the first router."""
    from lab.topology import RELATIONS

    routers = {r: {"asn": i + 1, "routerId": f"10.0.0.{i + 1}", "neighbors": []} for i, r in enumerate("abc")}
    for (x, y), rel in relations.items():
        routers[x]["neighbors"].append({"name": y, "peerAs": routers[y]["asn"], **({"relation": rel} if rel else {})})
        routers[y]["neighbors"].append({"name": x, "peerAs": routers[x]["asn"], **({"relation": RELATIONS[rel]} if rel else {})})
    return routers


def test_relations_are_checked_and_written():
    routers = chain({("a", "b"): "customer", ("b", "c"): "customer", ("a", "c"): "peer"})
    assert topology.validate(routers) == []
    assert topology.parse(topology.dump(routers))["routers"] == routers
    routers["b"]["neighbors"][0]["relation"] = "peer"  # b says a is a peer, a says b is a customer
    assert any("is not its" in p for p in topology.validate(routers))
    routers["b"]["neighbors"][0]["relation"] = "friend"
    assert any("must be one of" in p for p in topology.validate(routers))


def test_providers_must_not_form_a_cycle():
    routers = chain({("a", "b"): "customer", ("b", "c"): "customer", ("c", "a"): "customer"})
    assert any("providers form a cycle: a → b → c → a" in p for p in topology.validate(routers))
