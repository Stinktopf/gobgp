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
    for expected in ("unknown routers z", "AS 1: iBGP does not carry routes of", "router ID", "peerAs", "does not list"):
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


def ibgp_as(reflector: bool) -> dict:
    """AS 65002 of three routers, a full mesh or b reflecting for a and c,
    and router x of AS 65001 at a."""
    n = lambda name, asn, **kw: {"name": name, "peerAs": asn, **kw}
    if reflector:
        sessions = {"a": [n("b", 65002)], "b": [n("a", 65002, rrClient=True), n("c", 65002, rrClient=True)], "c": [n("b", 65002)]}
    else:
        sessions = {"a": [n("b", 65002), n("c", 65002)], "b": [n("a", 65002), n("c", 65002)], "c": [n("a", 65002), n("b", 65002)]}
    sessions["a"].append(n("x", 65001))
    routers = {r: {"asn": 65002, "routerId": f"10.0.0.{i}", "neighbors": sessions[r]} for i, r in enumerate("abc", 1)}
    routers["x"] = {"asn": 65001, "routerId": "10.0.0.9", "neighbors": [n("a", 65002)]}
    return routers


def test_routers_of_one_as_speak_ibgp_in_a_mesh_or_through_a_reflector():
    for reflector in (False, True):
        routers = ibgp_as(reflector)
        assert topology.validate(routers) == []
        assert topology.parse(topology.dump(routers))["routers"] == routers


def test_ibgp_must_reach_every_router_of_the_as():
    routers = ibgp_as(True)
    for n in routers["b"]["neighbors"]:
        n.pop("rrClient")  # b reflects nothing: routes of a do not reach c
    assert "AS 65002: iBGP does not carry routes of a to c" in " ".join(topology.validate(routers))
    routers = ibgp_as(True)
    routers["x"]["neighbors"][0]["rrClient"] = True
    routers["a"]["neighbors"][1]["relation"] = "customer"
    routers["a"]["neighbors"][0]["localPref"] = 200
    problems = " ".join(topology.validate(routers))
    assert "a is in another AS and cannot be a route reflector client" in problems
    assert "b is in the same AS, relation and Local Preference are for other ASes" in problems


def test_a_network_becomes_one_as_with_reflectors_and_neighbors():
    from lab import sndlib

    t = sndlib.convert("abilene", sndlib.networks()["abilene"]) if "abilene" in sndlib.networks() else None
    if t is None:
        pytest.skip("SNDlib archive without abilene")
    one = topology.one_as(t, externals=3)
    assert topology.validate(one["routers"], one["roles"]) == []
    inside = [r for r, cfg in one["routers"].items() if cfg["asn"] == 65000]
    assert len(inside) == len(t["routers"]) and one["roles"]["origins"] == ["ext-1"] and len(one["roles"]["externals"]) == 3
    reflectors = [r for r in inside if any(n.get("rrClient") for n in one["routers"][r]["neighbors"])]
    assert len(reflectors) == 2
    text = topology.dump(one["routers"], one["roles"])
    again = topology.parse(text)
    assert topology.dump(again["routers"], again["roles"]) == text


def test_igp_med_and_leak_are_checked_and_written():
    routers = ibgp_as(False)
    routers["a"]["igp"] = [{"name": "b", "cost": 10}]
    routers["b"]["igp"] = [{"name": "a", "cost": 10}]
    routers["x"]["neighbors"][0]["med"] = 5
    routers["x"]["neighbors"][0]["denyVia"] = 65009
    routers["x"]["leak"] = True
    assert topology.validate(routers) == []
    again = topology.parse(topology.dump(routers))["routers"]
    assert again["a"]["igp"] == [{"name": "b", "cost": 10}] and again["x"]["neighbors"][0]["med"] == 5 and again["x"]["leak"] is True
    assert again["x"]["neighbors"][0]["denyVia"] == 65009
    routers["b"]["igp"][0]["cost"] = 3
    routers["a"]["igp"].append({"name": "x", "cost": 1})
    routers["a"]["neighbors"][0]["med"] = 1
    problems = " ".join(topology.validate(routers))
    assert "b does not list the IGP link with cost 10" in problems and "IGP link to x leaves the AS" in problems
    assert "MED towards b must be a number from 0, to another AS" in problems


def test_a_deleted_file_is_forgotten_by_the_cache(lab_files):
    from lab import scenario

    topology.save("t-gone", {"a": {"asn": 1, "routerId": "10.0.0.1", "neighbors": []}})
    topology.load("t-gone")
    scenario.path("t-gone").write_text("name: t-gone\nsteps:\n  - wait: 1\n")
    scenario.load("t-gone")
    topology.path("t-gone").unlink()
    scenario.path("t-gone").unlink()
    assert "t-gone" not in topology.names() and "t-gone" not in scenario.names()
    assert topology.path("t-gone") not in topology._parsed and scenario.path("t-gone") not in scenario._parsed


def test_a_tag_is_a_community_towards_another_as():
    routers = {"a": {"asn": 1, "routerId": "10.0.0.1", "neighbors": [{"name": "b", "peerAs": 2, "tag": "0:3"}]},
               "b": {"asn": 2, "routerId": "10.0.0.2", "neighbors": [{"name": "a", "peerAs": 1, "tag": "no-export"}]}}
    assert topology.validate(routers) == []
    assert topology.parse(topology.dump(routers))["routers"]["a"]["neighbors"][0]["tag"] == "0:3"  # stays a text
    routers["a"]["neighbors"][0]["tag"] = "0:70000"
    assert any("tag of b" in p for p in topology.validate(routers))


def test_partial_transit_is_for_customers():
    routers = {"p": {"asn": 1, "routerId": "10.0.0.1", "neighbors": [{"name": "c", "peerAs": 2, "relation": "customer", "partialTransit": True}]},
               "c": {"asn": 2, "routerId": "10.0.0.2", "neighbors": [{"name": "p", "peerAs": 1, "relation": "provider"}]}}
    assert topology.validate(routers) == []
    assert "partialTransit: true" in topology.dump(routers)
    routers["c"]["neighbors"][0]["partialTransit"] = True  # the customer cannot give its provider partial transit
    assert any("partial transit is for a customer" in p for p in topology.validate(routers))


def test_a_route_server_serves_other_ases_only():
    from lab import topology

    t = topology.load("ixp")
    assert topology.validate(t["routers"], t["roles"]) == []
    t["routers"]["a"]["asn"] = 65100  # now in the route server's AS
    t["routers"]["o"]["neighbors"][0]["peerAs"] = 65100
    t["routers"]["rs"]["neighbors"][0]["peerAs"] = 65100
    t["routers"]["a"]["neighbors"][1]["peerAs"] = 65100
    assert any("cannot be a route server client" in p for p in topology.validate(t["routers"], t["roles"]))


def test_a_role_has_a_name_of_its_own():
    from lab import topology

    t = topology.load("ixp")
    for bad in ({"rs": ["a"]}, {"Clients": ["a"]}):
        assert any("names use lowercase" in p for p in topology.validate(t["routers"], {**t["roles"], **bad}))
