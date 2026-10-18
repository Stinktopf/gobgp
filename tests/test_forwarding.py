"""The forwarding check of the lab, the simulator's ported: same networks,
same verdicts (internal/pkg/obgpsim/sim_test.go)."""

from lab import forwarding, runner


def rr_network() -> dict:
    """TestFilteredIBGPLoopsBehindARouteReflector: routers r1, r2 and r4 share AS
    65002 behind reflector r2, IGP links r1-r2 and r1-r4 of cost 10."""
    asn = {"r0": 65001, "r1": 65002, "r2": 65002, "r3": 65004, "r4": 65002}
    igp = {"r1": [{"name": "r2", "cost": 10}, {"name": "r4", "cost": 10}], "r2": [{"name": "r1", "cost": 10}], "r4": [{"name": "r1", "cost": 10}]}
    return {r: {"asn": a, "igp": igp.get(r, [])} for r, a in asn.items()}


def test_the_loop_the_simulator_finds_behind_a_route_reflector():
    # The next hops of OBGP with iBGP filtered in the simulator: r1 to r2, r2 to r4.
    hops = {"r0": "r0", "r1": "r2", "r2": "r4", "r3": "r0", "r4": "r0"}
    assert forwarding.check(rr_network(), hops) == ["forwarding loops between r1, r2"]
    # BGP's: r1 and r2 both to r4, no loop.
    assert forwarding.check(rr_network(), {**hops, "r1": "r4"}) == []


def test_a_next_hop_without_a_route_is_a_black_hole():
    hops = {"r0": "r0", "r1": "r4", "r2": "r4", "r3": "r0", "r4": None}
    assert forwarding.check(rr_network(), hops, ["r1"]) == ["forwarding from r1 ends at a router without a route"]


def test_equal_paths_are_broken_as_the_simulator_breaks_them():
    # r0 to r3 over r1 or r2 at the same cost: the first found, r1, as Floyd-Warshall in the simulator.
    routers = {r: {"asn": 1, "igp": []} for r in ("r0", "r1", "r2", "r3")}
    for a, b in (("r0", "r1"), ("r0", "r2"), ("r1", "r3"), ("r2", "r3")):
        routers[a]["igp"].append({"name": b, "cost": 1})
        routers[b]["igp"].append({"name": a, "cost": 1})
    assert forwarding.shortest(routers)["r0"]["r3"] == "r1"


def test_routes_of_the_routers_become_next_hops():
    tables = {"r0": {"p": {"from": None, "as_path": [], "next_hop": "0.0.0.0"}},
              "r1": {"p": {"from": "r2", "as_path": [65004, 65001], "next_hop": "10.1.0.2"}},
              "r2": {"p": {"from": "r4", "as_path": [65001], "next_hop": "10.1.0.4"}},
              "r3": {"p": {"from": "r0", "as_path": [65001], "next_hop": "10.1.0.0"}},
              "r4": {"p": {"from": "r0", "as_path": [65001], "next_hop": "10.1.0.0"}}}
    addresses = {f"10.1.0.{i}": f"r{i}" for i in range(5)}
    assert runner.check_forwarding(rr_network(), {"p"}, tables, addresses, ["r1"]) == ["p: forwarding loops between r1, r2"]


def test_an_as_whose_borders_send_different_paths_is_inconsistent():
    topology = {"a": {"asn": 65002}, "b": {"asn": 65002}, "x": {"asn": 65001}, "y": {"asn": 65003}}
    same = {"a": {"x": {"p": [65002, 65004, 9]}}, "b": {"y": {"p": [65002, 65002, 65004, 9]}}}  # b prepends: the same path
    assert runner.check_consistency(topology, {"p"}, same) == []
    other = {"a": {"x": {"p": [65002, 65004, 9]}}, "b": {"y": {"p": [65002, 65005, 9]}}}
    assert runner.check_consistency(topology, {"p"}, other) == ["p: AS 65002 offers 2 different paths"]


def test_an_igp_step_changes_the_costs_the_check_uses():
    routers = rr_network()
    changed = runner.with_igp(routers, {frozenset(("r1", "r4")): 0})
    assert changed["r1"]["igp"] == [{"name": "r2", "cost": 10}] and changed["r4"]["igp"] == []
    assert routers["r1"]["igp"] == [{"name": "r2", "cost": 10}, {"name": "r4", "cost": 10}]  # the topology stays
    hops = {"r0": "r0", "r1": "r2", "r2": "r4", "r3": "r0", "r4": "r0"}
    assert forwarding.check(changed, hops, ["r1"]) == ["forwarding from r1 ends at a router without a route"]
