"""The case page of the Simulation, simulation.js and the map of sim-map.js,
run in Node on small runs made by hand: what a visitor reads at a step must
follow from the run."""

import json
import re
import shutil
import subprocess

import pytest

from lab.config import ROOT

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="needs node")

# The page's script with its inner functions handed out, on a document that only records.
STUBS = """
const store = {};
function El() {
  const e = { children: [], dataset: {}, style: {}, attrs: {}, innerHTML: "", textContent: "", hidden: false, value: "",
    classList: { toggle() {} }, append() {}, prepend() {}, replaceChildren() {}, setAttribute() {}, getAttribute() {},
    hasAttribute: () => false, getBoundingClientRect: () => ({ left: 0, right: 100 }), addEventListener() {},
    querySelector: (s) => q(s), querySelectorAll: () => [], insertAdjacentHTML(_, h) { e.innerHTML += h; }, closest: () => null,
    selectedOptions: [] };
  return e;
}
const q = (s) => (store[s] ||= El());
const root = q("#sim");
root.dataset = { modes: JSON.stringify(PER_MODE), proof: "outside its model", search: "1", finding: "1" };
global.UI = { css: () => "", icon: () => "" };
global.matchMedia = () => ({ matches: false });
global.ResizeObserver = class { observe() {} };
global.requestAnimationFrame = () => 0;
global.fetch = () => new Promise(() => {});
global.document = {
  getElementById: (id) => (id === "sim" ? root : id === "sim-example" ? { textContent: JSON.stringify(EXAMPLE) }
    : id === "pure-modes" ? { textContent: JSON.stringify(["bgp", "obgp-rp", "obgp-sp", "obgp-hp", "obgp-np", "obgp-paper"]) } : null),
  createElementNS: El, createElement: El, addEventListener() {}, querySelector: (s) => q(s), querySelectorAll: () => [],
};
"""


def page(example: dict, per_mode: dict, calls: str) -> dict:
    """Runs simulation.js on a case and returns what calls, JavaScript with the page's functions in scope, gives."""
    source = (ROOT / "lab/web/static/simulation.js").read_text()
    source = re.sub(r"\}\)\(\);\s*$", f"process.stdout.write(JSON.stringify((() => {{ {calls} }})()));\n}})();", source)
    script = f"const EXAMPLE = {json.dumps(example)}, PER_MODE = {json.dumps(per_mode)};\n{STUBS}\n{source}"
    done = subprocess.run(["node", "-"], input=script, capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def plain(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html).replace("⁠", "").replace(" ", " ")


def router(best=None, hop=-1, ins=(), outs=(), exported=None, waits=False):
    return {"best": best, "next_hop": hop, "forward": hop, "admitted": [], "set_aside": [], "exported": exported if exported is not None else best,
            "waits": waits, "in": list(ins), "out": list(outs)}


def got(sender, path=None, fate="none", over="ebgp", **more):
    return {"from": sender, "path": path, "fate": fate, "over": over, **more}


def sends(to, path=None, why=""):
    return {"to": to, "path": path, **({"not": why} if why else {})}


def test_routes_name_an_aggregate_once_prepends_as_such_and_confederation_segments_in_full():
    example = {"instance": {"routers": 3, "links": [[0, 1], [1, 2]], "origin_set": [64601, 64600], "confeds": [{"members": [1, 2], "id": 65500}]},
               "finding": {"mode": "obgp-rp", "kind": "transient-hole", "routers": None, "detail": ""}}
    r = router([65002, 65001], 0, ins=[got(0, [65002, 65001], "best")])
    out = page(example, {}, f"""const r = {json.dumps(r)};
      return [route([65002, 65001, 64600, 64601]), route([64601, 64600]), route([65002, 65001, 65001, 65001]),
              route(full(r, [0, 65001])), route(listOf([65003, 65002, 65001]))];""")
    assert [plain(x) for x in out] == ["via r1→r0", "own prefix", "via r1→r0, r0 prepended 2×", "via r1→r0", "via the confederation→r0"]


def test_a_router_without_a_route_hears_why_from_every_neighbor_that_has_one():
    # Router 2 of confederation 65500 lost its link to router 3, the other member. Router 1 offers, as OBGP does,
    # the worst path it admitted, which runs through 65500: router 2 cannot take it.
    example = {"instance": {"routers": 4, "links": [[0, 1], [0, 3], [1, 2], [2, 3]], "confeds": [{"members": [2, 3], "id": 65500}],
                            "events": [{"after": 1 << 30, "kind": "down", "from": 2, "to": 3}]},
               "finding": {"mode": "obgp-rp", "kind": "unreachable", "routers": [2], "detail": ""}}
    rest = {"kind": "event", "event": {"kind": "down", "from": 2, "to": 3}, "sent": 0, "routers": [
        router([], 0, ins=[got(1), got(3)], outs=[sends(1, [65001]), sends(3, [65001])]),
        router([65001], 0, ins=[got(0, [65001], "best"), got(3, [65500, 65001], "admitted", lost="shorter AS path"), got(2)],
               outs=[sends(0, why="its AS is in the path"), sends(2, why="its AS is in the path")], exported=[65500, 65001]),
        router(None, ins=[got(1), got(3, over="confed")], outs=[sends(1, why="nothing to offer"), sends(3, why="the session is down")]),
        router([65001], 0, ins=[got(0, [65001], "best"), got(2, over="confed")],
               outs=[sends(0, why="back to its source"), sends(1, [65500, 65001]), sends(2, why="the session is down")])]}
    trace = {"mode": "obgp-rp", "result": {"converged": True}, "steps": [rest], "problem": {"at": 1}}
    told = page(example, {"obgp-rp": {"routers": [2]}}, f"const t = {json.dumps(trace)}; return why(t);")
    assert plain(told) == ("r1 offers only via AS 65500→r0, which runs through r2's confederation 65500. "
                           "r3 offers only via r0, but its link to r2 is down.")


def test_a_loop_from_a_message_sent_before_its_sender_changed_says_so():
    # The origin withdraws. Router 1 then gets router 2's route, sent at the start, while router 2 already uses router 1's.
    example = {"instance": {"routers": 3, "links": [[0, 1], [0, 2], [1, 2]]}, "finding": {"mode": "bgp", "kind": "transient-loop", "routers": None, "detail": ""}}
    gone = {"kind": "event", "event": {"kind": "withdraw"}, "sent": 0, "routers": [
        router(None), router([65001], 0, ins=[got(0, [65001], "best")]), router([65002, 65001], 1, ins=[got(1, [65002, 65001], "best")], outs=[sends(1, why="back to its source")])]}
    late = {"kind": "update", "from": 2, "to": 1, "path": [65003, 65001], "sent": 0, "loop": [1, 2], "routers": [
        router(None), router([65003, 65001], 2, ins=[got(2, [65003, 65001], "best")]), gone["routers"][2]]}
    trace = {"mode": "bgp", "result": {"converged": True}, "steps": [gone, late], "problem": {"at": 2}}
    told = plain(page(example, {"bgp": {"routers": []}}, f"const t = {json.dumps(trace)}; return why(t);"))
    assert told.startswith("r1 takes via r2→r0 from a message r2 sent at the start, before r2's offer changed.")
    assert "r1 only knows r2's route. r2 only knows r1's route." in told
    # Still offered among several routes, as a route server does: the offer did not change.
    still = {**gone, "routers": gone["routers"][:2] + [{**gone["routers"][2], "out": [sends(1, [65001]), sends(1, [65003, 65001])]}]}
    trace = {**trace, "steps": [still, {**late, "routers": late["routers"][:2] + still["routers"][2:]}]}
    told = plain(page(example, {"bgp": {"routers": []}}, f"const t = {json.dumps(trace)}; return why(t);"))
    assert "offer changed" not in told


def model(inst: dict, trace: dict, calls: str):
    """Runs sim-map.js's model of a run, without the page, and returns what calls gives with the model as m."""
    source = (ROOT / "lab/web/static/sim-map.js").read_text()
    script = (f"global.window = {{}}; global.document = {{ addEventListener() {{}} }};\n{source}\n"
              f"const m = window.SimMap.model({json.dumps(inst)}, {json.dumps(trace)});\n"
              f"process.stdout.write(JSON.stringify((() => {{ {calls} }})()));")
    done = subprocess.run(["node", "-"], input=script, capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def triangle_loop():
    """The origin withdraws. Router 1 then gets router 2's route, sent at the start, while router 2 already uses router 1's."""
    inst = {"routers": 3, "links": [[0, 1], [0, 2], [1, 2]]}
    start = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [
        router([], 0, outs=[sends(1, [65001]), sends(2, [65001])]), router([65001], 0, ins=[got(0, [65001], "best")], outs=[sends(0, why="back to its source"), sends(2, [65002, 65001])]),
        router(None)]}
    gone = {"kind": "event", "event": {"kind": "withdraw"}, "sent": 0, "routers": [
        router(None, outs=[sends(1, why="nothing to offer"), sends(2, why="nothing to offer")]), start["routers"][1],
        router([65002, 65001], 1, ins=[got(1, [65002, 65001], "best")], outs=[sends(1, why="back to its source"), sends(0, [65003, 65002, 65001])])]}
    late = {"kind": "update", "from": 2, "to": 1, "path": [65003, 65001], "sent": 0, "loop": [1, 2], "routers": [
        gone["routers"][0], router([65003, 65001], 2, ins=[got(2, [65003, 65001], "best"), got(0)], outs=[sends(2, why="back to its source")]), gone["routers"][2]]}
    news = {"kind": "withdraw", "from": 0, "to": 1, "path": None, "sent": 2, "routers": late["routers"]}
    return inst, {"mode": "bgp", "result": {"converged": True}, "steps": [start, gone, late, news]}


def test_every_step_arrives_and_a_step_that_makes_messages_also_sends():
    inst, trace = triangle_loop()
    told = model(inst, trace, "return [m.TL, m.K, m.loopAt(2)];")
    # The start sends, the first update arrives, the withdrawal happens and sends, the late update arrives, the news arrives.
    assert [[t["k"], t["ph"]] for t in told[0]] == [[-1, "arrive"], [-1, "send"], [0, "arrive"], [1, "arrive"], [1, "send"], [2, "arrive"], [3, "arrive"]]
    assert told[1] == 2 and told[2] == [1, 2]


def test_a_late_route_is_no_longer_true_and_the_router_forwards_on_it():
    inst, trace = triangle_loop()
    told = model(inst, trace, "return [m.untrue(1, 2), m.arrivalText(2), m.arrivalText(0)];")
    assert told[0] is True
    assert told[1][0] == "This route is stale: its sender no longer sends it. Forwards on it now. Drops r0's route."
    assert told[2][0] == "Forwards on it now."


def test_what_leaves_is_grouped_by_message_and_says_why_not_to_others():
    inst, trace = triangle_loop()
    told = model(inst, trace, "return [m.sendItems(-1), m.whyNot(2, 1), m.eventItems({kind: 'withdraw'}), m.eventItems({kind: 'down', from: 1, to: 2, value: 1})];")
    assert told[0] == [[0, ["Sends r1 its route:", {"chips": [65001]}]], [2, ["Sends r1 its route:", {"chips": [65003, 65001]}]]]
    assert told[1] == ["Not back to r2: it came from there."]  # "nothing to offer" goes without saying
    assert told[2] == [0, "Withdraws its prefix. It has no route now."]
    assert told[3] == [1, "Its link to r2 is cut. Both ends keep the routes as stale for now."]


def test_obgp_says_when_the_threshold_moves_and_shows_it_in_the_table():
    inst = {"routers": 3, "links": [[0, 1], [0, 2], [1, 2]]}
    first = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [
        router([], 0), router([65001], 0, ins=[got(0, [65001], "best")], outs=[sends(0, why="back to its source"), sends(2, [65002, 65001])]),
        router([65001], 0, outs=[sends(1, [65003, 65001])])]}
    longer = {"kind": "update", "from": 2, "to": 1, "path": [65003, 65001], "sent": 0, "routers": [
        router([], 0), {**router([65001], 0, ins=[got(0, [65001], "best"), got(2, [65003, 65001], "admitted", lost="shorter AS path")],
                                outs=[sends(0, why="back to its source"), sends(2, [65002, 65003, 65001])], exported=[65003, 65001]),
                        "admitted": [[65001], [65003, 65001]]}, first["routers"][2]]}
    told = model(inst, {"mode": "obgp-rp", "result": {"converged": True}, "steps": [first, longer]}, "return [m.arrivalText(1), m.rowsOf(1, 1)];")
    assert told[0][:3] == ["Keeps it, but does not forward on it: the other is shorter.", "Its threshold is now:", {"chips": [65002, 65003, 65001]}]
    assert [r["text"] for r in told[1]] == ["forwards on", "threshold"]


def test_a_router_without_a_route_at_rest_is_marked_from_its_last_change():
    example = {"instance": {"routers": 3, "links": [[0, 1], [1, 2]]}, "finding": {"mode": "obgp-rp", "kind": "unreachable", "routers": [2], "detail": ""}}
    has = {"kind": "update", "from": 0, "to": 1, "sent": 0, "routers": [router([], 0), router([65001], 0), router([65002, 65001], 1)]}
    lost = {"kind": "withdraw", "from": 1, "to": 2, "sent": 1, "routers": [router([], 0), router([65001], 0), router(None)]}
    quiet = {"kind": "update", "from": 2, "to": 1, "sent": 2, "routers": lost["routers"]}
    trace = {"mode": "obgp-rp", "result": {"converged": True}, "steps": [has, lost, quiet]}
    assert page(example, {"obgp-rp": {"routers": [2]}}, f"return marksOf({json.dumps(trace)});") == [[], [2], [2]]
    assert page(example, {"obgp-rp": {"routers": [2]}}, f"return marksOf({json.dumps({**trace, 'mode': 'bgp'})});") == [[], [], []]


def test_an_aggregate_or_a_confederation_in_front_does_not_make_a_route_untrue():
    # The origin offers its prefix with the aggregate's AS_SET, its message carries the path without it.
    inst = {"routers": 2, "links": [[0, 1]], "origin_set": [64600]}
    step = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [
        router([], 0, outs=[sends(1, [65001, 64600])]), router([65001], 0, ins=[got(0, [65001], "best")])]}
    assert model(inst, {"mode": "bgp", "result": {"converged": True}, "steps": [step]}, "return m.untrue(0, 0);") is False
    # Inside a confederation the sender offers its member AS in front, the message does not carry it.
    inst = {"routers": 3, "links": [[0, 1], [1, 2]], "confeds": [{"members": [1, 2], "id": 65500}]}
    step = {"kind": "update", "from": 1, "to": 2, "path": [65001], "sent": 0, "routers": [
        router([], 0), router([65001], 0, outs=[sends(2, [65002, 65001])]), router([65001], 1)]}
    assert model(inst, {"mode": "bgp", "result": {"converged": True}, "steps": [step]}, "return m.untrue(0, 0);") is False


def test_a_waiting_router_keeps_what_it_set_aside_and_pruning_is_said():
    inst = {"routers": 3, "links": [[0, 1], [1, 2], [0, 2]]}
    before = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [
        router([], 0), router([65001], 0, ins=[got(0, [65001], "best"), got(2, [65003, 65001], "admitted")]), router([65001], 0)]}
    waits = {**router(None, ins=[got(0), got(2, [65003, 65001], "pruned")], waits=True), "set_aside": [[65003, 65002, 65001]]}
    gone = {"kind": "withdraw", "from": 0, "to": 1, "path": None, "sent": 0, "routers": [router([], 0), waits, router([65001], 0)]}
    told = model(inst, {"mode": "obgp-hp", "result": {"converged": True}, "steps": [before, gone]}, "return [m.rowsOf(1, 1), m.arrivalText(1)];")
    assert [r["text"] for r in told[0]] == ["waits for a refresh", "set aside", "pruned"]
    assert "Drops r2's route too: a withdrawal through the same ASes prunes it until r2 sends it again." in told[1][0]


def test_reasons_name_the_relation_the_filter_and_why_a_route_wins():
    inst = {"routers": 4, "links": [[0, 1], [1, 2], [1, 3]], "peers": [[0, 1]], "customers": [[2, 1]],
            "sessions": [{"from": 1, "to": 3, "deny_via": 65001}]}
    rt = router([65001], 0, ins=[got(0, [65001], "best")], outs=[sends(0, why="back to its source"), sends(2, why="the relation forbids it"),
                                                                 sends(3, why="the export filter drops it")])
    step = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [router([], 0), rt, router(None), router(None)]}
    told = model(inst, {"mode": "bgp", "result": {"converged": True}, "steps": [step]}, "return m.whyNot(0, 1);")
    assert told == ["Not back to r0: it came from there.", "Not to r2: a route from its peer goes only to its customers.",
                    "Not to r3: it sends no path through r0 there."]
    # Local preference makes the longer route win: the bubble says so.
    inst = {"routers": 3, "links": [[0, 1], [1, 2], [0, 2]]}
    first = {"kind": "update", "from": 0, "to": 2, "path": [65001], "sent": 0, "routers": [
        router([], 0), router([65001], 0, outs=[sends(2, [65002, 65001])]), router([65001], 0, ins=[got(0, [65001], "best")])]}
    second = {"kind": "update", "from": 1, "to": 2, "path": [65002, 65001], "sent": 0, "routers": [
        router([], 0), router([65001], 0, outs=[sends(2, [65002, 65001])]), router([65002, 65001], 1, ins=[got(0, [65001], "admitted", lost="higher local preference"), got(1, [65002, 65001], "best")])]}
    told = model(inst, {"mode": "bgp", "result": {"converged": True}, "steps": [first, second]}, "return m.arrivalText(1);")
    assert told[0] == "Forwards on it now: it has a higher local preference. Keeps r0's route as well."


def test_groups_get_letters_policies_follow_events_and_a_leak_is_said():
    inst = {"routers": 4, "as": [0, 1, 1, 2], "links": [[0, 1], [1, 2], [2, 3]], "confeds": [], "sessions": [{"from": 2, "to": 3, "local_pref": 200}]}
    gone = {"kind": "event", "event": {"kind": "local-pref", "from": 2, "to": 3, "value": 0}, "sent": 0, "routers": [router([], 0)] + [router(None)] * 3}
    told = model(inst, {"mode": "bgp", "result": {"converged": True}, "steps": [gone]},
                 "return [m.groups.map((g) => [g.letter, g.kind, g.members]), m.policy(-1, 2, 3).local_pref, m.policy(0, 2, 3).local_pref];")
    assert told == [[["A", "AS", [1, 2]]], 200, 0]
    # r1 leaks its provider r0's route to its other provider r2.
    inst = {"routers": 3, "links": [[0, 1], [1, 2]], "customers": [[0, 1], [2, 1]], "leakers": [1]}
    step = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [
        router([], 0), router([65001], 0, ins=[got(0, [65001], "best")], outs=[sends(2, [65002, 65001])]), router(None)]}
    leak = {"kind": "update", "from": 1, "to": 2, "path": [65002, 65001], "sent": 1, "routers": step["routers"]}
    told = model(inst, {"mode": "bgp", "result": {"converged": True}, "steps": [step, leak]}, "return m.sendItems(0);")
    assert told[0][1][-1] == "That is a leak: r2 is its provider, and so is r0, where the route comes from."


def test_forwarding_by_ingress_shows_where_a_neighbors_packets_go_and_when_that_changes():
    inst = {"routers": 3, "links": [[0, 1], [1, 2], [0, 2]]}
    def r1(hop2):
        return {**router([65001], 0, outs=[sends(2, [65002, 65001])]), "ingress": {"2": {"path": [65001], "next_hop": hop2}}}
    a = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [router([], 0), r1(0), router([65001], 0)]}
    b = {"kind": "update", "from": 2, "to": 1, "path": [65003, 65001], "sent": 0, "routers": [router([], 0), r1(2), router([65001], 0)]}
    told = model(inst, {"mode": "bgp-pn", "result": {"converged": True}, "steps": [a, b]}, "return [m.rowsOf(0, 1), m.rowsOf(1, 1), m.arrivalText(1)];")
    assert [r["text"] for r in told[0]] == ["forwards on"]
    assert [r["text"] for r in told[1]] == ["forwards on", "from r2, on to r2"]
    assert "Packets from r2 now go on to r2." in told[2][0]


def test_beside_the_counter_each_position_says_what_kind_of_step_it_is():
    inst, trace = triangle_loop()
    told = model(inst, trace, "return m.TL.map((_, i) => m.phaseText(i));")
    assert told == ["Start", "r0 and r2 send", "r0's update arrives at r1", "From outside at r0: withdraws its prefix", "r0 sends",
                    "r2's update arrives at r1", "r0's withdrawal arrives at r1"]


def test_a_route_is_no_longer_true_only_once_its_sender_changed():
    # r2 queues r1's route to r3. r1 loses it before it arrives, but its withdrawal has not reached r2: r2 still offers
    # the route, so it stays true, also as the message of the loop.
    inst = {"routers": 4, "links": [[0, 1], [1, 2], [2, 3], [3, 1]]}
    r1 = router([65001], 0, ins=[got(0, [65001], "best")], outs=[sends(2, [65002, 65001]), sends(3, [65002, 65001])])
    r2 = router([65002, 65001], 1, ins=[got(1, [65002, 65001], "best")], outs=[sends(3, [65003, 65002, 65001])])
    has = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [router([], 0), r1, router(None), router(None)]}
    on = {"kind": "update", "from": 1, "to": 2, "path": [65002, 65001], "sent": 1, "routers": [router([], 0), r1, r2, router(None)]}
    gone = {"kind": "event", "event": {"kind": "withdraw"}, "sent": 0, "routers": [router(None), r1, r2, router(None)]}
    lost = {"kind": "withdraw", "from": 0, "to": 1, "path": None, "sent": 3, "routers": [router(None), router(None, ins=[got(0)]), r2, router(None)]}
    late = {"kind": "update", "from": 2, "to": 3, "path": [65003, 65002, 65001], "sent": 2, "loop": [2, 3], "routers": [
        router(None), lost["routers"][1], r2, router([65003, 65002, 65001], 2, ins=[got(2, [65003, 65002, 65001], "best")])]}
    trace = {"mode": "bgp", "result": {"converged": True}, "steps": [has, on, gone, lost, late]}
    told = model(inst, trace, "return [m.K, m.untrue(1, 4), m.untrue(3, 4), m.arrivalText(4)[0]];")
    assert told == [4, False, False, "Forwards on it now."]
    # Once r2 learns of it and offers r3 nothing, the route is no longer true. Never at the step it was queued.
    knows = {"kind": "withdraw", "from": 1, "to": 2, "path": None, "sent": 4, "routers": [router(None), router(None), router(None), router(None)]}
    told = model(inst, {**trace, "steps": [has, on, gone, lost, knows, late]}, "return [m.untrue(1, 5), m.untrue(4, 5)];")
    assert told == [False, True]


def test_a_route_server_offers_one_neighbor_several_routes_and_each_stays_true():
    inst = {"routers": 3, "links": [[0, 1], [1, 2], [0, 2]], "route_servers": [1]}
    rs = router([65001], 0, outs=[sends(2, [65001]), sends(2, [65003, 65001])])
    other = {"kind": "update", "from": 0, "to": 2, "path": [65001], "sent": 1, "routers": [router([], 0), rs, router([65001], 0)]}
    step = {"kind": "update", "from": 1, "to": 2, "path": [65003, 65001], "sent": 1, "routers": other["routers"]}
    assert model(inst, {"mode": "bgp", "result": {"converged": True}, "steps": [other, step]}, "return m.untrue(0, 1);") is False


def test_a_withdrawn_pruned_route_is_dropped_and_a_run_without_rest_does_not_say_it_sends_nothing():
    inst = {"routers": 3, "links": [[0, 1], [1, 2], [0, 2]]}
    pruned = router(None, ins=[got(0), got(2, [65003, 65001], "pruned")])
    a = {"kind": "withdraw", "from": 0, "to": 1, "path": None, "sent": 0, "routers": [router([], 0), pruned, router([65001], 0)]}
    b = {"kind": "withdraw", "from": 2, "to": 1, "path": None, "sent": 0, "routers": [router([], 0), router(None, ins=[got(0), got(2)]), router([65001], 0)]}
    told = model(inst, {"mode": "obgp-hp", "result": {"converged": True}, "steps": [a, b]}, "return [m.arrivalText(1), m.rowsOf(0, 1)];")
    assert told[0] == ["Drops r2's pruned route."]
    # A row knows the neighbor it came from, so a route server's mark goes only on the route that came through it.
    assert [(r["text"], r.get("from")) for r in told[1]] == [("pruned", 2)]
    # The last step of a run without rest: r1 changes its offer, the message it queued is not in the run.
    first = {"kind": "update", "from": 0, "to": 1, "path": [65001], "sent": 0, "routers": [
        router([], 0), router([65001], 0, ins=[got(0, [65001], "best")], outs=[sends(0, why="back to its source")]), router(None)]}
    second = {**first, "routers": [router([], 0), {**first["routers"][1], "out": [sends(0, why="back to its source"), sends(2, [65002, 65001])]}, router(None)]}
    for result, says in [({"converged": False}, False), ({"converged": True}, True)]:
        told = model(inst, {"mode": "bgp", "result": result, "steps": [first, second]}, "return m.arrivalText(1);")
        assert ("Sends nothing." in told) is says
