"""Where packets go, from the best routes of the routers: the same check as
the simulator's (internal/pkg/obgpsim/oracle.go), so that the lab and the
simulator judge a network alike.

A packet goes to the BGP next hop of the router it is at: over the session
to a neighbor in another AS, or, inside an AS, one IGP hop towards the
next hop over the cheapest links, where the next router decides again. No
IGP runs: the costs of the topology are the IGP. Ties between equally
cheap paths are broken as the simulator breaks them, by the order of the
routers and links in the topology.

A router with a table per neighbor, NS-BGP (bgp-pn) and OBGP (-pn) alike,
forwards by ingress: it sends a packet from an eBGP neighbor on the route
it sends that neighbor, and inside an AS through a tunnel to the exit, the
router of the route's next AS beside its border router, as the paper of
NS-BGP forwards. Its next hops are then an Ingress. In a mixed mode the
routers with one table forward on their best route, whoever sent the packet.
"""

import functools


class Ingress(dict):
    """Where a router with a table per neighbor sends packets: by the eBGP neighbor they came
    from, None for its own, each the router its route leads to and the first
    AS of the route, None for none."""


def links(routers: dict) -> list[tuple[str, str, int]]:
    """The IGP links of a topology, each once, in the order of the file."""
    out, seen = [], set()
    for name, r in routers.items():
        for link in r.get("igp", []):
            pair = frozenset((name, link["name"]))
            if pair not in seen:
                seen.add(pair)
                out.append((name, link["name"], int(link["cost"])))
    return out


def shortest(routers: dict) -> dict[str, dict[str, str | None]]:
    """The first IGP hop from a router towards another of its AS, or None.
    Floyd-Warshall as in the simulator, keeping the first of equal paths.
    Kept for each set of routers and links: the analysis checks forwarding
    tens of thousands of times a run, while the costs change only with an
    igp step. Callers only read the answer."""
    return _shortest(tuple(routers), tuple(links(routers)))


@functools.lru_cache(maxsize=64)
def _shortest(names: tuple[str, ...], edges: tuple[tuple[str, str, int], ...]) -> dict[str, dict[str, str | None]]:
    inf = float("inf")
    dist = {a: {b: (0 if a == b else inf) for b in names} for a in names}
    first = {a: {b: (a if a == b else None) for b in names} for a in names}
    for a, b, cost in edges:
        for x, y in ((a, b), (b, a)):
            if cost < dist[x][y]:
                dist[x][y], first[x][y] = cost, y
    for k in names:
        for a in names:
            for b in names:
                if dist[a][k] + dist[k][b] < dist[a][b]:
                    dist[a][b], first[a][b] = dist[a][k] + dist[k][b], first[a][k]
    return first


def exit_of(routers: dict, border: str, asn: int | None) -> str | None:
    """The router in AS asn beside a border router, the first of its
    neighbors, as the simulator's tunnelExit, None for none. asn may also be
    the router's confederation."""
    for n in routers[border].get("neighbors", []):
        other = routers.get(n["name"])
        if other and asn is not None and asn in (int(other["asn"]), other.get("confederation")) and other["asn"] != routers[border]["asn"]:
            return n["name"]
    return None


def check(routers: dict, next_hops: dict, starts: list[str] | None = None) -> list[str]:
    """The problems of forwarding one prefix from the starts, all routers if
    none: next_hops gives for every router the router its best route leads
    to, itself for the origin, None for no route, or with a table per neighbor an Ingress.
    Loops and black holes, as the simulator names them."""
    igp = shortest(routers)
    asn = {name: str(r.get("asn")) for name, r in routers.items()}
    by_ingress = lambda name: isinstance(next_hops.get(name), Ingress)

    # Packets of a route server's clients come straight from them, sent on
    # the route the router sends the route server, as the simulator has it.
    clients = {name: {n["name"] for n in r.get("neighbors", []) if n.get("rsClient")} for name, r in routers.items()}

    def route(at: str, came: str | None) -> tuple[str | None, int | None]:
        v = next_hops.get(at)
        if v == at:  # the origin, or a router the analysis does not know yet: packets end there, from any neighbor
            return at, None
        if isinstance(v, Ingress):
            if came not in v:
                came = next((rs for rs in v if rs is not None and came in clients.get(rs, ())), came)
            return v.get(came) or (None, None)
        return v, None  # one table: its best route, whoever sent the packet

    loops, holes = {}, []
    for start in starts if starts is not None else routers:
        if route(start, None)[0] is None:
            continue
        seen, state = [], (start, None)
        while True:
            at, came = state
            hop, first = route(at, came)
            if hop is None:
                holes.append(start)
                break
            if hop == at:
                break  # the origin
            if state in seen:
                cycle = sorted({x for x, _ in seen[seen.index(state):]})
                loops[tuple(cycle)] = cycle
                break
            seen.append(state)
            nxt, came = hop, at
            if hop in asn and asn[hop] == asn[at]:
                if by_ingress(at):  # the tunnel ends at the exit, or at the origin if it is in this AS
                    nxt, came = (exit_of(routers, hop, first), hop) if first is not None else (hop, None)
                else:
                    nxt, came = igp[at][hop], None
            if nxt is None or not by_ingress(nxt) and next_hops.get(nxt) is None:
                holes.append(start)
                break
            state = (nxt, came if by_ingress(nxt) else None)
    problems = [f"forwarding loops between {', '.join(c)}" for c in loops.values()]
    if holes:
        problems.append(f"forwarding from {', '.join(holes)} ends at a router without a route")
    return problems


def with_igp(routers: dict, costs: dict) -> dict:
    """The routers with the costs igp steps set, 0 taking a link away."""
    if not costs:
        return routers
    out = {}
    for name, r in routers.items():
        links = [{**link, "cost": costs.get(frozenset((name, link["name"])), link["cost"])} for link in r.get("igp", [])]
        out[name] = {**r, "igp": [link for link in links if link["cost"] > 0]}
    return out


def relations(routers: dict) -> dict[tuple[int, int], str]:
    """Between ASes, what the second is to the first: customer, peer, provider or sibling."""
    asn = {name: int(r.get("asn")) for name, r in routers.items() if r.get("asn") is not None}
    return {(asn[name], asn[n["name"]]): n["relation"] for name, r in routers.items() for n in r.get("neighbors", [])
            if n.get("relation") and name in asn and n.get("name") in asn}


def valley_free(between: dict[tuple[int, int], str], own: int, as_path: list[int]) -> bool | None:
    """Whether packets along an AS path go up to providers, over at most one
    peer, then down to customers only, as Gao-Rexford asks. Siblings count
    as neither. None where a hop has no relation: nothing to judge."""
    hops = [own]
    for a in as_path:  # a prepended AS once
        if a != hops[-1]:
            hops.append(a)
    down = False
    for x, y in zip(hops, hops[1:]):
        rel = between.get((x, y))
        if rel is None:
            return None
        if rel == "sibling":
            continue
        if down and rel != "customer":
            return False
        down = down or rel in ("peer", "customer")
    return True
