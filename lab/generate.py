"""Generated topologies, for curves over the size of a network.

Erdős-Rényi (1959): every pair of routers linked with the same chance, here
set by the average number of links per router.

Watts-Strogatz (1998): a ring in which every router links to its k nearest,
then every link is moved to a random router with a chance.

Barabási-Albert (1999): m + 1 routers linked to each other, then every new
router links to m of the earlier ones, picked in proportion to their degree.
With relations, the first ones peer and every new router is a customer of
those it links to.

Waxman (1988): routers at random points of the unit square, each pair linked
with the probability alpha * exp(-d / (beta * L)), d their distance and L the
largest one, the parameters as NetworkX names them.

Elmokashfi, Kvalbein and Dovrolis (CoNEXT 2008, Section 3 and Table 1): the
Baseline growth model. Tier-1s peer in a clique, mid-level transit networks
(15 %) buy transit from Tier-1s or earlier mid-level ones, content providers
(5 %) and stubs (80 %) from either, all picked by preferential attachment and
only within their regions. Then mid-level networks peer with each other by
preferential attachment, content providers with mid-level ones and with each
other at random, never inside their own customer tree. The paper uses 1,000
to 10,000 networks, smaller sizes keep its shares and averages. Its roles
name the four kinds for scenarios.

With Gao-Rexford, the other models get relations by the number of links:
the router with more links is the provider, those with as many peer. As
providers are earlier routers or ones with more links, no router is its own
provider. A network that comes out in parts is joined
by the fewest links: the closest pairs where routers have places, random ones
else. The origin is a router of the smallest degree, at the edge.
"""

import math
import random
from dataclasses import dataclass, field

from . import topology

WIDTH = 900  # of the graph view, in pixels
MAX_ROUTERS = 2000


@dataclass
class Field:
    name: str
    label: str
    default: float | bool
    tip: str
    step: float = 1
    min: float = 1
    max: float | None = None

    def parse(self, value) -> float | bool:
        if isinstance(self.default, bool):
            return value not in (None, "", False, "false", "off")
        if value in (None, ""):
            return self.default
        return int(value) if isinstance(self.default, int) else float(str(value).replace(",", "."))


@dataclass
class Model:
    label: str
    what: str
    good_for: str
    source: str  # short: authors, venue, year
    title: str  # of the paper
    url: str
    fields: list[Field] = field(default_factory=list)


@dataclass
class Graph:
    links: set
    points: list = field(default_factory=list)
    relation: dict = field(default_factory=dict)  # (a, b) -> what b is to a
    roles: dict = field(default_factory=dict)  # name -> router indexes


DEGREE = Field("degree", "Average links per router", 4, "Higher gives a denser network. Stays the same as the network grows", min=2)
RELATIONS = Field("relations", "Gao-Rexford", False, "Customers, providers and peers. The router with more links is the provider, equal ones peer")
MODELS = {
    "er": Model("Erdős–Rényi", "Every pair of routers links with the same chance.",
                "a baseline without structure.",
                "Erdős and Rényi, 1959", "On random graphs I", "https://www.renyi.hu/~p_erdos/1959-11.pdf", [DEGREE, RELATIONS]),
    "ws": Model("Watts–Strogatz", "A ring of near links, some moved to random routers.",
                "the effect of a few shortcuts.",
                "Watts and Strogatz, Nature 1998", "Collective dynamics of small-world networks", "https://doi.org/10.1038/30918",
                [Field("degree", "Links per router", 4, "An even number. The ring links every router to this many nearest ones", step=2, min=2),
                 Field("rewire", "Moved links", 0.1, "Share of links moved to random routers. 0 keeps the ring, 1 is random", step=0.01, min=0, max=1),
                 RELATIONS]),
    "ba": Model("Barabási–Albert", "New routers link to those with many links, so hubs form.",
                "load and churn at hubs.",
                "Barabási and Albert, Science 1999", "Emergence of scaling in random networks", "https://doi.org/10.1126/science.286.5439.509",
                [Field("m", "Links per new router", 2, "2 gives a sparse network, 3 or 4 a denser one"),
                 Field("relations", "Gao-Rexford", False, "Customers, providers and peers. New routers buy transit from those they link to")]),
    "waxman": Model("Waxman", "Routers at random places link more often when close.",
                    "meshes with many alternative paths.",
                    "Waxman, IEEE JSAC 1988", "Routing of multipoint connections", "https://doi.org/10.1109/49.12889",
                    [Field("alpha", "Link density", 0.4, "From 0.01 to 1, higher gives more links. Larger networks get denser, so lower it as they grow", step=0.01, min=0.01, max=1),
                     Field("beta", "Long links", 0.1, "Higher links far routers more often, lower keeps links short. Often 0.1 to 0.5", step=0.01, min=0.01),
                     RELATIONS]),
    "elmokashfi": Model("Elmokashfi", "Tier-1s, transit, content and stubs in regions, as on the Internet.",
                        "growth like the Internet, with Gao-Rexford.",
                        "Elmokashfi, Kvalbein and Dovrolis, CoNEXT 2008", "On the scalability of BGP: the roles of topology growth and update rate-limiting", "https://sites.cc.gatech.edu/home/dovrolis/Papers/bgp-scale-conext08.pdf"),
}


def _join(n: int, links: set, rng: random.Random, points: list) -> None:
    """Links the parts of a network, the closest pairs if routers have places."""
    part = list(range(n))

    def find(x):
        while part[x] != x:
            part[x] = part[part[x]]
            x = part[x]
        return x

    for a, b in links:
        part[find(a)] = find(b)
    while len(roots := sorted({find(x) for x in range(n)})) > 1:
        if points:
            a, b = min(((a, b) for a in range(n) for b in range(a + 1, n) if find(a) != find(b)), key=lambda p: math.dist(points[p[0]], points[p[1]]))
        else:
            a = rng.choice([x for x in range(n) if find(x) == roots[0]])
            b = rng.choice([x for x in range(n) if find(x) == roots[1]])
        links.add((min(a, b), max(a, b)))
        part[find(a)] = find(b)


def erdos_renyi(n: int, degree: int = 4, seed: int = 1) -> Graph:
    rng = random.Random(seed)
    p = min(1, degree / (n - 1))
    links = {(a, b) for a in range(n) for b in range(a + 1, n) if rng.random() < p}
    _join(n, links, rng, [])
    return Graph(links)


def watts_strogatz(n: int, degree: int = 4, rewire: float = 0.1, seed: int = 1) -> Graph:
    if degree % 2 or not 2 <= degree < n:
        raise ValueError("links per router must be even and less than the number of routers")
    rng = random.Random(seed)
    links = {(a, (a + j) % n) for a in range(n) for j in range(1, degree // 2 + 1)}
    for a, b in sorted(links):
        if rng.random() < rewire:
            linked = {y for x, y in links if x == a} | {x for x, y in links if y == a} | {a}
            if len(linked) < n:
                links.discard((a, b))
                links.add((a, rng.choice([c for c in range(n) if c not in linked])))
    links = {(min(a, b), max(a, b)) for a, b in links}
    # The ring, as it is drawn: router i at the angle of i.
    points = [(0.5 + 0.45 * math.cos(2 * math.pi * i / n), 0.5 + 0.45 * math.sin(2 * math.pi * i / n)) for i in range(n)]
    _join(n, links, rng, points)
    return Graph(links, points)


def waxman(n: int, alpha: float = 0.4, beta: float = 0.1, seed: int = 1) -> Graph:
    rng = random.Random(seed)
    points = [(rng.random(), rng.random()) for _ in range(n)]
    dist = lambda a, b: math.dist(points[a], points[b])
    largest = max((dist(a, b) for a in range(n) for b in range(a + 1, n)), default=1) or 1
    links = {(a, b) for a in range(n) for b in range(a + 1, n) if rng.random() < alpha * math.exp(-dist(a, b) / (beta * largest))}
    _join(n, links, rng, points)
    return Graph(links, points)


def barabasi_albert(n: int, m: int = 2, seed: int = 1, relations: bool = False) -> Graph:
    if not 1 <= m < n:
        raise ValueError("links per new router must be at least 1 and less than the number of routers")
    rng = random.Random(seed)
    links, relation, ends = set(), {}, []  # ends: every router once per link, for picks by degree
    for a in range(m + 1):
        for b in range(a + 1, m + 1):
            links.add((a, b))
            ends += [a, b]
            relation[(a, b)] = relation[(b, a)] = "peer"
    for new in range(m + 1, n):
        chosen = set()
        while len(chosen) < m:
            chosen.add(rng.choice(ends))
        for old in sorted(chosen):
            links.add((old, new))
            ends += [old, new]
            relation[(new, old)], relation[(old, new)] = "provider", "customer"
    return Graph(links, relation=relation if relations else {})


def elmokashfi(n: int, seed: int = 1) -> Graph:
    """The Baseline growth model, Table 1 of the paper, at n networks."""
    if n < 10:
        raise ValueError("Elmokashfi needs at least 10 routers")
    rng = random.Random(seed)
    # Up to 2n / 10000 the averages grow with the network, as in Table 1.
    d_m, d_cp, d_c = 2 + 2.5 * n / 10000, 2 + 1.5 * n / 10000, 1 + 5 * n / 100000
    p_m, p_cp_m, p_cp_cp = 1 + 2 * n / 10000, 0.2 + 2 * n / 10000, 0.05 + 5 * n / 100000
    t_m, t_cp, t_c = 0.375, 0.375, 0.125
    n_t = 4 if n < 1000 else 5  # 4 to 6 in the paper
    n_m, n_cp = round(0.15 * n), round(0.05 * n)
    kinds = ["T"] * n_t + ["M"] * n_m + ["CP"] * n_cp + ["C"] * (n - n_t - n_m - n_cp)
    regions = 5
    where = []
    for k in kinds:  # T everywhere, 20 % of M and 5 % of CP in two regions
        first = rng.randrange(regions)
        two = (k == "M" and rng.random() < 0.2) or (k == "CP" and rng.random() < 0.05)
        where.append(set(range(regions)) if k == "T" else {first, (first + 1 + rng.randrange(regions - 1)) % regions} if two else {first})
    links, relation, degree, peering = set(), {}, [0] * n, [0] * n
    customers = [set() for _ in range(n)]

    def count(average: float, low: float) -> int:
        # Uniform from low to twice the average less low, rounded at random: its mean is the average.
        x = rng.uniform(low, 2 * average - low)
        return int(x) + (rng.random() < x - int(x))

    def link(a: int, b: int, rel: str) -> None:  # rel: what b is to a
        links.add((min(a, b), max(a, b)))
        relation[(a, b)], relation[(b, a)] = rel, {"provider": "customer", "customer": "provider", "peer": "peer"}[rel]
        degree[a] += 1
        degree[b] += 1

    def pick(candidates: list[int], weight) -> int:
        return rng.choices(candidates, weights=[weight(c) + 1 for c in candidates])[0]

    for a in range(n_t):
        for b in range(a + 1, n_t):
            link(a, b, "peer")
    tier1 = list(range(n_t))
    for a, kind in enumerate(kinds):
        if kind == "T":
            continue
        d, t = {"M": (d_m, t_m), "CP": (d_cp, t_cp), "C": (d_c, t_c)}[kind]
        mids = [b for b in range(n_t, a) if kinds[b] == "M" and where[a] & where[b]]
        chosen = set()
        for _ in range(max(1, count(d, 1))):
            pool = [b for b in (tier1 if rng.random() < t or not mids else mids) if b not in chosen]
            pool = pool or [b for b in tier1 + mids if b not in chosen]
            if pool:
                chosen.add(pick(pool, lambda b: degree[b]))
        for b in chosen:
            link(a, b, "provider")
            customers[b].add(a)

    def cone(a: int) -> set:
        seen, todo = set(), [a]
        while todo:
            for c in customers[todo.pop()]:
                if c not in seen:
                    seen.add(c)
                    todo.append(c)
        return seen

    cones = {}
    def may_peer(a: int, b: int) -> bool:
        if (min(a, b), max(a, b)) in links or a == b:
            return False
        for x in (a, b):
            cones.setdefault(x, cone(x))
        return b not in cones[a] and a not in cones[b] and bool(where[a] & where[b])

    def peer(a: int, number: int, kind: str, weight) -> None:
        for _ in range(number):
            pool = [b for b, k in enumerate(kinds) if k == kind and may_peer(a, b)]
            if not pool:
                return
            b = pick(pool, weight)
            link(a, b, "peer")
            peering[a] += 1
            peering[b] += 1

    for a, kind in enumerate(kinds):
        if kind == "M":
            peer(a, count(p_m, 0), "M", lambda b: peering[b])
    for a, kind in enumerate(kinds):
        if kind == "CP":
            peer(a, count(p_cp_m, 0), "M", lambda b: 0)
            peer(a, count(p_cp_cp, 0), "CP", lambda b: 0)
    names = {"T": "tier1", "M": "transit", "CP": "content", "C": "stubs"}
    roles = {names[k]: [i for i, x in enumerate(kinds) if x == k] for k in names if k in kinds}
    return Graph(links, relation=relation, roles=roles)


def by_degree(links: set) -> dict:
    """Relations of a network without its own: the router with more links is
    the provider, those with as many peer. A provider has strictly more
    links than its customer, so no router is its own provider."""
    degree = {}
    for a, b in links:
        degree[a], degree[b] = degree.get(a, 0) + 1, degree.get(b, 0) + 1
    relation = {}
    for a, b in links:
        rel = "peer" if degree[a] == degree[b] else "provider" if degree[b] > degree[a] else "customer"
        relation[(a, b)], relation[(b, a)] = rel, {"provider": "customer", "customer": "provider", "peer": "peer"}[rel]
    return relation


def build(n: int, graph: Graph) -> tuple[dict, dict]:
    """Routers and roles as lab.topology works with them."""
    names = [f"r{i}" for i in range(n)]
    routers = {}
    for i, name in enumerate(names):
        routers[name] = {"asn": 65000 + i if n <= 500 else 4200000000 + i,
                         "routerId": f"10.{(i + 1) // 65536}.{(i + 1) // 256 % 256}.{(i + 1) % 256}", "neighbors": []}
        if graph.points:
            routers[name]["position"] = {"x": round(graph.points[i][0] * WIDTH, 1), "y": round(graph.points[i][1] * WIDTH, 1)}
    for a, b in sorted(graph.links):
        for x, y in ((a, b), (b, a)):
            neighbor = {"name": names[y], "peerAs": routers[names[y]]["asn"]}
            if (x, y) in graph.relation:
                neighbor["relation"] = graph.relation[(x, y)]
            routers[names[x]]["neighbors"].append(neighbor)
    origin = min(routers, key=lambda r: (len(routers[r]["neighbors"]), -names.index(r)))
    return routers, {"origins": [origin], **{k: [names[i] for i in v] for k, v in graph.roles.items()}}


def name_of(model: str, n: int, seed: int, p: dict) -> str:
    """The name of a generated topology, its parameters in it; names have no dots, so shares are in percent."""
    part = {"er": lambda: f"k{p['degree']}", "ws": lambda: f"k{p['degree']}-r{round(100 * p['rewire'])}",
            "ba": lambda: f"m{p['m']}",
            "waxman": lambda: f"a{round(100 * p['alpha'])}-b{round(100 * p['beta'])}", "elmokashfi": lambda: ""}[model]()
    return "-".join(x for x in (model, "gr" if p.get("relations") else "", part, str(n), f"s{seed}") if x)


def params_of(model: str, given: dict) -> dict:
    """The parameters of a model from what was given, by name, with its defaults."""
    if model not in MODELS:
        raise ValueError(f"no model {model}, one of {', '.join(MODELS)}")
    return {f.name: f.parse(given.get(f.name)) for f in MODELS[model].fields}


def graph_of(model: str, n: int, seed: int, p: dict) -> Graph:
    graph = {"er": lambda: erdos_renyi(n, p["degree"], seed), "ws": lambda: watts_strogatz(n, p["degree"], p["rewire"], seed),
            "ba": lambda: barabasi_albert(n, p["m"], seed, p["relations"]), "waxman": lambda: waxman(n, p["alpha"], p["beta"], seed),
            "elmokashfi": lambda: elmokashfi(n, seed)}[model]()
    if p.get("relations") and not graph.relation:
        graph.relation = by_degree(graph.links)
    return graph


def generate(model: str, sizes: list[int], seed: int = 1, name: str = "", **given) -> list[str]:
    """Saves a topology for every size and returns their names: the name
    given, with the size appended if there are several, or else a name of
    the model and its parameters."""
    p = params_of(model, given)
    if not sizes or any(not 2 <= n <= MAX_ROUTERS for n in sizes):
        raise ValueError(f"sizes must be from 2 to {MAX_ROUTERS} routers")
    for f in MODELS[model].fields:
        if not isinstance(f.default, bool) and (p[f.name] < f.min or (f.max is not None and p[f.name] > f.max)):
            raise ValueError(f"{f.label} must be from {f.min:g}" + (f" to {f.max:g}" if f.max is not None else " on"))
    name = name.strip()
    names = [(f"{name}-{n}" if len(sizes) > 1 else name) if name else name_of(model, n, seed, p) for n in sizes]
    if len(set(names)) < len(names):
        raise ValueError("every size only once")
    if taken := [n for n in names if topology.path(n).exists()]:
        raise FileExistsError(f"Topologies exist already: {', '.join(taken)}.")
    for n, name in zip(sizes, names):
        routers, roles = build(n, graph_of(model, n, seed, p))
        if problems := topology.validate(routers, roles):
            raise ValueError(f"{name}: {problems[0]}")
        topology.save(name, routers, roles, f"generated/{model}?n={n}&seed={seed}" + "".join(f"&{k}={v}" for k, v in p.items()))
    return names
