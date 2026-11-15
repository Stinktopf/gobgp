package obgpsim

import (
	"fmt"
	"slices"
)

// Finding is where a mode deviates: it does not converge, a router has no
// path although BGP has one, or forwarding loops or ends at a router without
// a path.
type Finding struct {
	Mode    Mode   `json:"mode"`
	Kind    string `json:"kind"` // no-convergence, unreachable, loop, black-hole, leaked, forward-valley, transient-loop, transient-blocked, transient-hole
	Routers []int  `json:"routers"`
	Detail  string `json:"detail"`
}

// Transient makes Check report forwarding loops on the way, after any
// delivered message, BGP included. No proof rules them out: the proofs claim
// loop freedom at rest only. Off by default, as BGP loops on the way as a rule.
var Transient bool

// MaxSteps bounds a run: a network still busy then counts as not converging.
const MaxSteps = 20000

// Check plays the instance in every mode and compares the OBGP modes with
// BGP on the same instance and seed. Where BGP itself does not converge,
// there is no reference, and only convergence and forwarding are checked.
func Check(inst *Instance, modes ...Mode) (map[Mode]Result, []Finding) {
	if len(modes) == 0 {
		modes = Modes
	}
	results := map[Mode]Result{}
	for _, m := range append([]Mode{BGP}, modes...) {
		if _, done := results[m]; !done {
			results[m] = Run(inst, m, MaxSteps)
		}
	}
	ref := results[BGP]
	var findings []Finding
	for _, m := range modes {
		r := results[m]
		// For a moment on the way, BGP included: what happens on the way, which no proof claims.
		if Transient && r.Transient != nil {
			findings = append(findings, Finding{m, "transient-loop", r.Transient, "forwarding went in a circle on the way"})
		}
		if Transient && r.Blocked > 0 {
			findings = append(findings, Finding{m, "transient-blocked", nil, fmt.Sprintf("after %d of %d messages some router had no route and waited for a route refresh", r.Blocked, r.Steps)})
		}
		if Transient && r.Holes > 0 {
			findings = append(findings, Finding{m, "transient-hole", nil, fmt.Sprintf("after %d of %d messages some router had lost its route for a while", r.Holes, r.Steps)})
		}
		if !r.Converged {
			if ref.Converged || m == BGP {
				findings = append(findings, Finding{m, "no-convergence", nil, busy(r)})
			}
			continue
		}
		if m != BGP && ref.Converged {
			var lost []int
			for i := range r.Best {
				if r.Best[i] == nil && ref.Best[i] != nil {
					lost = append(lost, i)
				}
			}
			if len(lost) > 0 {
				findings = append(findings, Finding{m, "unreachable", lost, "BGP has a path, this mode none"})
			}
		}
		findings = append(findings, forwarding(inst, m, r)...)
		if m != BGP {
			findings = append(findings, exportConsistency(inst, m, r)...)
		}
		var leaks []int
		if len(inst.Leakers) > 0 {
			if leaks = leaked(inst, r); len(leaks) > 0 {
				findings = append(findings, Finding{m, "leaked", leaks, "these routers use a path that is not valley-free"})
			}
		}
		if valleys := forwardValleys(inst, r, leaks); len(valleys) > 0 {
			findings = append(findings, Finding{m, "forward-valley", valleys, "the packets of these routers go against the relations, although their paths do not"})
		}
	}
	return results, findings
}

// busy tells why a run did not come to rest: an order without end, or only
// the bound.
func busy(r Result) string {
	if r.Cycle != nil {
		return fmt.Sprintf("after message %d back in its state after message %d: an order without end", r.Cycle.From+r.Cycle.Length, r.Cycle.From)
	}
	return fmt.Sprintf("still busy after %d messages, an order without end not shown", r.Steps)
}

// leaked are the routers whose path is not valley-free: a route leak reached
// them. Along the path, from the origin on, a route goes up to providers,
// across at most one peer, then down to customers.
func leaked(inst *Instance, r Result) []int {
	rel := relations(inst)
	var out []int
	for v, path := range r.Best {
		if path == nil {
			continue
		}
		router := map[uint32]int{} // one router per AS in the families with leaks
		for i := range inst.Routers {
			router[inst.ASN(i)] = i
		}
		hops := []int{v} // routers from v back to the origin, prepending collapsed
		for _, as := range path {
			if x := router[as]; x != hops[len(hops)-1] {
				hops = append(hops, x)
			}
		}
		if !valleyFree(rel, hops) {
			out = append(out, v)
		}
	}
	return out
}

// relations are the Gao-Rexford relations by pair of routers: what the
// second is to the first.
func relations(inst *Instance) map[[2]int]Relation {
	rel := map[[2]int]Relation{}
	for _, c := range inst.Customers {
		rel[c], rel[[2]int{c[1], c[0]}] = Customer, Provider
	}
	for _, p := range inst.Peers {
		rel[p], rel[[2]int{p[1], p[0]}] = Peer, Peer
	}
	for _, p := range inst.Siblings {
		rel[p], rel[[2]int{p[1], p[0]}] = Sibling, Sibling
	}
	return rel
}

// valleyFree tells whether routers from a router back to the origin follow
// the relations: from the origin on, up to providers, across at most one
// peer, then down to customers. Pairs without a relation, inside an AS or
// to a route server, are neither up nor down.
func valleyFree(rel map[[2]int]Relation, hops []int) bool {
	down := false
	for k := len(hops) - 1; k > 0; k-- { // from the origin outwards: hops[k] sends to hops[k-1]
		switch rel[[2]int{hops[k], hops[k-1]}] {
		case Provider: // up, to a provider
			if down {
				return false
			}
		case Peer:
			if down {
				return false
			}
			down = true
		case Customer:
			down = true
		case Sibling: // one organization: neither up nor down
		}
	}
	return true
}

// forwardValleys are the routers whose packets go against the relations
// although their own path does not: forwarding left the paths sent. With a
// table per neighbor an OBGP router sends each neighbor a route of its own
// but forwards on its best. Routers in leaks use such a path by policy.
func forwardValleys(inst *Instance, r Result, leaks []int) []int {
	if len(inst.Customers)+len(inst.Peers) == 0 {
		return nil
	}
	rel, igp := relations(inst), shortest(inst, r.Costs)
	var out []int
	for v := range r.Best {
		if r.Best[v] == nil || slices.Contains(leaks, v) {
			continue
		}
		if trail, cycle, hole := walk(inst, r, igp, v); cycle == nil && !hole && !valleyFree(rel, trail) {
			out = append(out, v)
		}
	}
	return out
}

// forwarding follows a packet from every router with a path: to the BGP next
// hop of the router it is at, over an eBGP link or, inside an AS, one IGP
// hop towards it, where the next router decides again. Inside an AS this is
// where route reflectors with too little information make loops.
func forwarding(inst *Instance, m Mode, r Result) []Finding {
	return forwardingFrom(inst, m, r, nil)
}

// firstLoop is the first forwarding loop of a result, nil for none.
func firstLoop(inst *Instance, r Result, igp [][]int) []int {
	for start := range r.Best {
		if r.Best[start] == nil {
			continue
		}
		if _, cycle, _ := walk(inst, r, igp, start); cycle != nil {
			return cycle
		}
	}
	return nil
}

// walk follows a packet from start: the routers of the circle it runs in,
// sorted, or whether it ends at a router without a path, neither if it
// arrives, then the routers on its way, the origin last. A router with a
// table per neighbor (r.Ingress), NS-BGP and OBGP alike, sends a packet from
// an eBGP neighbor on the route it sends that neighbor, and inside an AS
// through a tunnel to the exit, as the paper of NS-BGP forwards.
func walk(inst *Instance, r Result, igp [][]int, start int) (trail, cycle []int, hole bool) {
	type state struct{ at, from int } // from: the eBGP neighbor it came from, -1 for none
	var seen []state
	for s := (state{start, -1}); ; {
		path, hop := r.Best[s.at], r.NextHop[s.at]
		if s.from >= 0 && byIngress(r, s.at) {
			h, ok := r.Ingress[s.at][s.from]
			if !ok {
				return nil, nil, true
			}
			path, hop = h.Path, h.NextHop
		}
		if hop == s.at { // the origin
			for _, x := range seen {
				trail = append(trail, x.at)
			}
			return append(trail, s.at), nil, false
		}
		if i := slices.Index(seen, s); i >= 0 {
			for _, x := range seen[i:] {
				if !slices.Contains(cycle, x.at) {
					cycle = append(cycle, x.at)
				}
			}
			slices.Sort(cycle)
			return nil, cycle, false
		}
		seen = append(seen, s)
		next, from := hop, s.at
		if hop >= 0 && inst.asOf(hop) == inst.asOf(s.at) {
			switch {
			case byIngress(r, s.at) && len(path) == 0: // the origin is in this AS: the tunnel ends there
				from = -1
			case byIngress(r, s.at):
				next, from = tunnelExit(inst, hop, path), hop
			case Tunnel:
				next = tunnelExit(inst, hop, path)
			default: // one IGP hop: the next router decides as for its own packets
				next, from = igp[s.at][hop], -1
			}
		}
		if hop < 0 || next < 0 || !byIngress(r, next) && r.Best[next] == nil {
			return nil, nil, true
		}
		if !byIngress(r, next) {
			from = -1
		}
		s = state{next, from}
	}
}

// byIngress tells whether router x forwards by ingress: with a table per
// neighbor, also among routers with one table in a mixed mode.
func byIngress(r Result, x int) bool {
	return x < len(r.Ingress) && r.Ingress[x] != nil
}

// forwardingFrom follows packets from the starts only, all routers if none:
// the lab's expect step with forwarding (lab/forwarding.py).
func forwardingFrom(inst *Instance, m Mode, r Result, starts []int) []Finding {
	var findings []Finding
	igp := shortest(inst, r.Costs)
	loops, holes := map[string][]int{}, []int{}
	if starts == nil {
		for i := range r.Best {
			starts = append(starts, i)
		}
	}
	for _, start := range starts {
		if r.Best[start] == nil {
			continue
		}
		_, cycle, hole := walk(inst, r, igp, start)
		if cycle != nil {
			loops[fmt.Sprint(cycle)] = cycle
		}
		if hole {
			holes = append(holes, start)
		}
	}
	for _, cycle := range loops {
		findings = append(findings, Finding{m, "loop", cycle, "forwarding goes in a circle"})
	}
	if len(holes) > 0 {
		findings = append(findings, Finding{m, "black-hole", holes, "forwarding ends at a router without a path"})
	}
	return findings
}

// shortest gives, inside every AS, the first IGP hop from a router towards
// another, -1 if there is none, by the costs of the links: those given, as
// igp events left them, else the instance's. A cost of 0 is no link.
func shortest(inst *Instance, costs []int) [][]int {
	n := inst.Routers
	const inf = 1 << 30
	dist, next := make([][]int, n), make([][]int, n)
	for a := range n {
		dist[a], next[a] = make([]int, n), make([]int, n)
		for b := range n {
			dist[a][b], next[a][b] = inf, -1
		}
		dist[a][a], next[a][a] = 0, a
	}
	for k, l := range inst.Links {
		if inst.asOf(l[0]) != inst.asOf(l[1]) {
			continue
		}
		cost := 1
		if k < len(costs) {
			cost = costs[k]
		} else if k < len(inst.Costs) && inst.Costs[k] > 0 {
			cost = inst.Costs[k]
		}
		if cost <= 0 {
			continue
		}
		for _, e := range [][2]int{l, {l[1], l[0]}} {
			if cost < dist[e[0]][e[1]] {
				dist[e[0]][e[1]], next[e[0]][e[1]] = cost, e[1]
			}
		}
	}
	for k := range n { // Floyd-Warshall, ties to the lower router for determinism
		for a := range n {
			for b := range n {
				if d := dist[a][k] + dist[k][b]; d < dist[a][b] {
					dist[a][b], next[a][b] = d, next[a][k]
				}
			}
		}
	}
	return next
}

// exportConsistency names the ASes whose routers send their neighbors in
// other ASes different paths, their own AS and prepends taken off, as the
// lab reads them from the routes sent (lab/runner.py): the model of OBGP
// has one export path per node, and native iBGP makes the AS that node. A
// table per neighbor sends each neighbor its own path by design.
func exportConsistency(inst *Instance, m Mode, r Result) []Finding {
	if len(inst.AS) == 0 || len(r.Offered) == 0 || PerNeighborMode(m) {
		return nil
	}
	// In a mixed mode only the ASes all of whose routers run OBGP with one table.
	mixed := map[int]bool{}
	for b, mode := range inst.Mixed[m] {
		if mode.plain() || PerNeighborMode(mode) {
			mixed[inst.asOf(b)] = true
		}
	}
	offered := map[int]map[string]bool{}
	routers := map[int][]int{}
	for b, paths := range r.Offered {
		as := inst.asOf(b)
		if mixed[as] {
			continue
		}
		for _, path := range paths {
			if offered[as] == nil {
				offered[as] = map[string]bool{}
			}
			offered[as][fmt.Sprint(path)] = true
			if !slices.Contains(routers[as], b) {
				routers[as] = append(routers[as], b)
			}
		}
	}
	var findings []Finding
	for as, paths := range offered {
		if len(paths) > 1 {
			slices.Sort(routers[as])
			findings = append(findings, Finding{m, "inconsistent-export", routers[as], fmt.Sprintf("AS %d offers %d different paths", inst.ASN(routers[as][0]), len(paths))})
		}
	}
	slices.SortFunc(findings, func(a, b Finding) int { return a.Routers[0] - b.Routers[0] })
	return findings
}

// Tunnel forwards inside an AS as over tunnels to the exit, e.g. MPLS: the
// first router sends a packet to the border router of its path, which
// sends it out over the session that path came in on. No router in between
// decides again. Off, every router forwards hop by hop over the IGP.
var Tunnel bool

// tunnelExit is the router in the next AS of path beside border router b,
// -1 for none, the next AS also a confederation. The families with iBGP
// have one router in every other AS.
func tunnelExit(inst *Instance, b int, path []uint32) int {
	if len(path) == 0 {
		return -1
	}
	outside := func(x int) uint32 {
		for _, c := range inst.Confeds {
			if slices.Contains(c.Members, inst.asOf(x)) {
				return c.ID
			}
		}
		return inst.ASN(x)
	}
	for _, l := range inst.Links {
		for k, x := range l {
			if l[1-k] == b && inst.asOf(x) != inst.asOf(b) && (inst.ASN(x) == path[0] || outside(x) == path[0]) {
				return x
			}
		}
	}
	return -1
}
