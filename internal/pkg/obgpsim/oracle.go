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
	Kind    string `json:"kind"` // no-convergence, unreachable, loop, black-hole, leaked, transient-loop
	Routers []int  `json:"routers"`
	Detail  string `json:"detail"`
}

// Transient makes Check report forwarding loops on the way, after any
// delivered message, BGP included: the loop freedom at every instant the
// proof claims. Off by default, as BGP loops on the way as a rule.
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
		// For a moment on the way, BGP included: the paper's loop freedom at every instant.
		if Transient && r.Transient != nil {
			findings = append(findings, Finding{m, "transient-loop", r.Transient, "forwarding went in a circle on the way"})
		}
		if !r.Converged {
			if ref.Converged || m == BGP {
				findings = append(findings, Finding{m, "no-convergence", nil, fmt.Sprintf("still busy after %d messages", r.Steps)})
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
		if len(inst.Leakers) > 0 {
			if leaked := leaked(inst, r); len(leaked) > 0 {
				findings = append(findings, Finding{m, "leaked", leaked, "these routers use a path that is not valley-free"})
			}
		}
	}
	return results, findings
}

// leaked are the routers whose path is not valley-free: a route leak reached
// them. Along the path, from the origin on, a route goes up to providers,
// across at most one peer, then down to customers.
func leaked(inst *Instance, r Result) []int {
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
		down := false
		for k := len(hops) - 1; k > 0; k-- { // from the origin outwards: hops[k] sends to hops[k-1]
			switch rel[[2]int{hops[k], hops[k-1]}] {
			case Provider: // up, to a provider
				if down {
					out = append(out, v)
					k = 0
				}
			case Peer, Customer:
				if down && rel[[2]int{hops[k], hops[k-1]}] == Peer {
					out = append(out, v)
					k = 0
				}
				down = true
			case Sibling: // one organization: neither up nor down
			}
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
		seen := []int{}
		for at := start; ; {
			hop := r.NextHop[at]
			if hop == at {
				break
			}
			if slices.Contains(seen, at) {
				cycle := slices.Clone(seen[slices.Index(seen, at):])
				slices.Sort(cycle)
				return cycle
			}
			seen = append(seen, at)
			next := hop
			if hop >= 0 && inst.asOf(hop) == inst.asOf(at) {
				next = igp[at][hop]
			}
			if hop < 0 || next < 0 || r.Best[next] == nil {
				break
			}
			at = next
		}
	}
	return nil
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
		seen := []int{}
		for at := start; ; {
			hop := r.NextHop[at]
			if hop == at {
				break // the origin
			}
			if slices.Contains(seen, at) {
				cycle := slices.Clone(seen[slices.Index(seen, at):])
				slices.Sort(cycle)
				loops[fmt.Sprint(cycle)] = cycle
				break
			}
			seen = append(seen, at)
			next := hop
			if hop >= 0 && inst.asOf(hop) == inst.asOf(at) {
				next = igp[at][hop]
			}
			if hop < 0 || next < 0 || r.Best[next] == nil {
				holes = append(holes, start)
				break
			}
			at = next
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
// has one export path per node, and native iBGP makes the AS that node.
func exportConsistency(inst *Instance, m Mode, r Result) []Finding {
	if len(inst.AS) == 0 || len(r.Offered) == 0 {
		return nil
	}
	offered := map[int]map[string]bool{}
	routers := map[int][]int{}
	for b, paths := range r.Offered {
		as := inst.asOf(b)
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
