package obgpsim

import (
	"fmt"
	"math/rand"
	"slices"
)

// A family varies one kind of policy over a topology: every placement, so
// that the search is exhaustive for small networks. In the model of OBGP a
// router sends all neighbors the same path or none, and export filters
// depend only on the Gao-Rexford class of a neighbor.
type Family struct {
	Name     string
	InModel  bool // inside the model of OBGP: no deviation expected
	Variants func(routers int, links [][2]int) []Instance
}

// Families are the policies the search varies. Those outside the model are
// expected to find deviations, those inside are not.
var Families = []Family{
	{"withdraw", true, func(r int, l [][2]int) []Instance {
		return []Instance{{Events: []Event{{After: 1 << 30, Kind: "withdraw"}}}}
	}},
	{"link-down", true, func(r int, l [][2]int) []Instance {
		var out []Instance
		for _, x := range l {
			out = append(out, Instance{Events: []Event{{After: 1 << 30, Kind: "down", From: x[0], To: x[1]}}})
		}
		return out
	}},
	{"gao-rexford", true, gaoRexford},
	// Gao-Rexford where a provider gives one customer partial transit: only
	// the paths of its own customers, as to a peer.
	{"partial-transit", true, func(r int, links [][2]int) []Instance {
		var out []Instance
		for _, inst := range gaoRexford(r, links) {
			if len(inst.Customers) > 0 {
				c := inst.Customers[0]
				inst.Sessions = append(slices.Clone(inst.Sessions), Session{From: c[0], To: c[1], Partial: true})
				out = append(out, inst)
			}
		}
		return out
	}},
	// Gao-Rexford with two ASes of one organization: a link of a customer
	// becomes one of siblings, which pass each other every route.
	{"siblings", true, func(r int, links [][2]int) []Instance {
		var out []Instance
		for _, inst := range gaoRexford(r, links) {
			if len(inst.Customers) > 0 {
				inst.Siblings, inst.Customers = [][2]int{inst.Customers[0]}, inst.Customers[1:]
				out = append(out, inst)
			}
		}
		return out
	}},
	// The origin announces an aggregate, its AS_SET out of order on purpose,
	// once withdrawn and once with a link failing.
	{"aggregation", true, func(r int, links [][2]int) []Instance {
		out := []Instance{{OriginSet: []uint32{64601, 64600}, Events: []Event{{After: 1 << 30, Kind: "withdraw"}}}}
		for _, x := range links {
			out = append(out, Instance{OriginSet: []uint32{64601, 64600}, Events: []Event{{After: 1 << 30, Kind: "down", From: x[0], To: x[1]}}})
		}
		return out
	}},
	// The origin asks not to pass its route on: no-export once learned, or
	// 0:AS not to one AS, as the lab's routers enforce them on export.
	{"communities", false, func(r int, links [][2]int) []Instance {
		out := []Instance{{OriginCommunities: []string{"no-export"}}}
		for x := 1; x < r; x++ {
			out = append(out, Instance{OriginCommunities: []string{fmt.Sprintf("0:%d", AS(x))}})
		}
		return out
	}},
	// An AS tags the routes from one neighbor, asking not to pass them to
	// another AS: other routes of the same prefix it may pass on, but OBGP
	// exports one path to all. Outside the model, as a filter per neighbor.
	{"tagging", false, func(r int, links [][2]int) []Instance {
		var out []Instance
		for z := 0; z < r; z++ {
			out = append(out, perSession(func(s Session) []Instance {
				if z == s.To {
					return nil
				}
				return []Instance{{Sessions: []Session{{From: s.From, To: s.To, Tag: fmt.Sprintf("0:%d", AS(z))}}}}
			})(r, links)...)
		}
		return out
	}},
	// The origin poisons one AS, which drops the route as a loop.
	{"poison", false, func(r int, links [][2]int) []Instance {
		var out []Instance
		for x := 1; x < r; x++ {
			out = append(out, Instance{OriginPoison: []uint32{AS(x)}})
		}
		return out
	}},
	{"export-filter", false, perSession(func(s Session) []Instance {
		return []Instance{
			{Sessions: []Session{{From: s.From, To: s.To, DenyExport: true}}},
			{Events: []Event{{After: 1 << 30, Kind: "deny-export", From: s.From, To: s.To, Value: 1}}},
		}
	})},
	// An export filter by content: no path through one AS towards one neighbor.
	{"as-path-filter", false, func(r int, links [][2]int) []Instance {
		var out []Instance
		for _, l := range links {
			for _, s := range []Session{{From: l[0], To: l[1]}, {From: l[1], To: l[0]}} {
				for k := 0; k < r; k++ {
					if k != s.From && k != s.To {
						out = append(out, Instance{Sessions: []Session{{From: s.From, To: s.To, DenyVia: AS(k)}}})
					}
				}
			}
		}
		return out
	}},
	{"prepend", false, perSession(func(s Session) []Instance {
		return []Instance{
			{Sessions: []Session{{From: s.From, To: s.To, Prepend: 2}}},
			{Events: []Event{{After: 1 << 30, Kind: "prepend", From: s.From, To: s.To, Value: 2}}},
		}
	})},
	{"import-filter", false, perSession(func(s Session) []Instance {
		return []Instance{{Events: []Event{{After: 1 << 30, Kind: "deny-import", From: s.From, To: s.To, Value: 1}}}}
	})},
	{"local-pref", false, localPref},
	{"ibgp-mesh", false, func(r int, links [][2]int) []Instance { return ibgp(r, links, false, false) }},
	{"ibgp-rr", false, func(r int, links [][2]int) []Instance { return ibgp(r, links, true, false) }},
	{"med-rr", false, func(r int, links [][2]int) []Instance { return ibgp(r, links, true, true) }},
	{"confed", false, confederations},
	// A route server between its neighbors, as gobgpd's, with filters of clients on it.
	{"route-server", false, routeServers},
	{"route-leak", false, func(r int, links [][2]int) []Instance {
		var out []Instance
		for _, inst := range gaoRexford(r, links) {
			for leaker := 1; leaker < r; leaker++ {
				leak := inst
				leak.Leakers = []int{leaker}
				out = append(out, leak)
			}
		}
		return out
	}},
}

func perSession(each func(Session) []Instance) func(int, [][2]int) []Instance {
	return func(r int, links [][2]int) []Instance {
		var out []Instance
		for _, l := range links {
			for _, s := range []Session{{From: l[0], To: l[1]}, {From: l[1], To: l[0]}} {
				out = append(out, each(s)...)
			}
		}
		return out
	}
}

// routeServers makes each router but the origin with two neighbors or more
// a route server, without a filter and with every filter of one client
// against one AS on the path.
func routeServers(r int, links [][2]int) []Instance {
	var out []Instance
	for x := 1; x < r; x++ {
		var clients []int
		for _, l := range links {
			if l[0] == x {
				clients = append(clients, l[1])
			} else if l[1] == x {
				clients = append(clients, l[0])
			}
		}
		if len(clients) < 2 {
			continue
		}
		base := Instance{RouteServers: []int{x}}
		out = append(out, base)
		for _, j := range clients {
			for k := 0; k < r; k++ {
				if k != x && k != j {
					inst := base
					inst.Sessions = []Session{{From: x, To: j, DenyVia: AS(k)}}
					out = append(out, inst)
				}
			}
		}
	}
	return out
}

// gaoRexford gives every link a relation, all combinations for small
// networks, a sample beyond.
func gaoRexford(r int, links [][2]int) []Instance {
	combinations := 1
	for range links {
		combinations *= 3
	}
	pick := func(code int) Instance {
		var inst Instance
		for _, l := range links {
			switch code % 3 {
			case 0:
				inst.Customers = append(inst.Customers, l)
			case 1:
				inst.Customers = append(inst.Customers, [2]int{l[1], l[0]})
			case 2:
				inst.Peers = append(inst.Peers, l)
			}
			code /= 3
		}
		return inst
	}
	var out []Instance
	if combinations <= 243 {
		for c := range combinations {
			if inst := pick(c); acyclic(r, inst.Customers) {
				out = append(out, inst)
			}
		}
		return out
	}
	rng := rand.New(rand.NewSource(int64(r*1000 + len(links))))
	for range 243 {
		if inst := pick(rng.Intn(combinations)); acyclic(r, inst.Customers) {
			out = append(out, inst)
		}
	}
	return out
}

// acyclic tells whether no AS is its own indirect provider, a condition of
// Gao-Rexford.
func acyclic(r int, customers [][2]int) bool {
	state := make([]int, r) // 0 new, 1 on the stack, 2 done
	var visit func(int) bool
	visit = func(a int) bool {
		state[a] = 1
		for _, c := range customers {
			if c[0] == a && (state[c[1]] == 1 || state[c[1]] == 0 && !visit(c[1])) {
				return false
			}
		}
		state[a] = 2
		return true
	}
	for a := range r {
		if state[a] == 0 && !visit(a) {
			return false
		}
	}
	return true
}

// localPref prefers, at every router, one neighbor over the others: the
// policies of Bad Gadget and Disagree, among others.
func localPref(r int, links [][2]int) []Instance {
	var out []Instance
	rng := rand.New(rand.NewSource(int64(r*1000 + len(links))))
	for range 20 {
		var inst Instance
		for _, l := range links {
			for _, s := range [][2]int{l, {l[1], l[0]}} {
				if rng.Intn(2) == 0 {
					inst.Sessions = append(inst.Sessions, Session{From: s[0], To: s[1], LocalPref: 200})
				}
			}
		}
		out = append(out, inst)
	}
	return out
}

// ibgp groups 2 or 3 routers, not the origin, into one AS, in every way
// whose routers the IGP connects: links inside are IGP links with costs
// 1 or 10, the others eBGP sessions. The AS speaks iBGP in a full mesh, or
// through each of its routers as the route reflector. With med, the eBGP
// neighbors set MEDs, 0 or 10.
func ibgp(r int, links [][2]int, reflectors, med bool) []Instance {
	rng := rand.New(rand.NewSource(int64(r*1000 + len(links))))
	var out []Instance
	for mask := 1; mask < 1<<(r-1); mask++ {
		var group []int
		for i := 1; i < r; i++ {
			if mask&(1<<(i-1)) != 0 {
				group = append(group, i)
			}
		}
		if len(group) < 2 || len(group) > 3 {
			continue
		}
		as := make([]int, r)
		for i := range as {
			as[i] = i
			if slices.Contains(group, i) {
				as[i] = group[0]
			}
		}
		var inside [][2]int
		costs := make([]int, len(links))
		for k, l := range links {
			costs[k] = 1
			if as[l[0]] == as[l[1]] {
				inside = append(inside, l)
				costs[k] = []int{1, 10}[rng.Intn(2)]
			}
		}
		if !connectedSet(group, inside) {
			continue
		}
		var setups [][]IBGP
		if reflectors {
			for _, rr := range group {
				setups = append(setups, []IBGP{{AS: group[0], Reflectors: []int{rr}}})
			}
		} else {
			setups = append(setups, nil)
		}
		for _, setup := range setups {
			var sessions []Session
			if med {
				for _, l := range links {
					for _, s := range [][2]int{l, {l[1], l[0]}} {
						if as[s[0]] != as[s[1]] && slices.Contains(group, s[1]) {
							sessions = append(sessions, Session{From: s[0], To: s[1], MED: []uint32{0, 10}[rng.Intn(2)]})
						}
					}
				}
			}
			out = append(out, Instance{AS: as, Costs: costs, IBGP: setup, Sessions: sessions})
		}
	}
	return out
}

// confederations make 2 or 3 routers, not the origin, the members of one
// confederation, AS 65500 to the world, in every connected way, once quiet
// and once with each link failing.
func confederations(r int, links [][2]int) []Instance {
	var out []Instance
	for mask := 1; mask < 1<<(r-1); mask++ {
		var group []int
		for i := 1; i < r; i++ {
			if mask&(1<<(i-1)) != 0 {
				group = append(group, i)
			}
		}
		var inside [][2]int
		for _, l := range links {
			if slices.Contains(group, l[0]) && slices.Contains(group, l[1]) {
				inside = append(inside, l)
			}
		}
		if len(group) < 2 || len(group) > 3 || !connectedSet(group, inside) {
			continue
		}
		confed := []Confed{{Members: group, ID: 65500}}
		out = append(out, Instance{Confeds: confed})
		for _, l := range links {
			out = append(out, Instance{Confeds: confed, Events: []Event{{After: 1 << 30, Kind: "down", From: l[0], To: l[1]}}})
		}
	}
	return out
}

func connectedSet(group []int, links [][2]int) bool {
	seen := map[int]bool{group[0]: true}
	for changed := true; changed; {
		changed = false
		for _, l := range links {
			if seen[l[0]] != seen[l[1]] {
				seen[l[0]], seen[l[1]], changed = true, true, true
			}
		}
	}
	return len(seen) == len(group)
}

// Topologies are all connected graphs of n routers, labeled, router 0 the
// origin.
func Topologies(n int) [][][2]int {
	var pairs [][2]int
	for a := 0; a < n; a++ {
		for b := a + 1; b < n; b++ {
			pairs = append(pairs, [2]int{a, b})
		}
	}
	var out [][][2]int
	for mask := 0; mask < 1<<len(pairs); mask++ {
		var links [][2]int
		for i, p := range pairs {
			if mask&(1<<i) != 0 {
				links = append(links, p)
			}
		}
		if connected(n, links) {
			out = append(out, links)
		}
	}
	return out
}

func connected(n int, links [][2]int) bool {
	seen := map[int]bool{0: true}
	for changed := true; changed; {
		changed = false
		for _, l := range links {
			if seen[l[0]] != seen[l[1]] {
				seen[l[0]], seen[l[1]], changed = true, true, true
			}
		}
	}
	return len(seen) == n
}

// Instances are every placement of a family on every topology of n routers,
// each with the given seeds.
func Instances(f Family, n int, seeds []int64) []Instance {
	var out []Instance
	for _, links := range Topologies(n) {
		for _, v := range f.Variants(n, links) {
			for _, seed := range seeds {
				inst := v
				inst.Family, inst.Routers, inst.Links, inst.Seed = f.Name, n, links, seed
				out = append(out, inst)
			}
		}
	}
	return out
}
