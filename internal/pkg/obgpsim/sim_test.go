//go:build obgpsim

package obgpsim

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func triangle() Instance {
	return Instance{Routers: 3, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}}, Seed: 1}
}

func TestAllModesReachEveryRouterOfALine(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}}, Seed: 1}
	results, findings := Check(&inst)
	assert.Empty(t, findings)
	for _, m := range Modes {
		assert.True(t, results[m].Converged)
		assert.Equal(t, []uint32{AS(2), AS(1), AS(0)}, results[m].Best[3], m)
	}
}

func TestOBGPExportsTheWorstPathAndBGPTheBest(t *testing.T) {
	inst := triangle()
	results, _ := Check(&inst)
	assert.Equal(t, []uint32{AS(0)}, results[BGP].Exported[1])
	assert.Equal(t, []uint32{AS(0)}, results[OBGPHard].Best[1]) // the longer path via router 2 is not admitted
}

// The case of the lab's outside-model-withdraw: a filter towards one neighbor
// withdraws the path there, and pruning also removes the valid path learned
// from another neighbor. Without pruning nothing is lost.
func TestAnExportFilterTowardsOneNeighborPrunesTheValidPathOfAnother(t *testing.T) {
	inst := triangle()
	inst.Events = []Event{{After: 1 << 30, Kind: "deny-export", From: 0, To: 1, Value: 1}}
	results, findings := Check(&inst)
	assert.Equal(t, []Finding{{OBGPHard, "unreachable", []int{1}, "BGP has a path, this mode none"}, {OBGPPaper, "unreachable", []int{1}, "BGP has a path, this mode none"}}, findings)
	assert.Equal(t, []uint32{AS(2), AS(0)}, results[OBGPNP].Best[1])
}

// A path rejected by the router's own import filter is a withdrawal in
// gobgpd, and pruning takes the path of the other neighbor with it.
func TestAnOwnImportFilterPrunesTheValidPathOfAnotherNeighbor(t *testing.T) {
	inst := triangle()
	inst.Events = []Event{{After: 1 << 30, Kind: "deny-import", From: 0, To: 1, Value: 1}}
	_, findings := Check(&inst)
	assert.Equal(t, []Finding{{OBGPHard, "unreachable", []int{1}, "BGP has a path, this mode none"}, {OBGPPaper, "unreachable", []int{1}, "BGP has a path, this mode none"}}, findings)
}

// A lost session prunes nothing.
func TestALinkFailureLosesNothing(t *testing.T) {
	inst := triangle()
	inst.Events = []Event{{After: 1 << 30, Kind: "down", From: 0, To: 1}}
	results, findings := Check(&inst)
	assert.Empty(t, findings)
	assert.Equal(t, []uint32{AS(2), AS(0)}, results[OBGPHard].Best[1])
}

// Gao-Rexford, inside the model: router 1 hears the short route of its peer
// first and then rejects the longer route of its customer. The peer route may
// not go to its provider 3, which gets nothing. BGP prefers and exports the
// customer route.
func TestGaoRexfordWithWorstExportCanLeaveAProviderWithoutAPath(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}, {1, 3}},
		Customers: [][2]int{{2, 0}, {1, 2}, {3, 1}}, Peers: [][2]int{{0, 1}}, Seed: 2}
	results, findings := Check(&inst)
	assert.Equal(t, []uint32{AS(1), AS(2), AS(0)}, results[BGP].Best[3])
	assert.Contains(t, findings, Finding{OBGPHard, "unreachable", []int{3}, "BGP has a path, this mode none"})
	assert.Contains(t, findings, Finding{OBGPNP, "unreachable", []int{3}, "BGP has a path, this mode none"})
}

// Bad Gadget: every router prefers the path through its clockwise neighbor
// to its direct path, and permits no other. It has no stable state: BGP
// oscillates, OBGPHard propagates by length and converges.
func TestBadGadgetOscillatesInBGPOnly(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {0, 2}, {0, 3}, {1, 2}, {2, 3}, {3, 1}}, Seed: 1,
		Sessions: []Session{
			{From: 2, To: 1, LocalPref: 200, DenyVia: AS(3)},
			{From: 3, To: 2, LocalPref: 200, DenyVia: AS(1)},
			{From: 1, To: 3, LocalPref: 200, DenyVia: AS(2)},
		}}
	results, findings := Check(&inst)
	assert.False(t, results[BGP].Converged)
	assert.True(t, results[OBGPHard].Converged)
	assert.True(t, results[OBGPNP].Converged)
	assert.True(t, results[BGPPN].Converged) // the filters are export filters, NS-BGP's case
	// BGP returns to an earlier state: an order without end, not only a long run.
	if assert.NotNil(t, results[BGP].Cycle) {
		assert.Equal(t, []Finding{{BGP, "no-convergence", nil, busy(results[BGP])}}, findings)
		assert.Contains(t, findings[0].Detail, "an order without end")
	}
}

// A step after the lab's until_stable comes once quiet, or where BGP never
// rests after a share of the messages, as the runner after the timeout: the
// withdraw then ends the oscillation, and the step without rest is counted.
func TestABoundedStepComesAlsoWithoutRest(t *testing.T) {
	gadget := func(bounded bool) Instance {
		return Instance{Routers: 4, Links: [][2]int{{0, 1}, {0, 2}, {0, 3}, {1, 2}, {2, 3}, {3, 1}}, Seed: 1,
			Sessions: []Session{
				{From: 2, To: 1, LocalPref: 200, DenyVia: AS(3)},
				{From: 3, To: 2, LocalPref: 200, DenyVia: AS(1)},
				{From: 1, To: 3, LocalPref: 200, DenyVia: AS(2)},
			},
			Events: []Event{{After: 1 << 30, Kind: "withdraw", Bounded: bounded}}}
	}
	waits := gadget(false)
	assert.False(t, Run(&waits, BGP, MaxSteps).Converged) // the withdraw waits for a rest that never comes
	bounded := gadget(true)
	r := Run(&bounded, BGP, MaxSteps)
	assert.True(t, r.Converged)
	assert.Equal(t, 1, r.Restless)
	r = Run(&bounded, OBGPHard, MaxSteps)
	assert.True(t, r.Converged)
	assert.Zero(t, r.Restless) // at rest before the withdraw
}

// With NS-BGP a router sends a packet on the route it sent the neighbor the
// packet came from: two routers whose own routes point at each other do not
// loop, as each sent the other a route through the origin.
func TestNSBGPForwardsByIngress(t *testing.T) {
	inst := triangle()
	r := Result{
		Best:    [][]uint32{{}, {AS(2), AS(0)}, {AS(1), AS(0)}},
		NextHop: []int{0, 2, 1},
		Ingress: []map[int]Hop{
			{1: {nil, 0}, 2: {nil, 0}},
			{2: {[]uint32{AS(0)}, 0}},
			{1: {[]uint32{AS(0)}, 0}},
		},
	}
	assert.Empty(t, forwarding(&inst, BGPPN, r))
	r.Ingress = nil
	assert.Equal(t, []Finding{{BGPPN, "loop", []int{1, 2}, "forwarding goes in a circle"}}, forwarding(&inst, BGPPN, r))
	r.Ingress = []map[int]Hop{{}, {2: {[]uint32{AS(0)}, 0}}, {}}
	assert.Equal(t, []Finding{{BGPPN, "black-hole", []int{1, 2}, "forwarding ends at a router without a path"}}, forwarding(&inst, BGPPN, r))
}

// A route leak: router 1 sends the route of its provider 0 to its other
// provider 2, which prefers it as a customer route.
func TestALeakedPathIsNotValleyFree(t *testing.T) {
	inst := Instance{Routers: 3, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}},
		Customers: [][2]int{{0, 1}, {2, 1}}, Peers: [][2]int{{0, 2}}, Leakers: []int{1}, Seed: 1}
	results, findings := Check(&inst)
	assert.Equal(t, []uint32{AS(1), AS(0)}, results[BGP].Best[2])
	assert.Contains(t, findings, Finding{BGP, "leaked", []int{2}, "these routers use a path that is not valley-free"})
	assert.NotContains(t, findings, Finding{OBGPHard, "leaked", []int{2}, "these routers use a path that is not valley-free"})
}

// Router 3 uses the path through its customer 1, but its packets go to its
// customer 2, which forwards them to its peer 1: up after a peer, a valley
// on the way of the packets that the path does not have.
func TestPacketsAgainstTheRelationsAreAForwardValley(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}, {1, 3}},
		Customers: [][2]int{{1, 0}, {3, 2}, {3, 1}}, Peers: [][2]int{{1, 2}}, Seed: 1}
	r := Result{
		Best:    [][]uint32{{}, {AS(0)}, {AS(1), AS(0)}, {AS(1), AS(0)}},
		NextHop: []int{0, 0, 1, 2},
	}
	assert.Equal(t, []int{3}, forwardValleys(&inst, r, nil))
	assert.Empty(t, forwardValleys(&inst, r, []int{3})) // a leak by policy
	r.NextHop[3] = 1
	assert.Empty(t, forwardValleys(&inst, r, nil))
	rel := relations(&inst)
	assert.True(t, valleyFree(rel, []int{2, 1, 0}))
	assert.False(t, valleyFree(rel, []int{3, 2, 1, 0}))
}

// Without leaks BGP forwards on the paths it sends: no forward valley.
func TestBGPHasNoForwardValley(t *testing.T) {
	inst := Instance{Routers: 3, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}},
		Customers: [][2]int{{0, 1}, {2, 1}}, Peers: [][2]int{{0, 2}}, Seed: 1}
	_, findings := Check(&inst)
	for _, f := range findings {
		assert.NotEqual(t, "forward-valley", f.Kind)
	}
}

func TestTheSearchIsExhaustiveForSmallNetworks(t *testing.T) {
	assert.Len(t, Topologies(3), 4)  // three paths and the triangle
	assert.Len(t, Topologies(4), 38) // the connected labeled graphs of four nodes
	assert.Len(t, Topologies(5), 58) // of five, one per graph up to renumbering all but the origin
	for _, f := range Families {
		assert.NotEmpty(t, Instances(f, 3, []int64{1}), f.Name)
	}
	// Every acyclic assignment of relations: the triangle has 3^3 = 27, two of them cyclic.
	assert.Len(t, gaoRexford(3, [][2]int{{0, 1}, {0, 2}, {1, 2}}), 25)
	// Every local preference where it can matter: DISAGREE is among them.
	prefs := localPref(3, [][2]int{{0, 1}, {0, 2}, {1, 2}})
	assert.Len(t, prefs, 16) // 2^4: routers 1 and 2 each from two neighbors, the origin from none
	assert.Contains(t, prefs, Instance{Sessions: []Session{{From: 1, To: 2, LocalPref: 200}, {From: 2, To: 1, LocalPref: 200}}})
	// Beyond PolicyLimit a sample of distinct assignments.
	many := assignments(slices.Repeat([]int{2}, 20), PolicyLimit, rand.New(rand.NewSource(1)))
	assert.Len(t, many, PolicyDraws)
	assert.Len(t, assignments([]int{2, 3}, PolicyLimit, nil), 6)
}

// Renumbering every router but the origin keeps a graph, the origin's place does not.
func TestCanonicalNamesAGraphUpToRenumbering(t *testing.T) {
	assert.Equal(t, canonical(4, [][2]int{{0, 1}, {1, 2}, {2, 3}}), canonical(4, [][2]int{{0, 3}, {3, 1}, {1, 2}}))
	assert.NotEqual(t, canonical(4, [][2]int{{0, 1}, {1, 2}, {2, 3}}), canonical(4, [][2]int{{0, 2}, {1, 2}, {2, 3}}))
}

// Same seed, same run: findings can be replayed.
func TestARunIsReproducible(t *testing.T) {
	for _, f := range Families {
		for _, inst := range Instances(f, 4, []int64{7})[:5] {
			for _, m := range Modes {
				assert.Equal(t, Run(&inst, m, MaxSteps), Run(&inst, m, MaxSteps), f.Name)
			}
		}
	}
}

// An AS of three routers, 1, 2 and 4, behind route reflector 2. With iBGP
// paths filtered, as in the paper's code, clients get only the worst path
// of the reflector: client 1 knows only the detour through 2, while 2
// forwards to 4 over 1. BGP gives clients the best path and does not loop,
// nor does native iBGP.
func TestFilteredIBGPLoopsBehindARouteReflector(t *testing.T) {
	inst := Instance{Routers: 5, AS: []int{0, 1, 1, 3, 1}, Links: [][2]int{{0, 3}, {0, 4}, {1, 2}, {1, 4}, {2, 3}},
		Costs: []int{1, 1, 10, 10, 1}, IBGP: []IBGP{{AS: 1, Reflectors: []int{2}}}, Seed: 2}
	_, findings := Check(&inst, OBGPPaper)
	assert.Contains(t, findings, Finding{OBGPPaper, "loop", []int{1, 2}, "forwarding goes in a circle"})
	results, findings := Check(&inst, OBGP, OBGPHard, OBGPNP)
	assert.Empty(t, findings)
	assert.True(t, results[BGP].Converged)
}

// The iBGP of the simulator is sound: BGP reaches every router without
// loops in every small network with an AS of several routers.
func TestBGPOverIBGPNeitherLoopsNorLosesRouters(t *testing.T) {
	for _, f := range Families {
		if f.Name != "ibgp-mesh" && f.Name != "ibgp-rr" {
			continue
		}
		for _, inst := range Instances(f, 4, []int64{1, 2}) {
			r := Run(&inst, BGP, MaxSteps)
			assert.True(t, r.Converged)
			assert.Empty(t, forwarding(&inst, BGP, r), "%+v", inst)
			for i, best := range r.Best {
				assert.NotNil(t, best, "router %d in %+v", i, inst)
			}
		}
	}
}

func ptr(i int) *int { return &i }

// The lab's steps, played by the simulator: an origin other than router 0,
// set_preference, prepend towards all, and expect.
func TestTheLabsStepsAsEvents(t *testing.T) {
	// A square 0-1-2-3-0, router 2 announces.
	inst := Instance{Routers: 4, Origin: 2, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}, {3, 0}}, Seed: 1, Events: []Event{
		{After: 1 << 30, Kind: "expect", Routers: []int{0, 1, 3}, Forwarding: true},
		{After: 1 << 30, Kind: "local-pref", From: 3, To: 0, Value: 300},
		{After: 1 << 30, Kind: "expect", Routers: []int{0}, Via: ptr(3)},
		{After: 1 << 30, Kind: "prepend-all", From: 3, Value: 3},
		{After: 1 << 30, Kind: "expect", Routers: []int{0}, Avoid: ptr(3)},
		{After: 1 << 30, Kind: "withdraw"},
		{After: 1 << 30, Kind: "expect", Routers: []int{0, 1, 3}, Prefixes: "none"},
	}}
	r := Run(&inst, BGP, MaxSteps)
	assert.True(t, r.Converged)
	assert.Len(t, r.Checks, 4)
	assert.True(t, r.Checks[0].Passed, r.Checks[0].Problems)
	assert.True(t, r.Checks[1].Passed, r.Checks[1].Problems) // Local Preference wins over the tie
	// The prepended path via 3 is longer, but 300 still wins in BGP: 0 routes through 3.
	assert.Equal(t, Verdict{Passed: false, Problems: []string{"router 0 routes through 3"}}, r.Checks[2])
	assert.True(t, r.Checks[3].Passed, r.Checks[3].Problems)
}

// A second router announces the prefix too, as the lab's originate step:
// every router has a route, in BGP its neighbor takes the shorter path, and
// when the origin withdraws, the copy is left for every router.
func TestASecondOriginAnnouncesThePrefixToo(t *testing.T) {
	line := func(events ...Event) Instance {
		return Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}}, Seed: 1, Events: events}
	}
	inst := line(Event{After: 1 << 30, Kind: "originate", From: 3, Value: 1})
	for _, m := range Modes {
		r := Run(&inst, m, MaxSteps)
		assert.True(t, r.Converged, m)
		assert.Equal(t, []uint32{}, r.Best[3], m) // its own
		for i, best := range r.Best {
			assert.NotNil(t, best, "%s %d", m, i)
		}
	}
	assert.Equal(t, []uint32{AS(3)}, Run(&inst, BGP, MaxSteps).Best[2]) // the shorter path, in BGP
	inst = line(Event{After: 1 << 30, Kind: "originate", From: 3, Value: 1}, Event{After: 1 << 30, Kind: "withdraw"})
	for _, m := range Modes {
		r := Run(&inst, m, MaxSteps)
		assert.Equal(t, []uint32{AS(1), AS(2), AS(3)}, r.Best[0], m)
	}
	inst = line(Event{After: 1 << 30, Kind: "originate", From: 3, Value: 1}, Event{After: 1 << 30, Kind: "originate", From: 3})
	assert.Equal(t, []uint32{AS(0)}, Run(&inst, BGP, MaxSteps).Best[1]) // withdrawn at 3: the origin's alone
}

// An event at any point comes among the messages, before the network is
// quiet in some orders, and once it is quiet at the latest. Events before
// the announcement set the state the origin announces into.
func TestEventsAtAnyPointAndBeforeTheAnnouncement(t *testing.T) {
	early := 0
	for seed := int64(1); seed <= 20; seed++ {
		inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}, {3, 0}}, Seed: seed,
			Events: []Event{{After: 1 << 30, Any: true, Kind: "down", From: 0, To: 1}}}
		var steps []Step
		r := runRecorded(&inst, BGP, MaxSteps, nil, &steps)
		assert.True(t, r.Converged)
		assert.Equal(t, []uint32{AS(3), AS(0)}, r.Best[2])
		if k := slices.IndexFunc(steps, func(s Step) bool { return s.Kind == "event" }); k < len(steps)-1 {
			early++ // messages came after it
		}
	}
	assert.Positive(t, early)
	inst := Instance{Routers: 3, Links: [][2]int{{0, 1}, {1, 2}}, Seed: 1, Events: []Event{{After: -1, Kind: "down", From: 1, To: 2}}}
	r := Run(&inst, BGP, MaxSteps)
	assert.Equal(t, 1, r.Steps) // 0 to 1 only: nothing ever crossed to 2
	assert.Nil(t, r.Best[2])
}

// A session that goes down loses its messages and their send times: a
// message delivered after it comes back was sent after it went down.
func TestASessionDownForgetsTheSendTimesOfItsMessages(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}, {3, 0}}, Seed: seed,
			Events: []Event{{After: 1 << 30, Any: true, Kind: "down", From: 1, To: 2}, {After: 1 << 30, Any: true, Kind: "up", From: 1, To: 2}}}
		_, steps := Record(&inst, BGP)
		down := 0
		for k, s := range steps {
			if s.Kind == "event" && s.Event.Kind == "down" {
				down = k + 1 // the replay counts from 1
			} else if s.Kind != "event" && down > 0 && (s.From == 1 && s.To == 2 || s.From == 2 && s.To == 1) {
				assert.Greater(t, s.Sent, down, "seed %d, step %d", seed, k+1)
			}
		}
	}
}

// An aggregate keeps its AS_SET over several hops, one hop long, and all
// modes agree with BGP whatever the order of its members.
func TestAnAggregateKeepsItsSet(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}, {0, 3}}, OriginSet: []uint32{64601, 64600}, Seed: 1}
	results, findings := Check(&inst)
	assert.Empty(t, findings)
	assert.Equal(t, []uint32{AS(0), 64601, 64600}, results[OBGPHard].Best[1])
	best := results[OBGPHard].Best[2] // two hops away: over router 1 or 3, then the origin and its set
	assert.Len(t, best, 4)
	assert.Equal(t, []uint32{AS(0), 64601, 64600}, best[1:])
	for _, f := range Families {
		if f.Name == "aggregation" {
			for _, inst := range Instances(f, 4, []int64{1, 2}) {
				_, findings := Check(&inst)
				assert.Empty(t, findings, "%+v", inst)
			}
		}
	}
}

// A confederation of routers 1 and 2: inside, the member AS goes into the
// confederation segment, outside only the identifier shows.
func TestAConfederationLooksLikeOneASFromOutside(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}}, Confeds: []Confed{{Members: []int{1, 2}, ID: 65500}}, Seed: 1}
	results, findings := Check(&inst)
	assert.Empty(t, findings)
	for _, m := range Modes {
		assert.Equal(t, []uint32{AS(1), AS(0)}, results[m].Best[2], m) // the confederation segment, then the origin
		assert.Equal(t, []uint32{65500, AS(0)}, results[m].Best[3], m) // the identifier only
	}
}

// An igp event changes where packets go inside an AS, not the routes: the
// loop behind the reflector, with iBGP filtered, ends when r1 reaches r4
// over r2 no more.
func TestAnIGPLinkChangesForwardingOnly(t *testing.T) {
	inst := Instance{Routers: 5, AS: []int{0, 1, 1, 3, 1}, Links: [][2]int{{0, 3}, {0, 4}, {1, 2}, {1, 4}, {2, 3}},
		Costs: []int{1, 1, 10, 10, 1}, IBGP: []IBGP{{AS: 1, Reflectors: []int{2}}}, Seed: 2,
		Events: []Event{{After: 1 << 30, Kind: "expect", Routers: []int{1}, Forwarding: true}}}
	before := Run(&inst, OBGPPaper, MaxSteps)
	assert.False(t, before.Checks[0].Passed)
	inst.Events = append([]Event{{After: 1 << 30, Kind: "igp", From: 1, To: 4, Value: 0}}, inst.Events...)
	after := Run(&inst, OBGPPaper, MaxSteps)
	assert.Equal(t, before.Best, after.Best) // the same routes
	assert.Equal(t, 0, after.Costs[3])
}

// Communities of the origin, as the lab's controller enforces them on every
// router: 0:AS keeps the route from that AS, also over the other way;
// no-export keeps it in the ASes next to the origin.
func TestCommunitiesKeepRoutesFromNeighbors(t *testing.T) {
	inst := triangle()
	inst.OriginCommunities = []string{fmt.Sprintf("0:%d", AS(1))}
	results, findings := Check(&inst)
	assert.Empty(t, findings)
	for _, m := range Modes {
		assert.Nil(t, results[m].Best[1], m)
		assert.Equal(t, []uint32{AS(0)}, results[m].Best[2], m)
	}
	line := Instance{Routers: 3, Links: [][2]int{{0, 1}, {1, 2}}, OriginCommunities: []string{"no-export"}, Seed: 1}
	results, _ = Check(&line)
	for _, m := range Modes {
		assert.NotNil(t, results[m].Best[1], m)
		assert.Nil(t, results[m].Best[2], m)
	}
}

// A poisoned AS drops the route as a loop, in every mode.
func TestAPoisonedASDropsTheRoute(t *testing.T) {
	inst := triangle()
	inst.OriginPoison = []uint32{AS(1)}
	results, _ := Check(&inst)
	for _, m := range Modes {
		assert.Nil(t, results[m].Best[1], m)
		assert.Equal(t, []uint32{AS(0), AS(1), AS(0)}, results[m].Best[2], m)
	}
}

// Siblings pass each other every route, which keeps its class: a route of
// a peer goes up to no provider of the sibling, a route of a customer does.
func TestSiblingsKeepTheClassOfARoute(t *testing.T) {
	line := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {2, 3}}, Siblings: [][2]int{{1, 2}}, Customers: [][2]int{{3, 2}}, Seed: 1}
	peer := line
	peer.Peers = [][2]int{{0, 1}}
	results, findings := Check(&peer)
	assert.Empty(t, findings)
	for _, m := range Modes {
		assert.NotNil(t, results[m].Best[2], m)
		assert.Nil(t, results[m].Best[3], m)
	}
	customer := line
	customer.Customers = [][2]int{{3, 2}, {1, 0}}
	results, findings = Check(&customer)
	assert.Empty(t, findings)
	for _, m := range Modes {
		assert.Equal(t, []uint32{AS(2), AS(1), AS(0)}, results[m].Best[3], m)
	}
}

// Partial transit: a provider passes a customer only the paths of its own
// customers, as to a peer, not those of its peers.
func TestPartialTransitPassesOnlyRoutesOfCustomers(t *testing.T) {
	full := Instance{Routers: 3, Links: [][2]int{{0, 1}, {1, 2}}, Peers: [][2]int{{0, 1}}, Customers: [][2]int{{1, 2}}, Seed: 1}
	partial := full
	partial.Sessions = []Session{{From: 1, To: 2, Partial: true}}
	for _, m := range Modes {
		assert.NotNil(t, Run(&full, m, MaxSteps).Best[2], m)
		assert.Nil(t, Run(&partial, m, MaxSteps).Best[2], m)
	}
}

// A route server between clients, as gobgpd's: transparent, it sends a
// client every path its filter allows, so a filter leaves the client the
// other path. In obgp-paper it chooses first, then filters.
func TestARouteServerIsTransparentAndFiltersBeforeItsChoice(t *testing.T) {
	// 0 originates behind 1 and 2, clients of route server 3 with 4.
	inst := Instance{Routers: 5, Links: [][2]int{{0, 1}, {0, 2}, {1, 3}, {2, 3}, {3, 4}}, RouteServers: []int{3}, Seed: 1}
	results, findings := Check(&inst)
	assert.Empty(t, findings)
	for _, m := range Modes {
		assert.True(t, results[m].Converged, m)
		assert.Len(t, results[m].Best[4], 2, m)                              // the route server adds no AS
		assert.Equal(t, results[m].Best[4][0], AS(results[m].NextHop[4]), m) // and leaves the next hop
	}
	// 4 filters paths through the AS it uses: BGP gets the other one. Under
	// OBGP the other client may export only its path through the route
	// server, one route per AS, then 4 has none, never the filtered one.
	chosen := results[BGP].NextHop[4]
	inst.Sessions = []Session{{From: 3, To: 4, DenyVia: AS(chosen)}}
	results, _ = Check(&inst)
	assert.Len(t, results[BGP].Best[4], 2)
	for _, m := range Modes {
		if m != OBGPPaper && results[m].Best[4] != nil {
			assert.NotEqual(t, chosen, results[m].NextHop[4], m)
		}
	}
}

// Trace writes a line per message, and the run is the one Run plays.
func TestTraceWritesEveryMessage(t *testing.T) {
	inst := Instance{Routers: 3, Links: [][2]int{{0, 1}, {1, 2}, {0, 2}}, Seed: 1}
	var out strings.Builder
	r := Trace(&inst, OBGP, &out)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != r.Steps || !strings.Contains(lines[0], "0: local") {
		t.Fatalf("%d lines for %d messages:\n%s", len(lines), r.Steps, out.String())
	}
	if plain := Run(&inst, OBGP, MaxSteps); plain.Steps != r.Steps || !plain.Converged {
		t.Fatalf("trace changed the run: %d against %d messages", r.Steps, plain.Steps)
	}
}

// Over tunnels to the exit, a router inside an AS no longer decides again:
// a network whose AS loops on the way hop by hop does not with tunnels.
func TestTunnelsToTheExitRemoveLoopsInsideAnAS(t *testing.T) {
	Transient = true
	defer func() { Transient, Tunnel = false, false }()
	for _, inst := range Instances(familyNamed("ibgp-rr"), 5, []int64{1, 2, 3}) {
		Tunnel = false
		if Run(&inst, OBGP, MaxSteps).Transient == nil {
			continue
		}
		Tunnel = true
		r := Run(&inst, OBGP, MaxSteps)
		assert.True(t, r.Converged)
		assert.Nil(t, r.Transient)
		assert.Empty(t, forwarding(&inst, OBGP, r))
		return
	}
	t.Fatal("no network loops inside an AS hop by hop")
}

// The way to rest is told apart: a loop is counted exactly when one was
// seen, BGP never blocks as it never waits for a route refresh, and refresh
// pruning blocks in some network, as a router of DUAL waits while active.
func TestTheWayToRestSeparatesLoopsBlockingAndHoles(t *testing.T) {
	Transient = true
	defer func() { Transient = false }()
	blocked := false
	for _, inst := range Instances(familyNamed("withdraw"), 4, []int64{1, 2, 3}) {
		for _, m := range []Mode{BGP, OBGP} {
			r := Run(&inst, m, MaxSteps)
			assert.Equal(t, r.Transient != nil, r.Looped > 0, "%v %s", inst.Links, m)
			if m == BGP {
				assert.Zero(t, r.Blocked, "%v", inst.Links)
			} else if r.Blocked > 0 {
				blocked = true
			}
		}
	}
	assert.True(t, blocked, "refresh pruning never waited without a route")
}

// Recording a run changes nothing: the same result as Run, one step per
// message delivered beside the events, and the last step forwards as the run ends.
func TestRecordShowsTheRunItPlays(t *testing.T) {
	for _, inst := range Instances(familyNamed("withdraw"), 4, []int64{1, 2}) {
		for _, m := range []Mode{BGP, OBGP} {
			plain := Run(&inst, m, MaxSteps)
			r, steps := Record(&inst, m)
			assert.Equal(t, plain.Steps, r.Steps)
			assert.Equal(t, plain.Best, r.Best)
			messages := 0
			for _, st := range steps {
				if st.Kind != "event" {
					messages++
				}
			}
			if assert.Equal(t, r.Steps, messages) && len(steps) > 0 {
				for i, rs := range steps[len(steps)-1].Routers {
					assert.Equal(t, r.NextHop[i], rs.NextHop, "router %d", i)
				}
			}
		}
	}
}

func familyNamed(name string) Family {
	for _, f := range Families {
		if f.Name == name {
			return f
		}
	}
	panic(name)
}

// With a table per neighbor, a router that admitted a short peer route
// first still sends its providers a customer route: a network that loses a
// route under Gao-Rexford with one route per AS does not. It forwards by
// ingress: its provider's packets take the customer route it sent the
// provider, not its own peer route, so no forward valley either.
func TestATablePerNeighborKeepsGaoRexfordRoutes(t *testing.T) {
	Transient = true
	defer func() { Transient, PerNeighbor = false, false }()
	for _, inst := range Instances(familyNamed("gao-rexford"), 4, []int64{1, 2, 3}) {
		PerNeighbor = false
		if _, findings := Check(&inst, OBGP); !slices.ContainsFunc(findings, func(f Finding) bool { return f.Kind == "unreachable" }) {
			continue
		}
		PerNeighbor = true
		results, findings := Check(&inst, OBGP)
		assert.Empty(t, findings)
		r := results[OBGP]
		assert.Equal(t, []uint32{AS(1), AS(2), AS(0)}, r.Best[3]) // through customer 1 and its customer 2
		assert.Equal(t, 0, r.NextHop[1])                          // 1's own packets take its peer route
		assert.Equal(t, 2, r.Ingress[1][3].NextHop)               // those of its provider 3 the customer route
		assert.True(t, r.Converged)
		return
	}
	t.Fatal("no network loses a route under Gao-Rexford")
}

// Without export filters every table per neighbor holds what the main one
// holds, from the start and in the same order: OBGP per neighbor sends and
// forwards exactly as OBGP with one table, message by message.
func TestATablePerNeighborWithoutFiltersIsTheMainTable(t *testing.T) {
	Transient = true
	defer func() { Transient, PerNeighbor = false, false }()
	for _, name := range []string{"withdraw", "aggregation"} {
		for n := 2; n <= 5; n++ {
			for _, inst := range Instances(familyNamed(name), n, []int64{1, 2, 3}) {
				for _, m := range []Mode{OBGP, OBGPHard} {
					PerNeighbor = false
					one := Run(&inst, m, MaxSteps)
					PerNeighbor = true
					per := Run(&inst, m, MaxSteps)
					// The same messages and tables. Forwarding by ingress may loop on the way where one table does not, or the other way round.
					per.Ingress, per.Transient, per.Looped, per.Holes = nil, one.Transient, one.Looped, one.Holes
					if !assert.Equal(t, one, per, "%s %v %s", name, inst.Links, m) {
						return
					}
				}
			}
		}
	}
}

func TestATraceTellsWhatGoesInAndOutPerNeighbor(t *testing.T) {
	// Gao-Rexford: 0 a customer of 2, 2 of 1, 1 of 3, 0 and 1 peers. One OBGP table at 1
	// admits the peer route, sets the customer route aside and may not offer the peer route to its provider 3.
	inst := Instance{Family: "gao-rexford", Routers: 4, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}, {1, 3}},
		Customers: [][2]int{{2, 0}, {1, 2}, {3, 1}}, Peers: [][2]int{{0, 1}}, Seed: 2}
	_, steps := Record(&inst, OBGP)
	r := steps[len(steps)-1].Routers[1]
	assert.Contains(t, r.In, Received{From: 2, Path: []uint32{65003, 65001}, Fate: "set aside", Over: "ebgp"})
	assert.Contains(t, r.Out, Sent{To: 3, Not: notRelation})
	_, steps = Record(&inst, BGP)
	r = steps[len(steps)-1].Routers[1]
	assert.Contains(t, r.In, Received{From: 2, Path: []uint32{65003, 65001}, Fate: "best", Over: "ebgp"})
	assert.Contains(t, r.Out, Sent{To: 3, Path: []uint32{65002, 65003, 65001}})
}

// The trace explains the loop behind the route reflector: each router's
// packets go to the router the forwarding check follows, inside the AS the
// IGP's first hop, and every path a router admits but does not use names the
// step of BGP's selection it loses at.
func TestATraceExplainsWhereAndWhyPacketsGo(t *testing.T) {
	inst := Instance{Routers: 5, AS: []int{0, 1, 1, 3, 1}, Links: [][2]int{{0, 3}, {0, 4}, {1, 2}, {1, 4}, {2, 3}},
		Costs: []int{1, 1, 10, 10, 1}, IBGP: []IBGP{{AS: 1, Reflectors: []int{2}}}, Seed: 2}
	for _, m := range []Mode{BGP, OBGPPaper, BGPPN} {
		r, steps := Record(&inst, m)
		last := steps[len(steps)-1].Routers
		igp := shortest(&inst, r.Costs)
		for i, rs := range last {
			want := rs.NextHop
			if want >= 0 && want != i && inst.asOf(want) == inst.asOf(i) && m != BGPPN {
				want = igp[i][want]
			}
			if m != BGPPN {
				assert.Equal(t, want, rs.Forward, "%s router %d", m, i)
			}
			for _, in := range rs.In {
				if in.Fate == "admitted" && m != OBGPPaper {
					assert.NotEmpty(t, in.Lost, "%s router %d, path from %d", m, i, in.From)
				}
			}
		}
		assert.Equal(t, "ibgp", last[1].In[0].Over) // 1 has a session to reflector 2
		assert.Equal(t, "igp", last[1].In[1].Over)  // and a link to 4 without one
		if m == OBGPPaper {
			assert.Equal(t, 2, last[1].Forward)
			assert.Equal(t, 1, last[2].Forward) // the loop: 1 to 2, 2 over 1 towards 4
		}
		if m == BGPPN {
			assert.NotEmpty(t, last[3].Ingress)
		}
	}
}

// A mixed mode with the same mode on every router plays as that mode: the
// per-router settings change nothing where all routers share them.
func TestAMixedModeOfOneModePlaysAsThatMode(t *testing.T) {
	Transient = true
	defer func() { Transient = false }()
	for _, f := range Families {
		all := Instances(f, 4, []int64{1, 2})
		for k := 0; k < len(all); k += max(1, len(all)/40) {
			inst := all[k]
			for _, m := range BothTables {
				mixed := inst
				mixed.Mixed = map[Mode][]Mode{"same": slices.Repeat([]Mode{m}, inst.Routers)}
				want, wantSteps := Record(&inst, m)
				got, gotSteps := Record(&mixed, "same")
				got.Mode = m
				assert.Equal(t, want, got, "%s %s %v", f.Name, m, inst.Links)
				assert.Equal(t, wantSteps, gotSteps, "%s %s %v", f.Name, m, inst.Links)
			}
		}
	}
}

// In a mixed mode each router decides by its own mode: an OBGP router
// exports its worst admitted path, a BGP router beside it its best.
func TestAMixedModeDecidesPerRouter(t *testing.T) {
	inst := triangle()
	inst.Mixed = map[Mode][]Mode{"half": {BGP, OBGPNP, BGP}}
	results, _ := Check(&inst, "half")
	assert.Equal(t, []uint32{AS(2), AS(0)}, results["half"].Exported[1])
	assert.Equal(t, []uint32{AS(0)}, results["half"].Exported[2])
	assert.Equal(t, []uint32{AS(0)}, results[BGP].Exported[1])
	inst.Mixed["half"] = []Mode{BGP, BGP, BGP}
	assert.Error(t, (&Instance{Routers: 2, Mixed: map[Mode][]Mode{"x": {BGPPN, BGP}}}).Validate())
	assert.NoError(t, inst.Validate())
}

// With an MRAI an update still on a session gives way to a newer update or
// withdrawal of its path ID, which goes behind the others. Refresh requests
// and withdrawals wait for nothing, nor do sessions inside an AS.
func TestAnMRAICoalescesTheUpdatesOfAPathIDOnASession(t *testing.T) {
	update := func(id uint32, as uint32) message { return message{id: id, route: route{path: []uint32{as}}} }
	sends := []message{update(0, 1), {refresh: true}, update(0, 2), {id: 1, withdraw: true}, update(1, 3), {id: 0, withdraw: true}}
	queued := func(mrai bool, as []int) []message {
		n := &network{inst: &Instance{Routers: 2, AS: as, MRAI: mrai}, queues: map[session][]message{}, sentAt: map[session][]int{}, sends: map[session]int{}}
		for k, m := range sends {
			n.cur = k + 1
			n.send(session{0, 1}, m)
		}
		assert.Len(t, n.sentAt[session{0, 1}], len(n.queues[session{0, 1}]))
		return n.queues[session{0, 1}]
	}
	assert.Equal(t, []message{sends[1], sends[3], sends[4], sends[5]}, queued(true, nil))
	assert.Equal(t, sends, queued(false, nil))
	assert.Equal(t, sends, queued(true, []int{0, 0})) // iBGP
}

// An MRAI coalesces: over many networks fewer messages are delivered. Not
// in every order, as the orders drawn differ once a message gives way.
func TestAnMRAIDeliversFewerMessagesOverall(t *testing.T) {
	without, with := 0, 0
	for _, f := range Families {
		for _, inst := range Instances(f, 4, []int64{1, 2})[:20] {
			mrai := inst
			mrai.MRAI = true
			a, b := Run(&inst, BGP, MaxSteps), Run(&mrai, BGP, MaxSteps)
			if a.Converged && b.Converged {
				without, with = without+a.Steps, with+b.Steps
			}
		}
	}
	assert.Less(t, with, without)
}

// Graceful restart, on a line 0-1-2 from origin 0: router 1 restarts
// gracefully, router 2 keeps its route stale until 1 is back and has sent
// its routes. Without graceful restart 2 loses it at once.
func TestAGracefulRestartKeepsTheRoutesStaleUntilTheRouterIsBack(t *testing.T) {
	quiet := 1 << 30
	inst := Instance{Routers: 3, Links: [][2]int{{0, 1}, {1, 2}}, Events: []Event{
		{After: quiet, Kind: "restart", From: 1, Value: 1},
		{After: quiet, Kind: "expect", Routers: []int{2}},
		{After: quiet, Kind: "expect", Routers: []int{1}, Prefixes: "none"},
		{After: quiet, Kind: "up", From: 0, To: 1, Any: true},
		{After: quiet, Kind: "up", From: 1, To: 2, Any: true},
		{After: quiet, Kind: "expect", Routers: []int{1, 2}},
	}}
	for seed := range int64(20) {
		inst.Seed, inst.GracefulRestart = seed, true
		for _, m := range Modes {
			r, steps := Record(&inst, m)
			assert.True(t, r.Converged, m)
			assert.Equal(t, []Verdict{{Passed: true}, {Passed: true}, {Passed: true}}, r.Checks, m)
			last := steps[len(steps)-1].Routers[2].In
			assert.False(t, slices.ContainsFunc(last, func(x Received) bool { return x.Stale }), m) // sent again: no longer stale
			assert.True(t, slices.ContainsFunc(steps, func(s Step) bool { return s.Kind == "end-of-rib" }), m)
		}
		inst.GracefulRestart = false
		r := Run(&inst, BGP, MaxSteps)
		assert.False(t, r.Checks[0].Passed) // its peers drop its routes
		assert.True(t, r.Checks[2].Passed)
	}
}

// A silent failure with graceful restart: both ends keep the routes
// stale. Routes not sent again after the link is back go with the
// End-of-RIB, and they go once the restart time ends with the link down.
func TestASilentFailureKeepsTheRoutesStaleUntilEndOfRIBOrExpiry(t *testing.T) {
	quiet := 1 << 30
	line := func(events ...Event) Instance {
		return Instance{Routers: 3, Links: [][2]int{{0, 1}, {1, 2}}, GracefulRestart: true, Seed: 1, Events: events}
	}
	held := Event{After: quiet, Kind: "expect", Routers: []int{2}}
	gone := Event{After: quiet, Kind: "expect", Routers: []int{2}, Prefixes: "none"}
	cut := Event{After: quiet, Kind: "down", From: 1, To: 2, Value: 1}
	// Back after the origin withdrew: 1 sends nothing again, its End-of-RIB removes the stale route.
	inst := line(cut, held, Event{After: quiet, Kind: "withdraw"}, held, Event{After: quiet, Kind: "up", From: 1, To: 2}, gone)
	for _, m := range Modes {
		r := Run(&inst, m, MaxSteps)
		assert.Equal(t, []Verdict{{Passed: true}, {Passed: true}, {Passed: true}}, r.Checks, m)
	}
	// Never back: the restart time ends.
	inst = line(cut, held, Event{After: quiet, Kind: "expire", From: 1, To: 2}, gone)
	assert.Equal(t, []Verdict{{Passed: true}, {Passed: true}}, Run(&inst, BGP, MaxSteps).Checks)
	// One way, 2 dropping the packets of 1: 2 keeps 1's routes, 1 gets 2's notification and drops 2's.
	inst = line(Event{After: quiet, Kind: "down", From: 1, To: 2, Value: 2}, held)
	assert.True(t, Run(&inst, BGP, MaxSteps).Checks[0].Passed)
	inst = line(Event{After: quiet, Kind: "down", From: 2, To: 1, Value: 2}, gone)
	assert.True(t, Run(&inst, BGP, MaxSteps).Checks[0].Passed)
	// Without graceful restart a silent failure loses the routes at once, as before.
	inst = line(cut, gone)
	inst.GracefulRestart = false
	assert.True(t, Run(&inst, BGP, MaxSteps).Checks[0].Passed)
}

// What a router offers is its full path, a confederation segment too, and
// with a table per neighbor a filter set by an event gives the filter's
// reason, as with one table.
func TestTheOutputNamesFullPathsAndTheFiltersReason(t *testing.T) {
	inst := triangle()
	inst.Events = []Event{{After: 1 << 30, Kind: "deny-export", From: 0, To: 2, Value: 1}}
	for _, m := range []Mode{OBGP, OBGPPN} {
		_, steps := Record(&inst, m)
		out := steps[len(steps)-1].Routers[0].Out
		i := slices.IndexFunc(out, func(s Sent) bool { return s.To == 2 })
		assert.Equal(t, notFilter, out[i].Not, m)
	}
	confed := Instance{Routers: 3, AS: []int{0, 1, 2}, Links: [][2]int{{0, 1}, {1, 2}}, Confeds: []Confed{{Members: []int{1, 2}, ID: 64999}}, Seed: 1}
	r, steps := Record(&confed, BGP)
	assert.Equal(t, []uint32{AS(1), AS(0)}, r.Exported[2])
	assert.Equal(t, []uint32{AS(1), AS(0)}, steps[len(steps)-1].Routers[2].Exported)
	assert.Equal(t, [][]uint32{{AS(1), AS(0)}}, steps[len(steps)-1].Routers[2].Admitted)
}

// The sessions of a restart come back in an order the lab does not control:
// with a group each of them comes first in some order, the timing stays in
// place. Without one they come as listed.
func TestEventsOfAGroupComeInAnyOrder(t *testing.T) {
	quiet := 1 << 30
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {1, 2}, {1, 3}}, Events: []Event{
		{After: quiet, Kind: "restart", From: 1},
		{After: quiet, Kind: "up", From: 0, To: 1, Bounded: true, Group: 2},
		{After: quiet, Kind: "up", From: 1, To: 2, Bounded: true, Group: 2},
		{After: quiet, Kind: "up", From: 1, To: 3, Bounded: true, Group: 2},
		{After: quiet, Kind: "expect", Routers: []int{2, 3}},
	}}
	firsts := func() map[int]int {
		seen := map[int]int{}
		for seed := range int64(30) {
			inst.Seed = seed
			r, steps := Record(&inst, BGP)
			assert.True(t, r.Checks[0].Passed)
			for _, s := range steps {
				if s.Kind == "event" && s.Event.Kind == "up" {
					assert.True(t, s.Event.Bounded)
					seen[s.Event.From+s.Event.To]++
					break
				}
			}
		}
		return seen
	}
	assert.Len(t, firsts(), 3)
	for i := range inst.Events {
		inst.Events[i].Group = 0
	}
	assert.Equal(t, map[int]int{1: 30}, firsts())
}

// In a mixed mode only the routers with a table per neighbor forward by
// ingress: router 1 sends its provider's packets on the customer route it
// sent it, the BGP routers on their best route.
func TestInAMixedModeOnlyRoutersWithTablesForwardByIngress(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}, {1, 3}},
		Customers: [][2]int{{2, 0}, {1, 2}, {3, 1}}, Peers: [][2]int{{0, 1}}, Seed: 2,
		Mixed: map[Mode][]Mode{"mix": {BGP, OBGP + "-pn", BGP, BGP}}}
	results, findings := Check(&inst, "mix")
	r := results["mix"]
	assert.True(t, r.Converged)
	assert.Len(t, r.Ingress, 4)
	assert.Nil(t, r.Ingress[0])
	assert.NotNil(t, r.Ingress[1])
	for _, f := range findings {
		assert.NotContains(t, []string{"loop", "black-hole", "forward-valley"}, f.Kind)
	}
}

// TestRouteServerOfferMatchesWhatItSends: the trace states, at the step an update is queued, the offer
// of its sender towards its receiver. A route server offers by its own rules, so the trace must too.
func TestRouteServerOfferMatchesWhatItSends(t *testing.T) {
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}, {1, 3}}, RouteServers: []int{1},
		Sessions: []Session{{From: 1, To: 3, DenyVia: 65003}}, Seed: 1}
	for _, mode := range []Mode{OBGP, OBGPPaper, BGP} {
		_, steps := Record(&inst, mode)
		for _, s := range steps {
			if s.Kind != "update" || s.Sent == 0 || s.From != 1 {
				continue
			}
			found := false
			for _, o := range steps[s.Sent-1].Routers[s.From].Out {
				if o.To == s.To && o.Path != nil {
					found = true
				}
			}
			if !found {
				t.Errorf("%v: route server 1 sends %v to %d at step %d, its offer there says nothing", mode, s.Path, s.To, s.Sent)
			}
		}
	}
}
