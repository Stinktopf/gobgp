//go:build obgpsim

package obgpsim

import (
	"fmt"
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
	assert.Equal(t, []Finding{{BGP, "no-convergence", nil, "still busy after 20000 messages"}}, findings)
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

func TestTheSearchIsExhaustiveForSmallNetworks(t *testing.T) {
	assert.Len(t, Topologies(3), 4)  // three paths and the triangle
	assert.Len(t, Topologies(4), 38) // the connected labeled graphs of four nodes
	for _, f := range Families {
		assert.NotEmpty(t, Instances(f, 3, []int64{1}), f.Name)
	}
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

// A route server between clients, as gobgpd's: transparent, and a
// client's filter applies after the choice, so it may leave the client
// without a route, with BGP as with OBGP.
func TestARouteServerIsTransparentAndFiltersAfterItsChoice(t *testing.T) {
	// 0 originates behind 1 and 2, clients of route server 3 with 4.
	inst := Instance{Routers: 5, Links: [][2]int{{0, 1}, {0, 2}, {1, 3}, {2, 3}, {3, 4}}, RouteServers: []int{3}, Seed: 1}
	results, findings := Check(&inst)
	assert.Empty(t, findings)
	for _, m := range Modes {
		assert.True(t, results[m].Converged, m)
		assert.Len(t, results[m].Best[4], 2, m)                              // the route server adds no AS
		assert.Equal(t, results[m].Best[4][0], AS(results[m].NextHop[4]), m) // and leaves the next hop
	}
	// 4 filters paths through the AS the route server chose for it: BGP and OBGP alike leave it without one.
	chosen := results[BGP].NextHop[4]
	inst.Sessions = []Session{{From: 3, To: 4, DenyVia: AS(chosen)}}
	results, findings = Check(&inst)
	assert.Empty(t, findings)
	assert.Nil(t, results[BGP].Best[4])
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
