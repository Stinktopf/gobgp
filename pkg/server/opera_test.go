package server

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// The tests in this file check OBGP against BGP semantics: export
// policies, split horizon, AS loops, and the lifecycle of sessions and
// policies. As in the original model, a router sends every peer the
// same path, the worst admitted one, or none; export filters may only stop
// it, by the Gao-Rexford class of the peer. Filters per peer are outside the
// model. A router R in AS 65000 runs without sessions. Its peers are
// established, updates are fed in like handleUpdate does, and what R
// sends is read from the outgoing channel of each peer.

const operaLocalAS = 65000

var (
	operaPrefix   = netip.MustParsePrefix("10.0.0.0/24")
	operaOriginal = table.OperaOptions{Enabled: true, Pruning: true}
	operaNoPrune  = table.OperaOptions{Enabled: true, Pruning: false}
	operaModes    = map[string]table.OperaOptions{"obgp": operaOriginal, "obgp-np": operaNoPrune}
)

type operaRouter struct {
	t    *testing.T
	s    *BgpServer
	sent map[*peer]map[string]*table.Path
}

func newOperaRouter(t *testing.T, o table.OperaOptions) *operaRouter {
	t.Helper()
	s := NewBgpServer()
	old := table.GetOperaOptions()
	table.SetOperaOptions(o)
	t.Cleanup(func() { table.SetOperaOptions(old) })
	s.globalRib = table.NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
	require.NoError(t, s.policy.Reset(&oc.RoutingPolicy{}, nil))
	return &operaRouter{t: t, s: s, sent: map[*peer]map[string]*table.Path{}}
}

func (r *operaRouter) peer(address string, as uint32) *peer {
	p := newPeerandInfo(r.t, operaLocalAS, as, address, r.s.globalRib)
	p.policy = r.s.policy
	p.fsm.state.Store(bgp.BGP_FSM_ESTABLISHED)
	r.s.neighborMap[netip.MustParseAddr(address)] = p
	r.sent[p] = map[string]*table.Path{}
	return p
}

func (r *operaRouter) path(from *peer, asList []uint32, withdraw bool) *table.Path {
	nlri, _ := bgp.NewIPAddrPrefix(operaPrefix)
	nexthop, _ := bgp.NewPathAttributeNextHop(from.peerInfo.Address)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asList),
		}),
		nexthop,
	}
	return table.NewPath(bgp.RF_IPv4_UC, from.peerInfo, bgp.PathNLRI{NLRI: nlri}, withdraw, attrs, time.Now(), false)
}

// receive handles an update from a peer like handleUpdate does.
func (r *operaRouter) receive(from *peer, asList []uint32) {
	p := r.path(from, asList, false)
	from.adjRibIn.Update([]*table.Path{p})
	r.s.propagateUpdate(from, []*table.Path{p})
}

func (r *operaRouter) withdraw(from *peer, asList []uint32) {
	p := r.path(from, asList, true)
	from.adjRibIn.Update([]*table.Path{p})
	r.s.propagateUpdate(from, []*table.Path{p})
}

// sessionDown handles the end of a session like handleFSMMessage does.
func (r *operaRouter) sessionDown(p *peer, graceful bool) {
	families := []bgp.Family{bgp.RF_IPv4_UC}
	if graceful {
		r.s.propagateUpdate(p, p.StaleAll(families))
		return
	}
	r.s.propagateUpdate(p, p.DropAll(families))
}

// endOfRib ends a graceful restart like the End-of-RIB of the peer does.
func (r *operaRouter) endOfRib(p *peer) {
	r.s.propagateUpdate(p, p.adjRibIn.DropStale([]bgp.Family{bgp.RF_IPv4_UC}))
}

// route returns the AS path R has sent to p for the prefix, or nil.
func (r *operaRouter) route(p *peer) []uint32 {
	for {
		select {
		case m := <-p.fsm.outgoingCh.Out():
			for _, path := range m.(*fsmOutgoingMsg).Paths {
				if path.IsWithdraw {
					delete(r.sent[p], path.GetPrefix())
				} else {
					r.sent[p][path.GetPrefix()] = path
				}
			}
		case <-time.After(20 * time.Millisecond):
			if path := r.sent[p][operaPrefix.String()]; path != nil {
				return path.GetAsList()
			}
			return nil
		}
	}
}

// updates returns how many updates R sent to p since the last call.
func (r *operaRouter) updates(p *peer) int {
	n := 0
	for {
		select {
		case m := <-p.fsm.outgoingCh.Out():
			for _, path := range m.(*fsmOutgoingMsg).Paths {
				n++
				if path.IsWithdraw {
					delete(r.sent[p], path.GetPrefix())
				} else {
					r.sent[p][path.GetPrefix()] = path
				}
			}
		case <-time.After(20 * time.Millisecond):
			return n
		}
	}
}

func (r *operaRouter) known() [][]uint32 {
	l := [][]uint32{}
	for _, p := range r.s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC}) {
		l = append(l, p.GetAsList())
	}
	return l
}

func (r *operaRouter) best() []uint32 {
	l := r.s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC})
	if len(l) == 0 {
		return nil
	}
	return l[0].GetAsList()
}

// rejectExport makes R reject, towards the peer at address, every path
// whose AS path matches the regular expression. Export policies see the AS
// path with the local AS in front.
func (r *operaRouter) rejectExport(address, asPath string) {
	r.t.Helper()
	require.NoError(r.t, r.s.policy.Reset(&oc.RoutingPolicy{
		DefinedSets: oc.DefinedSets{
			NeighborSets: []oc.NeighborSet{{NeighborSetName: "q", NeighborInfoList: []string{address}}},
			BgpDefinedSets: oc.BgpDefinedSets{
				AsPathSets: []oc.AsPathSet{{AsPathSetName: "a", AsPathList: []string{asPath}}},
			},
		},
		PolicyDefinitions: []oc.PolicyDefinition{{
			Name: "reject",
			Statements: []oc.Statement{{
				Name: "reject",
				Conditions: oc.Conditions{
					MatchNeighborSet: oc.MatchNeighborSet{NeighborSet: "q"},
					BgpConditions:    oc.BgpConditions{MatchAsPathSet: oc.MatchAsPathSet{AsPathSet: "a"}},
				},
				Actions: oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE},
			}},
		}},
	}, map[string]oc.ApplyPolicy{table.GLOBAL_RIB_NAME: {Config: oc.ApplyPolicyConfig{
		ExportPolicyList:    []string{"reject"},
		DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
		DefaultImportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
	}}}))
}

// clearPolicy removes every policy of R.
func (r *operaRouter) clearPolicy() {
	r.t.Helper()
	require.NoError(r.t, r.s.policy.Reset(&oc.RoutingPolicy{}, map[string]oc.ApplyPolicy{table.GLOBAL_RIB_NAME: {}}))
}

func sent(asList ...uint32) []uint32 {
	return append([]uint32{operaLocalAS}, asList...)
}

func forEachMode(t *testing.T, f func(t *testing.T, r *operaRouter)) {
	for name, o := range operaModes {
		t.Run(name, func(t *testing.T) { f(t, newOperaRouter(t, o)) })
	}
}

func TestOperaExportAndLocalPaths(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		a, b, q := r.peer("10.0.1.1", 9), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 7)

		r.receive(b, []uint32{2, 9})
		r.receive(a, []uint32{9})

		// The FIB and best-path watchers get the local choice ...
		assert.Equal(t, []uint32{9}, r.best())
		// ... while peers are sent the worst admitted path. b is not sent its
		// own path, and a would drop it as an AS loop.
		assert.Equal(t, sent(2, 9), r.route(q))
		assert.Nil(t, r.route(b))
		assert.Nil(t, r.route(a))
	})
}

func TestOperaExportUnchangedByBetterPath(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		a, b, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 7)

		r.receive(b, []uint32{2, 5, 9})
		assert.Equal(t, sent(2, 5, 9), r.route(q))

		r.receive(a, []uint32{1, 9})
		assert.Zero(t, r.updates(q))
		assert.Equal(t, sent(2, 5, 9), r.route(q))
	})
}

func TestOperaExportStopsForAClass(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		customer, provider, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 3)
		// Gao-Rexford: routes of provider 2 are not sent to provider 3.
		r.rejectExport("10.0.1.3", "^65000_2_")

		r.receive(provider, []uint32{2, 5, 9})
		assert.Nil(t, r.route(q))

		// The provider route stays the export path, so q gets no route,
		// although the customer route could go to q.
		r.receive(customer, []uint32{1, 9})
		assert.Nil(t, r.route(q))
		assert.Equal(t, sent(2, 5, 9), r.route(customer))
	})
}

func TestOperaExportStopsOnAsLoop(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		a, b, q := r.peer("10.0.1.1", 7), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 4)

		// The export path (7 4 9) contains the AS of q, which would drop it.
		r.receive(a, []uint32{7, 4, 9})
		r.receive(b, []uint32{2, 9})

		assert.Nil(t, r.route(q))
		assert.Equal(t, sent(7, 4, 9), r.route(b))
	})
}

func TestOperaExportStopsOnIBGPSplitHorizon(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		e, i1, i2 := r.peer("10.0.1.1", 1), r.peer("10.0.2.1", operaLocalAS), r.peer("10.0.2.2", operaLocalAS)

		// The export path is learned over iBGP and must not go to another
		// iBGP peer, so i2 gets no route at all. iBGP is not evaluated.
		r.receive(i1, []uint32{3, 5, 9})
		r.receive(e, []uint32{1, 9})

		assert.Nil(t, r.route(i2))
		assert.Equal(t, sent(3, 5, 9), r.route(e))
	})
}

// Outside the model: a filters only its export to R, not to its other
// providers.
func TestOperaPruningRemovesPathsOfOtherPeers(t *testing.T) {
	r := newOperaRouter(t, operaOriginal)
	a, b, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 3), r.peer("10.0.1.3", 7)

	r.receive(a, []uint32{1, 9})
	r.receive(b, []uint32{3, 1, 9})
	assert.ElementsMatch(t, [][]uint32{{1, 9}}, r.known())

	// a withdraws, e.g. because of its export policy towards R. b still
	// advertises (3 1 9), but the original design prunes it.
	r.withdraw(a, []uint32{1, 9})
	assert.Empty(t, r.known())
	assert.Nil(t, r.route(q))
	assert.Equal(t, 1, b.adjRibIn.Count([]bgp.Family{bgp.RF_IPv4_UC}), "the Adj-RIB-In keeps the pruned path")

	// A soft reset in brings the pruned path back.
	require.NoError(t, r.s.softResetIn("10.0.1.2", bgp.RF_IPv4_UC))
	assert.Equal(t, [][]uint32{{3, 1, 9}}, r.known())
	assert.Equal(t, sent(3, 1, 9), r.route(q))
}

func TestOperaNoPruningKeepsPathsOfOtherPeers(t *testing.T) {
	r := newOperaRouter(t, operaNoPrune)
	a, b, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 3), r.peer("10.0.1.3", 7)

	r.receive(b, []uint32{3, 1, 9})
	r.receive(a, []uint32{1, 9})

	r.withdraw(a, []uint32{1, 9})
	assert.Equal(t, [][]uint32{{3, 1, 9}}, r.known())
	assert.Equal(t, sent(3, 1, 9), r.route(q))

	// An AS path change of a does not remove it either.
	r.receive(a, []uint32{1, 9})
	r.receive(a, []uint32{1, 5, 9})
	assert.ElementsMatch(t, [][]uint32{{3, 1, 9}, {1, 5, 9}}, r.known())
}

func TestOperaPruningOnAsPathChange(t *testing.T) {
	r := newOperaRouter(t, operaOriginal)
	a, b := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 3)

	r.receive(b, []uint32{3, 1, 9})
	r.receive(a, []uint32{1, 9})
	r.receive(a, []uint32{1, 5, 9})

	// (3 1 9) is pruned and stays gone, as b sends nothing new.
	assert.Equal(t, [][]uint32{{1, 5, 9}}, r.known())
}

// Lifecycle

func TestOperaSoftResetOutAfterExportPolicyChange(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		customer, provider, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 3)
		r.receive(provider, []uint32{2, 5, 9})
		r.receive(customer, []uint32{1, 9})
		assert.Equal(t, sent(2, 5, 9), r.route(q))

		// The new policy only applies to q after a soft reset out, which
		// withdraws the export path.
		r.rejectExport("10.0.1.3", "^65000_2_")
		require.NoError(t, r.s.softResetOut("10.0.1.3", bgp.RF_IPv4_UC, false))
		assert.Nil(t, r.route(q))

		r.clearPolicy()
		require.NoError(t, r.s.softResetOut("10.0.1.3", bgp.RF_IPv4_UC, false))
		assert.Equal(t, sent(2, 5, 9), r.route(q))
	})
}

func TestSoftResetOutWithdrawsRejectedRoutesWithoutObgp(t *testing.T) {
	r := newOperaRouter(t, table.OperaOptions{})
	a, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.3", 3)
	r.receive(a, []uint32{1, 9})
	assert.Equal(t, sent(1, 9), r.route(q))

	r.rejectExport("10.0.1.3", "_9$")
	require.NoError(t, r.s.softResetOut("10.0.1.3", bgp.RF_IPv4_UC, false))
	assert.Nil(t, r.route(q))
}

func TestOperaRouteRefresh(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		customer, provider, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 3)
		r.receive(provider, []uint32{2, 5, 9})
		r.receive(customer, []uint32{1, 9})

		// A route refresh resends the export path.
		paths, _ := r.s.getBestFromLocal(q, []bgp.Family{bgp.RF_IPv4_UC}, false)
		require.Len(t, paths, 1)
		assert.Equal(t, sent(2, 5, 9), paths[0].GetAsList())

		r.rejectExport("10.0.1.3", "^65000_2_")
		paths, _ = r.s.getBestFromLocal(q, []bgp.Family{bgp.RF_IPv4_UC}, false)
		assert.Empty(t, paths)
	})
}

func TestOperaImportPolicyChange(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		a, b, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 7)
		r.receive(b, []uint32{2, 5, 9})
		r.receive(a, []uint32{1, 9})

		// Rejecting the routes of a on import withdraws them after a soft
		// reset in. (2 5 9) is left and still sent.
		require.NoError(t, r.s.policy.Reset(&oc.RoutingPolicy{
			DefinedSets: oc.DefinedSets{NeighborSets: []oc.NeighborSet{{NeighborSetName: "a", NeighborInfoList: []string{"10.0.1.1"}}}},
			PolicyDefinitions: []oc.PolicyDefinition{{
				Name: "reject",
				Statements: []oc.Statement{{
					Name:       "reject",
					Conditions: oc.Conditions{MatchNeighborSet: oc.MatchNeighborSet{NeighborSet: "a"}},
					Actions:    oc.Actions{RouteDisposition: oc.ROUTE_DISPOSITION_REJECT_ROUTE},
				}},
			}},
		}, map[string]oc.ApplyPolicy{table.GLOBAL_RIB_NAME: {Config: oc.ApplyPolicyConfig{
			ImportPolicyList:    []string{"reject"},
			DefaultImportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
			DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
		}}}))
		require.NoError(t, r.s.softResetIn("10.0.1.1", bgp.RF_IPv4_UC))
		assert.Equal(t, [][]uint32{{2, 5, 9}}, r.known())
		assert.Equal(t, sent(2, 5, 9), r.route(q))

		// Accepting them again admits (1 9) again.
		r.clearPolicy()
		require.NoError(t, r.s.softResetIn("10.0.1.1", bgp.RF_IPv4_UC))
		assert.ElementsMatch(t, [][]uint32{{1, 9}, {2, 5, 9}}, r.known())
	})
}

func TestOperaSessionDownKeepsOtherPeersPaths(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		a, b, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 3), r.peer("10.0.1.3", 7)
		r.receive(b, []uint32{3, 1, 9})
		r.receive(a, []uint32{1, 9})

		r.sessionDown(a, false)
		assert.Equal(t, [][]uint32{{3, 1, 9}}, r.known())
		assert.Equal(t, sent(3, 1, 9), r.route(q))

		// The session comes back and a sends its route again.
		r.receive(a, []uint32{1, 9})
		assert.ElementsMatch(t, [][]uint32{{3, 1, 9}, {1, 9}}, r.known())
		assert.Equal(t, sent(3, 1, 9), r.route(q))
	})
}

func TestOperaGracefulRestart(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		a, b, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 3), r.peer("10.0.1.3", 7)
		r.receive(b, []uint32{3, 1, 9})
		r.receive(a, []uint32{1, 9})
		r.updates(q)

		// While a restarts, its stale route is kept and nothing changes.
		r.sessionDown(a, true)
		assert.ElementsMatch(t, [][]uint32{{3, 1, 9}, {1, 9}}, r.known())
		assert.Zero(t, r.updates(q))

		// a sends the same route again and ends with End-of-RIB.
		r.receive(a, []uint32{1, 9})
		r.endOfRib(a)
		assert.ElementsMatch(t, [][]uint32{{3, 1, 9}, {1, 9}}, r.known())
		assert.Equal(t, sent(3, 1, 9), r.route(q))
	})
}

func TestOperaGracefulRestartWithoutRoute(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		a, b, q := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 7)
		r.receive(b, []uint32{2, 5, 9})
		r.receive(a, []uint32{1, 9})

		// a restarts and no longer has the route: End-of-RIB removes it.
		r.sessionDown(a, true)
		r.endOfRib(a)
		assert.Equal(t, [][]uint32{{2, 5, 9}}, r.known())
		assert.Equal(t, sent(2, 5, 9), r.route(q))
	})
}

func TestOperaManyPeersExport(t *testing.T) {
	forEachMode(t, func(t *testing.T, r *operaRouter) {
		peers := make([]*peer, 0, 8)
		for i := range 8 {
			peers = append(peers, r.peer(fmt.Sprintf("10.0.3.%d", i+1), uint32(100+i)))
		}
		q := r.peer("10.0.4.1", 7)
		// Shorter paths arrive later, so all are admitted.
		for i, p := range peers {
			as := []uint32{uint32(100 + i)}
			for range 8 - i {
				as = append(as, 50)
			}
			r.receive(p, append(as, 9))
		}
		assert.Len(t, r.known(), 8)
		assert.Equal(t, sent(100, 50, 50, 50, 50, 50, 50, 50, 50, 9), r.route(q))
	})
}

func TestOperaSuppressedCount(t *testing.T) {
	r := newOperaRouter(t, operaOriginal)
	a, b := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2)

	r.receive(a, []uint32{1, 9})
	r.receive(b, []uint32{2, 5, 9})
	info := r.s.globalRib.Tables[bgp.RF_IPv4_UC].Info()
	assert.Equal(t, 1, info.NumPath)
	assert.Equal(t, 1, info.NumSuppressed)
}
