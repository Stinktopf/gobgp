package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enhanced gives a peer the route refresh capabilities of its OPEN.
func enhanced(p *peer, err bool) {
	p.fsm.capMap = map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface{bgp.BGP_CAP_ROUTE_REFRESH: {bgp.NewCapRouteRefresh()}}
	if err {
		p.fsm.capMap[bgp.BGP_CAP_ENHANCED_ROUTE_REFRESH] = []bgp.ParameterCapabilityInterface{bgp.NewCapEnhancedRouteRefresh()}
	}
}

func refreshMsg(subtype uint8) *fsmMsg {
	f := bgp.RF_IPv4_UC
	return &fsmMsg{MsgData: bgp.NewBGPRouteRefreshMessage(f.Afi(), subtype, f.Safi())}
}

// outgoing is what the router queued for a peer.
func outgoing(p *peer) []*fsmOutgoingMsg {
	var out []*fsmOutgoingMsg
	for {
		select {
		case m := <-p.fsm.outgoingCh.Out():
			out = append(out, m.(*fsmOutgoingMsg))
		case <-time.After(20 * time.Millisecond):
			return out
		}
	}
}

// With Enhanced Route Refresh on both ends the answer is framed, also when
// it is empty; without, it is the routes alone, as before.
func TestOperaRefreshAnswerIsFramedWithEnhancedRouteRefresh(t *testing.T) {
	r := newOperaRouter(t, table.OperaOptions{Enabled: true, Pruning: table.PruneRefresh})
	a, b, c := r.peer("10.0.1.1", 1), r.peer("10.0.1.2", 2), r.peer("10.0.1.3", 3)
	enhanced(b, true)
	enhanced(c, false)
	r.receive(a, []uint32{1, 9})
	outgoing(b)
	outgoing(c)

	assert.Nil(t, r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_REQUEST)))
	m := outgoing(b)
	require.Len(t, m, 1)
	assert.Equal(t, []bgp.Family{bgp.RF_IPv4_UC}, m[0].Answer)
	assert.Len(t, m[0].Paths, 1)

	assert.Len(t, r.s.handleRouteRefresh(c, refreshMsg(bgp.BGP_ROUTE_REFRESH_REQUEST)), 1)
	assert.Empty(t, outgoing(c))

	// Turned off, or BGP, which never offers it: answers stay as GoBGP sends them.
	table.SetOperaOptions(table.OperaOptions{Enabled: true, Pruning: table.PruneRefresh, PlainRefresh: true})
	assert.Len(t, r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_REQUEST)), 1)
	table.SetOperaOptions(table.OperaOptions{})
	assert.Len(t, r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_REQUEST)), 1)
}

// A request stays open until its answer ends: a table that waits meanwhile
// asks again only then, not every interval.
func TestOperaRefreshAsksAgainOnlyAfterTheAnswer(t *testing.T) {
	r := newOperaRouter(t, table.OperaOptions{Enabled: true, Pruning: table.PruneRefresh, RefreshInterval: time.Nanosecond})
	b := r.peer("10.0.1.2", 2)
	enhanced(b, true)
	addr := netip.MustParseAddr("10.0.1.2")
	refreshes := func() int {
		n := 0
		for _, m := range outgoing(b) {
			n += len(m.Refresh)
		}
		return n
	}

	r.s.operaQueueRefresh(addr, bgp.RF_IPv4_UC, false)
	assert.Equal(t, 1, refreshes())
	time.Sleep(time.Millisecond)
	r.s.operaQueueRefresh(addr, bgp.RF_IPv4_UC, false) // the answer is still on its way
	assert.Zero(t, refreshes())

	r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_BEGIN))
	r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_END))
	assert.Equal(t, 1, refreshes()) // the one that waited

	// Without Enhanced Route Refresh the router asks every interval, as before.
	enhanced(b, false)
	r.s.operaRefreshDown(b)
	time.Sleep(time.Millisecond)
	r.s.operaQueueRefresh(addr, bgp.RF_IPv4_UC, false)
	assert.Equal(t, 1, refreshes())
	time.Sleep(time.Millisecond)
	r.s.operaQueueRefresh(addr, bgp.RF_IPv4_UC, false)
	assert.Equal(t, 1, refreshes())
}

// The end of an answer withdraws the routes it did not repeat (RFC 7313).
func TestOperaRefreshAnswerEndWithdrawsWhatItDidNotRepeat(t *testing.T) {
	r := newOperaRouter(t, table.OperaOptions{Enabled: true, Pruning: table.PruneRefresh})
	b := r.peer("10.0.1.2", 2)
	enhanced(b, true)
	r.receive(b, []uint32{2, 9})
	require.Equal(t, [][]uint32{{2, 9}}, r.known())

	// repeated: it stays
	r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_BEGIN))
	p := r.path(b, []uint32{2, 9}, false)
	b.adjRibIn.Update([]*table.Path{p})
	r.s.operaAnswerRepeats(b, []*table.Path{p})
	r.s.propagateUpdate(b, []*table.Path{p})
	r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_END))
	assert.Equal(t, [][]uint32{{2, 9}}, r.known())

	// not repeated: it goes
	r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_BEGIN))
	r.s.handleRouteRefresh(b, refreshMsg(bgp.BGP_ROUTE_REFRESH_END))
	assert.Empty(t, r.known())
	assert.Zero(t, b.adjRibIn.Count([]bgp.Family{bgp.RF_IPv4_UC}))
}

// An answer to a route refresh is not held back by the MRAI and drops an
// older advertisement of the same route that waits.
func TestMRAIAnswerGoesOutAtOnce(t *testing.T) {
	m := newMRAI(time.Minute, func(bgp.Family) bool { return false })
	r := newOperaRouter(t, table.OperaOptions{})
	b := r.peer("10.0.1.2", 2)
	now := time.Now()
	m.add([]*table.Path{r.path(b, []uint32{2, 9}, false)}, now) // goes out, the interval starts
	m.add([]*table.Path{r.path(b, []uint32{2, 7, 9}, false)}, now)
	require.False(t, m.due().IsZero())
	answer := []*table.Path{r.path(b, []uint32{2, 8, 9}, false)}
	assert.Equal(t, answer, m.answer(answer))
	assert.True(t, m.due().IsZero())
}
