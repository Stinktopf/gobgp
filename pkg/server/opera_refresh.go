package server

import (
	"net/netip"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// operaRefresh asks the neighbors OBGP waits for under refresh pruning for
// their current routes: at most one route refresh per neighbor and interval,
// the first after the delay, all prefixes waiting meanwhile in it, queued
// behind what the session already carries, so behind the router's own withdrawal.
type operaRefresh struct {
	mu      sync.Mutex
	last    map[netip.Addr]time.Time
	pending map[netip.Addr]map[bgp.Family]bool
}

func (s *BgpServer) operaAskRefresh(family bgp.Family, dsts []*table.Update) {
	for _, d := range dsts {
		for _, src := range d.Waiting {
			s.operaQueueRefresh(src.Address, family, false)
		}
	}
}

// operaQueueRefresh asks addr for a route refresh of family. With later the
// request waits at least for the server's next turn, behind what the caller
// is still to send.
func (s *BgpServer) operaQueueRefresh(addr netip.Addr, family bgp.Family, later bool) {
	r := &s.refresh
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		r.last, r.pending = map[netip.Addr]time.Time{}, map[netip.Addr]map[bgp.Family]bool{}
	}
	if r.pending[addr] == nil {
		r.pending[addr] = map[bgp.Family]bool{}
	}
	if r.pending[addr][family] {
		return // already asked for or due
	}
	r.pending[addr][family] = true
	o := table.GetOperaOptions()
	wait := operaRefreshWait(r.last[addr], time.Now(), o.RefreshInterval, o.RefreshDelay)
	if wait <= 0 && !later {
		s.operaSendRefresh(addr)
		return
	}
	if len(r.pending[addr]) == 1 { // the first of this interval: send them all when it ends
		time.AfterFunc(max(wait, 0), func() {
			_ = s.mgmtOperation(func() error {
				r.mu.Lock()
				defer r.mu.Unlock()
				s.operaSendRefresh(addr)
				return nil
			}, false)
		})
	}
}

// operaRefreshWait is how long a refresh to a neighbor last asked at last
// waits: until the interval has passed, and at least the delay.
func operaRefreshWait(last, now time.Time, interval, delay time.Duration) time.Duration {
	if interval == 0 {
		interval = time.Second
	}
	return max(last.Add(interval).Sub(now), delay)
}

// operaSendRefresh sends the pending refresh of a neighbor; r.mu is held.
func (s *BgpServer) operaSendRefresh(addr netip.Addr) {
	r := &s.refresh
	families := make([]bgp.Family, 0, len(r.pending[addr]))
	for f := range r.pending[addr] {
		families = append(families, f)
	}
	delete(r.pending, addr)
	r.last[addr] = time.Now()
	if peer, ok := s.neighborMap[addr]; ok && peer.State() == bgp.BGP_FSM_ESTABLISHED {
		peer.fsm.outgoingCh.In() <- &fsmOutgoingMsg{Refresh: families}
	}
}

// operaRefreshCapable tells whether the peer at addr answers a route refresh,
// as it said in its OPEN. Those that do not get their paths back as with soft pruning.
func (s *BgpServer) operaRefreshCapable(addr netip.Addr) bool {
	peer, ok := s.neighborMap[addr]
	if !ok {
		return false
	}
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	_, capable := peer.fsm.capMap[bgp.BGP_CAP_ROUTE_REFRESH]
	return capable
}
