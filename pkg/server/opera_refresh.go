package server

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// operaAnswerTimeout is how long a route refresh to a neighbor with Enhanced
// Route Refresh stays open without its end: then the router may ask again.
const operaAnswerTimeout = 5 * time.Minute

// operaRefresh asks the neighbors OBGP waits for under refresh pruning for
// their current routes: at most one route refresh per neighbor and interval,
// the first after the delay, all prefixes waiting meanwhile in it, queued
// behind what the session already carries, so behind the router's own withdrawal.
// With Enhanced Route Refresh (RFC 7313) on both ends a request stays open
// until the answer's end, and the router asks that neighbor again only then:
// a busy neighbor is not asked for its whole table again while the last
// answer is still on its way. The answer's end removes the routes it did not
// repeat.
type operaRefresh struct {
	mu      sync.Mutex
	last    map[netip.Addr]time.Time
	pending map[netip.Addr]map[bgp.Family]bool
	armed   map[netip.Addr]bool                           // a send waits for the end of the interval
	open    map[netip.Addr]map[bgp.Family]time.Time       // asked with Enhanced Route Refresh, until the answer's end
	answer  map[netip.Addr]map[bgp.Family]map[string]bool // routes held from the neighbor its answer has not repeated yet
}

func (r *operaRefresh) init() {
	if r.last == nil {
		r.last, r.pending, r.armed = map[netip.Addr]time.Time{}, map[netip.Addr]map[bgp.Family]bool{}, map[netip.Addr]bool{}
		r.open, r.answer = map[netip.Addr]map[bgp.Family]time.Time{}, map[netip.Addr]map[bgp.Family]map[string]bool{}
	}
}

// isOpen tells whether a request to addr for family waits for the end of its
// answer; r.mu is held.
func (r *operaRefresh) isOpen(addr netip.Addr, family bgp.Family) bool {
	at, ok := r.open[addr][family]
	if ok && time.Since(at) >= operaAnswerTimeout {
		delete(r.open[addr], family)
		return false
	}
	return ok
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
// is still to send. A request still open waits for the end of its answer.
func (s *BgpServer) operaQueueRefresh(addr netip.Addr, family bgp.Family, later bool) {
	r := &s.refresh
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	if r.pending[addr] == nil {
		r.pending[addr] = map[bgp.Family]bool{}
	}
	if r.pending[addr][family] {
		return // already asked for or due
	}
	r.pending[addr][family] = true
	if r.isOpen(addr, family) {
		return // asked again at the answer's end
	}
	s.operaScheduleRefresh(addr, later)
}

// operaScheduleRefresh sends what is pending for addr now, or once the
// interval has passed; r.mu is held.
func (s *BgpServer) operaScheduleRefresh(addr netip.Addr, later bool) {
	r := &s.refresh
	if r.armed[addr] {
		return
	}
	o := table.GetOperaOptions()
	wait := operaRefreshWait(r.last[addr], time.Now(), o.RefreshInterval, o.RefreshDelay)
	if wait <= 0 && !later {
		s.operaSendRefresh(addr)
		return
	}
	r.armed[addr] = true // the first of this interval: send them all when it ends
	time.AfterFunc(max(wait, 0), func() {
		_ = s.mgmtOperation(func() error {
			r.mu.Lock()
			defer r.mu.Unlock()
			delete(r.armed, addr)
			s.operaSendRefresh(addr)
			return nil
		}, false)
	})
}

// operaRefreshWait is how long a refresh to a neighbor last asked at last
// waits: until the interval has passed, and at least the delay.
func operaRefreshWait(last, now time.Time, interval, delay time.Duration) time.Duration {
	if interval == 0 {
		interval = time.Second
	}
	return max(last.Add(interval).Sub(now), delay)
}

// operaSendRefresh sends the pending refreshes of a neighbor that are not
// open; r.mu is held.
func (s *BgpServer) operaSendRefresh(addr netip.Addr) {
	r := &s.refresh
	families := make([]bgp.Family, 0, len(r.pending[addr]))
	for f := range r.pending[addr] {
		if !r.isOpen(addr, f) {
			families = append(families, f)
			delete(r.pending[addr], f)
		}
	}
	if len(families) == 0 {
		return
	}
	r.last[addr] = time.Now()
	peer, ok := s.neighborMap[addr]
	if !ok || peer.State() != bgp.BGP_FSM_ESTABLISHED {
		return
	}
	if s.operaEnhancedRefresh(peer) {
		if r.open[addr] == nil {
			r.open[addr] = map[bgp.Family]time.Time{}
		}
		for _, f := range families {
			r.open[addr][f] = r.last[addr]
		}
	}
	peer.fsm.outgoingCh.In() <- &fsmOutgoingMsg{Refresh: families}
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

// operaEnhancedRefresh tells whether both ends of the session use Enhanced
// Route Refresh: the router offers it with OBGP on unless
// GOBGP_OPERA_ENHANCED_REFRESH is off, the peer in its OPEN.
func (s *BgpServer) operaEnhancedRefresh(peer *peer) bool {
	if !table.OperaEnhancedRefresh() {
		return false
	}
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	_, capable := peer.fsm.capMap[bgp.BGP_CAP_ENHANCED_ROUTE_REFRESH]
	return capable
}

// operaRouteKey names a route of a neighbor: its prefix and path ID.
func operaRouteKey(p *table.Path) string {
	return fmt.Sprint(p.GetNlri().String(), "|", p.RemoteID())
}

// operaAnswerBegins notes the routes held from the peer when its answer to a
// route refresh begins: those it does not repeat before the end are gone.
func (s *BgpServer) operaAnswerBegins(peer *peer, family bgp.Family) {
	held := map[string]bool{}
	for _, p := range peer.adjRibIn.PathList([]bgp.Family{family}, false) {
		held[operaRouteKey(p)] = true
	}
	r := &s.refresh
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	addr := peer.peerInfo.Address
	if r.answer[addr] == nil {
		r.answer[addr] = map[bgp.Family]map[string]bool{}
	}
	r.answer[addr][family] = held
}

// operaAnswerRepeats ticks off the routes an update of the peer repeats or
// withdraws while its answer runs.
func (s *BgpServer) operaAnswerRepeats(peer *peer, paths []*table.Path) {
	r := &s.refresh
	r.mu.Lock()
	defer r.mu.Unlock()
	answers := r.answer[peer.peerInfo.Address]
	if len(answers) == 0 {
		return
	}
	for _, p := range paths {
		if held := answers[p.GetFamily()]; held != nil {
			delete(held, operaRouteKey(p))
		}
	}
}

// operaAnswerEnds withdraws the routes the peer's answer did not repeat, as
// RFC 7313 asks, and sends a request for the family that waited meanwhile.
func (s *BgpServer) operaAnswerEnds(peer *peer, family bgp.Family) {
	r := &s.refresh
	addr := peer.peerInfo.Address
	r.mu.Lock()
	r.init()
	gone := r.answer[addr][family]
	delete(r.answer[addr], family)
	r.mu.Unlock()
	if len(gone) > 0 {
		var withdrawn []*table.Path
		for _, p := range peer.adjRibIn.PathList([]bgp.Family{family}, false) {
			if gone[operaRouteKey(p)] {
				w := p.Clone(true)
				w.SetDropped(true)
				withdrawn = append(withdrawn, w)
			}
		}
		if len(withdrawn) > 0 {
			peer.adjRibIn.Update(withdrawn)
			s.propagateUpdate(peer, withdrawn)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.open[addr], family)
	if r.pending[addr][family] {
		s.operaScheduleRefresh(addr, false)
	}
}

// operaRefreshDown forgets the open requests and answers of a peer whose
// session went down: a new session starts with all its routes.
func (s *BgpServer) operaRefreshDown(peer *peer) {
	r := &s.refresh
	r.mu.Lock()
	defer r.mu.Unlock()
	addr := peer.peerInfo.Address
	delete(r.open, addr)
	delete(r.answer, addr)
	delete(r.pending, addr)
}
