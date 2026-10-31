package server

import (
	"slices"
	"strings"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// OBGP per neighbor, see internal/pkg/table/opera_neighbor.go: the server
// feeds every path into the table of each eBGP neighbor its export policy
// lets it through to, sends each neighbor the export of its table, and
// gives the FIB and the API the forwarding path within the bound.

// operaUpdate is what one path changed in the tables per neighbor.
type operaUpdate struct {
	peers          map[*peer]bool // those with a table
	changes        map[*peer][2]*table.Path
	fwdOld, fwdNew *table.Path
}

// operaHasView tells whether OBGP keeps a table for this neighbor in a
// family: an eBGP neighbor of the global table.
func operaHasView(p *peer, f bgp.Family) bool {
	return table.OperaPerNeighbor(f) && !p.isIBGPPeer() && !p.isRouteServerClient()
}

// operaSessionUp starts feeding the tables of a neighbor whose session came
// up. The FSM stores the new state only after the server handled the change,
// so the session decides, not the state.
func (s *BgpServer) operaSessionUp(nb *peer) {
	if s.operaUp == nil {
		s.operaUp = map[string]bool{}
	}
	s.operaUp[nb.ID()] = true
}

// operaViewPeers are the neighbors with a table in a family, from their
// session coming up until operaDropViews.
func (s *BgpServer) operaViewPeers(f bgp.Family) []*peer {
	if !table.OperaPerNeighbor(f) {
		return nil
	}
	var out []*peer
	for _, p := range s.neighborMap {
		if s.operaUp[p.ID()] && operaHasView(p, f) && p.IsFamilyEnabled(f) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b *peer) int { return strings.Compare(a.ID(), b.ID()) })
	return out
}

// operaAllows tells whether path p goes into the table of a neighbor: if
// the export policy lets it through. The neighbor's own path and one through
// its AS go in for the threshold if only split horizon and the AS loop stop
// them, they are never sent. The policy judges them as the send path would,
// with the router's AS in front.
func (s *BgpServer) operaAllows(nb *peer, p *table.Path) bool {
	if p.IsWithdraw {
		return false
	}
	src := p.GetSource()
	if !p.IsLocal() && src != nil && src.Address.String() == nb.ID() || slices.Contains(p.GetAsList(), nb.AS()) {
		nb.fsm.lock.Lock()
		q := table.UpdatePathAttrs(nb.fsm.logger, nb.fsm.gConf, nb.fsm.pConf, nb.peerInfo, p)
		nb.fsm.lock.Unlock()
		options := &table.PolicyOptions{Info: nb.peerInfo, OldNextHop: p.GetNexthop()}
		return nb.policy.ApplyPolicy(nb.TableID(), table.POLICY_DIRECTION_EXPORT, q, options) != nil
	}
	return s.filterpath(nb, p, nil) != nil
}

// operaBefore are the exports to the neighbors before path p changes the table.
func (s *BgpServer) operaBefore(rib *table.TableManager, p *table.Path) (*operaUpdate, map[*peer]*table.Path) {
	if rib != s.globalRib {
		return nil, nil
	}
	peers := s.operaViewPeers(p.GetFamily())
	if len(peers) == 0 {
		return nil, nil
	}
	u := &operaUpdate{peers: map[*peer]bool{}, changes: map[*peer][2]*table.Path{}}
	before := map[*peer]*table.Path{}
	d := rib.GetDestination(p)
	for _, nb := range peers {
		u.peers[nb] = true
		if d != nil {
			before[nb] = d.OperaExport(nb.ID())
		}
	}
	return u, before
}

// operaFeed feeds path p, already in the main table, into the tables of the
// neighbors, and notes what each is to be sent and the forwarding path.
func (s *BgpServer) operaFeed(rib *table.TableManager, p *table.Path, u *operaUpdate, before map[*peer]*table.Path) {
	d := rib.GetDestination(p)
	if d != nil {
		allows := map[string]bool{}
		for nb := range u.peers {
			allows[nb.ID()] = s.operaAllows(nb, p)
		}
		d.OperaFeedAll(s.logger, p, allows, true)
	}
	for nb := range u.peers {
		var after *table.Path
		if d != nil {
			after = d.OperaExport(nb.ID())
		}
		if after != before[nb] {
			u.changes[nb] = [2]*table.Path{before[nb], after}
		}
	}
	if d != nil {
		u.fwdOld, u.fwdNew = d.OperaForward()
	}
	rib.OperaRelease(p)
}

// operaSend sends a neighbor with a table what changed in it.
func (s *BgpServer) operaSend(nb *peer, change [2]*table.Path) {
	old, path := change[0], change[1]
	if path == nil {
		if old == nil {
			return
		}
		path = old.Clone(true)
	}
	if paths := s.processOutgoingPaths(nb, []*table.Path{path}, []*table.Path{old}); len(paths) > 0 {
		sendfsmOutgoingMsg(nb, paths)
	}
}

// operaSync brings the table of a neighbor up to date with its export
// policy, built anew for a neighbor that just came up, and returns what it
// is to be sent, and what it was sent before and is no longer.
func (s *BgpServer) operaSync(nb *peer, f bgp.Family) (paths, gone []*table.Path) {
	t := s.globalRib.Tables[f]
	if t == nil {
		return nil, nil
	}
	key := nb.ID()
	for _, d := range t.GetDestinations() {
		old := d.OperaExport(key)
		for _, c := range d.OperaCandidates(key) {
			d.OperaFeed(s.logger, key, c, s.operaAllows(nb, c), false)
		}
		d.OperaShare(key)
		e := d.OperaExport(key)
		var p *table.Path
		if e != nil {
			p = s.filterpath(nb, e, nil)
		}
		if p != nil {
			paths = append(paths, p)
		} else if old != nil {
			// nothing to send, also when the export names the neighbor:
			// what it got before is withdrawn
			gone = append(gone, old)
		}
		s.operaNotifyForward(d.OperaForward())
		// a policy change can leave the table waiting, as an update can, and
		// the request goes behind what the caller sends the neighbor
		for _, src := range d.OperaWaiting() {
			s.operaQueueRefresh(src.Address, f, true)
		}
	}
	return paths, gone
}

// operaExports are what the neighbor's tables export now, as sent, without
// bringing them up to date. Their entries passed the export policy when they
// were fed, so the policy is not asked again: a changed one counts only after
// a sync, which also sends.
func (s *BgpServer) operaExports(nb *peer, f bgp.Family) (paths []*table.Path) {
	t := s.globalRib.Tables[f]
	if t == nil {
		return nil
	}
	for _, d := range t.GetDestinations() {
		if e := d.OperaExport(nb.ID()); e != nil {
			if p, _, stop := s.prePolicyFilterpath(nb, e, nil); !stop {
				if p = s.postFilterpath(nb, p); p != nil && !p.IsWithdraw {
					paths = append(paths, p)
				}
			}
		}
	}
	return paths
}

// operaNotifyForward tells the best path watchers, zebra among them, a
// forwarding path that changed outside an update, as the update path does.
func (s *BgpServer) operaNotifyForward(old, best *table.Path) {
	if best == old {
		return
	}
	if best == nil {
		best = old.Clone(true)
	}
	s.notifyBestWatcher([]*table.Path{best}, nil)
}

// operaDropViews forgets the tables of a neighbor that went down.
func (s *BgpServer) operaDropViews(nb *peer) {
	delete(s.operaUp, nb.ID())
	for f, t := range s.globalRib.Tables {
		if !operaHasView(nb, f) {
			continue
		}
		for _, d := range t.GetDestinations() {
			d.OperaDropView(nb.ID())
			s.operaNotifyForward(d.OperaForward())
		}
	}
}
