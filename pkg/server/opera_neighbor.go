package server

import (
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// OBGP per neighbor, see internal/pkg/table/opera_neighbor.go: the server
// feeds every path into the table of each eBGP neighbor its export policy
// lets it through to, sends each neighbor the export of its table, and
// gives the FIB and the API the forwarding path within the bound. With OBGP
// off the tables give NS-BGP and the FIB the best path of the main table.

// operaUpdate is what one path changed in the tables per neighbor. Its
// lists hold one entry per neighbor with a table, sorted by ID.
type operaUpdate struct {
	peers          []*peer
	ids            []string
	changes        [][2]*table.Path // the export before and after
	ready          []*table.Path    // the new path as sent, where it is the export
	fwdOld, fwdNew *table.Path
	buf            *operaBuffers
}

// operaBuffers hold the lists an update needs while it is handled, kept for
// the next update instead of made anew for each: one entry per neighbor with
// a table. An update handled while another is gets lists of its own.
type operaBuffers struct {
	update  operaUpdate
	changes [][2]*table.Path
	ready   []*table.Path
	allows  []bool
	sent    []*table.Path
	exports []*table.Path
	busy    bool
}

// sized is s with n zero entries, in s's memory where it has room.
func sized[T any](s []T, n int) []T {
	if cap(s) < n {
		return make([]T, n)
	}
	s = s[:n]
	clear(s)
	return s
}

// operaDone gives the lists of an update back, emptied, so that they keep
// no path alive.
func (s *BgpServer) operaDone(u *operaUpdate) {
	if u == nil {
		return
	}
	b := u.buf
	clear(b.changes)
	clear(b.ready)
	clear(b.sent)
	clear(b.exports)
	b.update = operaUpdate{}
	b.busy = false
}

// slot is the entry of neighbor nb, if it has a table.
func (u *operaUpdate) slot(nb *peer) (int, bool) {
	if u == nil {
		return 0, false
	}
	i := nb.operaSlot
	return i, i < len(u.peers) && u.peers[i] == nb
}

// operaHasView tells whether the router keeps a table for this neighbor in a
// family: an eBGP neighbor of the global table.
func operaHasView(p *peer, f bgp.Family) bool {
	return table.OperaPerNeighbor(f) && !p.isIBGPPeer() && !p.isRouteServerClient()
}

// operaSessionUp starts feeding the tables of a neighbor whose session came
// up. The FSM stores the new state only after the server handled the change,
// so the session decides, not the state.
func (s *BgpServer) operaSessionUp(nb *peer) {
	if s.operaUp == nil {
		s.operaUp = map[*peer]string{}
	}
	s.operaUp[nb] = nb.ID()
	s.operaOrder, s.operaViews = nil, nil
}

// operaSessionGone stops feeding the tables of a neighbor.
func (s *BgpServer) operaSessionGone(nb *peer) {
	delete(s.operaUp, nb)
	s.operaOrder, s.operaViews = nil, nil
}

type operaViewList struct {
	peers []*peer
	ids   []string
}

// operaViewPeers are the neighbors with a table in a family, from their
// session coming up until operaDropViews, sorted by ID, with their IDs.
// Made once until a session comes or goes, not for every update: callers
// only read them.
func (s *BgpServer) operaViewPeers(f bgp.Family) (peers []*peer, ids []string) {
	if !table.OperaPerNeighbor(f) {
		return nil, nil
	}
	if v, ok := s.operaViews[f]; ok {
		return v.peers, v.ids
	}
	if s.operaOrder == nil {
		s.operaOrder = slices.SortedFunc(maps.Keys(s.operaUp), func(a, b *peer) int { return strings.Compare(s.operaUp[a], s.operaUp[b]) })
	}
	for _, p := range s.operaOrder {
		if id, up := s.operaUp[p]; up && operaHasView(p, f) && p.IsFamilyEnabled(f) {
			peers, ids = append(peers, p), append(ids, id)
		}
	}
	if s.operaViews == nil {
		s.operaViews = map[bgp.Family]operaViewList{}
	}
	s.operaViews[f] = operaViewList{peers, ids}
	return peers, ids
}

// operaAllows tells whether path p goes into the table of a neighbor: if
// the export policy lets it through. The neighbor's own path and one through
// its AS go in for the threshold if only split horizon and the AS loop stop
// them, they are never sent. The policy judges them as the send path would,
// with the router's AS in front. NS-BGP, with OBGP off, has no threshold:
// its table holds only what the neighbor may get, so that it gets the best
// of those.
func (s *BgpServer) operaAllows(nb *peer, p *table.Path) bool {
	allows, _ := s.operaFilter(nb, p)
	return allows
}

// operaFilter is operaAllows, with the path as sent to the neighbor where
// the policy judged it as sent: it is what filterpath returns for it.
func (s *BgpServer) operaFilter(nb *peer, p *table.Path) (bool, *table.Path) {
	if p.IsWithdraw {
		return false, nil
	}
	src := p.GetSource()
	if !p.IsLocal() && src != nil && src.Address == nb.address() || p.HasAS(nb.AS()) {
		if !table.IsOperaEnabled() {
			return false, nil
		}
		nb.fsm.lock.Lock()
		q := s.exported(nb, p)
		nb.fsm.lock.Unlock()
		o := &s.options // in place, see filterpath
		*o = table.PolicyOptions{Info: nb.peerInfo, OldNextHop: p.GetNexthop()}
		defer func() { *o = table.PolicyOptions{} }()
		return nb.policy.ApplyPolicy(nb.TableID(), table.POLICY_DIRECTION_EXPORT, q, o) != nil, nil
	}
	q := s.filterpath(nb, p, nil)
	return q != nil, q
}

// operaBefore notes the exports to the neighbors before path p changes the
// table, as unchanged until operaFeed.
func (s *BgpServer) operaBefore(rib *table.TableManager, p *table.Path) *operaUpdate {
	if rib != s.globalRib {
		return nil
	}
	peers, ids := s.operaViewPeers(p.GetFamily())
	if len(peers) == 0 {
		return nil
	}
	b := &s.operaBuf
	if b.busy {
		b = &operaBuffers{}
	}
	b.busy = true
	b.changes, b.ready = sized(b.changes, len(peers)), sized(b.ready, len(peers))
	b.update = operaUpdate{peers: peers, ids: ids, changes: b.changes, ready: b.ready, buf: b}
	u := &b.update
	d := rib.GetDestination(p)
	var exports []*table.Path
	if d != nil {
		u.fwdOld = d.OperaForwarding() // kept, as the update may delete the destination
		b.exports = d.OperaExportsInto(ids, b.exports)
		exports = b.exports
	}
	for i, nb := range peers {
		nb.operaSlot = i
		if exports != nil {
			u.changes[i] = [2]*table.Path{exports[i], exports[i]}
		}
	}
	return u
}

// operaFeed feeds path p, already in the main table, into the tables of the
// neighbors, and notes what each is to be sent and the forwarding path.
func (s *BgpServer) operaFeed(rib *table.TableManager, p *table.Path, u *operaUpdate) {
	d := rib.GetDestination(p)
	var sent, after []*table.Path
	if d != nil {
		b := u.buf
		b.allows, b.sent = sized(b.allows, len(u.peers)), sized(b.sent, len(u.peers))
		allows := b.allows
		sent = b.sent
		for i, nb := range u.peers {
			allows[i], sent[i] = s.operaFilter(nb, p)
		}
		d.OperaFeedSorted(s.logger, p, u.ids, allows, true)
		b.exports = d.OperaExportsInto(u.ids, b.exports) // the exports before were copied into changes
		after = b.exports
	}
	for i := range u.peers {
		var a *table.Path
		if after != nil {
			a = after[i]
		}
		u.changes[i][1] = a
		if a != u.changes[i][0] && a == p && sent[i] != nil {
			u.ready[i] = sent[i]
		}
	}
	if d != nil {
		u.fwdOld, u.fwdNew = d.OperaForward()
	} else {
		u.fwdNew = nil // the last path went: the forwarding path with it
	}
	rib.OperaRelease(p)
}

// operaSend sends a neighbor with a table what changed in it, ready if the
// new path is the export and was already filtered for it.
func (s *BgpServer) operaSend(nb *peer, change [2]*table.Path, ready *table.Path) {
	if ready != nil {
		if needToAdvertise(nb) {
			sendfsmOutgoingMsg(nb, []*table.Path{ready})
		}
		return
	}
	old, path := change[0], change[1]
	if path == nil {
		if old == nil {
			return
		}
		path = s.withdrawal(old)
	}
	if !needToAdvertise(nb) { // as processOutgoingPaths, without its lists
		return
	}
	if p := s.filterpath(nb, path, old); p != nil {
		sendfsmOutgoingMsg(nb, []*table.Path{p})
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
	return s.operaExportsOf(nb, t.GetDestinations())
}

// operaExportsOf are the exports of the neighbor's tables to the given
// destinations only.
func (s *BgpServer) operaExportsOf(nb *peer, dsts []*table.Destination) (paths []*table.Path) {
	for _, d := range dsts {
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

// operaExactDestinations are the destinations of family that prefixes name
// exactly, and ok when every prefix is an exact one: a listing of a few
// prefixes then needs only theirs, not every export of the table.
func (s *BgpServer) operaExactDestinations(family bgp.Family, prefixes []*apiutil.LookupPrefix) (dsts []*table.Destination, ok bool) {
	t := s.globalRib.Tables[family]
	if len(prefixes) == 0 || t == nil || (family != bgp.RF_IPv4_UC && family != bgp.RF_IPv6_UC) {
		return nil, false
	}
	for _, p := range prefixes {
		if p.LookupOption != apiutil.LOOKUP_EXACT {
			return nil, false
		}
		prefix, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			return nil, false // a single address or an error: the full lookup handles both
		}
		nlri, err := bgp.NewIPAddrPrefix(prefix)
		if err != nil {
			return nil, false
		}
		if d := t.GetDestination(nlri); d != nil {
			dsts = append(dsts, d)
		}
	}
	return dsts, true
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
	s.operaSessionGone(nb)
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
