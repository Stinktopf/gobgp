package table

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"unique"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// OBGP per neighbor. A router keeps one OBGP table per eBGP neighbor. Into
// it go the paths the router's own export policy lets through to that
// neighbor, and the neighbor's own paths, which count for the threshold but
// are never sent back. Each table admits, prunes and asks for route
// refreshes as the main one does, and the neighbor gets its worst admitted
// path. The router forwards on its preferred path among those admitted in
// any of its tables that are no longer than any of its exports, so that the
// length still falls along every forwarding hop, whatever the policies.

// With OBGP off the same tables give NS-BGP (Wang, Schapira, Rexford 2009):
// each table runs BGP's decision and the neighbor gets its best path, the
// best one its export policy allows. The router forwards on the best path of
// its main table. NS-BGP forwards a packet by the neighbor it came from,
// which one table cannot, so the lab and the simulator check forwarding per
// ingress from the exports.

// Neighbors share a table as long as their export policies decided alike on
// every path fed in. The first path they differ on copies it, so each still
// behaves as a table of its own. A table built anew for a neighbor joins one
// in the same state. That saves the memory of a table per neighbor for the
// neighbors that get everything, customers under Gao-Rexford.

// operaView is the table of one or more neighbors.
type operaView struct {
	dest   *Destination
	member map[string]bool // the paths fed in, by source and path ID
	users  int             // the neighbors sharing it
}

func newOperaView(nlri bgp.NLRI, users int) *operaView {
	return &operaView{dest: NewDestination(nlri, 64), member: map[string]bool{}, users: users}
}

// copy is a table in the same state, for one neighbor.
func (v *operaView) copy() *operaView {
	d := v.dest
	paths := map[*Path]*Path{}
	clone := func(l []*Path) []*Path {
		var out []*Path
		for _, p := range l {
			if paths[p] == nil {
				q := *p
				paths[p] = &q
			}
			out = append(out, paths[p])
		}
		return out
	}
	c := &Destination{nlri: d.nlri, knownPathList: clone(d.knownPathList), localIdMap: &Bitmap{bitmap: slices.Clone(d.localIdMap.bitmap)}}
	if d.opera != nil {
		c.opera = &operaState{suppressed: clone(d.opera.suppressed), pruned: clone(d.opera.pruned)}
	}
	return &operaView{dest: c, member: maps.Clone(v.member), users: 1}
}

// same tells whether two tables are in the same state, so that they decide
// alike from now on. The numbers a table gives its paths do not count, they
// are never sent.
func (v *operaView) same(w *operaView) bool {
	samePaths := func(a, b []*Path) bool {
		return slices.EqualFunc(a, b, func(p, q *Path) bool {
			return p.parent == q.parent && p.info == q.info && len(p.pathAttrs) == 0 && len(q.pathAttrs) == 0 &&
				len(p.dels) == 0 && len(q.dels) == 0 && p.attrsHash == q.attrsHash && p.remoteID == q.remoteID &&
				p.family == q.family && p.rejected == q.rejected && p.policyRejected == q.policyRejected &&
				p.dropped == q.dropped && p.IsNexthopInvalid == q.IsNexthopInvalid && p.IsWithdraw == q.IsWithdraw
		})
	}
	return maps.Equal(v.member, w.member) && samePaths(v.dest.knownPathList, w.dest.knownPathList) &&
		samePaths(v.dest.operaSuppressed(), w.dest.operaSuppressed()) && samePaths(v.dest.operaPruned(), w.dest.operaPruned())
}

// operaEntry is the table of one neighbor in a destination. Its key is
// unique: every destination holds the same string for a neighbor.
type operaEntry struct {
	key  unique.Handle[string]
	view *operaView
}

func (dest *Destination) viewIndex(key string) (int, bool) {
	return slices.BinarySearchFunc(dest.views, key, func(e operaEntry, k string) int { return strings.Compare(e.key.Value(), k) })
}

// view is the table of neighbor key, nil for none.
func (dest *Destination) view(key string) *operaView {
	if i, ok := dest.viewIndex(key); ok {
		return dest.views[i].view
	}
	return nil
}

// setView makes v the table of neighbor key.
func (dest *Destination) setView(key string, v *operaView) {
	i, ok := dest.viewIndex(key)
	if ok {
		dest.views[i].view = v
		return
	}
	dest.views = slices.Insert(dest.views, i, operaEntry{unique.Make(key), v})
}

// addViews makes v the table of the neighbors keys, which have none.
func (dest *Destination) addViews(keys []string, v *operaView) {
	for _, k := range keys {
		dest.views = append(dest.views, operaEntry{unique.Make(k), v})
	}
	slices.SortFunc(dest.views, func(a, b operaEntry) int { return strings.Compare(a.key.Value(), b.key.Value()) })
}

// operaViewList are the distinct tables per neighbor, in the order of their
// first neighbor.
func (dest *Destination) operaViewList() []*operaView {
	var out []*operaView
	for _, e := range dest.views {
		if !slices.Contains(out, e.view) {
			out = append(out, e.view)
		}
	}
	return out
}

// OperaPerNeighbor tells whether the router keeps a table per neighbor in a
// family: OBGP per neighbor, or NS-BGP with OBGP off.
func OperaPerNeighbor(f bgp.Family) bool {
	return (f == bgp.RF_IPv4_UC || f == bgp.RF_IPv6_UC) && operaOptions.Load().PerNeighbor
}

func operaKey(p *Path) string {
	if p.IsLocal() || p.GetSource() == nil {
		return fmt.Sprint("local ", p.remoteID)
	}
	return fmt.Sprint(p.GetSource().Address, " ", p.remoteID)
}

// operaOriginal is the path a table per neighbor holds a clone of.
func operaOriginal(p *Path) *Path {
	if p != nil && p.parent != nil {
		return p.parent
	}
	return p
}

// OperaCandidates are the paths a neighbor's table may hold: the admitted
// and the set-aside ones of the main table, and those its table holds. The
// worst come first in the OBGP order, so that a table built from them
// admits every one and exports the worst, as if they had come in so.
func (dest *Destination) OperaCandidates(key string) []*Path {
	var out []*Path
	for _, p := range slices.Concat(dest.knownPathList, dest.operaSuppressed(), dest.operaPruned()) {
		if isOperaValid(p) && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if v := dest.view(key); v != nil {
		for _, p := range slices.Concat(v.dest.knownPathList, v.dest.operaSuppressed(), v.dest.operaPruned()) {
			if o := operaOriginal(p); isOperaValid(o) && !slices.Contains(out, o) {
				out = append(out, o)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b *Path) int { return compareOperaPath(b, a) })
	return out
}

// OperaFeed puts path p into the table towards neighbor key if in, or takes
// it out if it was in and is no longer, a withdrawal or rejected by the
// export policy now. An update is fed even if its source's path was in
// before, a sync only where the policy's answer changed.
func (dest *Destination) OperaFeed(logger *slog.Logger, key string, p *Path, in, update bool) {
	v := dest.view(key)
	switch {
	case v == nil:
		v = newOperaView(dest.nlri, 1)
		dest.setView(key, v)
	case v.users > 1:
		v.users--
		v = v.copy()
		dest.setView(key, v)
	}
	v.feed(logger, p, in, update)
}

// OperaFeedAll feeds path p to the tables of the neighbors in allows, each
// told whether its export policy lets p in, as OperaFeed for each.
func (dest *Destination) OperaFeedAll(logger *slog.Logger, p *Path, allows map[string]bool, update bool) {
	keys := slices.Sorted(maps.Keys(allows))
	in := make([]bool, len(keys))
	for i, k := range keys {
		in[i] = allows[k]
	}
	dest.OperaFeedSorted(logger, p, keys, in, update)
}

// OperaFeedSorted is OperaFeedAll for the neighbors keys, sorted and
// distinct, each told by allows at the same index.
func (dest *Destination) OperaFeedSorted(logger *slog.Logger, p *Path, keys []string, allows []bool, update bool) {
	// the table of each key, in one walk through both sorted lists
	of := make([]*operaView, len(keys))
	var fresh []string
	j := 0
	for i, k := range keys {
		for j < len(dest.views) && dest.views[j].key.Value() < k {
			j++
		}
		if j < len(dest.views) && dest.views[j].key.Value() == k {
			of[i] = dest.views[j].view
		} else {
			fresh = append(fresh, k)
		}
	}
	if len(fresh) > 0 {
		v := newOperaView(dest.nlri, len(fresh))
		dest.addViews(fresh, v)
		for i := range of {
			if of[i] == nil {
				of[i] = v
			}
		}
	}
	// the neighbors of each table, counted by the answer of their policy
	count := map[*operaView]*[2]int{} // out, in
	var order []*operaView
	for i, v := range of {
		if count[v] == nil {
			count[v] = &[2]int{}
			order = append(order, v)
		}
		if allows[i] {
			count[v][1]++
		} else {
			count[v][0]++
		}
	}
	type target struct {
		v  *operaView
		in bool
	}
	var targets []target
	for _, v := range order {
		c := count[v]
		// v stays with the first part if every neighbor sharing it is fed,
		// the other parts get a copy, made before v changes
		keep := c[0]+c[1] == v.users
		for _, in := range []bool{true, false} {
			n := c[0]
			if in {
				n = c[1]
			}
			if n == 0 {
				continue
			}
			w := v
			if !keep {
				w = v.copy()
				w.users = n
				v.users -= n
				for i, k := range keys {
					if of[i] == v && allows[i] == in {
						dest.setView(k, w)
					}
				}
			}
			keep = false
			targets = append(targets, target{w, in})
		}
	}
	for _, t := range targets {
		t.v.feed(logger, p, t.in, update)
	}
	// a table the path brought into the state of another is shared again
	for _, t := range targets {
		dest.operaMerge(t.v)
	}
}

// operaMerge lets the neighbors of table v share another table in the same
// state, which decides alike from now on (same).
func (dest *Destination) operaMerge(v *operaView) {
	for _, w := range dest.operaViewList() {
		if w == v {
			continue
		}
		if w.same(v) {
			for i := range dest.views {
				if dest.views[i].view == v {
					dest.views[i].view = w
				}
			}
			w.users += v.users
			return
		}
	}
}

// OperaShare lets the table of neighbor key be shared with another one in
// the same state, after it was built anew.
func (dest *Destination) OperaShare(key string) {
	v := dest.view(key)
	if v == nil || v.users > 1 {
		return
	}
	for _, w := range dest.operaViewList() {
		if w != v && w.same(v) {
			w.users++
			dest.setView(key, w)
			return
		}
	}
}

func (v *operaView) feed(logger *slog.Logger, p *Path, in, update bool) {
	k := operaKey(p)
	switch {
	case in && !p.IsWithdraw && (update || !v.member[k]):
		v.member[k] = true
		q := p.Clone(false)
		q.localID = 0 // the table numbers its paths itself
		v.dest.Calculate(logger, q)
	case !in && v.member[k]:
		delete(v.member, k)
		q := p.Clone(true)
		q.localID = 0
		if p.IsSessionDropped() {
			q.SetSessionDropped()
		}
		if !p.IsWithdraw || p.IsPolicyRejected() {
			q.SetPolicyRejected() // the own export policy rejects it now
		}
		v.dest.Calculate(logger, q)
	}
}

// OperaExport is the path the router sends neighbor key: the worst admitted
// of its table, its best with OBGP off, nil for none.
func (dest *Destination) OperaExport(key string) *Path {
	if v := dest.view(key); v != nil {
		return v.export()
	}
	return nil
}

func (v *operaView) export() *Path {
	if !IsOperaEnabled() {
		return operaOriginal(v.dest.GetBestPath(GLOBAL_RIB_NAME, 0))
	}
	return operaOriginal(getOperaWorstPath(GLOBAL_RIB_NAME, 0, v.dest.knownPathList))
}

// OperaExports are OperaExport for the neighbors keys, sorted, in one walk
// through the tables.
func (dest *Destination) OperaExports(keys []string) []*Path {
	out := make([]*Path, len(keys))
	j := 0
	for i, k := range keys {
		for j < len(dest.views) && dest.views[j].key.Value() < k {
			j++
		}
		if j < len(dest.views) && dest.views[j].key.Value() == k {
			out[i] = dest.views[j].view.export()
		}
	}
	return out
}

// OperaViewState is what the table towards neighbor key holds, as AS paths:
// the admitted and the set-aside ones, for checks.
func (dest *Destination) OperaViewState(key string) (admitted, aside [][]uint32) {
	v := dest.view(key)
	if v == nil {
		return nil, nil
	}
	for _, p := range v.dest.knownPathList {
		admitted = append(admitted, p.GetAsList())
	}
	for _, p := range v.dest.operaSuppressed() {
		aside = append(aside, p.GetAsList())
	}
	return admitted, aside
}

// OperaDropView forgets the table of a neighbor that is gone.
func (dest *Destination) OperaDropView(key string) {
	if i, ok := dest.viewIndex(key); ok {
		dest.views[i].view.users--
		dest.views = slices.Delete(dest.views, i, i+1)
	}
}

// OperaForward is the path the router forwards on with tables per
// neighbor: its preferred one among the admitted of all its tables no
// longer than any of its exports, with OBGP off the best of the main table.
// old is the one before.
func (dest *Destination) OperaForward() (old, best *Path) {
	if !IsOperaEnabled() {
		old, dest.operaForward = dest.operaForward, dest.GetBestPath(GLOBAL_RIB_NAME, 0)
		return old, dest.operaForward
	}
	bound := -1
	for _, v := range dest.operaViewList() {
		if e := getOperaWorstPath(GLOBAL_RIB_NAME, 0, v.dest.knownPathList); e != nil && (bound < 0 || e.GetAsPathLen() < bound) {
			bound = e.GetAsPathLen()
		}
	}
	var cands []*Path
	add := func(p *Path) {
		if p = operaOriginal(p); isOperaValid(p) && (bound < 0 || p.GetAsPathLen() <= bound) && !slices.Contains(cands, p) {
			cands = append(cands, p)
		}
	}
	for _, p := range dest.knownPathList {
		add(p)
	}
	for _, v := range dest.operaViewList() {
		for _, p := range v.dest.knownPathList {
			add(p)
		}
	}
	sorted := &Destination{}
	for _, p := range cands {
		sorted.insertSort(p)
	}
	old = dest.operaForward
	dest.operaForward = getBestPath(GLOBAL_RIB_NAME, 0, sorted.knownPathList)
	return old, dest.operaForward
}

// OperaForwarding is the path OperaForward chose last, nil without tables
// per neighbor.
func (dest *Destination) OperaForwarding() *Path {
	return dest.operaForward
}

// operaViewsEmpty tells whether no table per neighbor holds a path.
func (dest *Destination) operaViewsEmpty() bool {
	for _, e := range dest.views {
		if e.view.dest.operaHolds() {
			return false
		}
	}
	return true
}

// OperaRelease deletes the destination of p once no table holds a path.
func (manager *TableManager) OperaRelease(p *Path) {
	t := manager.Tables[p.GetFamily()]
	if t == nil {
		return
	}
	if d := t.GetDestination(p.GetNlri()); d != nil && !d.operaHolds() && d.operaViewsEmpty() {
		t.deleteDest(d)
	}
}
