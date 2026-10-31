package table

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"

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

// operaViewList are the distinct tables per neighbor, in the order of their
// first neighbor.
func (dest *Destination) operaViewList() []*operaView {
	var out []*operaView
	for _, k := range slices.Sorted(maps.Keys(dest.views)) {
		if v := dest.views[k]; !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// OperaPerNeighbor tells whether OBGP keeps a table per neighbor in a family.
func OperaPerNeighbor(f bgp.Family) bool {
	return isOperaFamily(f) && operaOptions.Load().PerNeighbor
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
	if v := dest.views[key]; v != nil {
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
	if dest.views == nil {
		dest.views = map[string]*operaView{}
	}
	v := dest.views[key]
	switch {
	case v == nil:
		v = newOperaView(dest.nlri, 1)
		dest.views[key] = v
	case v.users > 1:
		v.users--
		v = v.copy()
		dest.views[key] = v
	}
	v.feed(logger, p, in, update)
}

// OperaFeedAll feeds path p to the tables of the neighbors in allows, each
// told whether its export policy lets p in, as OperaFeed for each.
func (dest *Destination) OperaFeedAll(logger *slog.Logger, p *Path, allows map[string]bool, update bool) {
	if dest.views == nil {
		dest.views = map[string]*operaView{}
	}
	keys := slices.Sorted(maps.Keys(allows))
	var fresh []string
	for _, k := range keys {
		if dest.views[k] == nil {
			fresh = append(fresh, k)
		}
	}
	if len(fresh) > 0 {
		v := newOperaView(dest.nlri, len(fresh))
		for _, k := range fresh {
			dest.views[k] = v
		}
	}
	// the neighbors of each table, split by the answer of their policy
	type parts struct{ in, out []string }
	split := map[*operaView]*parts{}
	var order []*operaView
	for _, k := range keys {
		v := dest.views[k]
		if split[v] == nil {
			split[v] = &parts{}
			order = append(order, v)
		}
		if allows[k] {
			split[v].in = append(split[v].in, k)
		} else {
			split[v].out = append(split[v].out, k)
		}
	}
	type target struct {
		v  *operaView
		in bool
	}
	var targets []target
	for _, v := range order {
		g := split[v]
		// v stays with the first part if every neighbor sharing it is fed,
		// the other parts get a copy, made before v changes
		keep := len(g.in)+len(g.out) == v.users
		for _, part := range []struct {
			keys []string
			in   bool
		}{{g.in, true}, {g.out, false}} {
			if len(part.keys) == 0 {
				continue
			}
			w := v
			if !keep {
				w = v.copy()
				w.users = len(part.keys)
				v.users -= len(part.keys)
				for _, k := range part.keys {
					dest.views[k] = w
				}
			}
			keep = false
			targets = append(targets, target{w, part.in})
		}
	}
	for _, t := range targets {
		t.v.feed(logger, p, t.in, update)
	}
}

// OperaShare lets the table of neighbor key be shared with another one in
// the same state, after it was built anew.
func (dest *Destination) OperaShare(key string) {
	v := dest.views[key]
	if v == nil || v.users > 1 {
		return
	}
	for _, w := range dest.operaViewList() {
		if w != v && w.same(v) {
			w.users++
			dest.views[key] = w
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
// of its table, nil for none.
func (dest *Destination) OperaExport(key string) *Path {
	v := dest.views[key]
	if v == nil {
		return nil
	}
	return operaOriginal(getOperaWorstPath(GLOBAL_RIB_NAME, 0, v.dest.knownPathList))
}

// OperaViewState is what the table towards neighbor key holds, as AS paths:
// the admitted and the set-aside ones, for checks.
func (dest *Destination) OperaViewState(key string) (admitted, aside [][]uint32) {
	v := dest.views[key]
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
	if v := dest.views[key]; v != nil {
		v.users--
		delete(dest.views, key)
	}
}

// OperaForward is the path the router forwards on with tables per
// neighbor: its preferred one among the admitted of all its tables no
// longer than any of its exports. old is the one before.
func (dest *Destination) OperaForward() (old, best *Path) {
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
	for _, v := range dest.views {
		if v.dest.operaHolds() {
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
