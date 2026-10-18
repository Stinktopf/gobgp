package table

import (
	"cmp"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Pruning is what OBGP does with the paths of other peers that contain the
// AS sequence of a path withdrawn, or whose AS path changed.
type Pruning uint8

const (
	// PruneRefresh, the default, sets them aside as soft does, but never
	// takes one back unasked: once no valid path is left, the router asks
	// the neighbors of the paths set aside for their current routes by a
	// route refresh (RFC 2918), sent behind its own withdrawal. A stale path
	// then cannot make forwarding loop, and no valid path is lost. Neighbors
	// without route refresh get their paths back as with soft pruning.
	PruneRefresh Pruning = iota
	// PruneSoft moves them to the rejected candidates, so that they come
	// back when no valid path is left, and prunes nothing when the router's
	// own import policy rejected a path. Inside the model it prunes as hard
	// does, outside it costs no reachability, but a path that comes back
	// may be stale and make forwarding loop until routes settle.
	PruneSoft
	// PruneHard removes them, admitted or rejected: the paper's design,
	// in which a router sends all neighbors the same path or none, and
	// export filters depend only on the Gao-Rexford class of a neighbor.
	// Outside that model, a withdrawal caused by a filter towards one
	// neighbor, or by the own import policy, also removes paths still
	// valid via another peer.
	PruneHard
	// PruneOff keeps them: a derivative of the original design.
	PruneOff
)

func (p Pruning) String() string {
	return [...]string{"refresh", "soft", "hard", "off"}[p]
}

// OperaOptions are the settings of OBGP. They apply to the whole process.
// The zero value is OBGP as built here: refresh pruning, iBGP paths unfiltered
// and AS_SET ordered canonically. The paper's is PruneHard, FilterIBGP and
// ReceivedSetOrder.
type OperaOptions struct {
	Enabled bool
	Pruning Pruning
	// RefreshInterval is the least time between two route refreshes the
	// router asks of one neighbor under PruneRefresh: the waiting paths of
	// all prefixes go into one. GOBGP_OPERA_REFRESH_S, zero for 1 s.
	RefreshInterval time.Duration
	// RefreshDelay is how long the first route refresh to a neighbor waits,
	// so that withdrawals elsewhere reach the neighbor before it answers.
	// GOBGP_OPERA_REFRESH_DELAY_S, zero to ask at once.
	RefreshDelay time.Duration
	// ReceivedSetOrder compares the members of an AS_SET in the order
	// received and a confederation segment as AS 0, as the paper's code
	// did. By default a set is one hop of its members in ascending order
	// and a confederation segment no hop (RFC 5065): the same paths
	// compare alike, however their sets were written.
	ReceivedSetOrder bool
	// FilterIBGP filters paths from iBGP peers as any others, as the
	// paper's code did. By default they pass without the import filter:
	// inside an AS the AS path does not grow, so the filter would compare
	// them unfairly with paths from other ASes. The threshold is still
	// over all admitted paths, so it holds for the whole AS.
	FilterIBGP bool
}

var operaOptions atomic.Pointer[OperaOptions]

func init() {
	operaOptions.Store(&OperaOptions{})
}

// InitOperaFromEnv reads the OBGP settings: GOBGP_OPERA_ENABLED enables OBGP
// if it is "1" or "true". GOBGP_OPERA_PRUNING is "refresh" (also empty), "soft",
// "hard" (also "true" or "1"), or "off" (also
// "false" or "0"). GOBGP_OPERA_AS_SET
// "received" orders AS_SET members as received. GOBGP_OPERA_IBGP "filter"
// filters iBGP paths as any others (FilterIBGP).
func InitOperaFromEnv() OperaOptions {
	enabled := strings.ToLower(os.Getenv("GOBGP_OPERA_ENABLED"))
	o := OperaOptions{
		Enabled:          enabled == "1" || enabled == "true",
		ReceivedSetOrder: strings.ToLower(os.Getenv("GOBGP_OPERA_AS_SET")) == "received",
		FilterIBGP:       strings.ToLower(os.Getenv("GOBGP_OPERA_IBGP")) == "filter",
	}
	switch strings.ToLower(os.Getenv("GOBGP_OPERA_PRUNING")) {
	case "hard", "true", "1":
		o.Pruning = PruneHard
	case "off", "false", "0":
		o.Pruning = PruneOff
	case "soft":
		o.Pruning = PruneSoft
	case "refresh":
		o.Pruning = PruneRefresh
	}
	if s, err := strconv.ParseFloat(os.Getenv("GOBGP_OPERA_REFRESH_S"), 64); err == nil && s >= 0 {
		o.RefreshInterval = time.Duration(s * float64(time.Second))
	}
	if s, err := strconv.ParseFloat(os.Getenv("GOBGP_OPERA_REFRESH_DELAY_S"), 64); err == nil && s >= 0 {
		o.RefreshDelay = time.Duration(s * float64(time.Second))
	}
	SetOperaOptions(o)
	return o
}

// SetOperaOptions replaces the OBGP settings.
func SetOperaOptions(o OperaOptions) {
	operaOptions.Store(&o)
}

func GetOperaOptions() OperaOptions {
	return *operaOptions.Load()
}

func IsOperaEnabled() bool {
	return operaOptions.Load().Enabled
}

func isOperaPruning() bool {
	return operaOptions.Load().Pruning != PruneOff
}

// isOperaPrunedBy tells whether a withdrawal or replacement p prunes. Unless
// FilterIBGP, an iBGP peer withdraws or replaces its path whenever its export
// path changes, also when split horizon keeps it from passing on its new
// one. That says nothing about the paths through the old one.
func isOperaPrunedBy(p *Path) bool {
	return isOperaPruning() && !(!operaOptions.Load().FilterIBGP && p.IsIBGP())
}

func isOperaSoftPruning() bool {
	p := operaOptions.Load().Pruning
	return p == PruneSoft || p == PruneRefresh
}

// OperaWaiting are the neighbors to ask for their current route under
// PruneRefresh: those of the valid paths set aside, once no valid path is
// left. Empty otherwise.
func (dest *Destination) OperaWaiting() []*PeerInfo {
	if operaOptions.Load().Pruning != PruneRefresh {
		return nil
	}
	for _, p := range dest.knownPathList {
		if isOperaValid(p) {
			return nil
		}
	}
	var out []*PeerInfo
	for _, p := range dest.operaSuppressed() {
		if isOperaValid(p) && p.GetSource() != nil && refreshCapable(p) {
			out = append(out, p.GetSource())
		}
	}
	return out
}

// operaSuppressedAll tells whether every valid path set aside passes ok.
func (dest *Destination) operaSuppressedAll(ok func(*Path) bool) bool {
	for _, p := range dest.operaSuppressed() {
		if isOperaValid(p) && !ok(p) {
			return false
		}
	}
	return true
}

// isOperaFamily reports whether OBGP applies to family f. OBGP is limited to
// unicast; other families such as RTC, which must consider all paths
// (RFC 4684), keep the standard behavior.
func isOperaFamily(f bgp.Family) bool {
	return IsOperaEnabled() && (f == bgp.RF_IPv4_UC || f == bgp.RF_IPv6_UC)
}

// operaImportAccept reports whether cand passes the OBGP import filter: it
// must be strictly better than the worst valid path in known. Withdrawals
// always pass, and the first valid candidate initializes the threshold.
func operaImportAccept(known []*Path, cand *Path) bool {
	if !isOperaFamily(cand.GetFamily()) || cand.IsWithdraw {
		return true
	}
	if !operaOptions.Load().FilterIBGP && cand.IsIBGP() {
		return true
	}

	var worst *Path
	for _, existing := range known {
		if !isOperaValid(existing) {
			continue
		}
		if worst == nil || isWorseOperaPath(existing, worst) {
			worst = existing
		}
	}
	if worst == nil {
		return true
	}
	return isBetterOperaPath(cand, worst)
}

// OBGP separates route propagation from local route choice. Peers are sent
// the worst admitted path (the export path), while the local choice, used for
// the FIB and best-path watchers, remains GoBGP's standard best path and
// multipath selection over the admitted paths. Forwarding over any admitted
// path is loop-free: a path is only admitted if it is not worse than the
// router's own export path, so the export path length strictly decreases
// along every forwarding hop.
//
// Selecting the export path costs O(n) comparisons for n admitted paths,
// which is bounded by the number of peers.

// GetExportChanges is GetChanges for the path advertised to peers.
func (u *Update) GetExportChanges(id string, as uint32) (*Path, *Path) {
	if !u.isOpera() {
		best, old, _ := u.GetChanges(id, as, false)
		return best, old
	}
	export := &Update{
		KnownPathList:    exportPathList(id, as, u.KnownPathList),
		OldKnownPathList: exportPathList(id, as, u.OldKnownPathList),
	}
	best, old, _ := export.GetChanges(id, as, false)
	return best, old
}

func (u *Update) isOpera() bool {
	for _, l := range [][]*Path{u.KnownPathList, u.OldKnownPathList} {
		if len(l) > 0 {
			return isOperaFamily(l[0].GetFamily())
		}
	}
	return false
}

// GetExportPathList is GetBestPathList for the paths advertised to peers.
func (manager *TableManager) GetExportPathList(id string, as uint32, rfList []bgp.Family) []*Path {
	if !IsOperaEnabled() || SelectionOptions.DisableBestPathSelection {
		return manager.GetBestPathList(id, as, rfList)
	}
	paths := make([]*Path, 0, manager.getDestinationCount(rfList))
	for _, t := range manager.tables(rfList...) {
		if !isOperaFamily(t.Family) {
			paths = append(paths, t.Bests(id, as)...)
			continue
		}
		for _, dst := range t.GetDestinations() {
			if p := getOperaWorstPath(id, as, dst.knownPathList); p != nil {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

func exportPathList(id string, as uint32, pathList []*Path) []*Path {
	if p := getOperaWorstPath(id, as, pathList); p != nil {
		return []*Path{p}
	}
	return nil
}

// getOperaWorstPath returns the worst valid path according to the OBGP order.
func getOperaWorstPath(id string, as uint32, pathList []*Path) *Path {
	var worst *Path
	for _, p := range pathList {
		if rsFilter(id, as, p) || !isOperaValid(p) {
			continue
		}
		if worst == nil || isWorseOperaPath(p, worst) {
			worst = p
		}
	}
	return worst
}

// compareOperaPath orders paths by AS path length first and then
// lexicographically by ASN. It returns -1 if a is better than b, 1 if a is
// worse and 0 if both AS paths are equal. The order is only canonical for
// AS_SEQUENCE segments; AS_SET and confederation segments are not supported.
func compareOperaPath(a, b *Path) int {
	if c := cmp.Compare(a.GetAsPathLen(), b.GetAsPathLen()); c != 0 {
		return c
	}
	if !operaOptions.Load().ReceivedSetOrder && (hasSetOrConfed(a) || hasSetOrConfed(b)) {
		return slices.CompareFunc(operaHops(a), operaHops(b), slices.Compare[[]uint32])
	}
	return slices.Compare(a.GetAsList(), b.GetAsList()) // the same order for sequences, without allocating hops
}

func hasSetOrConfed(p *Path) bool {
	if aspath := p.GetAsPath(); aspath != nil {
		for _, segment := range aspath.Value {
			if segment.GetType() != bgp.BGP_ASPATH_ATTR_TYPE_SEQ {
				return true
			}
		}
	}
	return false
}

// operaHops is the AS path as the hops the OBGP order and pruning look at.
// An AS of a sequence is a hop, a set is one hop of its members in ascending
// order, and confederation segments are no hops (RFC 5065). With
// ReceivedSetOrder every listed AS is a hop, as GetAsList lists them.
func operaHops(p *Path) [][]uint32 {
	var hops [][]uint32
	if operaOptions.Load().ReceivedSetOrder {
		for _, as := range p.GetAsList() {
			hops = append(hops, []uint32{as})
		}
		return hops
	}
	if aspath := p.GetAsPath(); aspath != nil {
		for _, segment := range aspath.Value {
			switch segment.GetType() {
			case bgp.BGP_ASPATH_ATTR_TYPE_SEQ:
				for _, as := range segment.GetAS() {
					hops = append(hops, []uint32{as})
				}
			case bgp.BGP_ASPATH_ATTR_TYPE_SET:
				set := slices.Clone(segment.GetAS())
				slices.Sort(set)
				hops = append(hops, slices.Compact(set))
			}
		}
	}
	return hops
}

func sameOperaHops(a, b *Path) bool {
	return slices.EqualFunc(operaHops(a), operaHops(b), slices.Equal[[]uint32])
}

func isBetterOperaPath(newPath, existingPath *Path) bool {
	if newPath == nil || existingPath == nil {
		return false
	}
	return compareOperaPath(newPath, existingPath) < 0
}

func isWorseOperaPath(newPath, existingPath *Path) bool {
	if newPath == nil || existingPath == nil {
		return false
	}
	return compareOperaPath(newPath, existingPath) > 0
}

// operaState holds the per-destination OBGP state beyond the admitted paths
// in knownPathList. It is allocated only when needed, so a destination
// without OBGP state costs a single nil pointer.
type operaState struct {
	// suppressed holds the candidates rejected by the import filter, at most
	// one per source and path ID. Together with knownPathList it forms the
	// complete candidate set of the destination.
	suppressed []*Path
}

func (dest *Destination) operaSuppressed() []*Path {
	if dest.opera == nil {
		return nil
	}
	return dest.opera.suppressed
}

func (dest *Destination) operaSuppress(p *Path) {
	if dest.opera == nil {
		dest.opera = &operaState{}
	}
	dest.opera.suppressed = append(dest.opera.suppressed, p)
}

func (dest *Destination) setOperaSuppressed(l []*Path) {
	if len(l) == 0 {
		dest.opera = nil
		return
	}
	dest.opera.suppressed = l
}

// operaUnsuppress removes the suppressed path with the same source and path
// ID as p and returns it, or nil if there is none.
func (dest *Destination) operaUnsuppress(p *Path) *Path {
	l := dest.operaSuppressed()
	for i, s := range l {
		if p.EqualBySourceAndPathID(s) {
			dest.setOperaSuppressed(append(l[:i], l[i+1:]...))
			return s
		}
	}
	return nil
}

// operaReadmit re-admits the best suppressed path according to the OBGP
// order once no valid path is left, so that a destination stays reachable
// while a neighbor still advertises a valid path. The choice depends only on
// the current state, not on the order in which paths arrived.
// OperaRefreshCapable tells whether the neighbor at an address answers a
// route refresh. The server sets it, nil means all do.
var OperaRefreshCapable atomic.Pointer[func(netip.Addr) bool]

func refreshCapable(p *Path) bool {
	f := OperaRefreshCapable.Load()
	return f == nil || p.GetSource() == nil || (*f)(p.GetSource().Address)
}

func (dest *Destination) operaReadmit() {
	refresh := operaOptions.Load().Pruning == PruneRefresh
	if refresh && dest.operaSuppressedAll(refreshCapable) {
		return // the neighbors are asked instead, see OperaWaiting
	}
	for _, p := range dest.knownPathList {
		if isOperaValid(p) {
			return
		}
	}
	idx := -1
	l := dest.operaSuppressed()
	for i, p := range l {
		if !isOperaValid(p) || refresh && refreshCapable(p) { // those neighbors are asked
			continue
		}
		if idx == -1 || isOperaPreferred(p, l[idx]) {
			idx = i
		}
	}
	if idx == -1 {
		return
	}
	p := l[idx]
	dest.setOperaSuppressed(append(l[:idx], l[idx+1:]...))
	dest.insertSort(p)
}

func isOperaValid(p *Path) bool {
	return p != nil && !p.IsWithdraw && !p.IsNexthopInvalid
}

// isOperaPreferred reports whether a is preferred over b. Paths with equal
// AS paths are ordered by source address and path ID, which makes the order
// strict and total.
func isOperaPreferred(a, b *Path) bool {
	if isBetterOperaPath(a, b) {
		return true
	}
	if isBetterOperaPath(b, a) {
		return false
	}
	if c := a.GetSource().Address.Compare(b.GetSource().Address); c != 0 {
		return c < 0
	}
	return a.remoteID < b.remoteID
}

// operaPruneSupersets removes every candidate, admitted or suppressed, whose AS
// path contains the hops of base as a contiguous subsequence. With
// soft pruning, admitted ones become suppressed instead, and suppressed ones
// stay.
func (dest *Destination) operaPruneSupersets(base *Path) {
	baseHops := operaHops(base)
	if len(baseHops) == 0 {
		return
	}
	if isOperaSoftPruning() {
		n := 0
		for _, other := range dest.knownPathList {
			if containsHopSubsequence(operaHops(other), baseHops) {
				dest.operaSuppress(other) // keeps its local ID: it may come back
				continue
			}
			dest.knownPathList[n] = other
			n++
		}
		dest.knownPathList = dest.knownPathList[:n]
		return
	}

	keep := func(l []*Path) []*Path {
		n := 0
		for _, other := range l {
			if containsHopSubsequence(operaHops(other), baseHops) {
				// The path is gone from the destination; a later
				// re-advertisement gets a new local ID.
				if other.localID != 0 {
					dest.localIdMap.Unflag(uint(other.localID))
				}
				continue
			}
			l[n] = other
			n++
		}
		return l[:n]
	}
	dest.knownPathList = keep(dest.knownPathList)
	if dest.opera != nil {
		dest.setOperaSuppressed(keep(dest.opera.suppressed))
	}
}

func containsHopSubsequence(haystack, needle [][]uint32) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if slices.EqualFunc(haystack[i:i+len(needle)], needle, slices.Equal[[]uint32]) {
			return true
		}
	}
	return false
}

func containsASSubsequence(haystack, needle []uint32) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
outer:
	for i := 0; i <= len(haystack)-len(needle); i++ {
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
