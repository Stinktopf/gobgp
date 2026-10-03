package table

import (
	"cmp"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// OperaOptions are the settings of OBGP. They apply to the whole process.
type OperaOptions struct {
	Enabled bool
	// Pruning removes, when a path is withdrawn or its AS path changes,
	// every path that contains its old AS sequence, from any peer. It is
	// part of the original design, in which a router sends all neighbors
	// the same path or none, and export filters depend only on the
	// Gao-Rexford class of a neighbor. Other export policies are
	// outside that model: a withdrawal caused by them also removes valid
	// paths learned from other peers. Without pruning, OBGP is a
	// derivative of the original design.
	Pruning bool
}

var operaOptions atomic.Pointer[OperaOptions]

func init() {
	operaOptions.Store(&OperaOptions{Pruning: true})
}

// InitOperaFromEnv reads the OBGP settings: GOBGP_OPERA_ENABLED enables OBGP
// if it is "1" or "true", and GOBGP_OPERA_PRUNING disables superset pruning
// if it is "0" or "false".
func InitOperaFromEnv() OperaOptions {
	enabled := strings.ToLower(os.Getenv("GOBGP_OPERA_ENABLED"))
	pruning := strings.ToLower(os.Getenv("GOBGP_OPERA_PRUNING"))
	o := OperaOptions{
		Enabled: enabled == "1" || enabled == "true",
		Pruning: pruning != "0" && pruning != "false",
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
	return operaOptions.Load().Pruning
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
	return slices.Compare(a.GetAsList(), b.GetAsList())
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
func (dest *Destination) operaReadmit() {
	for _, p := range dest.knownPathList {
		if isOperaValid(p) {
			return
		}
	}
	idx := -1
	l := dest.operaSuppressed()
	for i, p := range l {
		if !isOperaValid(p) {
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
// path contains baseAS as a contiguous subsequence.
func (dest *Destination) operaPruneSupersets(baseAS []uint32) {
	if len(baseAS) == 0 {
		return
	}

	keep := func(l []*Path) []*Path {
		n := 0
		for _, other := range l {
			if containsASSubsequence(other.GetAsList(), baseAS) {
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
