package table

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var operaTestPrefix = netip.MustParsePrefix("10.0.0.0/24")

// withOpera sets the paper's hard pruning, which most tests here describe.
func withOpera(t *testing.T) {
	t.Helper()
	withOperaOptions(t, OperaOptions{Enabled: true, Pruning: PruneHard})
}

func withOperaOptions(t *testing.T, o OperaOptions) {
	t.Helper()
	old := GetOperaOptions()
	SetOperaOptions(o)
	t.Cleanup(func() { SetOperaOptions(old) })
}

// operaPath builds a path for operaTestPrefix learned from the peer at addr.
// The peer AS is taken from the first ASN of the AS path.
func operaPath(addr string, asList []uint32, withdraw bool) *Path {
	return operaPathMed(addr, asList, withdraw, 0)
}

func operaPathMed(addr string, asList []uint32, withdraw bool, med uint32) *Path {
	nlri, _ := bgp.NewIPAddrPrefix(operaTestPrefix)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(addr))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asList),
		}),
		nexthop,
		bgp.NewPathAttributeMultiExitDisc(med),
	}
	var peerAS uint32
	if len(asList) > 0 {
		peerAS = asList[0]
	}
	peer := &PeerInfo{AS: peerAS, Address: netip.MustParseAddr(addr), ID: netip.MustParseAddr(addr)}
	return NewPath(bgp.RF_IPv4_UC, peer, bgp.PathNLRI{NLRI: nlri}, withdraw, attrs, time.Now(), false)
}

// newOperaDestination creates a destination like Table.update does.
func newOperaDestination() *Destination {
	nlri, _ := bgp.NewIPAddrPrefix(operaTestPrefix)
	return NewDestination(nlri, 64)
}

func asLists(paths []*Path) [][]uint32 {
	l := make([][]uint32, 0, len(paths))
	for _, p := range paths {
		l = append(l, p.GetAsList())
	}
	return l
}

func knownAsLists(d *Destination) [][]uint32 {
	return asLists(d.knownPathList)
}

func suppressedAsLists(d *Destination) [][]uint32 {
	return asLists(d.operaSuppressed())
}

func TestOperaPathOrder(t *testing.T) {
	tests := []struct {
		name   string
		a, b   []uint32
		better bool
		worse  bool
	}{
		{"shorter is better", []uint32{1, 9}, []uint32{2, 5, 9}, true, false},
		{"longer is worse", []uint32{2, 5, 9}, []uint32{1, 9}, false, true},
		{"equal length, lower ASN is better", []uint32{1, 9}, []uint32{2, 9}, true, false},
		{"equal length, higher ASN is worse", []uint32{2, 9}, []uint32{1, 9}, false, true},
		{"tie broken at last ASN", []uint32{1, 5, 8}, []uint32{1, 5, 9}, true, false},
		{"identical paths are neither", []uint32{1, 9}, []uint32{1, 9}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := operaPath("1.1.1.1", tt.a, false)
			b := operaPath("2.2.2.2", tt.b, false)
			assert.Equal(t, tt.better, isBetterOperaPath(a, b))
			assert.Equal(t, tt.worse, isWorseOperaPath(a, b))
		})
	}
	assert.False(t, isBetterOperaPath(nil, operaPath("1.1.1.1", []uint32{1}, false)))
	assert.False(t, isWorseOperaPath(operaPath("1.1.1.1", []uint32{1}, false), nil))
}

func TestOperaImportAccept(t *testing.T) {
	withOpera(t)

	short := operaPath("1.1.1.1", []uint32{1, 9}, false)
	long := operaPath("2.2.2.2", []uint32{2, 5, 9}, false)

	// The first candidate always initializes the threshold.
	assert.True(t, operaImportAccept(nil, long))
	// Strictly better than the worst known path is admitted.
	assert.True(t, operaImportAccept([]*Path{long}, short))
	// Worse than the worst known path is suppressed.
	assert.False(t, operaImportAccept([]*Path{short}, long))
	// Equal to the worst known path is suppressed (strict order).
	assert.False(t, operaImportAccept([]*Path{short}, operaPath("3.3.3.3", []uint32{1, 9}, false)))
	// Withdrawals are never filtered.
	assert.True(t, operaImportAccept([]*Path{short}, operaPath("2.2.2.2", []uint32{2, 5, 9}, true)))

	// Paths with an invalid next hop do not define the threshold.
	invalid := operaPath("4.4.4.4", []uint32{4, 4, 4, 4, 9}, false)
	invalid.IsNexthopInvalid = true
	assert.False(t, operaImportAccept([]*Path{short, invalid}, long))
	assert.True(t, operaImportAccept([]*Path{invalid}, long))
}

func TestOperaImportAcceptDisabled(t *testing.T) {
	short := operaPath("1.1.1.1", []uint32{1, 9}, false)
	long := operaPath("2.2.2.2", []uint32{2, 5, 9}, false)
	assert.True(t, operaImportAccept([]*Path{short}, long))
}

func TestOperaCalculateSuppressesWorsePath(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))

	assert.Equal(t, [][]uint32{{1, 9}}, knownAsLists(d))
	assert.Equal(t, [][]uint32{{2, 5, 9}}, suppressedAsLists(d))
}

func TestOperaExportsWorstPath(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 9}, false))
	u := d.Calculate(logger, operaPath("9.9.9.9", []uint32{9}, false))

	// The local choice is the standard BGP best path ...
	assert.Equal(t, [][]uint32{{9}, {2, 9}}, knownAsLists(d))
	assert.Equal(t, []uint32{9}, d.GetBestPath(GLOBAL_RIB_NAME, 0).GetAsList())
	best, _, _ := u.GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.Equal(t, []uint32{9}, best.GetAsList())

	// ... while peers are sent the worst path, which does not change when a
	// better path is admitted.
	export, old := u.GetExportChanges(GLOBAL_RIB_NAME, 0)
	assert.Nil(t, export)
	assert.Equal(t, []uint32{2, 9}, old.GetAsList())
}

func TestOperaExportChangesWithdraw(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	u := d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

	export, old := u.GetExportChanges(GLOBAL_RIB_NAME, 0)
	assert.True(t, export.IsWithdraw)
	assert.Equal(t, []uint32{1, 9}, old.GetAsList())
}

func TestOperaLocalMultipath(t *testing.T) {
	withOpera(t)
	UseMultiplePaths.Enabled = true
	t.Cleanup(func() { UseMultiplePaths.Enabled = false })
	d := newOperaDestination()

	// Two admitted paths that are equal for BGP but ordered for OBGP.
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 9}, false))
	u := d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))

	// Both are used locally, but only one is exported.
	_, _, multi := u.GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.ElementsMatch(t, [][]uint32{{1, 9}, {2, 9}}, asLists(multi))
	export, _ := u.GetExportChanges(GLOBAL_RIB_NAME, 0)
	assert.Nil(t, export)
	assert.Equal(t, []uint32{2, 9}, getOperaWorstPath(GLOBAL_RIB_NAME, 0, d.knownPathList).GetAsList())
}

func TestOperaExportPathList(t *testing.T) {
	withOpera(t)
	m := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})

	m.Update(operaPath("2.2.2.2", []uint32{2, 9}, false))
	m.Update(operaPath("9.9.9.9", []uint32{9}, false))

	assert.Equal(t, [][]uint32{{9}}, asLists(m.GetBestPathList(GLOBAL_RIB_NAME, 0, nil)))
	assert.Equal(t, [][]uint32{{2, 9}}, asLists(m.GetExportPathList(GLOBAL_RIB_NAME, 0, nil)))
}

func TestOperaExportDisabledUsesBgpBest(t *testing.T) {
	d := newOperaDestination()

	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 9}, false))
	d.Calculate(logger, operaPath("9.9.9.9", []uint32{9}, false))

	assert.Equal(t, []uint32{9}, d.GetBestPath(GLOBAL_RIB_NAME, 0).GetAsList())
}

func TestOperaPruneSupersetsOnExplicitWithdraw(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	// Insert the longer paths first so that the import filter admits them.
	d.Calculate(logger, operaPath("4.4.4.4", []uint32{4, 5, 9}, false))
	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	assert.Len(t, d.knownPathList, 3)

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

	// (3 1 9) contains the withdrawn (1 9) and is pruned; (4 5 9) is kept.
	assert.Equal(t, [][]uint32{{4, 5, 9}}, knownAsLists(d))
}

func TestOperaPruneSupersetsOnImplicitWithdraw(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))

	// Peer 1 replaces (1 9) with (1 7 9): paths through (1 9) are stale.
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 7, 9}, false))

	assert.Equal(t, [][]uint32{{1, 7, 9}}, knownAsLists(d))
}

func TestOperaNoPruneOnUnchangedAsPath(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))

	// Peer 1 re-advertises (1 9) with a different MED only.
	d.Calculate(logger, operaPathMed("1.1.1.1", []uint32{1, 9}, false, 50))

	assert.ElementsMatch(t, [][]uint32{{1, 9}, {3, 1, 9}}, knownAsLists(d))
}

func TestOperaUnchangedWorstPathKeepsPlace(t *testing.T) {
	for _, pruning := range []Pruning{PruneRefresh, PruneSoft, PruneHard, PruneOff} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: pruning})
		d := newOperaDestination()

		d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))

		// Peer 2 sends its path again, as a route refresh answer, then with a new MED.
		d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))
		d.Calculate(logger, operaPathMed("2.2.2.2", []uint32{2, 5, 9}, false, 50))

		assert.ElementsMatch(t, [][]uint32{{1, 9}, {2, 5, 9}}, knownAsLists(d), pruning)
		assert.Empty(t, suppressedAsLists(d), pruning)
		assert.Equal(t, []uint32{2, 5, 9}, getOperaWorstPath(GLOBAL_RIB_NAME, 0, d.knownPathList).GetAsList(), pruning)
	}
}

func TestOperaPruneDisabled(t *testing.T) {
	d := newOperaDestination()

	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

	assert.Equal(t, [][]uint32{{3, 1, 9}}, knownAsLists(d))
}

func TestContainsHopSubsequence(t *testing.T) {
	tests := []struct {
		name             string
		haystack, needle []uint32
		want             bool
	}{
		{"prefix", []uint32{1, 9, 5}, []uint32{1, 9}, true},
		{"suffix", []uint32{3, 1, 9}, []uint32{1, 9}, true},
		{"middle", []uint32{8, 1, 9, 5}, []uint32{1, 9}, true},
		{"identical", []uint32{1, 9}, []uint32{1, 9}, true},
		{"not contiguous", []uint32{1, 5, 9}, []uint32{1, 9}, false},
		{"needle longer", []uint32{9}, []uint32{1, 9}, false},
		{"empty needle", []uint32{1, 9}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hops := func(asns []uint32) [][]uint32 {
				var out [][]uint32
				for _, as := range asns {
					out = append(out, []uint32{as})
				}
				return out
			}
			assert.Equal(t, tt.want, containsHopSubsequence(hops(tt.haystack), hops(tt.needle)))
		})
	}
}

func TestOperaReadmitSuppressedOnWithdraw(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))

	// Peer 2 still advertises (2 5 9), so the destination must stay reachable.
	u := d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

	assert.Equal(t, [][]uint32{{2, 5, 9}}, knownAsLists(d))
	assert.Empty(t, suppressedAsLists(d))
	assert.Nil(t, d.opera)
	export, _ := u.GetExportChanges(GLOBAL_RIB_NAME, 0)
	assert.Equal(t, []uint32{2, 5, 9}, export.GetAsList())
}

func TestOperaReadmitPicksBestSuppressed(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("4.4.4.4", []uint32{4, 4, 4, 9}, false))
	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 5, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))
	assert.Len(t, d.operaSuppressed(), 3)

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

	// Only the best suppressed path is re-admitted; it becomes the new
	// threshold and the others stay suppressed.
	assert.Equal(t, [][]uint32{{2, 5, 9}}, knownAsLists(d))
	assert.ElementsMatch(t, [][]uint32{{4, 4, 4, 9}, {3, 5, 9}}, suppressedAsLists(d))
}

func TestOperaReadmitIsOrderIndependent(t *testing.T) {
	withOpera(t)

	// Two peers advertise the same AS path; the re-admitted path must not
	// depend on the arrival order.
	for _, order := range [][]string{{"2.2.2.2", "3.3.3.3"}, {"3.3.3.3", "2.2.2.2"}} {
		d := newOperaDestination()
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
		for _, addr := range order {
			d.Calculate(logger, operaPath(addr, []uint32{5, 9}, false))
		}
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

		assert.Len(t, d.knownPathList, 1)
		assert.Equal(t, "2.2.2.2", d.knownPathList[0].GetSource().Address.String(), "order %v", order)
	}
}

func TestOperaWithdrawSuppressed(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, true))

	assert.Equal(t, [][]uint32{{1, 9}}, knownAsLists(d))
	assert.Nil(t, d.opera)
}

func TestOperaImplicitWithdrawSuppressed(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))

	// A worse re-advertisement replaces the suppressed path instead of
	// adding a second one for the same peer.
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 6, 9}, false))
	assert.Equal(t, [][]uint32{{2, 6, 9}}, suppressedAsLists(d))

	// A better re-advertisement moves the peer from suppressed to admitted.
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2}, false))
	assert.Equal(t, [][]uint32{{2}, {1, 9}}, knownAsLists(d))
	assert.Nil(t, d.opera)
}

func TestOperaPruneSuppressed(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("4.4.4.4", []uint32{4, 5, 9}, false))

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

	// (3 1 9) depends on the withdrawn (1 9) and must not be re-admitted.
	// It stays pruned until 3.3.3.3 sends again, for tables built later.
	assert.Equal(t, [][]uint32{{4, 5, 9}}, knownAsLists(d))
	assert.Empty(t, suppressedAsLists(d))
	require.Len(t, d.operaPruned(), 1)
	assert.Equal(t, []uint32{3, 1, 9}, d.operaPruned()[0].GetAsList())
	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 7, 9}, false))
	assert.Empty(t, d.operaPruned())
}

func TestOperaTableKeepsReadmittedDestination(t *testing.T) {
	withOpera(t)
	tbl := NewTable(logger, bgp.RF_IPv4_UC)

	tbl.update(operaPath("1.1.1.1", []uint32{1, 9}, false))
	tbl.update(operaPath("2.2.2.2", []uint32{2, 5, 9}, false))
	tbl.update(operaPath("1.1.1.1", []uint32{1, 9}, true))

	nlri, _ := bgp.NewIPAddrPrefix(operaTestPrefix)
	d := tbl.GetDestination(nlri)
	if assert.NotNil(t, d) {
		assert.Equal(t, [][]uint32{{2, 5, 9}}, knownAsLists(d))
	}
}

func TestOperaInfoCountsKnownAndBlockedPrefixes(t *testing.T) {
	for _, pruning := range []Pruning{PruneRefresh, PruneSoft, PruneHard} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: pruning})
		tbl := NewTable(logger, bgp.RF_IPv4_UC)

		tbl.update(operaPath("1.1.1.1", []uint32{1, 9}, false))
		tbl.update(operaPath("2.2.2.2", []uint32{2, 5, 9}, false))
		info := tbl.Info()
		assert.Equal(t, 1, info.NumDestination, pruning)
		assert.Equal(t, 1, info.NumKnown, pruning)
		assert.Equal(t, 0, info.NumBlocked, pruning)

		// The admitted path goes. Under refresh pruning the one set aside waits for a
		// route refresh: known, blocked, no route. The other modes admit it again.
		tbl.update(operaPath("1.1.1.1", []uint32{1, 9}, true))
		info = tbl.Info()
		assert.Equal(t, 1, info.NumKnown, pruning)
		if pruning == PruneRefresh {
			assert.Equal(t, 0, info.NumDestination, pruning)
			assert.Equal(t, 1, info.NumBlocked, pruning)
		} else {
			assert.Equal(t, 1, info.NumDestination, pruning)
			assert.Equal(t, 0, info.NumBlocked, pruning)
		}
	}
}

func TestOperaPathOrderMultipleSegments(t *testing.T) {
	nlri, _ := bgp.NewIPAddrPrefix(operaTestPrefix)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("1.1.1.1"))
	peer := &PeerInfo{AS: 1, Address: netip.MustParseAddr("1.1.1.1")}
	withSegments := func(segs ...[]uint32) *Path {
		params := make([]bgp.AsPathParamInterface, 0, len(segs))
		for _, s := range segs {
			params = append(params, bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, s))
		}
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath(params),
			nexthop,
		}
		return NewPath(bgp.RF_IPv4_UC, peer, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
	}

	// The order compares the ASN sequence, independent of how it is split
	// into AS_SEQUENCE segments.
	assert.True(t, isBetterOperaPath(withSegments([]uint32{1, 2}), withSegments([]uint32{1}, []uint32{5})))
	assert.False(t, isBetterOperaPath(withSegments([]uint32{1, 2}, []uint32{3}), withSegments([]uint32{1, 2, 3})))
	assert.False(t, isWorseOperaPath(withSegments([]uint32{1, 2}, []uint32{3}), withSegments([]uint32{1, 2, 3})))
}

func TestOperaPruneReleasesLocalID(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	pruned := d.knownPathList[1]
	assert.Equal(t, []uint32{3, 1, 9}, pruned.GetAsList())
	id := pruned.localID
	assert.NotZero(t, id)

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 7, 9}, false))

	assert.False(t, d.localIdMap.GetFlag(uint(id)))
}

func TestOperaNoPruneOnSessionDrop(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 9}, false))
	d.Calculate(logger, operaPath("9.9.9.9", []uint32{9}, false))

	// The session to the origin's direct neighbor goes down; (2 9) learned
	// from peer 2 is still valid.
	w := operaPath("9.9.9.9", []uint32{9}, true)
	w.SetSessionDropped()
	d.Calculate(logger, w)

	assert.Equal(t, [][]uint32{{2, 9}}, knownAsLists(d))
}

// An iBGP peer withdraws its path when its export path
// becomes one it learned over iBGP, which split horizon keeps it from
// sending back. The paths through the withdrawn one stay.
func TestOperaNoPruneOnIBGPWithdraw(t *testing.T) {
	ibgp := func(withdraw bool) *Path {
		p := operaPath("5.5.5.5", []uint32{1, 9}, withdraw)
		p.GetSource().AS, p.GetSource().LocalAS = 5, 5
		return p
	}
	for _, filter := range []bool{true, false} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: PruneHard, FilterIBGP: filter})
		d := newOperaDestination()
		d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
		d.Calculate(logger, ibgp(false))

		d.Calculate(logger, ibgp(true))

		if !filter {
			assert.Equal(t, [][]uint32{{3, 1, 9}}, knownAsLists(d))
		} else {
			assert.Empty(t, knownAsLists(d))
		}
	}
}

func TestAdjRibDropState(t *testing.T) {
	families := []bgp.Family{bgp.RF_IPv4_UC}

	// A withdrawal received from the peer.
	adj := NewAdjRib(logger, families)
	adj.Update([]*Path{operaPath("1.1.1.1", []uint32{1, 9}, false)})
	w := operaPath("1.1.1.1", []uint32{1, 9}, true)
	adj.Update([]*Path{w})
	assert.True(t, w.IsDropped())
	assert.False(t, w.IsSessionDropped())

	// The session to the peer goes down.
	adj = NewAdjRib(logger, families)
	adj.Update([]*Path{operaPath("1.1.1.1", []uint32{1, 9}, false)})
	dropped := adj.Drop(families)
	if assert.Len(t, dropped, 1) {
		assert.True(t, dropped[0].IsDropped())
		assert.True(t, dropped[0].IsSessionDropped())
	}

	// Stale paths not re-advertised after a graceful restart.
	adj = NewAdjRib(logger, families)
	adj.Update([]*Path{operaPath("1.1.1.1", []uint32{1, 9}, false)})
	adj.StaleAll(families)
	stale := adj.DropStale(families)
	if assert.Len(t, stale, 1) {
		assert.True(t, stale[0].IsDropped())
		assert.False(t, stale[0].IsSessionDropped())
	}
}

func TestOperaReplaceSuppressedKeepsLocalID(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()

	// Peer 2's path is admitted first and gets a local ID ...
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 5, 9}, false))
	id := d.knownPathList[0].localID
	assert.NotZero(t, id)
	// ... and is suppressed after a worse re-advertisement once a better
	// path from peer 1 has lowered the threshold.
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 6, 6, 9}, false))
	assert.Equal(t, [][]uint32{{2, 6, 6, 9}}, suppressedAsLists(d))

	// Replacing the suppressed path must not leak its local ID.
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 7, 7, 9}, false))
	assert.Equal(t, id, d.operaSuppressed()[0].localID)
	// Withdrawals from a peer pass the adj-RIB-in, which marks them dropped.
	w := operaPath("2.2.2.2", []uint32{2, 7, 7, 9}, true)
	w.SetDropped(true)
	d.Calculate(logger, w)
	assert.False(t, d.localIdMap.GetFlag(uint(id)))
}

func TestOperaOnlyUnicast(t *testing.T) {
	withOpera(t)

	rt, _ := bgp.ParseRouteTarget("65000:1")
	nlri := bgp.NewRouteTargetMembershipNLRI(65000, rt)
	rtcPath := func(addr string, asList []uint32) *Path {
		p := operaPath(addr, asList, false)
		return NewPath(bgp.RF_RTC_UC, p.GetSource(), bgp.PathNLRI{NLRI: nlri}, false, p.GetPathAttrs(), time.Now(), false)
	}
	d := NewDestination(nlri, 64)

	// RTC must consider all paths (RFC 4684), so nothing is suppressed.
	d.Calculate(logger, rtcPath("1.1.1.1", []uint32{1, 9}))
	d.Calculate(logger, rtcPath("2.2.2.2", []uint32{2, 5, 9}))

	assert.Len(t, d.knownPathList, 2)
	assert.Nil(t, d.opera)
}

func TestOperaOptionsFromEnv(t *testing.T) {
	withOperaOptions(t, GetOperaOptions())
	tests := []struct {
		enabled, pruning string
		want             OperaOptions
	}{
		{"", "", OperaOptions{Enabled: false}},
		{"true", "", OperaOptions{Enabled: true}},
		{"1", "false", OperaOptions{Enabled: true, Pruning: PruneOff}},
		{"TRUE", "0", OperaOptions{Enabled: true, Pruning: PruneOff}},
		{"true", "true", OperaOptions{Enabled: true, Pruning: PruneHard}}, // as before soft pruning
		{"true", "soft", OperaOptions{Enabled: true, Pruning: PruneSoft}},
		{"true", "SOFT", OperaOptions{Enabled: true, Pruning: PruneSoft}},
		{"true", "hard", OperaOptions{Enabled: true, Pruning: PruneHard}},
		{"true", "off", OperaOptions{Enabled: true, Pruning: PruneOff}},
	}
	t.Setenv("GOBGP_OPERA_AS_SET", "")
	for _, tt := range tests {
		t.Setenv("GOBGP_OPERA_ENABLED", tt.enabled)
		t.Setenv("GOBGP_OPERA_PRUNING", tt.pruning)
		assert.Equal(t, tt.want, InitOperaFromEnv())
		assert.Equal(t, tt.want, GetOperaOptions())
	}
	t.Setenv("GOBGP_OPERA_REFRESH_S", "2")
	t.Setenv("GOBGP_OPERA_REFRESH_DELAY_S", "0.5")
	o := InitOperaFromEnv()
	assert.Equal(t, 2*time.Second, o.RefreshInterval)
	assert.Equal(t, 500*time.Millisecond, o.RefreshDelay)
}

func TestOperaNoPruningKeepsSupersets(t *testing.T) {
	withOperaOptions(t, OperaOptions{Enabled: true, Pruning: PruneOff})
	d := newOperaDestination()

	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	// (1 9) changes to (1 5 9): (3 1 9) still contains (1 9) and stays.
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 5, 9}, false))
	assert.ElementsMatch(t, [][]uint32{{3, 1, 9}, {1, 5, 9}}, knownAsLists(d))

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 5, 9}, true))
	assert.Equal(t, [][]uint32{{3, 1, 9}}, knownAsLists(d))
	assert.Empty(t, suppressedAsLists(d))
}

func permutations(n int) [][]int {
	if n == 1 {
		return [][]int{{0}}
	}
	var l [][]int
	for _, p := range permutations(n - 1) {
		for i := 0; i <= len(p); i++ {
			q := append(append(append([]int{}, p[:i]...), n-1), p[i:]...)
			l = append(l, q)
		}
	}
	return l
}

// The admitted paths depend on the order in which paths arrive. Standard
// BGP depends on it too, e.g. through MED and the oldest-path tie-break,
// but less.
func TestOperaAdmissionDependsOnOrder(t *testing.T) {
	withOpera(t)
	paths := [][]uint32{{9}, {2, 9}, {3, 5, 9}}
	addrs := []string{"9.9.9.9", "2.2.2.2", "3.3.3.3"}

	outcomes := map[string]bool{}
	for _, order := range permutations(len(paths)) {
		d := newOperaDestination()
		for _, i := range order {
			d.Calculate(logger, operaPath(addrs[i], paths[i], false))
		}
		known := knownAsLists(d)
		// The best path in the OBGP order is always admitted, and every path
		// is either admitted or suppressed.
		assert.Contains(t, known, []uint32{9})
		assert.Len(t, append(known, suppressedAsLists(d)...), len(paths))
		outcomes[fmt.Sprint(known)] = true
	}
	// (9) first admits only (9). The worst path first admits all three.
	assert.Equal(t, map[string]bool{"[[9]]": true, "[[9] [2 9]]": true, "[[9] [2 9] [3 5 9]]": true}, outcomes)
}

// Local Preference only chooses among the admitted paths: a preferred path
// that arrives after a better one in the OBGP order is suppressed.
func TestOperaLocalPreferenceSeesAdmittedPathsOnly(t *testing.T) {
	withOpera(t)
	d := newOperaDestination()
	preferred := operaPath("2.2.2.2", []uint32{2, 5, 9}, false)
	preferred.setPathAttr(bgp.NewPathAttributeLocalPref(200))

	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, preferred)
	assert.Equal(t, []uint32{1, 9}, d.GetBestPath(GLOBAL_RIB_NAME, 0).GetAsList())
	assert.Equal(t, [][]uint32{{2, 5, 9}}, suppressedAsLists(d))

	// In the other order, both are admitted and the preference applies.
	d = newOperaDestination()
	d.Calculate(logger, preferred)
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	assert.Equal(t, []uint32{2, 5, 9}, d.GetBestPath(GLOBAL_RIB_NAME, 0).GetAsList())
}

func TestOperaReceivedSetOrderFromEnv(t *testing.T) {
	withOperaOptions(t, GetOperaOptions())
	t.Setenv("GOBGP_OPERA_ENABLED", "true")
	t.Setenv("GOBGP_OPERA_PRUNING", "")
	t.Setenv("GOBGP_OPERA_AS_SET", "received")
	assert.Equal(t, OperaOptions{Enabled: true, ReceivedSetOrder: true}, InitOperaFromEnv())
	t.Setenv("GOBGP_OPERA_AS_SET", "canonical") // the default, as before named
	assert.Equal(t, OperaOptions{Enabled: true}, InitOperaFromEnv())
	t.Setenv("GOBGP_OPERA_IBGP", "filter")
	assert.Equal(t, OperaOptions{Enabled: true, FilterIBGP: true}, InitOperaFromEnv())
}

// A filter of AS 1 towards this router only: AS 1 withdraws here, but the
// path via AS 3 is still valid. Pruning removes it, soft pruning keeps it as
// a candidate and re-admits it, since nothing else is left.
func TestOperaSoftPruningKeepsPrunedPathsAsFallback(t *testing.T) {
	for _, soft := range []bool{false, true} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: map[bool]Pruning{false: PruneHard, true: PruneSoft}[soft]})
		d := newOperaDestination()
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
		d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
		assert.Equal(t, [][]uint32{{3, 1, 9}}, suppressedAsLists(d))
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))
		if soft {
			assert.Equal(t, [][]uint32{{3, 1, 9}}, knownAsLists(d))
		} else {
			assert.Empty(t, knownAsLists(d))
		}
	}
}

// With another valid path left, a soft-pruned path waits as a candidate.
func TestOperaSoftPruningSuppressesWhileAnotherPathIsValid(t *testing.T) {
	withOperaOptions(t, OperaOptions{Enabled: true, Pruning: PruneSoft})
	d := newOperaDestination()
	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	assert.ElementsMatch(t, [][]uint32{{3, 1, 9}, {2, 9}, {1, 9}}, knownAsLists(d))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))
	assert.ElementsMatch(t, [][]uint32{{2, 9}}, knownAsLists(d))
	assert.Equal(t, [][]uint32{{3, 1, 9}}, suppressedAsLists(d))
	// The path of AS 3 leaves with its withdrawal, as any candidate.
	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, true))
	assert.Empty(t, suppressedAsLists(d))
}

// A rejection by the own import policy is a withdrawal, but not one of the
// peer: soft pruning prunes nothing for it, pruning does.
func TestOperaSoftPruningIgnoresOwnPolicyRejections(t *testing.T) {
	for _, soft := range []bool{false, true} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: map[bool]Pruning{false: PruneHard, true: PruneSoft}[soft]})
		d := newOperaDestination()
		d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 9}, false))
		d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 2, 9}, false))
		d.Calculate(logger, operaPath("4.4.4.4", []uint32{4, 5, 2, 9}, false))
		rejected := operaPath("2.2.2.2", []uint32{2, 9}, false).Clone(true)
		rejected.SetPolicyRejected()
		d.Calculate(logger, rejected)
		if soft {
			assert.Equal(t, [][]uint32{{3, 2, 9}}, knownAsLists(d))
			assert.Equal(t, [][]uint32{{4, 5, 2, 9}}, suppressedAsLists(d))
		} else {
			assert.Empty(t, knownAsLists(d))
			assert.Empty(t, suppressedAsLists(d))
		}
	}
}

func operaPathSegments(addr string, segments ...bgp.AsPathParamInterface) *Path {
	p := operaPath(addr, nil, false)
	p.setPathAttr(bgp.NewPathAttributeAsPath(segments))
	return p
}

// A set is one hop of its members in ascending order, whatever order they
// came in. Confederation members count after the length and are hops,
// unless IgnoreConfedHops.
func TestOperaSetsAreOrderedByTheirMembers(t *testing.T) {
	set := func(as ...uint32) bgp.AsPathParamInterface {
		return bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, as)
	}
	seq := func(as ...uint32) bgp.AsPathParamInterface {
		return bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, as)
	}
	confed := func(as ...uint32) bgp.AsPathParamInterface {
		return bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, as)
	}
	a := operaPathSegments("1.1.1.1", seq(1), set(7, 3))
	b := operaPathSegments("2.2.2.2", seq(1), set(3, 7))
	c := operaPathSegments("3.3.3.3", confed(64512), seq(1), set(3, 7))

	withOperaOptions(t, OperaOptions{Enabled: true, ReceivedSetOrder: true})
	assert.Equal(t, 1, compareOperaPath(a, b)) // as received: (1 7 3) after (1 3 7)

	withOperaOptions(t, OperaOptions{Enabled: true})
	assert.Equal(t, [][]uint32{{1}, {3, 7}}, operaHops(a))
	assert.Equal(t, 0, compareOperaPath(a, b))
	assert.Equal(t, -1, compareOperaPath(a, c)) // one hop between members more
	assert.Equal(t, [][]uint32{{64512}, {1}, {3, 7}}, operaHops(c))
	assert.True(t, containsHopSubsequence(operaHops(operaPathSegments("4.4.4.4", seq(4, 1), set(7, 3))), operaHops(b)))
	assert.False(t, containsHopSubsequence(operaHops(operaPathSegments("4.4.4.4", seq(4, 1, 3, 7))), operaHops(b)))

	withOperaOptions(t, OperaOptions{Enabled: true, IgnoreConfedHops: true})
	assert.Equal(t, 0, compareOperaPath(a, c))
	assert.Equal(t, [][]uint32{{1}, {3, 7}}, operaHops(c))
}

// A member's withdrawal prunes only paths through that member: the direct
// path of the same AS stays.
func TestOperaConfedWithdrawalPrunesOnlyThroughTheMember(t *testing.T) {
	member := func(addr string) *Path {
		return operaPathSegments(addr, bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint32{64512}),
			bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{1}))
	}
	for _, ignore := range []bool{false, true} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: PruneHard, IgnoreConfedHops: ignore})
		d := newOperaDestination()
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1}, false))
		d.Calculate(logger, member("2.2.2.2"))
		d.Calculate(logger, member("2.2.2.2").Clone(true))
		if ignore {
			assert.Empty(t, knownAsLists(d)) // the member's [1] looks like the direct one
		} else {
			assert.Equal(t, [][]uint32{{1}}, knownAsLists(d))
		}
	}
}

// Inside an AS the AS path does not grow: unless FilterIBGP, an iBGP path is
// admitted although it is no better than the worst admitted path.
func TestOperaAdmitsIBGPPathsUnfiltered(t *testing.T) {
	ibgp := func() *Path {
		p := operaPath("5.5.5.5", []uint32{2, 9}, false)
		p.GetSource().LocalAS = 2
		return p
	}
	for _, filter := range []bool{true, false} {
		withOperaOptions(t, OperaOptions{Enabled: true, FilterIBGP: filter})
		d := newOperaDestination()
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
		d.Calculate(logger, ibgp())
		if !filter {
			assert.ElementsMatch(t, [][]uint32{{1, 9}, {2, 9}}, knownAsLists(d))
		} else {
			assert.Equal(t, [][]uint32{{1, 9}}, knownAsLists(d))
		}
	}
}

// RFC 4456, section 9: with equal ORIGINATOR_ID, the route through fewer
// reflectors wins, before the neighbor address decides.
func TestShorterClusterListWins(t *testing.T) {
	withOperaOptions(t, OperaOptions{})
	reflected := func(addr string, clusters ...string) *Path {
		p := operaPath(addr, []uint32{2, 9}, false)
		p.GetSource().LocalAS = 2
		o, _ := bgp.NewPathAttributeOriginatorId(netip.MustParseAddr("10.9.9.9"))
		p.setPathAttr(o)
		if len(clusters) > 0 {
			var l []netip.Addr
			for _, c := range clusters {
				l = append(l, netip.MustParseAddr(c))
			}
			c, _ := bgp.NewPathAttributeClusterList(l)
			p.setPathAttr(c)
		}
		return p
	}
	d := newOperaDestination()
	d.Calculate(logger, reflected("1.1.1.1", "3.3.3.3"))
	d.Calculate(logger, reflected("4.4.4.4"))
	assert.Equal(t, "4.4.4.4", d.GetBestPath(GLOBAL_RIB_NAME, 0).GetSource().Address.String())
}

// Multipath takes the equally good paths among the admitted only: a path
// the import filter rejected never carries traffic.
func TestOperaMultipathUsesAdmittedPathsOnly(t *testing.T) {
	for _, pruning := range []Pruning{PruneHard, PruneSoft, PruneOff} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: pruning})
		d := newOperaDestination()
		d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 9}, false))
		d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
		d.Calculate(logger, operaPath("2.2.2.2", []uint32{2, 9}, false))
		d.Calculate(logger, operaPath("4.4.4.4", []uint32{4, 5, 9}, false)) // longer than the worst admitted: rejected
		assert.Equal(t, [][]uint32{{4, 5, 9}}, suppressedAsLists(d), pruning)
		paths := d.GetMultiBestPath(GLOBAL_RIB_NAME)
		assert.NotEmpty(t, paths, pruning)
		for _, p := range paths {
			assert.Contains(t, knownAsLists(d), p.GetAsList(), pruning)
			assert.NotContains(t, suppressedAsLists(d), p.GetAsList(), pruning)
		}
		assert.Len(t, paths, len(knownAsLists(d)), "equal AS path length and attributes: all admitted are equal")
	}
}

func operaPath6(addr string, asList []uint32) *Path {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/32"))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asList)}),
	}
	peer := &PeerInfo{AS: asList[0], Address: netip.MustParseAddr(addr), ID: netip.MustParseAddr(addr)}
	return NewPath(bgp.RF_IPv6_UC, peer, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
}

// OBGP applies to IPv6 unicast as to IPv4: a longer path than the worst
// admitted one waits as a candidate, and peers get the worst admitted.
func TestOperaIPv6(t *testing.T) {
	withOpera(t)
	assert.True(t, isOperaFamily(bgp.RF_IPv6_UC))
	assert.False(t, isOperaFamily(bgp.RF_IPv4_VPN))
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("2001:db8::/32"))
	d := NewDestination(nlri, 64)
	d.Calculate(logger, operaPath6("2001:db8::2", []uint32{2, 5, 9}))
	d.Calculate(logger, operaPath6("2001:db8::1", []uint32{1, 9}))
	d.Calculate(logger, operaPath6("2001:db8::3", []uint32{3, 4, 6, 9}))
	assert.ElementsMatch(t, [][]uint32{{2, 5, 9}, {1, 9}}, knownAsLists(d))
	assert.Equal(t, []uint32{2, 5, 9}, getOperaWorstPath(GLOBAL_RIB_NAME, 0, d.knownPathList).GetAsList())
}

// A 2-byte speaker sends AS_TRANS in AS_PATH and the real ASNs in AS4_PATH
// (RFC 6793). gobgpd merges them on receipt, and OBGP orders by the real
// ones: 400000 after 300000, where AS_TRANS, 23456, would come first.
func TestOperaOrdersFourByteASNsOfATwoByteSpeaker(t *testing.T) {
	nlri, _ := bgp.NewIPAddrPrefix(operaTestPrefix)
	nexthop, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.100"))
	msg := bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{100, bgp.AS_TRANS, 9})}),
		nexthop,
		bgp.NewPathAttributeAs4Path([]*bgp.As4PathParam{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{400000, 9})}),
	}, []bgp.PathNLRI{{NLRI: nlri}})
	UpdatePathAttrs4ByteAs(logger, msg.Body.(*bgp.BGPUpdate))
	peer := &PeerInfo{AS: 100, LocalAS: 65000, Address: netip.MustParseAddr("10.0.0.100"), ID: netip.MustParseAddr("10.0.0.100")}
	paths := ProcessMessage(msg, peer, time.Now(), false)
	assert.Len(t, paths, 1)
	merged := paths[0]
	assert.Equal(t, []uint32{100, 400000, 9}, merged.GetAsList())
	assert.Equal(t, 1, compareOperaPath(merged, operaPath("10.0.0.101", []uint32{100, 300000, 9}, false)))
}

// A transparent route server admits and prunes nothing and exports as plain
// GoBGP. With RouteServerAdmits it selects as an OBGP router.
func TestOperaRouteServerIsTransparent(t *testing.T) {
	for _, admits := range []bool{false, true} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: PruneHard, RouteServerAdmits: admits})
		tm := NewTableManager(logger, []bgp.Family{bgp.RF_IPv4_UC})
		tm.SetRouteServer()
		var u *Update
		for _, p := range []*Path{operaPath("1.1.1.1", []uint32{1, 9}, false), operaPath("2.2.2.2", []uint32{2, 3, 9}, false)} {
			u = tm.Update(p)[0]
		}
		u.OldKnownPathList = nil // the export as a new peer would get it
		export, _ := u.GetExportChanges(GLOBAL_RIB_NAME, 0)
		if admits {
			assert.Equal(t, [][]uint32{{1, 9}}, asLists(u.KnownPathList)) // the longer one is not strictly better
			assert.Equal(t, []uint32{1, 9}, export.GetAsList())
		} else {
			assert.ElementsMatch(t, [][]uint32{{1, 9}, {2, 3, 9}}, asLists(u.KnownPathList))
			assert.Equal(t, []uint32{1, 9}, export.GetAsList()) // the best, as plain GoBGP
			tm.Update(operaPath("3.3.3.3", []uint32{3, 9}, false))
			u = tm.Update(operaPath("1.1.1.1", []uint32{1, 9}, true))[0]
			assert.ElementsMatch(t, [][]uint32{{2, 3, 9}, {3, 9}}, asLists(u.KnownPathList)) // nothing pruned
			assert.Len(t, tm.GetExportPathList(GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_IPv4_UC}), 1)
		}
	}
}
