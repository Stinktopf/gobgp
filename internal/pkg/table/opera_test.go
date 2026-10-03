package table

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

var operaTestPrefix = netip.MustParsePrefix("10.0.0.0/24")

func withOpera(t *testing.T) {
	t.Helper()
	withOperaOptions(t, OperaOptions{Enabled: true, Pruning: true})
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

func TestOperaPruneDisabled(t *testing.T) {
	d := newOperaDestination()

	d.Calculate(logger, operaPath("3.3.3.3", []uint32{3, 1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, false))
	d.Calculate(logger, operaPath("1.1.1.1", []uint32{1, 9}, true))

	assert.Equal(t, [][]uint32{{3, 1, 9}}, knownAsLists(d))
}

func TestContainsASSubsequence(t *testing.T) {
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
			assert.Equal(t, tt.want, containsASSubsequence(tt.haystack, tt.needle))
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
	assert.Equal(t, [][]uint32{{4, 5, 9}}, knownAsLists(d))
	assert.Nil(t, d.opera)
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
		{"", "", OperaOptions{Enabled: false, Pruning: true}},
		{"true", "", OperaOptions{Enabled: true, Pruning: true}},
		{"1", "false", OperaOptions{Enabled: true, Pruning: false}},
		{"TRUE", "0", OperaOptions{Enabled: true, Pruning: false}},
		{"true", "true", OperaOptions{Enabled: true, Pruning: true}},
	}
	for _, tt := range tests {
		t.Setenv("GOBGP_OPERA_ENABLED", tt.enabled)
		t.Setenv("GOBGP_OPERA_PRUNING", tt.pruning)
		assert.Equal(t, tt.want, InitOperaFromEnv())
		assert.Equal(t, tt.want, GetOperaOptions())
	}
}

func TestOperaNoPruningKeepsSupersets(t *testing.T) {
	withOperaOptions(t, OperaOptions{Enabled: true, Pruning: false})
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
