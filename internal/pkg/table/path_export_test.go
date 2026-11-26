package table

import (
	"log/slog"
	"math/rand"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
)

// dropForExportByList is dropForExport as it was, over the list GetPathAttrs makes.
func dropForExportByList(path *Path, internal bool) {
	for _, a := range path.GetPathAttrs() {
		if _, known := bgp.PathAttrFlags[a.GetType()]; !known {
			if a.GetFlags()&bgp.BGP_ATTR_FLAG_TRANSITIVE == 0 {
				path.delPathAttr(a.GetType())
			}
		} else if !internal && (a.GetType() == bgp.BGP_ATTR_TYPE_CLUSTER_LIST || a.GetType() == bgp.BGP_ATTR_TYPE_ORIGINATOR_ID) {
			path.delPathAttr(a.GetType())
		}
	}
}

// exportAttr is one of the attributes that matter here, or one that does not.
func exportAttr(r *rand.Rand) bgp.PathAttributeInterface {
	switch r.Intn(7) {
	case 0:
		a, _ := bgp.NewPathAttributeClusterList([]netip.Addr{netip.MustParseAddr("10.0.0.1")})
		return a
	case 1:
		a, _ := bgp.NewPathAttributeOriginatorId(netip.MustParseAddr("10.0.0.2"))
		return a
	case 2:
		return bgp.NewPathAttributeUnknown(bgp.BGP_ATTR_FLAG_OPTIONAL, bgp.BGPAttrType(200+r.Intn(3)), []byte{1})
	case 3:
		return bgp.NewPathAttributeUnknown(bgp.BGP_ATTR_FLAG_OPTIONAL|bgp.BGP_ATTR_FLAG_TRANSITIVE, bgp.BGPAttrType(200+r.Intn(3)), []byte{2})
	case 4:
		return bgp.NewPathAttributeMultiExitDisc(uint32(r.Intn(100)))
	case 5:
		return bgp.NewPathAttributeLocalPref(uint32(r.Intn(200)))
	default:
		return bgp.NewPathAttributeCommunities([]uint32{uint32(r.Intn(1 << 20))})
	}
}

// Over paths with parents, attributes set, replaced and deleted on the way:
// the walk in place deletes what the list did, for eBGP and iBGP alike.
func TestDropForExportDeletesWhatTheListDid(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"))
	for i := range 3000 {
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
		for range r.Intn(5) {
			// each type once, as in an UPDATE: twice is an error, RFC 4271, 6.3
			if a := exportAttr(r); !slices.ContainsFunc(attrs, func(b bgp.PathAttributeInterface) bool { return b.GetType() == a.GetType() }) {
				attrs = append(attrs, a)
			}
		}
		slices.SortStableFunc(attrs, func(a, b bgp.PathAttributeInterface) int { return int(a.GetType()) - int(b.GetType()) })
		path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
		for range r.Intn(4) {
			path = path.Clone(false)
			for range r.Intn(3) {
				if r.Intn(3) == 0 {
					path.delPathAttr(exportAttr(r).GetType())
				} else {
					path.setPathAttr(exportAttr(r))
				}
			}
		}
		internal := i%2 == 0
		want, got := path.Clone(false), path.Clone(false)
		dropForExportByList(want, internal)
		got.dropForExport(internal)
		assert.Equal(t, want.GetPathAttrs(), got.GetPathAttrs(), "path %d, internal %v", i, internal)
	}
}

func TestHasASIsGetAsListContains(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"))
	types := []uint8{bgp.BGP_ASPATH_ATTR_TYPE_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET}
	for range 2000 {
		var params []bgp.AsPathParamInterface
		for range r.Intn(4) {
			var as []uint32
			for range 1 + r.Intn(4) {
				as = append(as, uint32(r.Intn(6)))
			}
			params = append(params, bgp.NewAs4PathParam(types[r.Intn(len(types))], as))
		}
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
		if r.Intn(5) > 0 {
			attrs = append(attrs, bgp.NewPathAttributeAsPath(params))
		}
		path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
		for as := range uint32(7) {
			assert.Equal(t, slices.Contains(path.GetAsList(), as), path.HasAS(as), "AS %d in %v", as, params)
		}
	}
}

func TestCommunitiesIsGetCommunitiesUncopied(t *testing.T) {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"))
	path := NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}, time.Now(), false)
	assert.Empty(t, path.communities())
	path.SetCommunities([]uint32{1, 2}, true)
	assert.Equal(t, path.GetCommunities(), path.communities())
	assert.Zero(t, testing.AllocsPerRun(10, func() { _ = path.communities() }))
}

// A path made for one neighbor and copied for another of its export class,
// with that neighbor's local address, is what UpdatePathAttrs makes for that
// neighbor directly: attribute by attribute, in order.
func TestExportForIsUpdatePathAttrsOfEachNeighbor(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	logger := slog.New(slog.DiscardHandler)
	global := &oc.Global{Config: oc.GlobalConfig{As: 65000, RouterId: netip.MustParseAddr("192.0.2.9")},
		Confederation: oc.Confederation{Config: oc.ConfederationConfig{Enabled: true, Identifier: 64999, MemberAsList: []uint32{65010}}}}
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("10.1.0.0/24"))
	source := func() *PeerInfo {
		if r.Intn(3) == 0 {
			return nil // local
		}
		return &PeerInfo{AS: 65100, ID: netip.MustParseAddr("192.0.2.1"), LocalID: netip.MustParseAddr("192.0.2.2"),
			Address: netip.MustParseAddr("10.9.0.1"), RouteReflectorClient: r.Intn(2) == 0, RouteReflectorClusterID: netip.MustParseAddr("192.0.2.3")}
	}
	for i := range 2000 {
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}
		if r.Intn(4) > 0 {
			attrs = append(attrs, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65100, uint32(64512 + r.Intn(3))})}))
		}
		nexthop := []string{"0.0.0.0", "10.9.0.1"}[r.Intn(2)]
		nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
		attrs = append(attrs, nh)
		if r.Intn(2) == 0 {
			attrs = append(attrs, bgp.NewPathAttributeMultiExitDisc(5))
		}
		if r.Intn(3) == 0 {
			attrs = append(attrs, bgp.NewPathAttributeLocalPref(200))
		}
		slices.SortStableFunc(attrs, func(a, b bgp.PathAttributeInterface) int { return int(a.GetType()) - int(b.GetType()) })
		path := NewPath(bgp.RF_IPv4_UC, source(), bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
		// one export class: what UpdatePathAttrs reads of a neighbor but its local address
		peer := &oc.Neighbor{Config: oc.NeighborConfig{LocalAs: 65000, PeerAs: []uint32{65200, 65010, 65000}[r.Intn(3)]},
			State: oc.NeighborState{PeerType: []oc.PeerType{oc.PEER_TYPE_EXTERNAL, oc.PEER_TYPE_INTERNAL}[r.Intn(2)]}}
		peer.RouteReflector.Config.RouteReflectorClient = r.Intn(2) == 0
		peer.RouteReflector.State.RouteReflectorClusterId = netip.MustParseAddr("192.0.2.4")
		locals := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
		info := func(local string) *PeerInfo { return &PeerInfo{LocalAddress: netip.MustParseAddr(local)} }
		template := UpdatePathAttrs(logger, global, peer, info(locals[0]), path)
		for _, local := range locals {
			want := UpdatePathAttrs(logger, global, peer, info(local), path)
			got := ExportFor(template, peer, path, netip.MustParseAddr(local))
			assert.Equal(t, want.GetPathAttrs(), got.GetPathAttrs(), "path %d to %s, %v", i, local, peer.State.PeerType)
			assert.Equal(t, want.GetNexthop(), got.GetNexthop())
		}
		assert.Equal(t, UpdatePathAttrs(logger, global, peer, info(locals[0]), path).GetPathAttrs(), template.GetPathAttrs(), "the template is left as made")
	}
}
