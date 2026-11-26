package server

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exportPolicy is an export policy as the lab's controller writes it: valley
// free by community towards peers and providers, the communities that ask
// not to send to an AS, and a MED and a denied AS path towards one neighbor each.
func exportPolicy(t *testing.T, s *BgpServer, peers []*peer) {
	ds := oc.DefinedSets{}
	ds.NeighborSets = append(ds.NeighborSets, oc.NeighborSet{NeighborSetName: "up", NeighborInfoList: []string{peers[0].ID(), peers[1].ID(), peers[2].ID()}},
		oc.NeighborSet{NeighborSetName: "med", NeighborInfoList: []string{peers[3].ID()}}, oc.NeighborSet{NeighborSetName: "via", NeighborInfoList: []string{peers[4].ID()}})
	ds.BgpDefinedSets.CommunitySets = append(ds.BgpDefinedSets.CommunitySets, oc.CommunitySet{CommunitySetName: "learned-up", CommunityList: []string{"65000:2", "65000:3"}})
	ds.BgpDefinedSets.AsPathSets = append(ds.BgpDefinedSets.AsPathSets, oc.AsPathSet{AsPathSetName: "via-64600", AsPathList: []string{"_64600_"}})
	reject := oc.Statement{Name: "valley-free"}
	reject.Conditions.MatchNeighborSet.NeighborSet = "up"
	reject.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "learned-up"
	reject.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_REJECT_ROUTE
	med := oc.Statement{Name: "med"}
	med.Conditions.MatchNeighborSet.NeighborSet = "med"
	med.Actions.BgpActions.SetMed = "7"
	via := oc.Statement{Name: "via"}
	via.Conditions.MatchNeighborSet.NeighborSet = "via"
	via.Conditions.BgpConditions.MatchAsPathSet.AsPathSet = "via-64600"
	via.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_REJECT_ROUTE
	// A next hop set to the neighbor's own address: its result holds for it alone.
	nh := oc.Statement{Name: "peer-address"}
	nh.Conditions.MatchNeighborSet.NeighborSet = "nh"
	nh.Actions.BgpActions.SetNextHop = "peer-address"
	ds.NeighborSets = append(ds.NeighborSets, oc.NeighborSet{NeighborSetName: "nh", NeighborInfoList: []string{peers[5].ID()}})
	statements := []oc.Statement{reject, med, via, nh}
	for _, as := range []uint32{65101, 65102, 65103} {
		name := fmt.Sprintf("as-%d", as)
		var list []string
		for _, p := range peers {
			if p.AS() == as {
				list = append(list, p.ID())
			}
		}
		ds.NeighborSets = append(ds.NeighborSets, oc.NeighborSet{NeighborSetName: name, NeighborInfoList: list})
		ds.BgpDefinedSets.CommunitySets = append(ds.BgpDefinedSets.CommunitySets, oc.CommunitySet{CommunitySetName: "not-to-" + name, CommunityList: []string{fmt.Sprintf("0:%d", as)}})
		st := oc.Statement{Name: "reject-" + name}
		st.Conditions.MatchNeighborSet.NeighborSet = name
		st.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "not-to-" + name
		st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_REJECT_ROUTE
		statements = append(statements, st)
	}
	pl := oc.RoutingPolicy{DefinedSets: ds, PolicyDefinitions: []oc.PolicyDefinition{{Name: "export", Statements: statements}}}
	require.NoError(t, s.policy.Reset(&pl, map[string]oc.ApplyPolicy{table.GLOBAL_RIB_NAME: {Config: oc.ApplyPolicyConfig{
		ExportPolicyList: []string{"export"}, DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
	}}}))
}

// With the path made for export once per export class and local address,
// shared by the neighbors that get it, every neighbor gets from filterpath
// what it gets alone, also after the others got theirs.
func TestExportClassesGiveWhatEachNeighborGetsAlone(t *testing.T) {
	r := newOperaRouter(t, table.OperaOptions{})
	var peers []*peer
	for i := range 9 {
		p := r.peer(fmt.Sprintf("10.100.0.%d", i+1), uint32(65101+i%3))
		p.peerInfo.LocalAddress = netip.MustParseAddr(fmt.Sprintf("10.200.0.%d", 1+i%4)) // some share a next hop
		peers = append(peers, p)
	}
	exportPolicy(t, r.s, peers)
	rnd := rand.New(rand.NewSource(4))
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix("20.0.0.0/24"))
	alone := func(nb *peer, path, old *table.Path) *table.Path {
		e, e1, u := r.s.exports, r.s.exported1, r.s.unpreffed
		r.s.exports, r.s.exported1, r.s.unpreffed = nil, nil, nil
		defer func() { r.s.exports, r.s.exported1, r.s.unpreffed = e, e1, u }()
		return r.s.filterpath(nb, path, old)
	}
	made, rejected, shared := 0, 0, 0
	var old *table.Path
	for i := range 400 {
		from := peers[rnd.Intn(len(peers))]
		as := []uint32{from.AS()}
		if rnd.Intn(3) == 0 {
			as = append(as, 64600)
		}
		var communities []uint32
		for _, c := range []uint32{65000<<16 | 2, 65000<<16 | 1, 65101, 65102, 65103} {
			if rnd.Intn(4) == 0 {
				communities = append(communities, c)
			}
		}
		nexthop, _ := bgp.NewPathAttributeNextHop(from.peerInfo.Address)
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, append(as, 9))}), nexthop}
		if len(communities) > 0 {
			attrs = append(attrs, bgp.NewPathAttributeCommunities(communities))
		}
		if rnd.Intn(2) == 0 { // as import policies set it: removed towards eBGP neighbors, on a copy
			attrs = append(attrs, bgp.NewPathAttributeLocalPref(uint32(50+rnd.Intn(100))))
		}
		path := table.NewPath(bgp.RF_IPv4_UC, from.peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
		if rnd.Intn(3) == 0 {
			old = nil
		}
		// one update
		r.s.exports, r.s.exported1, r.s.unpreffed = map[exportKey]*table.Path{}, map[exportKey]*table.Path{}, map[*table.Path]*table.Path{}
		got := make([]*table.Path, len(peers))
		for j, nb := range peers {
			got[j] = r.s.filterpath(nb, path, old)
		}
		for j, nb := range peers { // after every neighbor got its path: none changed another's
			want := alone(nb, path, old)
			if assert.Equal(t, want == nil, got[j] == nil, "path %d to %s", i, nb.ID()) && want != nil {
				assert.Equal(t, want.GetPathAttrs(), got[j].GetPathAttrs(), "path %d to %s", i, nb.ID())
				assert.Equal(t, want.IsWithdraw, got[j].IsWithdraw, "path %d to %s", i, nb.ID())
			}
			if want == nil {
				rejected++
			}
		}
		made += len(r.s.exports)
		distinct := map[*table.Path]bool{}
		for _, p := range got {
			if p != nil {
				distinct[p] = true
				shared++
			}
		}
		shared -= len(distinct)
		old = path
	}
	r.s.exports, r.s.exported1, r.s.unpreffed = nil, nil, nil
	assert.Less(t, made, 400*len(peers), "made once per class, not per neighbor")
	assert.Positive(t, shared, "neighbors with one local address share the path")
	assert.Positive(t, rejected, "the policy rejected some")
}
