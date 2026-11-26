package server

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

// benchPolicy is an export policy as the lab's controller writes it: one
// statement per neighboring AS, the communities that ask not to send to it.
func benchPolicy(b *testing.B, r *operaRouter, peers []*peer) {
	ds := oc.DefinedSets{}
	var rejects []oc.Statement
	for _, p := range peers {
		name := fmt.Sprintf("as-%d", p.AS())
		ds.NeighborSets = append(ds.NeighborSets, oc.NeighborSet{NeighborSetName: name, NeighborInfoList: []string{p.ID()}})
		ds.BgpDefinedSets.CommunitySets = append(ds.BgpDefinedSets.CommunitySets, oc.CommunitySet{CommunitySetName: "not-to-" + name, CommunityList: []string{fmt.Sprintf("0:%d", p.AS())}})
		st := oc.Statement{Name: "reject-" + name}
		st.Conditions.MatchNeighborSet.NeighborSet = name
		st.Conditions.BgpConditions.MatchCommunitySet.CommunitySet = "not-to-" + name
		st.Actions.RouteDisposition = oc.ROUTE_DISPOSITION_REJECT_ROUTE
		rejects = append(rejects, st)
	}
	pl := oc.RoutingPolicy{DefinedSets: ds, PolicyDefinitions: []oc.PolicyDefinition{{Name: "communities", Statements: rejects}}}
	require.NoError(b, r.s.policy.Reset(&pl, map[string]oc.ApplyPolicy{table.GLOBAL_RIB_NAME: {Config: oc.ApplyPolicyConfig{
		ExportPolicyList: []string{"communities"}, DefaultExportPolicy: oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE,
	}}}))
}

func BenchmarkOperaPerNeighborUpdates(b *testing.B) {
	for _, n := range []int{50, 200} {
		for _, mode := range []string{"obgp-pn", "obgp"} {
			b.Run(fmt.Sprintf("%s/%d", mode, n), func(b *testing.B) {
				t := &testing.T{}
				r := newOperaRouter(t, table.OperaOptions{Enabled: true, PerNeighbor: mode == "obgp-pn"})
				var peers []*peer
				for i := range n {
					peers = append(peers, r.peer(fmt.Sprintf("10.%d.%d.1", i/200, i%200), uint32(1000+i)))
				}
				benchPolicy(b, r, peers)
				const prefixes = 50
				b.ResetTimer()
				for b.Loop() {
					// every prefix from four neighbors, worse paths later, then withdrawn
					for x := range prefixes {
						nlri, _ := bgp.NewIPAddrPrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{20, byte(x / 256), byte(x % 256), 0}), 24))
						for k := range 4 {
							from := peers[(x*7+k*13)%n]
							nexthop, _ := bgp.NewPathAttributeNextHop(from.peerInfo.Address)
							as := []uint32{from.AS()}
							for range k {
								as = append(as, 64999)
							}
							attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0),
								bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, append(as, 9))}), nexthop}
							p := table.NewPath(bgp.RF_IPv4_UC, from.peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
							from.adjRibIn.Update([]*table.Path{p})
							r.s.propagateUpdate(from, []*table.Path{p})
						}
					}
					for x := range prefixes {
						nlri, _ := bgp.NewIPAddrPrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{20, byte(x / 256), byte(x % 256), 0}), 24))
						for k := range 4 {
							from := peers[(x*7+k*13)%n]
							p := table.NewPath(bgp.RF_IPv4_UC, from.peerInfo, bgp.PathNLRI{NLRI: nlri}, true, nil, time.Now(), false)
							from.adjRibIn.Update([]*table.Path{p})
							r.s.propagateUpdate(from, []*table.Path{p})
						}
					}
					for _, p := range peers { // the sent updates, drained
						for len(p.fsm.outgoingCh.Out()) > 0 {
							<-p.fsm.outgoingCh.Out()
						}
					}
				}
			})
		}
	}
}

func BenchmarkOperaPerNeighborMemory(b *testing.B) {
	for _, mode := range []string{"obgp-pn", "obgp"} {
		b.Run(mode, func(b *testing.B) {
			const n, prefixes = 200, 2000
			for b.Loop() {
				r := newOperaRouter(&testing.T{}, table.OperaOptions{Enabled: true, PerNeighbor: mode == "obgp-pn"})
				var peers []*peer
				for i := range n {
					peers = append(peers, r.peer(fmt.Sprintf("10.%d.%d.1", i/200, i%200), uint32(1000+i)))
				}
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				for x := range prefixes {
					nlri, _ := bgp.NewIPAddrPrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{20, byte(x / 256), byte(x % 256), 0}), 24))
					from := peers[x%n]
					nexthop, _ := bgp.NewPathAttributeNextHop(from.peerInfo.Address)
					attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0),
						bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{from.AS(), 9})}), nexthop}
					p := table.NewPath(bgp.RF_IPv4_UC, from.peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)
					from.adjRibIn.Update([]*table.Path{p})
					r.s.propagateUpdate(from, []*table.Path{p})
				}
				for _, p := range peers {
					for len(p.fsm.outgoingCh.Out()) > 0 {
						<-p.fsm.outgoingCh.Out()
					}
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/prefixes, "B/prefix")
				runtime.KeepAlive(r)
			}
		})
	}
}
