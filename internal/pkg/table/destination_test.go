// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package table

import (
	//"fmt"

	"net"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/stretchr/testify/assert"
)

func TestDestinationNewIPv4(t *testing.T) {
	peerD := DestCreatePeer()
	pathD := DestCreatePath(peerD)
	ipv4d := NewDestination(pathD[0].GetNlri(), 0)
	assert.NotNil(t, ipv4d)
}

func TestDestinationNewIPv6(t *testing.T) {
	peerD := DestCreatePeer()
	pathD := DestCreatePath(peerD)
	ipv6d := NewDestination(pathD[0].GetNlri(), 0)
	assert.NotNil(t, ipv6d)
}

func TestDestinationSetFamily(t *testing.T) {
	dd := &Destination{}
	dd.setFamily(bgp.RF_IPv4_UC)
	rf := dd.Family()
	assert.Equal(t, rf, bgp.RF_IPv4_UC)
}

func TestDestinationGetFamily(t *testing.T) {
	dd := &Destination{}
	dd.setFamily(bgp.RF_IPv6_UC)
	rf := dd.Family()
	assert.Equal(t, rf, bgp.RF_IPv6_UC)
}

func TestDestinationSetNlri(t *testing.T) {
	dd := &Destination{}
	nlri := bgp.NewIPAddrPrefix(24, "13.2.3.1")
	dd.setNlri(nlri)
	r_nlri := dd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}

func TestDestinationGetNlri(t *testing.T) {
	dd := &Destination{}
	nlri := bgp.NewIPAddrPrefix(24, "10.110.123.1")
	dd.setNlri(nlri)
	r_nlri := dd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}

func TestCalculate2(t *testing.T) {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := bgp.NewIPAddrPrefix(24, "10.10.0.0")

	// peer1 sends normal update message 10.10.0.0/24
	update1 := bgp.NewBGPUpdateMessage(nil, pathAttributes, []*bgp.IPAddrPrefix{nlri})
	peer1 := &PeerInfo{AS: 1, Address: net.IP{1, 1, 1, 1}}
	path1 := ProcessMessage(update1, peer1, time.Now())[0]

	d := NewDestination(nlri, 0)
	d.Calculate(logger, path1)

	// suppose peer2 sends grammaatically correct but semantically flawed update message
	// which has a withdrawal nlri not advertised before
	update2 := bgp.NewBGPUpdateMessage([]*bgp.IPAddrPrefix{nlri}, pathAttributes, nil)
	peer2 := &PeerInfo{AS: 2, Address: net.IP{2, 2, 2, 2}}
	path2 := ProcessMessage(update2, peer2, time.Now())[0]
	assert.Equal(t, path2.IsWithdraw, true)

	d.Calculate(logger, path2)

	// we have a path from peer1 here
	assert.Equal(t, len(d.knownPathList), 1)

	// after that, new update with the same nlri comes from peer2
	update3 := bgp.NewBGPUpdateMessage(nil, pathAttributes, []*bgp.IPAddrPrefix{nlri})
	path3 := ProcessMessage(update3, peer2, time.Now())[0]
	assert.Equal(t, path3.IsWithdraw, false)

	d.Calculate(logger, path3)

	// this time, we have paths from peer1 and peer2
	assert.Equal(t, len(d.knownPathList), 2)

	// now peer3 sends normal update message 10.10.0.0/24
	peer3 := &PeerInfo{AS: 3, Address: net.IP{3, 3, 3, 3}}
	update4 := bgp.NewBGPUpdateMessage(nil, pathAttributes, []*bgp.IPAddrPrefix{nlri})
	path4 := ProcessMessage(update4, peer3, time.Now())[0]

	d.Calculate(logger, path4)

	// we must have paths from peer1, peer2 and peer3
	assert.Equal(t, len(d.knownPathList), 3)
}

func TestNeighAddrTieBreak(t *testing.T) {
	nlri := bgp.NewIPAddrPrefix(24, "10.10.0.0")

	peer0 := &PeerInfo{AS: 65001, LocalAS: 1, Address: net.IP{2, 2, 2, 2}, ID: net.IP{2, 2, 2, 2}}

	p0 := func() *Path {
		aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001})})
		attrs := []bgp.PathAttributeInterface{aspath, bgp.NewPathAttributeMultiExitDisc(0)}
		return NewPath(peer0, nlri, false, attrs, time.Now(), false)
	}()

	peer1 := &PeerInfo{AS: 65001, LocalAS: 1, Address: net.IP{3, 3, 3, 3}, ID: net.IP{2, 2, 2, 2}} // same ID as peer0, separate eBGP session

	p1 := func() *Path {
		aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001})})
		attrs := []bgp.PathAttributeInterface{aspath, bgp.NewPathAttributeMultiExitDisc(0)}
		return NewPath(peer1, nlri, false, attrs, time.Now(), false)
	}()

	assert.Equal(t, compareByNeighborAddress(p0, p1), p0)
}

func TestMedTieBreaker(t *testing.T) {
	nlri := bgp.NewIPAddrPrefix(24, "10.10.0.0")

	p0 := func() *Path {
		aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65002}), bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65003, 65004})})
		attrs := []bgp.PathAttributeInterface{aspath, bgp.NewPathAttributeMultiExitDisc(0)}
		return NewPath(nil, nlri, false, attrs, time.Now(), false)
	}()

	p1 := func() *Path {
		aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65002}), bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65003, 65005})})
		attrs := []bgp.PathAttributeInterface{aspath, bgp.NewPathAttributeMultiExitDisc(10)}
		return NewPath(nil, nlri, false, attrs, time.Now(), false)
	}()

	// same AS
	assert.Equal(t, compareByMED(p0, p1), p0)

	p2 := func() *Path {
		aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65003})})
		attrs := []bgp.PathAttributeInterface{aspath, bgp.NewPathAttributeMultiExitDisc(10)}
		return NewPath(nil, nlri, false, attrs, time.Now(), false)
	}()

	// different AS
	assert.Equal(t, compareByMED(p0, p2), (*Path)(nil))

	p3 := func() *Path {
		aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint32{65003, 65004}), bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65003})})
		attrs := []bgp.PathAttributeInterface{aspath, bgp.NewPathAttributeMultiExitDisc(0)}
		return NewPath(nil, nlri, false, attrs, time.Now(), false)
	}()

	p4 := func() *Path {
		aspath := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65002}), bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint32{65005, 65006})})
		attrs := []bgp.PathAttributeInterface{aspath, bgp.NewPathAttributeMultiExitDisc(10)}
		return NewPath(nil, nlri, false, attrs, time.Now(), false)
	}()

	// ignore confed
	assert.Equal(t, compareByMED(p3, p4), p3)

	p5 := func() *Path {
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeMultiExitDisc(0)}
		return NewPath(nil, nlri, false, attrs, time.Now(), false)
	}()

	p6 := func() *Path {
		attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeMultiExitDisc(10)}
		return NewPath(nil, nlri, false, attrs, time.Now(), false)
	}()

	// no aspath
	assert.Equal(t, compareByMED(p5, p6), p5)
}

func TestTimeTieBreaker(t *testing.T) {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}
	nlri := bgp.NewIPAddrPrefix(24, "10.10.0.0")
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, []*bgp.IPAddrPrefix{nlri})
	peer1 := &PeerInfo{AS: 2, LocalAS: 1, Address: net.IP{1, 1, 1, 1}, ID: net.IP{1, 1, 1, 1}}
	path1 := ProcessMessage(updateMsg, peer1, time.Now())[0]

	peer2 := &PeerInfo{AS: 2, LocalAS: 1, Address: net.IP{2, 2, 2, 2}, ID: net.IP{2, 2, 2, 2}} // weaker router-id
	path2 := ProcessMessage(updateMsg, peer2, time.Now().Add(-1*time.Hour))[0]                 // older than path1

	d := NewDestination(nlri, 0)
	d.Calculate(logger, path1)
	d.Calculate(logger, path2)

	assert.Equal(t, len(d.knownPathList), 2)
	assert.Equal(t, true, d.GetBestPath("", 0).GetSource().ID.Equal(net.IP{2, 2, 2, 2})) // path from peer2 win

	// this option disables tie breaking by age
	SelectionOptions.ExternalCompareRouterId = true
	d = NewDestination(nlri, 0)
	d.Calculate(logger, path1)
	d.Calculate(logger, path2)

	assert.Equal(t, len(d.knownPathList), 2)
	assert.Equal(t, true, d.GetBestPath("", 0).GetSource().ID.Equal(net.IP{1, 1, 1, 1})) // path from peer1 win
}

func DestCreatePeer() []*PeerInfo {
	peerD1 := &PeerInfo{AS: 65000}
	peerD2 := &PeerInfo{AS: 65001}
	peerD3 := &PeerInfo{AS: 65002}
	peerD := []*PeerInfo{peerD1, peerD2, peerD3}
	return peerD
}

func DestCreatePath(peerD []*PeerInfo) []*Path {
	bgpMsgD1 := updateMsgD1()
	bgpMsgD2 := updateMsgD2()
	bgpMsgD3 := updateMsgD3()
	pathD := make([]*Path, 3)
	for i, msg := range []*bgp.BGPMessage{bgpMsgD1, bgpMsgD2, bgpMsgD3} {
		updateMsgD := msg.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgD.NLRI
		pathAttributes := updateMsgD.PathAttributes
		nlri_info := nlriList[0]
		pathD[i] = NewPath(peerD[i], nlri_info, false, pathAttributes, time.Now(), false)
	}
	return pathD
}

func updateMsgD1() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	return updateMsg
}

func updateMsgD2() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.100.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "20.20.20.0")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	return updateMsg
}

func updateMsgD3() *bgp.BGPMessage {
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.150.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "30.30.30.0")}
	w1 := bgp.NewIPAddrPrefix(23, "40.40.40.0")
	withdrawnRoutes := []*bgp.IPAddrPrefix{w1}
	updateMsg := bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
	UpdatePathAttrs4ByteAs(logger, updateMsg.Body.(*bgp.BGPUpdate))
	return updateMsg
}

func TestMultipath(t *testing.T) {
	UseMultiplePaths.Enabled = true
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.150.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	updateMsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	peer1 := &PeerInfo{AS: 1, Address: net.IP{1, 1, 1, 1}, ID: net.IP{1, 1, 1, 1}}
	path1 := ProcessMessage(updateMsg, peer1, time.Now())[0]
	peer2 := &PeerInfo{AS: 2, Address: net.IP{2, 2, 2, 2}, ID: net.IP{2, 2, 2, 2}}

	med = bgp.NewPathAttributeMultiExitDisc(100)
	nexthop = bgp.NewPathAttributeNextHop("192.168.150.2")
	pathAttributes = []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}
	updateMsg = bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path2 := ProcessMessage(updateMsg, peer2, time.Now())[0]

	d := NewDestination(nlri[0], 0)
	d.Calculate(logger, path2)

	best, old, multi := d.Calculate(logger, path1).GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.NotNil(t, best)
	assert.Equal(t, old, path2)
	assert.Equal(t, len(multi), 2)
	assert.Equal(t, len(d.GetKnownPathList(GLOBAL_RIB_NAME, 0)), 2)

	path3 := path2.Clone(true)
	dd := d.Calculate(logger, path3)
	best, old, multi = dd.GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.Nil(t, best)
	assert.Equal(t, old, path1)
	assert.Equal(t, len(multi), 1)
	assert.Equal(t, len(d.GetKnownPathList(GLOBAL_RIB_NAME, 0)), 1)

	peer3 := &PeerInfo{AS: 3, Address: net.IP{3, 3, 3, 3}, ID: net.IP{3, 3, 3, 3}}
	med = bgp.NewPathAttributeMultiExitDisc(50)
	nexthop = bgp.NewPathAttributeNextHop("192.168.150.3")
	pathAttributes = []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}
	updateMsg = bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path4 := ProcessMessage(updateMsg, peer3, time.Now())[0]
	dd = d.Calculate(logger, path4)
	best, _, multi = dd.GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.NotNil(t, best)
	assert.Equal(t, len(multi), 1)
	assert.Equal(t, len(d.GetKnownPathList(GLOBAL_RIB_NAME, 0)), 2)

	nexthop = bgp.NewPathAttributeNextHop("192.168.150.2")
	pathAttributes = []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}
	updateMsg = bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	path5 := ProcessMessage(updateMsg, peer2, time.Now())[0]
	best, _, multi = d.Calculate(logger, path5).GetChanges(GLOBAL_RIB_NAME, 0, false)
	assert.NotNil(t, best)
	assert.Equal(t, len(multi), 2)
	assert.Equal(t, len(d.GetKnownPathList(GLOBAL_RIB_NAME, 0)), 3)

	UseMultiplePaths.Enabled = false
}

func TestIdMap(t *testing.T) {
	d := NewDestination(bgp.NewIPAddrPrefix(24, "10.10.0.101"), 64)
	for i := 0; ; i++ {
		if id, err := d.localIdMap.FindandSetZeroBit(); err == nil {
			assert.Equal(t, uint(i+1), id)
		} else {
			assert.Equal(t, i, 63)
			break
		}
	}
	d.localIdMap.Expand()
	for i := range 64 {
		id, _ := d.localIdMap.FindandSetZeroBit()
		assert.Equal(t, id, uint(64+i))
	}
	_, err := d.localIdMap.FindandSetZeroBit()
	assert.NotNil(t, err)
}

func TestGetWithdrawnPath(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}
	p1 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.3.0"), false, attrs, time.Now(), false)
	p2 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.4.0"), false, attrs, time.Now(), false)
	p3 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.5.0"), false, attrs, time.Now(), false)

	u := &Update{
		KnownPathList:    []*Path{p2},
		OldKnownPathList: []*Path{p1, p2, p3},
	}

	l := u.GetWithdrawnPath()
	assert.Equal(t, len(l), 2)
	assert.Equal(t, l[0].GetNlri(), p1.GetNlri())
}

func TestDestination_Calculate_ExplicitWithdraw(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")

	peer1 := &PeerInfo{AS: 65001, Address: net.IP{1, 1, 1, 1}}
	peer2 := &PeerInfo{AS: 65002, Address: net.IP{2, 2, 2, 2}}

	// Create initial paths
	p1 := NewPath(peer1, nlri, false, attrs, time.Now(), false)
	p2 := NewPath(peer2, nlri, false, attrs, time.Now(), false)

	d := NewDestination(nlri, 1, p1, p2)
	logger := log.NewDefaultLogger()

	// Test explicit withdraw
	withdrawPath := NewPath(peer1, nlri, true, attrs, time.Now(), false)
	update := d.Calculate(logger, withdrawPath)

	assert.Len(t, update.KnownPathList, 1)
	assert.Equal(t, peer2.Address.String(), update.KnownPathList[0].GetSource().Address.String())
}

func TestDestination_Calculate_ImplicitWithdraw(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")
	peer1 := &PeerInfo{AS: 65001, Address: net.IP{1, 1, 1, 1}}

	// Create initial path
	p1 := NewPath(peer1, nlri, false, attrs, time.Now(), false)
	d := NewDestination(nlri, 0, p1)
	logger := log.NewDefaultLogger()

	// Send new path from same peer (should trigger implicit withdraw)
	newAttrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeMultiExitDisc(100),
	}
	p2 := NewPath(peer1, nlri, false, newAttrs, time.Now(), false)
	update := d.Calculate(logger, p2)

	assert.Len(t, update.KnownPathList, 1)
	assert.Equal(t, uint32(100), update.KnownPathList[0].getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC).(*bgp.PathAttributeMultiExitDisc).Value)
}

func TestDestination_GetBestPath_InvalidNexthop(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")
	peer1 := &PeerInfo{AS: 65001, Address: net.IP{1, 1, 1, 1}}

	p1 := NewPath(peer1, nlri, false, attrs, time.Now(), false)

	d := NewDestination(nlri, 0, p1)

	p1.IsNexthopInvalid = false
	bestPath := d.GetBestPath("", 0)
	assert.Equal(t, p1, bestPath)

	p1.IsNexthopInvalid = true
	bestPath = d.GetBestPath("", 0)
	assert.Nil(t, bestPath)
}

func TestDestination_Select_BestAndMultiPath(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")
	peer1 := &PeerInfo{AS: 65001, Address: net.IP{1, 1, 1, 1}}
	peer2 := &PeerInfo{AS: 65002, Address: net.IP{2, 2, 2, 2}}

	p1 := NewPath(peer1, nlri, false, attrs, time.Now(), false)
	p2 := NewPath(peer2, nlri, false, attrs, time.Now(), false)

	d := NewDestination(nlri, 0, p1, p2)

	// Test best path selection
	selected := d.Select(DestinationSelectOption{Best: true})
	assert.NotNil(t, selected)
	assert.Len(t, selected.GetAllKnownPathList(), 1)

	// Test multipath selection
	selected = d.Select(DestinationSelectOption{Best: true, MultiPath: true})
	assert.NotNil(t, selected)
	assert.Len(t, selected.GetAllKnownPathList(), 2)
}

func TestCompareByLLGRStaleCommunity(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")
	peer1 := &PeerInfo{AS: 65001, Address: net.IP{1, 1, 1, 1}}
	peer2 := &PeerInfo{AS: 65002, Address: net.IP{2, 2, 2, 2}}

	p1 := NewPath(peer1, nlri, false, attrs, time.Now(), false)
	p2 := NewPath(peer2, nlri, false, attrs, time.Now(), false)

	// Mock LLGR stale state
	p1.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, false)

	result := compareByLLGRStaleCommunity(p1, p2)
	assert.Equal(t, p2, result)
	result = compareByLLGRStaleCommunity(p2, p1)
	assert.Equal(t, p2, result)

	// Both stale
	p2.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, false)
	result = compareByLLGRStaleCommunity(p1, p2)
	assert.Nil(t, result)
}

func TestCompareByLocalOrigin(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")
	peer1 := &PeerInfo{AS: 65001, Address: net.IP{1, 1, 1, 1}}

	// Local path (peer = nil)
	localPath := NewPath(nil, nlri, false, attrs, time.Now(), false)
	peerPath := NewPath(peer1, nlri, false, attrs, time.Now(), false)

	result := compareByLocalOrigin(localPath, peerPath)
	assert.Equal(t, localPath, result)

	result = compareByLocalOrigin(peerPath, localPath)
	assert.Equal(t, localPath, result)

	// Same source
	result = compareByLocalOrigin(peerPath, peerPath)
	assert.Nil(t, result)
}

func TestCompareByASPath_IgnoreLength(t *testing.T) {
	oldIgnoreAsPathLength := SelectionOptions.IgnoreAsPathLength
	defer func() {
		SelectionOptions.IgnoreAsPathLength = oldIgnoreAsPathLength
	}()

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")

	aspath1 := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
	})
	attrs1 := []bgp.PathAttributeInterface{aspath1}
	p1 := NewPath(nil, nlri, false, attrs1, time.Now(), false)

	aspath2 := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001, 65002}),
	})
	attrs2 := []bgp.PathAttributeInterface{aspath2}
	p2 := NewPath(nil, nlri, false, attrs2, time.Now(), false)

	SelectionOptions.IgnoreAsPathLength = false
	result := compareByASPath(p1, p2)
	assert.Equal(t, result, p1)
	result = compareByASPath(p2, p1)
	assert.Equal(t, result, p1)

	SelectionOptions.IgnoreAsPathLength = true
	result = compareByASPath(p1, p2)
	assert.Nil(t, result)
}

func TestCompareByMED_AlwaysCompare(t *testing.T) {
	oldAlwaysCompareMed := SelectionOptions.AlwaysCompareMed
	defer func() {
		SelectionOptions.AlwaysCompareMed = oldAlwaysCompareMed
	}()
	SelectionOptions.AlwaysCompareMed = true

	nlri := bgp.NewIPAddrPrefix(24, "10.0.0.0")

	aspath1 := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65001}),
	})
	attrs1 := []bgp.PathAttributeInterface{aspath1, bgp.NewPathAttributeMultiExitDisc(50)}
	p1 := NewPath(nil, nlri, false, attrs1, time.Now(), false)

	aspath2 := bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{
		bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{65002}),
	})
	attrs2 := []bgp.PathAttributeInterface{aspath2, bgp.NewPathAttributeMultiExitDisc(100)}
	p2 := NewPath(nil, nlri, false, attrs2, time.Now(), false)

	SelectionOptions.AlwaysCompareMed = false
	result := compareByMED(p1, p2)
	assert.Nil(t, result)

	SelectionOptions.AlwaysCompareMed = true
	result = compareByMED(p1, p2)
	assert.Equal(t, p1, result)
}

func BenchmarkMultiPath(b *testing.B) {
	b.StopTimer()
	nlri := bgp.NewIPAddrPrefix(24, "10.10.0.0")

	// Create a 4 path setup for the given NLRI
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{65001})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("10.0.0.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)
	pathAttributes := []bgp.PathAttributeInterface{origin, aspath, nexthop, med}

	numPaths := 4
	pathList := make([]*Path, numPaths)
	for i := range numPaths {
		// peer1 sends normal update message 10.10.0.0/24
		update := bgp.NewBGPUpdateMessage(nil, pathAttributes, []*bgp.IPAddrPrefix{nlri})
		peeri := &PeerInfo{AS: uint32(i), ID: net.IP{byte(i), byte(i), byte(i), byte(i)}}
		pathList[i] = ProcessMessage(update, peeri, time.Now())[0]
	}

	b.Run("Benchmark Calculate", func(b *testing.B) {
		for range b.N {
			d := NewDestination(nlri, 0)
			b.StartTimer()
			for j := range pathList {
				d.Calculate(logger, pathList[j])
			}
			b.StopTimer()
		}
	})

	b.Run("Benchmark GetMultiBestPath", func(b *testing.B) {
		d := NewDestination(nlri, 0)
		for j := range pathList {
			d.Calculate(logger, pathList[j])
		}
		for range b.N {
			b.StartTimer()
			d.GetMultiBestPath(GLOBAL_RIB_NAME)
			b.StopTimer()
		}
	})
}

func TestDestination_Calculate_AddAndWithdrawPath(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
	}
	nlri := bgp.NewIPAddrPrefix(16, "13.2.0.0")
	p1 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.3.0"), false, attrs, time.Now(), false)
	p2 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.4.0"), false, attrs, time.Now(), false)
	p3 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.5.0"), false, attrs, time.Now(), false)
	d := NewDestination(nlri, 0, p1, p2, p3)

	logger := log.NewDefaultLogger()
	p4 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.6.0"), false, attrs, time.Now(), false)
	update := d.Calculate(logger, p4)
	assert.Len(t, update.KnownPathList, 3)
	assert.Len(t, update.KnownPathList, 3)
	assert.NotEqualValues(t, update.OldKnownPathList, update.KnownPathList)
	assert.Equal(t, "13.2.6.0/24", update.KnownPathList[0].GetNlri().String())
	assert.Equal(t, "13.2.4.0/24", update.KnownPathList[1].GetNlri().String())

	// p1 is no implecit withdrawn
	p1 = NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.3.0"), false, attrs, time.Now(), true)
	d = NewDestination(nlri, 0, p1, p2, p3)
	update = d.Calculate(logger, p4)
	assert.Len(t, update.KnownPathList, 3)
	assert.Len(t, update.KnownPathList, 3)
	assert.NotEqualValues(t, update.OldKnownPathList, update.KnownPathList)

	assert.Equal(t, "13.2.6.0/24", update.KnownPathList[0].GetNlri().String())
	assert.Equal(t, "13.2.3.0/24", update.KnownPathList[1].GetNlri().String())
	assert.Equal(t, "13.2.5.0/24", update.KnownPathList[2].GetNlri().String())

	p5 := NewPath(nil, bgp.NewIPAddrPrefix(24, "13.2.8.0"), false, attrs, time.Now(), false)
	d = NewDestination(nlri, 0, p1, p2, p3, p5)
	update = d.Calculate(logger, p4)

	assert.Len(t, update.KnownPathList, 4)
	assert.Len(t, update.KnownPathList, 4)
	assert.NotEqualValues(t, update.OldKnownPathList, update.KnownPathList)
	assert.Equal(t, "13.2.6.0/24", update.KnownPathList[0].GetNlri().String())
	assert.Equal(t, "13.2.3.0/24", update.KnownPathList[1].GetNlri().String())
	assert.Equal(t, "13.2.5.0/24", update.KnownPathList[2].GetNlri().String())
	assert.Equal(t, "13.2.8.0/24", update.KnownPathList[3].GetNlri().String())
}
