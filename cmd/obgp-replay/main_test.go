package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// record makes a BGP4MP record with four-byte ASNs, as gobgpd writes one.
func record(t *testing.T, ts uint32, msg *bgp.BGPMessage) []byte {
	t.Helper()
	data, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 20, 20+len(data))
	binary.BigEndian.PutUint32(body[0:], 65001)
	binary.BigEndian.PutUint32(body[4:], 65002)
	binary.BigEndian.PutUint16(body[10:], 1)
	copy(body[12:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	body = append(body, data...)
	head := make([]byte, 12)
	binary.BigEndian.PutUint32(head[0:], ts)
	binary.BigEndian.PutUint16(head[4:], mrtBGP4MP)
	binary.BigEndian.PutUint16(head[6:], mrtMessageAS4)
	binary.BigEndian.PutUint32(head[8:], uint32(len(body)))
	return append(head, body...)
}

func announce(t *testing.T, prefix string, as uint32) *bgp.BGPMessage {
	t.Helper()
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.0.0.1"))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{as})}),
		nh,
	}
	return bgp.NewBGPUpdateMessage(nil, attrs, []bgp.PathNLRI{{NLRI: nlri}})
}

func withdraw(prefix string) *bgp.BGPMessage {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	return bgp.NewBGPUpdateMessage([]bgp.PathNLRI{{NLRI: nlri}}, nil, nil)
}

func recording(t *testing.T) []byte {
	var data []byte
	data = append(data, record(t, 100, announce(t, "192.0.2.0/24", 65001))...)
	data = append(data, record(t, 100, announce(t, "198.51.100.0/24", 65001))...)
	data = append(data, record(t, 102, withdraw("192.0.2.0/24"))...)
	return data
}

func TestRecordedMessagesComeFromTheFeederAtTheirSecond(t *testing.T) {
	msgs, err := load(recording(t), netip.MustParseAddr("10.9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 || msgs[0].at != 100 || msgs[2].at != 102 || msgs[2].withdrawn[0] != "192.0.2.0/24" {
		t.Fatalf("got %+v", msgs)
	}
	sent, _ := bgp.ParseBGPMessage(msgs[0].data)
	for _, a := range sent.Body.(*bgp.BGPUpdate).PathAttributes {
		if nh, ok := a.(*bgp.PathAttributeNextHop); ok && nh.Value.String() != "10.9.9.9" {
			t.Fatalf("next hop %s, not the feeder's", nh.Value)
		}
	}
	// Paced, the two messages of one second share it, the third waits for its own.
	if got := schedule(msgs, true, 100); got[0] != 0 || got[1] != 500*time.Millisecond || got[2] != 2*time.Second {
		t.Fatalf("paced %v", got)
	}
	// Another neighbor sent first, at 97: this feeder keeps its three seconds after it.
	if got := schedule(msgs, true, 97); got[0] != 3*time.Second {
		t.Fatalf("paced after another neighbor %v", got)
	}
	if got := schedule(msgs, false, 100); got[2] != 0 {
		t.Fatalf("flood %v", got)
	}
}

func TestAFeederSendsItsRecordingAnswersARefreshAndKeepsWhatTheRouterSent(t *testing.T) {
	msgs, err := load(recording(t), netip.MustParseAddr("10.9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	f := &Feeder{As: 65001, ID: netip.MustParseAddr("1.1.1.1"), Hold: 90, Messages: msgs,
		sent: map[string][]bgp.PathAttributeInterface{}, received: map[string]string{}, lengths: map[string]int{}}
	feeder, router := net.Pipe()
	defer router.Close()
	ended := make(chan error, 1)
	go func() { ended <- f.Session(feeder) }()
	r := bufio.NewReader(router)
	expect := func(kind uint8) *bgp.BGPMessage {
		t.Helper()
		router.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			m, err := read(r)
			if err != nil {
				t.Fatal(err)
			}
			if m.Header.Type == kind {
				return m
			}
		}
	}
	send := func(m *bgp.BGPMessage) {
		t.Helper()
		data, _ := m.Serialize()
		if _, err := router.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	open := expect(bgp.BGP_MSG_OPEN).Body.(*bgp.BGPOpen)
	if open.MyAS != 65001 || open.HoldTime != 90 {
		t.Fatalf("open %+v", open)
	}
	enhanced := bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{bgp.NewCapEnhancedRouteRefresh()})
	ours, _ := bgp.NewBGPOpenMessage(65002, 90, netip.MustParseAddr("2.2.2.2"), []bgp.OptionParameterInterface{enhanced})
	send(ours)
	expect(bgp.BGP_MSG_KEEPALIVE)
	send(bgp.NewBGPKeepAliveMessage())
	for !f.Status().Established {
		time.Sleep(time.Millisecond)
	}
	go f.Send(time.Now(), false, 100)
	for range 3 {
		expect(bgp.BGP_MSG_UPDATE)
	}
	for f.Status().Done == 0 {
		time.Sleep(time.Millisecond)
	}
	// A refresh: the router holds one route of the feeder now, sent again between a beginning and an end.
	send(bgp.NewBGPRouteRefreshMessage(bgp.AFI_IP, bgp.BGP_ROUTE_REFRESH_REQUEST, bgp.SAFI_UNICAST))
	if m := expect(bgp.BGP_MSG_ROUTE_REFRESH).Body.(*bgp.BGPRouteRefresh); m.Demarcation != bgp.BGP_ROUTE_REFRESH_BEGIN {
		t.Fatalf("no beginning of the refresh: %+v", m)
	}
	again := expect(bgp.BGP_MSG_UPDATE).Body.(*bgp.BGPUpdate)
	if len(again.NLRI) != 1 || again.NLRI[0].NLRI.String() != "198.51.100.0/24" {
		t.Fatalf("refresh sent %v", again.NLRI)
	}
	if m := expect(bgp.BGP_MSG_ROUTE_REFRESH).Body.(*bgp.BGPRouteRefresh); m.Demarcation != bgp.BGP_ROUTE_REFRESH_END {
		t.Fatalf("no end of the refresh: %+v", m)
	}
	// What the router sends counts by prefix, a withdrawal removes it, and so does
	// the end of the router's own refresh for a route it did not send again.
	send(announce(t, "203.0.113.0/24", 65002))
	send(announce(t, "192.0.2.0/24", 65002))
	send(withdraw("192.0.2.0/24"))
	send(announce(t, "233.252.0.0/24", 65002))
	send(bgp.NewBGPRouteRefreshMessage(bgp.AFI_IP, bgp.BGP_ROUTE_REFRESH_BEGIN, bgp.SAFI_UNICAST))
	send(announce(t, "203.0.113.0/24", 65002))
	send(bgp.NewBGPRouteRefreshMessage(bgp.AFI_IP, bgp.BGP_ROUTE_REFRESH_END, bgp.SAFI_UNICAST))
	time.Sleep(50 * time.Millisecond)
	s := f.Status()
	if s.Sent != 3 || s.Updates != 5 || s.Refreshes != 1 || s.Prefixes != 1 || s.Digest == "" {
		t.Fatalf("status %+v", s)
	}
	other := &Feeder{received: map[string]string{"203.0.113.0/24": "x"}, lengths: map[string]int{}}
	if other.Status().Digest == s.Digest {
		t.Fatal("different routes, the same digest")
	}
}

func TestTheDigestOfWhatTheRouterSentLeavesOutItsNextHop(t *testing.T) {
	via := func(nh string) *Feeder {
		f := &Feeder{received: map[string]string{}, lengths: map[string]int{}}
		u := announce(t, "192.0.2.0/24", 65002).Body.(*bgp.BGPUpdate)
		for i, a := range u.PathAttributes {
			if _, ok := a.(*bgp.PathAttributeNextHop); ok {
				u.PathAttributes[i], _ = bgp.NewPathAttributeNextHop(netip.MustParseAddr(nh))
			}
		}
		f.receive(u)
		return f
	}
	if via("10.1.0.5").Status().Digest != via("10.1.9.9").Status().Digest {
		t.Fatal("the router's pod address changed the digest")
	}
}

func TestARefreshPacksThePrefixesOfEqualAttributes(t *testing.T) {
	msgs, _ := load(recording(t), netip.MustParseAddr("10.9.9.9"))
	f := &Feeder{sent: map[string][]bgp.PathAttributeInterface{}, received: map[string]string{}, lengths: map[string]int{}}
	for _, m := range msgs[:2] { // two prefixes, the same attributes
		for _, p := range m.announced {
			f.sent[p] = m.attrs
		}
	}
	feeder, router := net.Pipe()
	defer router.Close()
	f.w = bufio.NewWriter(feeder)
	go f.refresh()
	router.SetReadDeadline(time.Now().Add(5 * time.Second))
	m, err := read(bufio.NewReader(router))
	if err != nil {
		t.Fatal(err)
	}
	if u := m.Body.(*bgp.BGPUpdate); len(u.NLRI) != 2 {
		t.Fatalf("%d prefixes in one message, not 2", len(u.NLRI))
	}
}

func TestARefreshSendsPrefixesWhoseAttributesLeaveNoRoomOneByOne(t *testing.T) {
	nh, _ := bgp.NewPathAttributeNextHop(netip.MustParseAddr("10.9.9.9"))
	communities := make([]uint32, 1013) // 4,067 bytes of attributes: room for one /24 in a message, not for two
	attrs := []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh, bgp.NewPathAttributeCommunities(communities)}
	f := &Feeder{sent: map[string][]bgp.PathAttributeInterface{"192.0.2.0/24": attrs, "198.51.100.0/24": attrs}, received: map[string]string{}, lengths: map[string]int{}}
	feeder, router := net.Pipe()
	defer router.Close()
	f.w = bufio.NewWriter(feeder)
	done := make(chan error, 1)
	go func() { done <- f.refresh() }()
	r := bufio.NewReader(router)
	router.SetReadDeadline(time.Now().Add(5 * time.Second))
	for range 2 {
		m, err := read(r)
		if err != nil {
			t.Fatal(err)
		}
		if u := m.Body.(*bgp.BGPUpdate); len(u.NLRI) != 1 {
			t.Fatalf("%d prefixes, not one", len(u.NLRI))
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTheQualityOfWhatTheRouterSentIsThePathLengthPerPrefixOnly(t *testing.T) {
	via := func(as uint32) Status {
		f := &Feeder{received: map[string]string{}, lengths: map[string]int{}}
		f.receive(announce(t, "192.0.2.0/24", as).Body.(*bgp.BGPUpdate))
		return f.Status()
	}
	a, b := via(65002), via(65003) // another path of the same length, as timing may choose
	if a.Digest == b.Digest || a.Quality != b.Quality {
		t.Fatalf("exact %s %s, quality %s %s", a.Digest, b.Digest, a.Quality, b.Quality)
	}
}
