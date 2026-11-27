package server

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func TestReceivedPrefixesCountsEveryNLRI(t *testing.T) {
	prefix := func(s string) bgp.PathNLRI {
		n, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(s))
		require.NoError(t, err)
		return bgp.PathNLRI{NLRI: n}
	}
	v6 := func(s string) bgp.PathNLRI {
		n, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(s))
		require.NoError(t, err)
		return bgp.PathNLRI{NLRI: n}
	}
	reach, err := bgp.NewPathAttributeMpReachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{v6("2001:db8::/48"), v6("2001:db8:1::/48")}, netip.MustParseAddr("2001:db8::1"))
	require.NoError(t, err)
	unreach, err := bgp.NewPathAttributeMpUnreachNLRI(bgp.RF_IPv6_UC, []bgp.PathNLRI{v6("2001:db8:2::/48")})
	require.NoError(t, err)

	var r receivedPrefixes
	r.count(bgp.NewBGPUpdateMessage([]bgp.PathNLRI{prefix("10.0.0.0/24")}, nil, []bgp.PathNLRI{prefix("10.0.1.0/24"), prefix("10.0.2.0/24"), prefix("10.0.3.0/24")}).Body.(*bgp.BGPUpdate))
	r.count(bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{reach, unreach}, nil).Body.(*bgp.BGPUpdate))
	r.count(bgp.NewBGPUpdateMessage(nil, nil, nil).Body.(*bgp.BGPUpdate)) // End-of-RIB: an UPDATE without prefixes
	require.Equal(t, uint64(3), r.updates.Load())
	require.Equal(t, uint64(5), r.announced.Load())
	require.Equal(t, uint64(2), r.withdrawn.Load())
}
