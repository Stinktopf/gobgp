package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func mraiPath(prefix string, withdraw bool, as uint32) *table.Path {
	nlri, _ := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{as})}),
	}
	return table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, withdraw, attrs, time.Now(), false)
}

func mraiPrefixes(paths []*table.Path) []string {
	out := []string{}
	for _, p := range paths {
		out = append(out, p.GetNlri().String())
	}
	return out
}

func TestMRAIWithoutIntervalSendsAtOnce(t *testing.T) {
	m := newMRAI(0, func(bgp.Family) bool { return false })
	paths := []*table.Path{mraiPath("10.0.0.0/24", false, 1), mraiPath("10.0.1.0/24", true, 1)}
	assert.Equal(t, paths, m.add(paths, time.Now()))
	assert.True(t, m.due().IsZero())
}

// RFC 4271, 9.2.1.1: one batch of advertisements per interval, the newest
// of each route; withdrawals at once, taking a waiting advertisement along.
func TestMRAIHoldsAdvertisementsButNotWithdrawals(t *testing.T) {
	start := time.Unix(1000, 0)
	m := newMRAI(30*time.Second, func(bgp.Family) bool { return false })
	assert.Equal(t, []string{"10.0.0.0/24"}, mraiPrefixes(m.add([]*table.Path{mraiPath("10.0.0.0/24", false, 1)}, start)))

	newer := mraiPath("10.0.1.0/24", false, 3)
	assert.Empty(t, m.add([]*table.Path{mraiPath("10.0.1.0/24", false, 2), mraiPath("10.0.2.0/24", false, 2)}, start.Add(time.Second)))
	assert.Empty(t, m.add([]*table.Path{newer}, start.Add(2*time.Second)))
	assert.Equal(t, start.Add(30*time.Second), m.due())

	withdrawn := m.add([]*table.Path{mraiPath("10.0.2.0/24", true, 2)}, start.Add(3*time.Second))
	assert.Equal(t, []string{"10.0.2.0/24"}, mraiPrefixes(withdrawn))
	assert.True(t, withdrawn[0].IsWithdraw)

	assert.Empty(t, m.flush(start.Add(29*time.Second)))
	sent := m.flush(start.Add(30 * time.Second))
	assert.Equal(t, []*table.Path{newer}, sent) // the newest of 10.0.1.0/24, not 10.0.2.0/24 any more
	assert.True(t, m.due().IsZero())

	assert.Empty(t, m.add([]*table.Path{mraiPath("10.0.3.0/24", false, 1)}, start.Add(31*time.Second)))
	assert.Len(t, m.add(nil, start.Add(60*time.Second)), 1) // a later batch takes it along once the interval is over
}

// Without Add-Path a route is the prefix: paths of different sources, with
// different local IDs, replace each other, and a withdrawal drops whatever
// waits. Otherwise the neighbor would keep a path after its withdrawal.
func TestMRAIWithdrawalDropsAdvertisementOfAnotherSource(t *testing.T) {
	start := time.Unix(1000, 0)
	m := newMRAI(30*time.Second, func(bgp.Family) bool { return false })
	assert.Len(t, m.add([]*table.Path{mraiPath("10.0.0.0/24", false, 1)}, start), 1)
	first, second := mraiPath("10.0.1.0/24", false, 2), mraiPath("10.0.1.0/24", false, 3)
	first.SetLocalID(1)
	second.SetLocalID(2)
	assert.Empty(t, m.add([]*table.Path{first}, start.Add(time.Second)))
	assert.Empty(t, m.add([]*table.Path{second}, start.Add(2*time.Second)))
	gone := mraiPath("10.0.1.0/24", true, 3)
	gone.SetLocalID(2)
	assert.Equal(t, []*table.Path{gone}, m.add([]*table.Path{gone}, start.Add(3*time.Second)))
	assert.Empty(t, m.flush(start.Add(30*time.Second)))
}

// With Add-Path send every path is a route of its own.
func TestMRAIWithAddPathKeepsPathsApart(t *testing.T) {
	start := time.Unix(1000, 0)
	m := newMRAI(30*time.Second, func(bgp.Family) bool { return true })
	assert.Len(t, m.add([]*table.Path{mraiPath("10.0.0.0/24", false, 1)}, start), 1)
	first, second := mraiPath("10.0.1.0/24", false, 2), mraiPath("10.0.1.0/24", false, 3)
	first.SetLocalID(1)
	second.SetLocalID(2)
	assert.Empty(t, m.add([]*table.Path{first, second}, start.Add(time.Second)))
	assert.Len(t, m.flush(start.Add(30*time.Second)), 2)
}
