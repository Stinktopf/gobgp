package server

import (
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// rejectedWithdrawals withdraws the unicast paths in filtered. Without an
// Adj-RIB-Out, GoBGP does not know whether it sent them before, so a soft
// reset out after a change of the export policy withdraws them all, with
// OBGP or without. A peer ignores a withdrawal of a route it was never sent.
func rejectedWithdrawals(filtered []*table.Path) []*table.Path {
	l := make([]*table.Path, 0, len(filtered))
	for _, p := range filtered {
		if f := p.GetFamily(); f == bgp.RF_IPv4_UC || f == bgp.RF_IPv6_UC {
			l = append(l, p.Clone(true))
		}
	}
	return l
}

// GetOperaCounts returns, in one walk over the global RIB of family, how many
// paths OBGP sets aside, how many prefixes it knows with a valid path
// admitted or set aside, and how many of those are blocked: a valid path set
// aside, none admitted, so no route. One walk, as the metrics read it on
// every scrape.
func (s *BgpServer) GetOperaCounts(family bgp.Family) (suppressed, known, blocked int, err error) {
	info, err := s.getRibInfo("", family)
	if err != nil {
		return 0, 0, 0, err
	}
	return info.NumSuppressed, info.NumKnown, info.NumBlocked, nil
}

// GetOperaSuppressed returns how many paths of family in the global RIB OBGP
// keeps without admitting them. Together with the admitted paths, they are
// the memory OBGP needs for the destinations of family.
func (s *BgpServer) GetOperaSuppressed(family bgp.Family) (int, error) {
	info, err := s.getRibInfo("", family)
	if err != nil {
		return 0, err
	}
	return info.NumSuppressed, nil
}
