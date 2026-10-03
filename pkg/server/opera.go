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
