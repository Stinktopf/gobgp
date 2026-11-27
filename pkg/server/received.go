package server

import (
	"sync/atomic"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// receivedPrefixes counts the UPDATE messages the server handled from all
// neighbors since the start and the prefixes written in them: an UPDATE that
// carries many prefixes is cheaper per prefix than many that carry one each.
type receivedPrefixes struct {
	updates   atomic.Uint64
	announced atomic.Uint64
	withdrawn atomic.Uint64
}

func (r *receivedPrefixes) count(u *bgp.BGPUpdate) {
	announced, withdrawn := len(u.NLRI), len(u.WithdrawnRoutes)
	for _, a := range u.PathAttributes {
		switch v := a.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			announced += len(v.Value)
		case *bgp.PathAttributeMpUnreachNLRI:
			withdrawn += len(v.Value)
		}
	}
	r.updates.Add(1)
	r.announced.Add(uint64(announced))
	r.withdrawn.Add(uint64(withdrawn))
}

// ReceivedPrefixes returns how many UPDATE messages the server handled since
// the start and how many prefixes they announced and withdrew, all neighbors
// and families together.
func (s *BgpServer) ReceivedPrefixes() (updates, announced, withdrawn uint64) {
	return s.received.updates.Load(), s.received.announced.Load(), s.received.withdrawn.Load()
}
