package server

import (
	"fmt"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
)

// mrai holds back the advertisements to a peer, so that at most one batch
// of them goes out per MinRouteAdvertisementInterval (RFC 4271, 9.2.1.1),
// as routers commonly do towards eBGP peers. A newer advertisement of a
// route replaces the one that waits. Withdrawals are not held back, and
// drop an advertisement of the same route that waits. Without an interval
// everything goes out at once.
type mrai struct {
	interval time.Duration
	last     time.Time      // when the last advertisements went out
	waiting  map[string]int // a route's place in order
	order    []*table.Path  // what waits, nil where it was dropped
}

func newMRAI(interval time.Duration) *mrai {
	return &mrai{interval: interval, waiting: map[string]int{}}
}

func mraiKey(p *table.Path) string {
	return fmt.Sprintf("%d|%s|%d", p.GetFamily(), p.GetNlri().String(), p.LocalID())
}

// add takes a batch of paths for the peer and returns those to send now.
func (m *mrai) add(paths []*table.Path, now time.Time) []*table.Path {
	if m.interval <= 0 {
		return paths
	}
	var send []*table.Path
	for _, p := range paths {
		k := mraiKey(p)
		if i, ok := m.waiting[k]; ok {
			m.order[i] = nil
			delete(m.waiting, k)
		}
		if p.IsWithdraw {
			send = append(send, p)
			continue
		}
		m.waiting[k] = len(m.order)
		m.order = append(m.order, p)
	}
	if len(m.waiting) > 0 && now.Sub(m.last) >= m.interval {
		send = append(send, m.flush(now)...)
	}
	return send
}

// flush returns what waits, if its interval has passed.
func (m *mrai) flush(now time.Time) []*table.Path {
	if len(m.waiting) == 0 || now.Sub(m.last) < m.interval {
		return nil
	}
	send := make([]*table.Path, 0, len(m.waiting))
	for _, p := range m.order {
		if p != nil {
			send = append(send, p)
		}
	}
	m.order, m.waiting, m.last = nil, map[string]int{}, now
	return send
}

// due is when what waits may go out, the zero time if nothing waits.
func (m *mrai) due() time.Time {
	if len(m.waiting) == 0 {
		return time.Time{}
	}
	return m.last.Add(m.interval)
}
