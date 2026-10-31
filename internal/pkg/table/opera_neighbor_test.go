package table

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// Shared tables per neighbor behave as tables of their own: random updates,
// policies and rebuilds give the same exports, forwarding and refresh
// requests with and without sharing.
func TestOperaSharedViewsAsOwn(t *testing.T) {
	for _, pruning := range []Pruning{PruneRefresh, PruneSoft, PruneHard, PruneOff} {
		withOperaOptions(t, OperaOptions{Enabled: true, Pruning: pruning, PerNeighbor: true})
		for seed := range int64(300) {
			operaSharedRun(t, pruning, seed)
		}
	}
}

func operaSharedRun(t *testing.T, pruning Pruning, seed int64) {
	r := rand.New(rand.NewSource(seed))
	keys := []string{"n0", "n1", "n2", "n3", "n4"}
	// a fixed policy per neighbor, n0 and n1 let everything through
	allows := func(k string, p *Path) bool {
		if k == "n0" || k == "n1" {
			return true
		}
		h := fnv.New32a()
		fmt.Fprint(h, k, p.GetAsList())
		return h.Sum32()%3 != 0
	}
	shared, own := newOperaDestination(), newOperaDestination()
	saved := 0
	for step := range 60 {
		src := uint32(1 + r.Intn(4))
		as := []uint32{src}
		for range r.Intn(3) {
			as = append(as, uint32(5+r.Intn(3)))
		}
		as = append(as, 9)
		addr := fmt.Sprintf("10.0.0.%d", src)
		withdraw := r.Intn(4) == 0
		ps, po := operaPath(addr, as, withdraw), operaPath(addr, as, withdraw)
		shared.Calculate(logger, ps)
		own.Calculate(logger, po)
		m := map[string]bool{}
		for _, k := range keys {
			m[k] = allows(k, ps)
			own.OperaFeed(logger, k, po, allows(k, po), true)
		}
		shared.OperaFeedAll(logger, ps, m, true)
		if r.Intn(10) == 0 {
			k := keys[r.Intn(len(keys))]
			for _, d := range []*Destination{shared, own} {
				d.OperaDropView(k)
				for _, c := range d.OperaCandidates(k) {
					d.OperaFeed(logger, k, c, allows(k, c), false)
				}
			}
			shared.OperaShare(k)
		}
		where := fmt.Sprintf("pruning %d, seed %d, step %d", pruning, seed, step)
		for _, k := range keys {
			require.Equal(t, operaDescribe(own.OperaExport(k)), operaDescribe(shared.OperaExport(k)), "%s, export to %s", where, k)
		}
		_, fs := shared.OperaForward()
		_, fo := own.OperaForward()
		require.Equal(t, operaDescribe(fo), operaDescribe(fs), "%s, forwarding", where)
		require.ElementsMatch(t, operaPeers(own.OperaWaiting()), operaPeers(shared.OperaWaiting()), "%s, refresh", where)
		saved += len(own.operaViewList()) - len(shared.operaViewList())
		users := 0
		for _, v := range shared.operaViewList() {
			users += v.users
		}
		require.Equal(t, len(shared.views), users, "%s, users", where)
	}
	if seed == 0 {
		require.Positive(t, saved, "pruning %d: no table shared", pruning)
	}
}

func operaDescribe(p *Path) string {
	if p == nil {
		return "none"
	}
	return fmt.Sprint(p.GetSource().Address, p.GetAsList(), p.IsWithdraw)
}

// operaPeers are the neighbors asked, each once as the requests are queued
// per neighbor.
func operaPeers(l []*PeerInfo) []string {
	var out []string
	for _, p := range l {
		if a := p.Address.String(); !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}
