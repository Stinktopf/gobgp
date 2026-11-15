package table

// DecidingStep names the step of the best path selection, in the order of
// insertSort, at which path a wins over path b, "" if none tells them apart.
// For explanations only, as the simulator's trace gives them.
func DecidingStep(a, b *Path) string {
	routerID := func(p, q *Path) *Path {
		w, _ := compareByRouterID(p, q)
		return w
	}
	steps := []struct {
		name string
		by   func(*Path, *Path) *Path
	}{
		{"not stale", compareByLLGRStaleCommunity},
		{"reachable next hop", compareByReachableNexthop},
		{"higher local preference", compareByLocalPref},
		{"own route", compareByLocalOrigin},
		{"shorter AS path", compareByASPath},
		{"better origin", compareByOrigin},
		{"lower MED", compareByMED},
		{"eBGP before iBGP", compareByASNumber},
		{"older", compareByAge},
		{"lower router ID", routerID},
		{"shorter cluster list", compareByClusterListLength},
		{"lower neighbor address", compareByNeighborAddress},
	}
	for _, s := range steps {
		if w := s.by(a, b); w != nil {
			return s.name
		}
	}
	return ""
}
