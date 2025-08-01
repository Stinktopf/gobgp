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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sort"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/log"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

var (
	SelectionOptions oc.RouteSelectionOptionsConfig
	UseMultiplePaths oc.UseMultiplePathsConfig
)

type BestPathReason uint8

const (
	BPR_UNKNOWN BestPathReason = iota
	BPR_DISABLED
	BPR_ONLY_PATH
	BPR_OPERA
	BPR_REACHABLE_NEXT_HOP
	BPR_HIGHEST_WEIGHT
	BPR_LOCAL_PREF
	BPR_LOCAL_ORIGIN
	BPR_ASPATH
	BPR_ORIGIN
	BPR_MED
	BPR_ASN
	BPR_IGP_COST
	BPR_ROUTER_ID
	BPR_OLDER
	BPR_NON_LLGR_STALE
	BPR_NEIGH_ADDR
)

var BestPathReasonStringMap = map[BestPathReason]string{
	BPR_UNKNOWN:            "Unknown",
	BPR_DISABLED:           "Bestpath selection disabled",
	BPR_ONLY_PATH:          "Only Path",
	BPR_OPERA:              "OPERA L-relation",
	BPR_REACHABLE_NEXT_HOP: "Reachable Next Hop",
	BPR_HIGHEST_WEIGHT:     "Highest Weight",
	BPR_LOCAL_PREF:         "Local Pref",
	BPR_LOCAL_ORIGIN:       "Local Origin",
	BPR_ASPATH:             "AS Path",
	BPR_ORIGIN:             "Origin",
	BPR_MED:                "MED",
	BPR_ASN:                "ASN",
	BPR_IGP_COST:           "IGP Cost",
	BPR_ROUTER_ID:          "Router ID",
	BPR_OLDER:              "Older",
	BPR_NON_LLGR_STALE:     "no LLGR Stale",
	BPR_NEIGH_ADDR:         "Neighbor Address",
}

func (r *BestPathReason) String() string {
	return BestPathReasonStringMap[*r]
}

type PeerInfo struct {
	AS                      uint32
	ID                      net.IP
	LocalAS                 uint32
	LocalID                 net.IP
	Address                 net.IP
	LocalAddress            net.IP
	RouteReflectorClient    bool
	RouteReflectorClusterID net.IP
	MultihopTtl             uint8
	Confederation           bool
}

func (lhs *PeerInfo) Equal(rhs *PeerInfo) bool {
	if lhs == rhs {
		return true
	}

	if rhs == nil {
		return false
	}

	if lhs.AS == rhs.AS && lhs.ID.Equal(rhs.ID) && lhs.LocalID.Equal(rhs.LocalID) && lhs.Address.Equal(rhs.Address) {
		return true
	}
	return false
}

func (i *PeerInfo) String() string {
	if i.Address == nil {
		return "local"
	}
	s := bytes.NewBuffer(make([]byte, 0, 64))
	fmt.Fprintf(s, "{ %s | ", i.Address)
	fmt.Fprintf(s, "as: %d", i.AS)
	fmt.Fprintf(s, ", id: %s", i.ID)
	if i.RouteReflectorClient {
		fmt.Fprintf(s, ", cluster-id: %s", i.RouteReflectorClusterID)
	}
	s.WriteString(" }")
	return s.String()
}

func NewPeerInfo(g *oc.Global, p *oc.Neighbor) *PeerInfo {
	clusterID := net.ParseIP(string(p.RouteReflector.State.RouteReflectorClusterId)).To4()
	// exclude zone info
	naddr, _ := net.ResolveIPAddr("ip", p.State.NeighborAddress)
	return &PeerInfo{
		AS:                      p.Config.PeerAs,
		LocalAS:                 g.Config.As,
		LocalID:                 net.ParseIP(g.Config.RouterId).To4(),
		RouteReflectorClient:    p.RouteReflector.Config.RouteReflectorClient,
		Address:                 naddr.IP,
		RouteReflectorClusterID: clusterID,
		MultihopTtl:             p.EbgpMultihop.Config.MultihopTtl,
		Confederation:           p.IsConfederationMember(g),
	}
}

type Destination struct {
	family        bgp.Family
	nlri          bgp.AddrPrefixInterface
	knownPathList []*Path
	localIdMap    *Bitmap
}

func NewDestination(nlri bgp.AddrPrefixInterface, mapSize int, known ...*Path) *Destination {
	d := &Destination{
		family:        bgp.NewFamily(nlri.AFI(), nlri.SAFI()),
		nlri:          nlri,
		knownPathList: known,
		localIdMap:    NewBitmap(mapSize),
	}
	// the id zero means id is not allocated yet.
	if mapSize != 0 {
		d.localIdMap.Flag(0)
	}
	return d
}

func (dd *Destination) Family() bgp.Family {
	return dd.family
}

func (dd *Destination) setFamily(Family bgp.Family) {
	dd.family = Family
}

func (dd *Destination) GetNlri() bgp.AddrPrefixInterface {
	return dd.nlri
}

func (dd *Destination) setNlri(nlri bgp.AddrPrefixInterface) {
	dd.nlri = nlri
}

func (dd *Destination) GetAllKnownPathList() []*Path {
	return dd.knownPathList
}

func rsFilter(id string, as uint32, path *Path) bool {
	isASLoop := func(as uint32, path *Path) bool {
		return slices.Contains(path.GetAsList(), as)
	}

	return id != GLOBAL_RIB_NAME && (path.GetSource().Address.String() == id || isASLoop(as, path))
}

func (dd *Destination) GetKnownPathList(id string, as uint32) []*Path {
	list := make([]*Path, 0, len(dd.knownPathList))
	for _, p := range dd.knownPathList {
		if rsFilter(id, as, p) {
			continue
		}
		list = append(list, p)
	}
	return list
}

func getBestPath(id string, as uint32, pathList []*Path) *Path {
	for _, p := range pathList {
		if rsFilter(id, as, p) {
			continue
		}
		return p
	}
	return nil
}

func (dd *Destination) GetBestPath(id string, as uint32) *Path {
	p := getBestPath(id, as, dd.knownPathList)
	if p == nil || p.IsNexthopInvalid {
		return nil
	}
	return p
}

func (dd *Destination) GetMultiBestPath(id string) []*Path {
	return getMultiBestPath(id, dd.knownPathList)
}

// Calculates best-path among known paths for this destination.
//
// Modifies destination's state related to stored paths. Removes withdrawn
// paths from known paths. Also, adds new paths to known paths.
func (dest *Destination) Calculate(logger log.Logger, newPath *Path) *Update {
	oldKnownPathList := make([]*Path, len(dest.knownPathList))
	copy(oldKnownPathList, dest.knownPathList)

	if newPath.IsWithdraw {
		p := dest.explicitWithdraw(logger, newPath)
		if p != nil && newPath.IsDropped() {
			if id := p.GetNlri().PathLocalIdentifier(); id != 0 {
				dest.localIdMap.Unflag(uint(id))
			}
		}
	} else {
		dest.implicitWithdraw(logger, newPath)
		dest.insertSort(newPath)
	}

	for _, path := range dest.knownPathList {
		if path.GetNlri().PathLocalIdentifier() == 0 {
			id, err := dest.localIdMap.FindandSetZeroBit()
			if err != nil {
				dest.localIdMap.Expand()
				id, _ = dest.localIdMap.FindandSetZeroBit()
			}
			path.GetNlri().SetPathLocalIdentifier(uint32(id))
		}
	}

	l := make([]*Path, len(dest.knownPathList))
	copy(l, dest.knownPathList)
	return &Update{
		KnownPathList:    l,
		OldKnownPathList: oldKnownPathList,
	}
}

// Removes withdrawn paths.
//
// Note:
// We may have disproportionate number of withdraws compared to know paths
// since not all paths get installed into the table due to bgp policy and
// we can receive withdraws for such paths and withdrawals may not be
// stopped by the same policies.
func (dest *Destination) explicitWithdraw(logger log.Logger, withdraw *Path) *Path {
	if logger.GetLevel() >= log.DebugLevel {
		logger.Debug("Removing withdrawals",
			log.Fields{
				"Topic": "Table",
				"Key":   dest.GetNlri().String(),
			})
	}

	// If we have some withdrawals and no know-paths, it means it is safe to
	// delete these withdraws.
	if len(dest.knownPathList) == 0 {
		logger.Debug("Found withdrawals for path(s) that did not get installed",
			log.Fields{
				"Topic": "Table",
				"Key":   dest.GetNlri().String(),
			})
		return nil
	}

	// Match all withdrawals from destination paths.
	isFound := -1
	for i, path := range dest.knownPathList {
		// We have a match if the source and path-id are same.
		if path.EqualBySourceAndPathID(withdraw) {
			isFound = i
			withdraw.GetNlri().SetPathLocalIdentifier(path.GetNlri().PathLocalIdentifier())
		}
	}

	// We do no have any match for this withdraw.
	if isFound == -1 {
		logger.Warn("No matching path for withdraw found, may be path was not installed into table",
			log.Fields{
				"Topic": "Table",
				"Key":   dest.GetNlri().String(),
				"Path":  withdraw,
			})
		return nil
	} else {
		p := dest.knownPathList[isFound]
		dest.knownPathList = append(dest.knownPathList[:isFound], dest.knownPathList[isFound+1:]...)
		return p
	}
}

// Identifies which of known paths are old and removes them.
//
// Known paths will no longer have paths whose new version is present in
// new paths.
func (dest *Destination) implicitWithdraw(logger log.Logger, newPath *Path) {
	found := -1
	for i, path := range dest.knownPathList {
		if path.NoImplicitWithdraw() {
			continue
		}
		// Here we just check if source is same and not check if path
		// version num. as newPaths are implicit withdrawal of old
		// paths and when doing RouteRefresh (not EnhancedRouteRefresh)
		// we get same paths again.
		if newPath.EqualBySourceAndPathID(path) {
			if logger.GetLevel() >= log.DebugLevel {
				logger.Debug("Implicit withdrawal of old path, since we have learned new path from the same peer",
					log.Fields{
						"Topic": "Table",
						"Key":   dest.GetNlri().String(),
						"Path":  path,
					})
			}

			found = i
			newPath.GetNlri().SetPathLocalIdentifier(path.GetNlri().PathLocalIdentifier())
			break
		}
	}
	if found != -1 {
		dest.knownPathList = append(dest.knownPathList[:found], dest.knownPathList[found+1:]...)
	}
}

func (dest *Destination) insertSort(newPath *Path) {
	// Find the correct position for newPath
	insertIdx := sort.Search(len(dest.knownPathList), func(i int) bool {
		//Determine where in the array newPath belongs. The slice
		//is assumed to be in descending order: most preferred to least.
		//
		//	Best path processing will involve following steps:
		//  1. Select a path based on the OPERA L-relation
		//	2.  Select a path with a reachable next hop.
		//	3.  Select the path with the highest weight.
		//	4.  If path weights are the same, select the path with the highest
		//	local preference value.
		//	5.  Prefer locally originated routes (network routes, redistributed
		//	routes, or aggregated routes) over received routes.
		//	6.  Select the route with the shortest AS-path length.
		//	7.  If all paths have the same AS-path length, select the path based
		//	on origin: IGP is preferred over EGP; EGP is preferred over
		//	Incomplete.
		//	8.  If the origins are the same, select the path with lowest MED
		//	value.
		//	9.  If the paths have the same MED values, select the path learned
		//	via EBGP over one learned via IBGP.
		//	10.  Select the route with the lowest IGP cost to the next hop.
		//	11. Select the route received from the peer with the lowest BGP
		//	router ID.
		//
		//	Returns None if best-path among given paths cannot be computed else best
		//	path.
		//	Assumes paths from NC has source equal to None.
		//
		path1 := newPath
		path2 := dest.knownPathList[i]

		if b := compareByOpera(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByLLGRStaleCommunity(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByReachableNexthop(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByLocalPref(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByLocalOrigin(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByASPath(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByOrigin(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByMED(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByASNumber(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByAge(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b, _ := compareByRouterID(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}

		if b := compareByNeighborAddress(path1, path2); b == path1 {
			return true
		} else if b == path2 {
			return false
		}
		return true
	})

	// Insert at the found position
	dest.knownPathList = slices.Insert(dest.knownPathList, insertIdx, newPath)
}

type Update struct {
	KnownPathList    []*Path
	OldKnownPathList []*Path
}

func getMultiBestPath(id string, pathList []*Path) []*Path {
	// The path list of destinations in the global RIB are sorted
	// in descending order. One of the criteria for being a better
	// path is that it has a reachable next hop. Technically, if the
	// first path is unreachable, then it's assumed none of them
	// are. Therefore, we return an empty slice.
	if len(pathList) == 0 || len(pathList) > 0 && pathList[0].IsNexthopInvalid {
		// No reachable next hop found, so we return an empty slice.
		return []*Path{}
	}
	best := pathList[0]

	// Attempt to find the first path that is both reachable and worse than the
	// best path. Then return a slice paths from the best to that index.
	index := sort.Search(len(pathList), func(i int) bool {
		return pathList[i].IsNexthopInvalid || pathList[i].Compare(best) != 0
	})
	return pathList[:index]
}

func (u *Update) GetWithdrawnPath() []*Path {
	if len(u.KnownPathList) == len(u.OldKnownPathList) {
		return nil
	}

	l := make([]*Path, 0, len(u.OldKnownPathList))

	for _, p := range u.OldKnownPathList {
		y := func() bool {
			return slices.Contains(u.KnownPathList, p)
		}()
		if !y {
			l = append(l, p.Clone(true))
		}
	}
	return l
}

func (u *Update) GetChanges(id string, as uint32, peerDown bool) (*Path, *Path, []*Path) {
	best, old := func(id string) (*Path, *Path) {
		old := getBestPath(id, as, u.OldKnownPathList)
		best := getBestPath(id, as, u.KnownPathList)
		if best != nil && best.Equal(old) {
			// RFC4684 3.2. Intra-AS VPN Route Distribution
			// When processing RT membership NLRIs received from internal iBGP
			// peers, it is necessary to consider all available iBGP paths for a
			// given RT prefix, for building the outbound route filter, and not just
			// the best path.
			if best.GetFamily() == bgp.RF_RTC_UC {
				return best, old
			}
			// For BGP Nexthop Tracking, checks if the nexthop reachability
			// was changed or not.
			if best.IsNexthopInvalid != old.IsNexthopInvalid {
				// If the nexthop of the best path became unreachable, we need
				// to withdraw that path.
				if best.IsNexthopInvalid {
					return best.Clone(true), old
				}
				return best, old
			}
			return nil, old
		}
		if best == nil {
			if old == nil {
				return nil, nil
			}
			if peerDown {
				// withdraws were generated by peer
				// down so paths are not in knowpath
				// or adjin.
				old.IsWithdraw = true
				return old, old
			}
			return old.Clone(true), old
		}
		return best, old
	}(id)

	var multi []*Path

	if id == GLOBAL_RIB_NAME && UseMultiplePaths.Enabled {
		diff := func(lhs, rhs []*Path) bool {
			if len(lhs) != len(rhs) {
				return true
			}
			for idx, l := range lhs {
				if !l.Equal(rhs[idx]) {
					return true
				}
			}
			return false
		}
		oldM := getMultiBestPath(id, u.OldKnownPathList)
		newM := getMultiBestPath(id, u.KnownPathList)
		if diff(oldM, newM) {
			multi = newM
			if len(newM) == 0 {
				multi = []*Path{best}
			}
		}
	}
	return best, old, multi
}

func compareByLLGRStaleCommunity(path1, path2 *Path) *Path {
	p1 := path1.IsLLGRStale()
	p2 := path2.IsLLGRStale()
	if p1 == p2 {
		return nil
	} else if p1 {
		return path2
	}
	return path1
}

func compareByReachableNexthop(path1, path2 *Path) *Path {
	//	Compares given paths and selects best path based on reachable next-hop.
	//
	//	If no path matches this criteria, return nil.
	//	For BGP Nexthop Tracking, evaluates next-hop is validated by IGP.

	if path1.IsNexthopInvalid && !path2.IsNexthopInvalid {
		return path2
	} else if !path1.IsNexthopInvalid && path2.IsNexthopInvalid {
		return path1
	}

	return nil
}

func compareByOpera(path1, path2 *Path) *Path {
	if !isOperaEnabled() {
		return nil
	}

	if isBetterOperaPath(path1, path2) {
		fmt.Println("OPERA: new path is better")
		return path1
	}
	if isBetterOperaPath(path2, path1) {
		fmt.Println("OPERA: existing path is better")
		return path2
	}

	best, _ := compareByRouterID(path1, path2)
	fmt.Println("OPERA: Tie-break by Router ID")
	return best
}

func compareByLocalPref(path1, path2 *Path) *Path {
	//	Selects a path with highest local-preference.
	//
	//	Unlike the weight attribute, which is only relevant to the local
	//	router, local preference is an attribute that routers exchange in the
	//	same AS. Highest local-pref is preferred. If we cannot decide,
	//	we return None.
	//
	//	# Default local-pref values is 100
	localPref1, _ := path1.GetLocalPref()
	localPref2, _ := path2.GetLocalPref()
	// Highest local-preference value is preferred.
	if localPref1 > localPref2 {
		return path1
	} else if localPref1 < localPref2 {
		return path2
	} else {
		return nil
	}
}

func compareByLocalOrigin(path1, path2 *Path) *Path {
	// Select locally originating path as best path.
	// Locally originating routes are network routes, redistributed routes,
	// or aggregated routes.
	// Returns None if given paths have same source.
	//
	// If both paths are from same sources we cannot compare them here.
	if path1.GetSource().Equal(path2.GetSource()) {
		return nil
	}

	// Here we consider prefix from NC as locally originating static route.
	// Hence it is preferred.
	if path1.IsLocal() {
		return path1
	}

	if path2.IsLocal() {
		return path2
	}
	return nil
}

func compareByASPath(path1, path2 *Path) *Path {
	// Calculated the best-paths by comparing as-path lengths.
	//
	// Shortest as-path length is preferred. If both path have same lengths,
	// we return None.
	if SelectionOptions.IgnoreAsPathLength {
		return nil
	}

	l1 := path1.GetAsPathLen()
	l2 := path2.GetAsPathLen()

	if l1 > l2 {
		return path2
	} else if l1 < l2 {
		return path1
	} else {
		return nil
	}
}

func compareByOrigin(path1, path2 *Path) *Path {
	//	Select the best path based on origin attribute.
	//
	//	IGP is preferred over EGP; EGP is preferred over Incomplete.
	//	If both paths have same origin, we return None.

	attribute1 := path1.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)
	attribute2 := path2.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN)

	if attribute1 == nil || attribute2 == nil {
		return nil
	}

	origin1 := attribute1.(*bgp.PathAttributeOrigin).Value
	origin2 := attribute2.(*bgp.PathAttributeOrigin).Value

	// If both paths have same origins
	if origin1 == origin2 {
		return nil
	} else if origin1 < origin2 {
		return path1
	} else {
		return path2
	}
}

func compareByMED(path1, path2 *Path) *Path {
	//	Select the path based with lowest MED value.
	//
	//	If both paths have same MED, return None.
	//	By default, a route that arrives with no MED value is treated as if it
	//	had a MED of 0, the most preferred value.
	//	RFC says lower MED is preferred over higher MED value.
	//  compare MED among not only same AS path but also all path,
	//  like bgp always-compare-med

	isInternal := func() bool { return path1.GetAsPathLen() == 0 && path2.GetAsPathLen() == 0 }()

	isSameAS := func() bool {
		firstAS := func(path *Path) uint32 {
			if asPath := path.GetAsPath(); asPath != nil {
				for _, v := range asPath.Value {
					asList := v.GetAS()
					if len(asList) == 0 {
						continue
					}
					switch v.GetType() {
					case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
						continue
					}
					return asList[0]
				}
			}
			return 0
		}
		return firstAS(path1) != 0 && firstAS(path1) == firstAS(path2)
	}()

	if SelectionOptions.AlwaysCompareMed || isInternal || isSameAS {
		getMed := func(path *Path) uint32 {
			attribute := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
			if attribute == nil {
				return 0
			}
			med := attribute.(*bgp.PathAttributeMultiExitDisc).Value
			return med
		}

		med1 := getMed(path1)
		med2 := getMed(path2)
		if med1 == med2 {
			return nil
		} else if med1 < med2 {
			return path1
		}
		return path2
	} else {
		return nil
	}
}

func compareByASNumber(path1, path2 *Path) *Path {
	//Select the path based on source (iBGP/eBGP) peer.
	//
	//eBGP path is preferred over iBGP. If both paths are from same kind of
	//peers, return None.

	// Path from confederation member should be treated as internal (IBGP learned) path.
	isIBGP1 := path1.GetSource().Confederation || path1.IsIBGP()
	isIBGP2 := path2.GetSource().Confederation || path2.IsIBGP()
	// If one path is from ibgp peer and another is from ebgp peer, take the ebgp path.
	if isIBGP1 != isIBGP2 {
		if isIBGP1 {
			return path2
		}
		return path1
	}

	// If both paths are from ebgp or ibpg peers, we cannot decide.
	return nil
}

func compareByRouterID(path1, path2 *Path) (*Path, error) {
	//	Select the route received from the peer with the lowest BGP router ID.
	//
	//	If both paths are eBGP paths, then we do not do any tie breaking, i.e we do
	//	not pick best-path based on this criteria.
	//	RFC: http://tools.ietf.org/html/rfc5004
	//	We pick best path between two iBGP paths as usual.

	// If both paths are from NC we have same router Id, hence cannot compare.
	if path1.IsLocal() && path2.IsLocal() {
		return nil, nil
	}

	// If both paths are from eBGP peers, then according to RFC we need
	// not tie break using router id.
	if !SelectionOptions.ExternalCompareRouterId && !path1.IsIBGP() && !path2.IsIBGP() {
		return nil, nil
	}

	if !SelectionOptions.ExternalCompareRouterId && path1.IsIBGP() != path2.IsIBGP() {
		return nil, fmt.Errorf("this method does not support comparing ebgp with ibgp path")
	}

	// At least one path is not coming from NC, so we get local bgp id.
	id1 := binary.BigEndian.Uint32(path1.GetSource().ID)
	id2 := binary.BigEndian.Uint32(path2.GetSource().ID)

	// If both router ids are same/equal we cannot decide.
	// This case is possible since router ids are arbitrary.
	if id1 == id2 {
		return nil, nil
	} else if id1 < id2 {
		return path1, nil
	} else {
		return path2, nil
	}
}

func compareByNeighborAddress(path1, path2 *Path) *Path {
	// Select the route received from the peer with the lowest peer address as
	// per RFC 4271 9.1.2.2. g

	p1 := path1.GetSource().Address
	if p1 == nil {
		return path1
	}
	p2 := path2.GetSource().Address
	if p2 == nil {
		return path2
	}

	cmp := bytes.Compare(p1, p2)
	if cmp < 0 {
		return path1
	} else if cmp > 0 {
		return path2
	}
	return nil
}

func compareByAge(path1, path2 *Path) *Path {
	if !path1.IsIBGP() && !path2.IsIBGP() && !SelectionOptions.ExternalCompareRouterId {
		age1 := path1.GetTimestamp().UnixNano()
		age2 := path2.GetTimestamp().UnixNano()
		if age1 == age2 {
			return nil
		} else if age1 < age2 {
			return path1
		}
		return path2
	}
	return nil
}

func (dest *Destination) String() string {
	return fmt.Sprintf("Destination NLRI: %s", dest.nlri.String())
}

type DestinationSelectOption struct {
	ID        string
	AS        uint32
	VRF       *Vrf
	adj       bool
	Best      bool
	MultiPath bool
}

func (d *Destination) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.GetAllKnownPathList())
}

func (d *Destination) Select(option ...DestinationSelectOption) *Destination {
	id := GLOBAL_RIB_NAME
	var vrf *Vrf
	adj := false
	best := false
	mp := false
	as := uint32(0)
	for _, o := range option {
		if o.ID != "" {
			id = o.ID
		}
		if o.VRF != nil {
			vrf = o.VRF
		}
		adj = o.adj
		best = o.Best
		mp = o.MultiPath
		as = o.AS
	}
	var paths []*Path
	if adj {
		paths = make([]*Path, len(d.knownPathList))
		copy(paths, d.knownPathList)
	} else {
		paths = d.GetKnownPathList(id, as)
		if vrf != nil {
			ps := make([]*Path, 0, len(paths))
			for _, p := range paths {
				if CanImportToVrf(vrf, p) {
					ps = append(ps, p.ToLocal())
				}
			}
			paths = ps
		}
		if len(paths) == 0 {
			return nil
		}
		if best {
			if !mp {
				paths = []*Path{paths[0]}
			} else {
				ps := make([]*Path, 0, len(paths))
				var best *Path
				for _, p := range paths {
					if best == nil {
						best = p
						ps = append(ps, p)
					} else if best.Compare(p) == 0 {
						ps = append(ps, p)
					}
				}
				paths = ps
			}
		}
	}
	return NewDestination(d.nlri, 0, paths...)
}
