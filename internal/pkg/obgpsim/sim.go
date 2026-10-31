// Package obgpsim plays the BGP updates of one prefix between routers that
// run the decision code of the table package, as BGP or as OBGP, with
// policies at the sessions and the messages in random order. It finds where
// OBGP deviates from BGP: the network is simulated, the decisions are the
// ones gobgpd makes.
//
// Modeled like gobgpd: a session is a FIFO queue, a path is not sent back to
// the peer it came from nor to a peer whose AS it contains, a path rejected
// by an import filter becomes a withdrawal, and a lost session withdraws the
// paths of the peer as dropped by the session. Inside an AS, routers speak
// iBGP in a full mesh or through route reflectors, with next-hop-self at the
// border, and forward over the IGP. gobgpd compares no IGP costs, so they
// only steer forwarding. A route server adds no AS and leaves the next hop,
// as gobgpd's. Not modeled: timers such as MRAI and hold time, more than
// one prefix.
package obgpsim

import (
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand"
	"net/netip"
	"slices"
	"time"

	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Mode is the decision process all routers run.
type Mode string

const (
	BGP       Mode = "bgp"
	OBGP      Mode = "obgp-rp"    // refresh pruning, native iBGP, AS_SET ordered canonically, confederation hops counted
	OBGPSoft  Mode = "obgp-sp"    // soft pruning, otherwise as obgp-rp
	OBGPHard  Mode = "obgp-hp"    // hard pruning, otherwise as obgp-rp
	OBGPNP    Mode = "obgp-np"    // without pruning, otherwise as obgp-rp
	OBGPPaper Mode = "obgp-paper" // as in the paper: hard pruning, iBGP filtered, AS_SET as received, confederation hops ignored
)

var Modes = []Mode{BGP, OBGP, OBGPSoft, OBGPHard, OBGPNP, OBGPPaper}

// options are the settings of OBGP in mode m. obgp-paper filters iBGP paths
// and keeps the received AS_SET order and ignores confederation hops, the
// others run iBGP natively and count them.
func (m Mode) options() table.OperaOptions {
	pruning := map[Mode]table.Pruning{OBGPSoft: table.PruneSoft, OBGPHard: table.PruneHard, OBGPNP: table.PruneOff, OBGPPaper: table.PruneHard}[m]
	return table.OperaOptions{Enabled: m != BGP, Pruning: pruning, FilterIBGP: m == OBGPPaper, ReceivedSetOrder: m == OBGPPaper, IgnoreConfedHops: m == OBGPPaper}
}

// calculate runs the decision of router r.
func (n *network) calculate(r int, p *table.Path) {
	n.routers[r].dest.Calculate(logger, p)
	if n.perNeighbor() {
		allows := map[string]bool{}
		for _, j := range n.peers(r) {
			if !n.internal(r, j) {
				allows[fmt.Sprint(j)] = n.allows(r, j, p)
			}
		}
		n.routers[r].dest.OperaFeedAll(logger, p, allows, true)
	}
}

// PerNeighbor runs the OBGP modes but obgp-paper with a table per eBGP
// neighbor, as gobgpd's with GOBGP_OPERA_EXPORT=neighbor.
var PerNeighbor bool

func (n *network) perNeighbor() bool { return PerNeighbor && n.mode != BGP && n.mode != OBGPPaper }

// allows tells whether path p of router r goes into its table towards j,
// as gobgpd's operaAllows: if r's export policy lets it through, j's own
// path and one through j's AS also if only split horizon and the AS loop
// stop them, for the threshold.
func (n *network) allows(r, j int, p *table.Path) bool {
	if p.IsWithdraw {
		return false
	}
	ownSplit = true
	defer func() { ownSplit = false }()
	return n.offerEBGP(r, j, p) != nil
}

// ownSplit lets offerEBGP pass what only split horizon and the AS loop stop.
var ownSplit bool

// syncTables brings router r's tables per neighbor up to date with its
// export policy, as gobgpd's operaSync, and drops those of neighbors down.
func (n *network) syncTables(r int) {
	if !n.perNeighbor() {
		return
	}
	d := n.routers[r].dest
	for _, l := range n.inst.Links {
		for k, j := range l {
			if l[1-k] != r || n.internal(r, j) {
				continue
			}
			if !n.up[session{r, j}] {
				d.OperaDropView(fmt.Sprint(j))
				continue
			}
			for _, c := range d.OperaCandidates(fmt.Sprint(j)) {
				d.OperaFeed(logger, fmt.Sprint(j), c, n.allows(r, j, c), false)
			}
			d.OperaShare(fmt.Sprint(j))
		}
	}
}

// best is the path router i forwards on.
func (n *network) best(i int) *table.Path {
	d := n.routers[i].dest
	if n.perNeighbor() {
		d.OperaForward()
		return d.OperaForwarding()
	}
	return d.GetBestPath(table.GLOBAL_RIB_NAME, 0)
}

// exportTo is the path router i offers eBGP neighbor j before filters.
func (n *network) exportTo(i, j int) *table.Path {
	if n.perNeighbor() && !n.internal(i, j) {
		return n.routers[i].dest.OperaExport(fmt.Sprint(j))
	}
	return n.exportPath(i)
}

// Relation is what a neighbor is to a router under Gao-Rexford. Siblings,
// ASes of one organization, pass each other every route, and a route from
// a sibling keeps the class it was learned with there.
type Relation int

const (
	NoRelation Relation = iota
	Customer
	Peer
	Provider
	Sibling
)

// Local Preference by the relation of the neighbor a path came from, as in the lab.
var relationPref = map[Relation]uint32{Customer: 200, Peer: 150, Provider: 100}

// Session holds the policies of the directed eBGP session From -> To: what
// From exports to To, and what To imports from From.
type Session struct {
	From       int    `json:"from"`
	To         int    `json:"to"`
	DenyExport bool   `json:"deny_export,omitempty"`     // From exports nothing to To
	DenyVia    uint32 `json:"deny_via,omitempty"`        // From exports no path through this AS to To
	Prepend    int    `json:"prepend,omitempty"`         // extra copies of From's AS towards To
	MED        uint32 `json:"med,omitempty"`             // From sets this MED towards To
	DenyImport bool   `json:"deny_import,omitempty"`     // To rejects every path from From
	LocalPref  uint32 `json:"local_pref,omitempty"`      // at To for paths from From, 0 for the default
	Tag        string `json:"tag,omitempty"`             // To adds this community to the paths from From
	Partial    bool   `json:"partial_transit,omitempty"` // From, a provider, sends its customer To only the paths of its customers
}

// Event changes the network after a number of delivered messages, or once
// the network is quiet if that comes first. Events of the lab's steps:
// withdraw, announce, down, up (links), prepend-all (prepend: one session),
// deny-export (set_export), deny-import (set_import), local-pref
// (set_preference, From the neighbor, To the router) and expect.
type Event struct {
	After int    `json:"after"`
	Kind  string `json:"kind"`
	From  int    `json:"from,omitempty"`
	To    int    `json:"to,omitempty"`
	Value int    `json:"value,omitempty"` // prepend: copies, deny-*: 1 on, 0 off, local-pref: the value, 0 for the default
	// expect: as the lab's step checks the best routes of Routers.
	Routers    []int  `json:"routers,omitempty"`
	Prefixes   string `json:"prefixes,omitempty"` // all, none or any; empty: all
	Via        *int   `json:"via,omitempty"`
	Avoid      *int   `json:"avoid,omitempty"`
	Forwarding bool   `json:"forwarding,omitempty"`
	Consistent bool   `json:"consistent,omitempty"` // every AS sends its neighbors in other ASes one path
}

// Verdict is what an expect event found, as the lab's expect step reports it.
type Verdict struct {
	Passed   bool     `json:"passed"`
	Problems []string `json:"problems,omitempty"`
}

// IBGP is how the routers of an AS with more than one router speak iBGP: a
// full mesh, or clients of route reflectors that mesh among themselves.
type IBGP struct {
	AS         int   `json:"as"`
	Reflectors []int `json:"reflectors,omitempty"` // none: a full mesh
}

// Confed is a confederation (RFC 5065): its member ASes speak eBGP with
// each other, an AS_CONFED_SEQUENCE in the path, and the world sees them
// as one AS, the identifier.
type Confed struct {
	Members []int  `json:"members"` // AS indices
	ID      uint32 `json:"id"`
}

// Instance is one network: router Origin, 0 unless set, originates the
// prefix. Without AS, every router is an AS of its own, 65001 for router 0
// and so on.
type Instance struct {
	Family    string   `json:"family,omitempty"` // what the search varied
	Routers   int      `json:"routers"`
	Origin    int      `json:"origin,omitempty"`
	OriginSet []uint32 `json:"origin_set,omitempty"` // the origin announces an aggregate: an AS_SET of these
	// Poisoned ASes stand in the origin's path before its own, so that they
	// drop the route as a loop. Communities ask the routers on the way not
	// to pass it on: no-export, no-advertise, or 0:AS not to that AS.
	OriginPoison      []uint32  `json:"origin_poison,omitempty"`
	OriginCommunities []string  `json:"origin_communities,omitempty"`
	ASNumbers         []uint32  `json:"asns,omitempty"`       // the AS number of each AS index, 65001 + index if not given
	RouterIDs         []string  `json:"router_ids,omitempty"` // the BGP Identifier of each router, 10.0.0.1 on if not given
	AS                []int     `json:"as,omitempty"`         // the AS of each router, an index: AS number 65001 + index
	Links             [][2]int  `json:"links"`                // inside an AS a link of the IGP, else an eBGP session
	Costs             []int     `json:"costs,omitempty"`
	IBGP              []IBGP    `json:"ibgp,omitempty"`      // per AS with more routers; none given: a full mesh
	Confeds           []Confed  `json:"confeds,omitempty"`   // confederations of ASes, each AS a member
	Customers         [][2]int  `json:"customers,omitempty"` // (provider, customer) routers; with Peers the Gao-Rexford relations
	Peers             [][2]int  `json:"peers,omitempty"`
	Siblings          [][2]int  `json:"siblings,omitempty"`
	Leakers           []int     `json:"leakers,omitempty"` // routers that export everything to everyone, ignoring valley-free
	Sessions          []Session `json:"sessions,omitempty"`
	// Route servers pass their clients' paths on as they came, as gobgpd's:
	// one table for all clients, for each client the best path with BGP or
	// the worst admitted with OBGP of the others, then its export filter.
	RouteServers []int   `json:"route_servers,omitempty"`
	Events       []Event `json:"events,omitempty"`
	Seed         int64   `json:"seed"`
}

// AS is the AS number of AS index i, which is router i unless Instance.AS
// groups routers, when ASNumbers does not give it.
func AS(i int) uint32 { return 65001 + uint32(i) }

// ASN is the AS number of router r. The lab's numbers matter: OBGP orders
// paths by them.
func (inst *Instance) ASN(r int) uint32 {
	if a := inst.asOf(r); a < len(inst.ASNumbers) {
		return inst.ASNumbers[a]
	}
	return AS(inst.asOf(r))
}

// id is the BGP Identifier of router r. The lab's matter: iBGP and route
// reflectors break ties by them.
func (inst *Instance) id(r int) netip.Addr {
	if r < len(inst.RouterIDs) {
		if a, err := netip.ParseAddr(inst.RouterIDs[r]); err == nil {
			return a
		}
	}
	return addr(r)
}

func (inst *Instance) asOf(r int) int {
	if len(inst.AS) == 0 {
		return r
	}
	return inst.AS[r]
}

func addr(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i + 1)}) }

// Result is the network once it is quiet, or when it gave up.
type Result struct {
	Mode      Mode         `json:"mode"`
	Converged bool         `json:"converged"`
	Steps     int          `json:"steps"`
	Best      [][]uint32   `json:"best"`     // the AS path each router uses, nil for none
	NextHop   []int        `json:"next_hop"` // its BGP next hop, -1 for none, the router itself for the origin
	Exported  [][]uint32   `json:"exported"` // what each router offers its eBGP neighbors before per-neighbor filters
	Offered   [][][]uint32 `json:"offered"`  // what each router sends its neighbors in other ASes, own prepends taken off: as the lab sees it
	Checks    []Verdict    `json:"checks,omitempty"`
	Costs     []int        `json:"costs,omitempty"` // of the links at the end, igp events applied
	// Transient: forwarding went in a circle at some moment before the end,
	// as it was after a delivered message, the routers in the first circle.
	Transient []int `json:"transient,omitempty"`
	// After how many delivered messages forwarding went in a circle (Looped),
	// a router without a route waited for a route refresh (Blocked, as a
	// router of DUAL waits while it is active), or a router had no route for a
	// while without waiting, one it holds again at the end (Holes). Counted
	// only with Transient.
	Looped  int `json:"looped,omitempty"`
	Blocked int `json:"blocked,omitempty"`
	Holes   int `json:"holes,omitempty"`
}

var prefix = netip.MustParsePrefix("10.0.0.0/24")

var logger = slog.New(slog.NewTextHandler(io.Discard, nil))

type session struct{ from, to int }

// route is what a session carries for one path ID.
type route struct {
	path        []uint32 // the AS sequence
	set         []uint32 // an AS_SET after it, of an aggregate
	confed      []uint32 // an AS_CONFED_SEQUENCE before it, inside a confederation
	learned     Relation // the Gao-Rexford class it was learned from, carried as the lab's community
	communities []uint32 // those of the origin
	nexthop     int      // the router to forward to
	localPref   uint32
	med         uint32
	originator  int // set by a route reflector, else -1
	clusters    []int
}

type message struct {
	id       uint32 // the path ID, 0 unless several paths share a session
	withdraw bool
	refresh  bool // a request for the current routes, from the receiver's peer
	route    route
}

type router struct {
	dest *table.Destination
	sent map[session]map[uint32]string // what a session carries, by path ID
}

type network struct {
	inst      *Instance
	mode      Mode
	rng       *rand.Rand
	routers   []*router
	up        map[session]bool // eBGP and IGP links, both directions
	ibgp      map[session]bool // iBGP sessions, both directions
	client    map[session]bool // (reflector, client)
	queues    map[session][]message
	received  map[session]map[uint32]route     // Adj-RIB-In before import policy
	stamps    map[session]map[uint32]time.Time // when a route arrived, kept while it is resent unchanged
	policy    map[session]*Session
	relation  map[session]Relation // what To is to From
	asked     map[session]bool     // refresh requests still unanswered
	origin    *table.Path
	byAddress map[netip.Addr]int
	byID      map[netip.Addr]int
	checks    []Verdict
	costs     []int // of the links, changed by igp events
	// Path timestamps: GoBGP breaks ties between eBGP paths by age in whole
	// seconds, so the time must not depend on the machine. Between two
	// messages a second may pass or not, ticks decides with a generator of
	// its own, so that the order of messages stays as each seed has it.
	clock     int64
	ticks     *rand.Rand
	transient []int  // the first forwarding loop on the way, if any
	had       []bool // routers that held a route at some moment, for Blocked and Holes
	looped    int
	waits     [][]int // per delivered message, the routers without a route that wait for a refresh
	losses    [][]int // per delivered message, the routers without a route that do not wait
	igp       [][]int // next hops inside an AS, for the costs now
}

func (n *network) now() time.Time {
	n.clock++
	return time.Unix(1_700_000_000, n.clock)
}

// tick lets a second pass between two messages, or not.
func (n *network) tick() {
	if n.ticks.Intn(2) == 1 {
		n.clock += int64(time.Second)
	}
}

// Run plays the instance in one mode.
// The table settings are global to the process: runs must not overlap.
func Run(inst *Instance, mode Mode, maxSteps int) Result {
	return run(inst, mode, maxSteps, nil)
}

// Trace plays the instance in one mode as Run does and writes every message
// delivered to w, with the path and next hop each router forwards on after it.
func Trace(inst *Instance, mode Mode, w io.Writer) Result {
	return run(inst, mode, MaxSteps, w)
}

// Step is one delivered message and the state of every router after it,
// for tools that replay a run.
type Step struct {
	From    int           `json:"from"`
	To      int           `json:"to"`
	Kind    string        `json:"kind"` // update, withdraw, refresh, or event for a change from outside
	Path    []uint32      `json:"path,omitempty"`
	Event   *Event        `json:"event,omitempty"` // the change from outside, From and To -1
	Routers []RouterState `json:"routers"`
	Loop    []int         `json:"loop,omitempty"` // the routers of a forwarding loop now
}

// RouterState is what a router holds and does after a message.
type RouterState struct {
	Best     []uint32   `json:"best"`     // the AS path it forwards on, nil for none
	NextHop  int        `json:"next_hop"` // -1 for none, the router itself at the origin
	Admitted [][]uint32 `json:"admitted"`
	SetAside [][]uint32 `json:"set_aside"`
	Exported []uint32   `json:"exported"` // what it offers its eBGP neighbors: BGP its best, OBGP its worst admitted path
	Waits    bool       `json:"waits"`    // without a route, waiting for a route refresh
	In       []Received `json:"in"`       // per neighbor, what it last sent and what became of it
	Out      []Sent     `json:"out"`      // per neighbor, what it is sent now, or why nothing
}

// Received is the path a neighbor last sent a router and its fate there:
// best, admitted, set aside (OBGP's order keeps it out), filtered (the
// import policy), loop (the router's AS in it), pruned (hard pruning
// deleted it), dropped (gone from the table otherwise), or none (nothing sent).
type Received struct {
	From int      `json:"from"`
	Path []uint32 `json:"path"`
	Fate string   `json:"fate"`
}

// Sent is what a router sends a neighbor, the AS path as the neighbor gets
// it, or nil and why not.
type Sent struct {
	To   int      `json:"to"`
	Path []uint32 `json:"path"`
	Not  string   `json:"not,omitempty"`
}

// Record plays the instance in one mode as Run does and returns every step.
func Record(inst *Instance, mode Mode) (Result, []Step) {
	var steps []Step
	r := runRecorded(inst, mode, MaxSteps, nil, &steps)
	return r, steps
}

func kindOf(m message) string {
	switch {
	case m.refresh:
		return "refresh"
	case m.withdraw:
		return "withdraw"
	}
	return "update"
}

func pathOf(m message) []uint32 {
	if m.refresh || m.withdraw {
		return nil
	}
	return m.route.path
}

// record appends a step, a delivered message or an event, with the state of
// every router after it.
func (n *network) record(steps *[]Step, st Step) {
	st.Loop = n.circle()
	paths := func(ps []*table.Path) [][]uint32 {
		out := [][]uint32{}
		for _, p := range ps {
			if !p.IsWithdraw {
				out = append(out, p.GetAsList())
			}
		}
		return out
	}
	for i, r := range n.routers {
		rs := RouterState{NextHop: -1, Admitted: paths(r.dest.GetAllKnownPathList()), SetAside: paths(r.dest.OperaSetAside())}
		if best := n.best(i); best != nil && !best.IsWithdraw {
			rs.Best, rs.NextHop = flat(best), n.nexthop(i, best)
		}
		if p := n.exportPath(i); p != nil {
			rs.Exported = p.GetAsList()
		}
		rs.Waits = rs.Best == nil && len(r.dest.OperaWaiting()) > 0
		rs.In, rs.Out = n.ins(i), n.outs(i)
		st.Routers = append(st.Routers, rs)
	}
	*steps = append(*steps, st)
}

// neighbors are the routers router i has a link or an iBGP session to, in order.
func (n *network) neighbors(i int) []int {
	var l []int
	for j := range n.routers {
		linked := slices.ContainsFunc(n.inst.Links, func(k [2]int) bool { return k == [2]int{i, j} || k == [2]int{j, i} })
		if j != i && (linked || n.internal(i, j) && n.ibgp[session{i, j}]) {
			l = append(l, j)
		}
	}
	return l
}

// ins is, per neighbor, what it last sent router i and its fate there.
func (n *network) ins(i int) []Received {
	d := n.routers[i].dest
	same := func(a, b *table.Path) bool {
		return a.GetSource() != nil && b.GetSource() != nil && a.GetSource().Address == b.GetSource().Address &&
			slices.Equal(a.GetAsList(), b.GetAsList())
	}
	in := func(l []*table.Path, p *table.Path) bool {
		return slices.ContainsFunc(l, func(q *table.Path) bool { return !q.IsWithdraw && same(q, p) })
	}
	out := []Received{}
	for _, j := range n.neighbors(i) {
		s := session{j, i}
		ids := slices.Sorted(maps.Keys(n.received[s]))
		if len(ids) == 0 {
			out = append(out, Received{From: j, Fate: "none"})
			continue
		}
		for _, id := range ids {
			r := n.received[s][id]
			got := Received{From: j, Path: slices.Concat(r.confed, r.path, r.set)} // as GetAsList: the AS_SET at the end
			pol := n.policy[s]
			switch p := n.pathOf(s, id, false); {
			case slices.Contains(slices.Concat(r.confed, r.path, r.set), n.localAS(i, j)) || n.internal(j, i) && (r.originator == i || slices.Contains(r.clusters, i)):
				got.Fate = "loop"
			case !n.internal(j, i) && pol != nil && pol.DenyImport:
				got.Fate = "filtered"
			case n.best(i) != nil && same(n.best(i), p):
				got.Fate = "best"
			case in(d.GetAllKnownPathList(), p):
				got.Fate = "admitted"
			case in(d.OperaSetAside(), p):
				got.Fate = "set aside"
			case n.mode == OBGPHard || n.mode == OBGPPaper:
				got.Fate = "pruned" // hard pruning deleted it, and it stays out until the neighbor sends anew
			default:
				got.Fate = "dropped"
			}
			out = append(out, got)
		}
	}
	return out
}

// outs is, per neighbor, what router i sends it now, or why nothing.
func (n *network) outs(i int) []Sent {
	out := []Sent{}
	for _, j := range n.neighbors(i) {
		switch {
		case !n.internal(i, j) && !n.up[session{i, j}]:
			out = append(out, Sent{To: j, Not: "the session is down"})
		case n.internal(i, j):
			routes := n.offerIBGP(i, j)
			if len(routes) == 0 {
				out = append(out, Sent{To: j, Not: notNothing})
			}
			for _, id := range slices.Sorted(maps.Keys(routes)) {
				r := routes[id]
				out = append(out, Sent{To: j, Path: slices.Concat(r.confed, r.path, r.set)})
			}
		default:
			if r, why := n.offerWhy(i, j, n.exportTo(i, j)); r != nil {
				out = append(out, Sent{To: j, Path: slices.Concat(r.confed, r.path, r.set)})
			} else {
				out = append(out, Sent{To: j, Not: why})
			}
		}
	}
	return out
}

func run(inst *Instance, mode Mode, maxSteps int, trace io.Writer) Result {
	return runRecorded(inst, mode, maxSteps, trace, nil)
}

func runRecorded(inst *Instance, mode Mode, maxSteps int, trace io.Writer, record *[]Step) Result {
	old := table.GetOperaOptions()
	table.SetOperaOptions(mode.options())
	defer table.SetOperaOptions(old)

	n := &network{inst: inst, mode: mode, rng: rand.New(rand.NewSource(inst.Seed)), ticks: rand.New(rand.NewSource(inst.Seed ^ 0x5eed)),
		up: map[session]bool{}, ibgp: map[session]bool{}, client: map[session]bool{}, queues: map[session][]message{}, asked: map[session]bool{},
		received: map[session]map[uint32]route{}, stamps: map[session]map[uint32]time.Time{}, policy: map[session]*Session{}, relation: map[session]Relation{},
		byAddress: map[netip.Addr]int{}, byID: map[netip.Addr]int{}}
	nlri, _ := bgp.NewIPAddrPrefix(prefix)
	for i := 0; i < inst.Routers; i++ {
		n.routers = append(n.routers, &router{dest: table.NewDestination(nlri, 64), sent: map[session]map[uint32]string{}})
		n.byAddress[addr(i)] = i
		n.byID[inst.id(i)] = i
	}
	for _, l := range inst.Links {
		n.up[session{l[0], l[1]}], n.up[session{l[1], l[0]}] = true, true
	}
	n.meshIBGP()
	for k := range inst.Links {
		cost := 1
		if k < len(inst.Costs) && inst.Costs[k] > 0 {
			cost = inst.Costs[k]
		}
		n.costs = append(n.costs, cost)
	}
	for _, c := range inst.Customers {
		n.relation[session{c[0], c[1]}], n.relation[session{c[1], c[0]}] = Customer, Provider
	}
	for _, p := range inst.Peers {
		n.relation[session{p[0], p[1]}], n.relation[session{p[1], p[0]}] = Peer, Peer
	}
	for _, p := range inst.Siblings {
		n.relation[session{p[0], p[1]}], n.relation[session{p[1], p[0]}] = Sibling, Sibling
	}
	for i := range inst.Sessions {
		s := inst.Sessions[i]
		n.policy[session{s.From, s.To}] = &s
	}

	n.originate(true)
	steps, events := 0, slices.Clone(inst.Events)
	slices.SortStableFunc(events, func(a, b Event) int { return a.After - b.After })
	for {
		pending := n.pending()
		for len(events) > 0 && (events[0].After <= steps || len(pending) == 0) {
			n.apply(events[0])
			if record != nil && events[0].Kind != "expect" {
				e := events[0]
				n.record(record, Step{From: -1, To: -1, Kind: "event", Event: &e})
			}
			events = events[1:]
			pending = n.pending()
		}
		if len(pending) == 0 {
			break
		}
		if steps >= maxSteps {
			return n.result(false, steps)
		}
		s := pending[n.rng.Intn(len(pending))]
		m := n.queues[s][0]
		n.queues[s] = n.queues[s][1:]
		n.tick()
		n.deliver(s, m)
		steps++
		if trace != nil {
			n.trace(trace, steps, s, m)
		}
		if record != nil {
			n.record(record, Step{From: s.from, To: s.to, Kind: kindOf(m), Path: pathOf(m)})
		}
		if Transient {
			n.classify()
		}
	}
	return n.result(true, steps)
}

// trace writes one delivered message and how every router forwards after it:
// its best AS path, "local" at the origin, and the router it forwards to,
// inside an AS the exit.
func (n *network) trace(w io.Writer, step int, s session, m message) {
	what := "update " + fmt.Sprint(m.route.path)
	switch {
	case m.refresh:
		what = "route refresh"
	case m.withdraw:
		what = "withdraw"
	}
	fmt.Fprintf(w, "%5d  %d -> %d  %-24s |", step, s.from, s.to, what)
	for i := range n.routers {
		best := n.best(i)
		switch {
		case best == nil || best.IsWithdraw:
			fmt.Fprintf(w, "  %d: -", i)
		case best.IsLocal():
			fmt.Fprintf(w, "  %d: local", i)
		default:
			fmt.Fprintf(w, "  %d: %v > %d", i, best.GetAsList(), n.nexthop(i, best))
		}
	}
	fmt.Fprintln(w)
}

// classify counts the moment after a delivered message as a loop, a router
// blocked while it waits for a route refresh, or a router without a route
// that does not wait. A router counts only once it held a route, so that the
// first spread of the prefix is no hole.
func (n *network) classify() {
	if c := n.circle(); c != nil {
		if n.transient == nil {
			n.transient = c
		}
		n.looped++
	}
	if n.had == nil {
		n.had = make([]bool, len(n.routers))
	}
	var waits, losses []int
	for i := range n.routers {
		if best := n.best(i); best != nil && !best.IsWithdraw {
			n.had[i] = true
			continue
		}
		if !n.had[i] {
			continue
		}
		if d := n.routers[i].dest; d != nil && len(d.OperaWaiting()) > 0 {
			waits = append(waits, i)
		} else {
			losses = append(losses, i)
		}
	}
	n.waits, n.losses = append(n.waits, waits), append(n.losses, losses)
}

// waiting counts the messages after which some router waited for a route
// refresh without a route, whether the route comes back or not.
func waiting(moments [][]int) int {
	count := 0
	for _, routers := range moments {
		if len(routers) > 0 {
			count++
		}
	}
	return count
}

// passing counts the messages after which some router was without a route
// that it holds again at the end: lost for a while, not gone.
func passing(moments [][]int, final Result) int {
	count := 0
	for _, routers := range moments {
		for _, i := range routers {
			if final.Best[i] != nil {
				count++
				break
			}
		}
	}
	return count
}

// circle is a forwarding loop as the routers forward now, nil for none.
func (n *network) circle() []int {
	r := Result{Costs: n.costs}
	for i := range n.routers {
		best := n.best(i)
		if best == nil || best.IsWithdraw {
			r.Best, r.NextHop = append(r.Best, nil), append(r.NextHop, -1)
		} else {
			path := []uint32{} // enough to follow, but for the exit of a tunnel
			if Tunnel {
				path = flat(best)
			}
			r.Best, r.NextHop = append(r.Best, path), append(r.NextHop, n.nexthop(i, best))
		}
	}
	if n.igp == nil {
		n.igp = shortest(n.inst, n.costs)
	}
	return firstLoop(n.inst, r, n.igp)
}

// meshIBGP sets up the iBGP sessions of every AS with more than one router.
func (n *network) meshIBGP() {
	members := map[int][]int{}
	for r := range n.inst.Routers {
		members[n.inst.asOf(r)] = append(members[n.inst.asOf(r)], r)
	}
	reflectors := map[int][]int{}
	for _, c := range n.inst.IBGP {
		reflectors[c.AS] = c.Reflectors
	}
	for as, rs := range members {
		rr := reflectors[as]
		for _, a := range rs {
			for _, b := range rs {
				if a == b {
					continue
				}
				aRR, bRR := slices.Contains(rr, a), slices.Contains(rr, b)
				if len(rr) == 0 || aRR || bRR {
					n.ibgp[session{a, b}] = true
				}
				if aRR && !bRR {
					n.client[session{a, b}] = true
				}
			}
		}
	}
}

func (n *network) internal(a, b int) bool { return n.inst.asOf(a) == n.inst.asOf(b) }

func (n *network) asn(r int) uint32 { return n.inst.ASN(r) }

// confed is the confederation of router r, or nil.
func (n *network) confed(r int) *Confed {
	for k := range n.inst.Confeds {
		if slices.Contains(n.inst.Confeds[k].Members, n.inst.asOf(r)) {
			return &n.inst.Confeds[k]
		}
	}
	return nil
}

// confedPeers tells whether a and b are in different members of one confederation.
func (n *network) confedPeers(a, b int) bool {
	c := n.confed(a)
	return !n.internal(a, b) && c != nil && c == n.confed(b)
}

// localAS is the AS router i is to j: its own inside the confederation,
// else the confederation's identifier, as gobgpd's local-as.
func (n *network) localAS(i, j int) uint32 {
	if c := n.confed(i); c != nil && !n.internal(i, j) && !n.confedPeers(i, j) {
		return c.ID
	}
	return n.asn(i)
}

// learnedOf is the Gao-Rexford class a path of router i was learned from:
// of its session from outside, else as carried over iBGP and confederation
// sessions, as the lab's community.
func (n *network) learnedOf(i int, p *table.Path) Relation {
	if p.IsLocal() {
		return Customer // the own prefix goes to everyone
	}
	from := n.source(i, p)
	if !n.internal(i, from) && !n.confedPeers(i, from) && n.relation[session{i, from}] != Sibling {
		return n.relation[session{i, from}]
	}
	return n.received[session{from, i}][p.RemoteID()].learned // as the neighbor learned it
}

func (n *network) pending() []session {
	var l []session
	for s, q := range n.queues {
		if len(q) > 0 {
			l = append(l, s)
		}
	}
	// Map order is random in Go: sort, so that the seed alone decides.
	slices.SortFunc(l, func(a, b session) int {
		if a.from != b.from {
			return a.from - b.from
		}
		return a.to - b.to
	})
	return l
}

// peers are the BGP neighbors of router i: eBGP over links, iBGP by session.
func (n *network) peers(i int) []int {
	var l []int
	for j := range n.routers {
		if n.internal(i, j) && n.ibgp[session{i, j}] || !n.internal(i, j) && n.up[session{i, j}] {
			l = append(l, j)
		}
	}
	return l
}

func (n *network) originate(announce bool) {
	nlri, _ := bgp.NewIPAddrPrefix(prefix)
	if announce {
		nexthop, _ := bgp.NewPathAttributeNextHop(netip.IPv4Unspecified())
		var path []bgp.AsPathParamInterface
		if len(n.inst.OriginPoison) > 0 { // as the lab's controller: the poisoned, then the own
			path = append(path, bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, append(slices.Clone(n.inst.OriginPoison), n.asn(n.inst.Origin))))
		}
		if len(n.inst.OriginSet) > 0 {
			path = append(path, bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, n.inst.OriginSet))
		}
		if len(path) == 0 {
			path = []bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{})}
		}
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath(path),
			nexthop,
		}
		if len(n.inst.OriginCommunities) > 0 {
			attrs = append(attrs, bgp.NewPathAttributeCommunities(communities(n.inst.OriginCommunities)))
		}
		n.origin = table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false, attrs, n.now(), false)
		n.calculate(n.inst.Origin, n.origin)
	} else if n.origin != nil {
		n.calculate(n.inst.Origin, n.origin.Clone(true))
		n.origin = nil
	}
	n.advertise(n.inst.Origin)
}

func (n *network) peerInfo(from, to int) *table.PeerInfo {
	info := &table.PeerInfo{AS: n.localAS(from, to), LocalAS: n.localAS(to, from), ID: n.inst.id(from), LocalID: n.inst.id(to),
		Address: addr(from), LocalAddress: addr(to), Confederation: n.confedPeers(from, to)}
	if n.client[session{to, from}] {
		info.RouteReflectorClient, info.RouteReflectorClusterID = true, n.inst.id(to)
	}
	return info
}

// exportPath is what router i offers its eBGP neighbors: the best path for
// BGP, the worst admitted path for OBGP, by the code gobgpd uses.
func (n *network) exportPath(i int) *table.Path {
	u := &table.Update{KnownPathList: n.routers[i].dest.GetAllKnownPathList()}
	p, _ := u.GetExportChanges(table.GLOBAL_RIB_NAME, 0)
	if p != nil && (p.IsWithdraw || p.IsNexthopInvalid) {
		return nil
	}
	return p
}

// source is the router a path was learned from, or i itself for the origin.
func (n *network) source(i int, p *table.Path) int {
	if p.IsLocal() {
		return i
	}
	return n.byAddress[p.GetSource().Address]
}

// nexthop is the router a path leads to: the origin itself, the eBGP
// neighbor, or the border router that set itself as next hop.
func (n *network) nexthop(i int, p *table.Path) int {
	if p.IsLocal() {
		return i
	}
	if h, ok := n.byAddress[p.GetNexthop()]; ok {
		return h
	}
	return n.source(i, p)
}

func (n *network) routeOf(i int, p *table.Path) route {
	seq, set, confed := segments(p)
	r := route{path: seq, set: set, confed: confed, nexthop: n.nexthop(i, p), originator: -1, learned: n.learnedOf(i, p), communities: p.GetCommunities()}
	if lp, err := p.GetLocalPref(); err == nil {
		r.localPref = lp
	}
	if med, err := p.GetMed(); err == nil {
		r.med = med
	}
	if o := p.GetOriginatorID(); o.IsValid() && !o.IsUnspecified() {
		r.originator = n.byID[o]
	}
	for _, c := range p.GetClusterList() {
		r.clusters = append(r.clusters, n.byID[c])
	}
	return r
}

// communities are those of the lab's announce step: no-export,
// no-advertise, or AS:value.
func communities(texts []string) []uint32 {
	var out []uint32
	for _, t := range texts {
		switch t {
		case "no-export":
			out = append(out, uint32(bgp.COMMUNITY_NO_EXPORT))
		case "no-advertise":
			out = append(out, uint32(bgp.COMMUNITY_NO_ADVERTISE))
		default:
			var high, low uint32
			fmt.Sscanf(t, "%d:%d", &high, &low)
			out = append(out, high<<16|low)
		}
	}
	return out
}

// withheld tells whether communities keep a route from a neighbor, as the
// lab's controller has it: no-advertise from all, no-export from those out
// of the own AS or confederation once learned, 0:AS from that AS, from the
// origin on.
func withheld(cs []uint32, local, member bool, to uint32) bool {
	for _, c := range cs {
		if c == uint32(bgp.COMMUNITY_NO_ADVERTISE) || !member && (c == uint32(bgp.COMMUNITY_NO_EXPORT) && !local || c == to) {
			return true
		}
	}
	return false
}

// offerEBGP is the route router i sends eBGP neighbor j, or nil for nothing.
func (n *network) offerEBGP(i, j int, p *table.Path) *route {
	r, _ := n.offerWhy(i, j, p)
	return r
}

// Why a router sends an eBGP neighbor nothing, for the trace.
const (
	notNothing   = "nothing to offer"
	notSource    = "back to its source"
	notLoop      = "its AS is in the path"
	notRelation  = "the relation forbids it"
	notCommunity = "a community withholds it"
	notFilter    = "the export filter drops it"
)

// offerWhy is offerEBGP with the reason when it sends nothing.
func (n *network) offerWhy(i, j int, p *table.Path) (*route, string) {
	if p == nil {
		return nil, notNothing
	}
	from := n.source(i, p)
	if !ownSplit && from == j {
		return nil, notSource // not back to the source, as gobgpd
	}
	if !ownSplit && slices.Contains(p.GetAsList(), n.localAS(j, i)) {
		return nil, notLoop // nor into a loop: confederation segments count as AS 0 there
	}
	member := n.confedPeers(i, j)
	if len(n.relation) > 0 && !member && !p.IsLocal() && !slices.Contains(n.inst.Leakers, i) {
		partial := n.policy[session{i, j}] != nil && n.policy[session{i, j}].Partial
		down := n.relation[session{i, j}] == Customer && !partial || n.relation[session{i, j}] == Sibling
		if n.learnedOf(i, p) != Customer && !down {
			return nil, notRelation // valley-free: routes of peers and providers go to customers only
		}
	}
	if withheld(p.GetCommunities(), p.IsLocal(), member, n.asn(j)) {
		return nil, notCommunity
	}
	path, set, confed := segments(p)
	r := route{nexthop: i, originator: -1, set: set, communities: p.GetCommunities()}
	if s := n.policy[session{i, j}]; s != nil {
		if s.DenyExport || (s.DenyVia != 0 && slices.Contains(p.GetAsSeqList(), s.DenyVia)) { // as gobgpd's _AS_
			return nil, notFilter
		}
		for range s.Prepend {
			if !member {
				path = append([]uint32{n.localAS(i, j)}, path...)
			}
		}
		r.med = s.MED
	}
	if member { // to another member of the confederation: its own AS in the confederation segment
		r.path, r.confed, r.learned = path, append([]uint32{n.asn(i)}, confed...), n.learnedOf(i, p)
	} else { // out of the confederation, if any: its segments go, the identifier comes first
		r.path = append([]uint32{n.localAS(i, j)}, path...)
		if n.relation[session{i, j}] == Sibling { // the class it was learned with, as the lab's community
			r.learned = n.learnedOf(i, p)
		}
	}
	return &r, ""
}

// offerIBGP are the routes router i sends iBGP peer j, by path ID, with the
// rules of gobgpd: what came over iBGP goes on only through a route
// reflector, from a client to all, from others to clients.
func (n *network) offerIBGP(i, j int) map[uint32]route {
	out := map[uint32]route{}
	var p *table.Path
	if n.mode == BGP {
		p = n.routers[i].dest.GetBestPath(table.GLOBAL_RIB_NAME, 0)
	} else {
		p = n.exportPath(i)
	}
	if p == nil || p.IsWithdraw || withheld(p.GetCommunities(), p.IsLocal(), true, 0) { // no-advertise: inside the AS too
		return out
	}
	from := n.source(i, p)
	if from == j {
		return out
	}
	r := n.routeOf(i, p)
	switch {
	case p.IsLocal() || !n.internal(i, from):
		r.nexthop = i // next-hop-self at the border
		r.originator, r.clusters = -1, nil
		out[0] = r
	case n.reflects(i, from, j):
		out[0] = n.reflect(i, from, r)
	}
	return out
}

// reflects tells whether route reflector i passes an iBGP route of from to j.
func (n *network) reflects(i, from, j int) bool {
	return n.client[session{i, from}] || n.client[session{i, j}]
}

func (n *network) reflect(i, from int, r route) route {
	if r.originator < 0 {
		r.originator = from
	}
	r.clusters = append([]int{i}, r.clusters...)
	return r
}

func key(r route) string { return fmt.Sprint(r) }

// segments splits an AS path into its sequence and an AS_SET after it, the
// only sets the simulator makes: the aggregate of its origin.
func segments(p *table.Path) (seq, set, confed []uint32) {
	seq = []uint32{}
	if aspath := p.GetAsPath(); aspath != nil {
		for _, segment := range aspath.Value {
			switch segment.GetType() {
			case bgp.BGP_ASPATH_ATTR_TYPE_SET:
				set = append(set, segment.GetAS()...)
			case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
				confed = append(confed, segment.GetAS()...)
			default:
				seq = append(seq, segment.GetAS()...)
			}
		}
	}
	return seq, set, confed
}

// flat is an AS path with every number of every segment, as the lab's
// /routes gives it.
func flat(p *table.Path) []uint32 {
	seq, set, confed := segments(p)
	out := make([]uint32, 0, len(confed)+len(seq)+len(set)) // never nil: the origin's own path is empty, not missing
	return append(append(append(out, confed...), seq...), set...)
}

func asPath(r route) []bgp.AsPathParamInterface {
	out := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, r.path)}
	if len(r.confed) > 0 {
		out = append([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, r.confed)}, out...)
	}
	if len(r.set) > 0 {
		out = append(out, bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, r.set))
	}
	return out
}

func (n *network) advertise(i int) {
	for _, j := range n.peers(i) {
		want := map[uint32]route{}
		if n.routeServer(i) && n.mode != OBGPPaper {
			want = n.offerRSAll(i, j)
		} else if n.routeServer(i) {
			if r := n.offerRS(i, j); r != nil {
				want[0] = *r
			}
		} else if n.internal(i, j) {
			want = n.offerIBGP(i, j)
		} else if r := n.offerEBGP(i, j, n.exportTo(i, j)); r != nil {
			want[0] = *r
		}
		s := session{i, j}
		sent := n.routers[i].sent[s]
		if sent == nil {
			sent = map[uint32]string{}
			n.routers[i].sent[s] = sent
		}
		var ids []uint32
		for id := range sent {
			if _, ok := want[id]; !ok {
				ids = append(ids, id)
			}
		}
		for id := range want {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range slices.Compact(ids) {
			r, ok := want[id]
			last, was := sent[id]
			switch {
			case !ok && was:
				delete(sent, id)
				n.queues[s] = append(n.queues[s], message{id: id, withdraw: true})
			case ok && (!was || last != key(r)):
				sent[id] = key(r)
				n.queues[s] = append(n.queues[s], message{id: id, route: r})
			}
		}
	}
}

// askRefresh sends the neighbors router i waits for a route refresh request,
// once per wait, behind what the session already carries.
func (n *network) askRefresh(i int) {
	for _, src := range n.routers[i].dest.OperaWaiting() {
		j := n.byAddress[src.Address]
		s := session{i, j}
		if n.asked[s] || !n.up[s] && !n.ibgp[s] {
			continue
		}
		n.asked[s] = true
		n.queues[s] = append(n.queues[s], message{refresh: true})
	}
}

// answerRefresh is router j answering i's request: what it offers i now, a
// withdrawal where it offers nothing (RFC 7313: what is not sent again is gone).
func (n *network) answerRefresh(j, i int) {
	s := session{j, i}
	delete(n.routers[j].sent, s)
	before := len(n.queues[s])
	n.advertise(j)
	if len(n.queues[s]) == before {
		n.queues[s] = append(n.queues[s], message{id: 0, withdraw: true})
	}
}

func (n *network) deliver(s session, m message) {
	if m.refresh {
		n.answerRefresh(s.to, s.from)
		return
	}
	delete(n.asked, session{s.to, s.from}) // the neighbor answered or sent anew
	routes := n.received[s]
	if routes == nil {
		routes = map[uint32]route{}
		n.received[s] = routes
	}
	if n.stamps[s] == nil {
		n.stamps[s] = map[uint32]time.Time{}
	}
	if m.withdraw {
		delete(routes, m.id)
		delete(n.stamps[s], m.id)
	} else {
		// As gobgpd's Adj-RIB-In: a route resent unchanged keeps its age,
		// which breaks ties between paths (the older wins).
		if old, ok := routes[m.id]; !ok || key(old) != key(m.route) {
			n.stamps[s][m.id] = n.now()
		}
		routes[m.id] = m.route
	}
	n.importPath(s, m.id, false)
}

func (n *network) importPref(s session, learned Relation) uint32 {
	pref := uint32(100)
	if r, ok := n.relation[session{s.to, s.from}]; ok {
		if r == Sibling { // by the class the sibling learned it with
			r = learned
		}
		pref = relationPref[r]
	}
	if pol := n.policy[s]; pol != nil && pol.LocalPref != 0 {
		pref = pol.LocalPref
	}
	return pref
}

// importPath puts what From last sent To under a path ID through To's
// import policy into To's table: a rejected path is a withdrawal, as in
// gobgpd, and so is an iBGP route that went round a reflector loop.
func (n *network) importPath(s session, id uint32, dropped bool) {
	n.calculate(s.to, n.pathOf(s, id, dropped))
	n.advertise(s.to)
	// After its own withdrawal on each session: the neighbor answers knowing
	// that this router no longer has the route, not with a path through it.
	n.askRefresh(s.to)
}

// pathOf is what From last sent To under a path ID, through To's import policy.
func (n *network) pathOf(s session, id uint32, dropped bool) *table.Path {
	nlri, _ := bgp.NewIPAddrPrefix(prefix)
	info := n.peerInfo(s.from, s.to)
	r, ok := n.received[s][id]
	internal := n.internal(s.from, s.to)
	pol := n.policy[s]
	rejected := !internal && pol != nil && pol.DenyImport
	// gobgpd drops a path with its own AS anywhere in it, confederation
	// segments too, and withdraws the path the peer sent before (RFC 4271).
	if ok && slices.Contains(slices.Concat(r.confed, r.path, r.set), n.localAS(s.to, s.from)) {
		ok = false
	}
	looped := internal && ok && (r.originator == s.to || slices.Contains(r.clusters, s.to))
	var p *table.Path
	if !ok || rejected || looped {
		p = table.NewPath(bgp.RF_IPv4_UC, info, bgp.PathNLRI{NLRI: nlri, ID: id}, true, nil, n.now(), false)
		if dropped {
			p.SetSessionDropped()
		} else if ok {
			p.SetPolicyRejected() // as gobgpd marks a rejection by its own import policy
		}
	} else {
		nexthop, _ := bgp.NewPathAttributeNextHop(addr(r.nexthop))
		pref := r.localPref
		if !internal {
			pref = n.importPref(s, r.learned)
			if pol != nil && pol.Tag != "" { // as the lab's controller tags them on import
				r.communities = append(slices.Clone(r.communities), communities([]string{pol.Tag})...)
			}
		}
		attrs := []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath(asPath(r)),
			nexthop,
			bgp.NewPathAttributeMultiExitDisc(r.med),
			bgp.NewPathAttributeLocalPref(pref),
		}
		if r.originator >= 0 {
			o, _ := bgp.NewPathAttributeOriginatorId(n.inst.id(r.originator))
			var clusters []netip.Addr
			for _, c := range r.clusters {
				clusters = append(clusters, n.inst.id(c))
			}
			c, _ := bgp.NewPathAttributeClusterList(clusters)
			attrs = append(attrs, o, c)
		}
		if len(r.communities) > 0 {
			attrs = append(attrs, bgp.NewPathAttributeCommunities(r.communities))
		}
		stamp, ok := n.stamps[s][id]
		if !ok {
			stamp = n.now()
		}
		p = table.NewPath(bgp.RF_IPv4_UC, info, bgp.PathNLRI{NLRI: nlri, ID: id}, false, attrs, stamp, false)
	}
	return p
}

func (n *network) routeServer(i int) bool { return slices.Contains(n.inst.RouteServers, i) }

// offerRSAll are the routes route server rs sends client j with Add-Path,
// as gobgpd and the lab do: every path of the others its filter
// towards j allows, as received, without admission. The routes go on as the
// clients sent them, under a path ID of the client and its own.
func (n *network) offerRSAll(rs, j int) map[uint32]route {
	out := map[uint32]route{}
	for _, from := range n.peers(rs) {
		if from == j {
			continue
		}
		for id, r := range n.received[session{from, rs}] {
			if slices.Contains(slices.Concat(r.confed, r.path, r.set), n.asn(j)) {
				continue
			}
			if pol := n.policy[session{rs, j}]; pol != nil && (pol.DenyExport || pol.DenyVia != 0 && slices.Contains(r.path, pol.DenyVia)) {
				continue
			}
			if withheld(r.communities, false, false, n.asn(j)) {
				continue
			}
			r.nexthop, r.originator, r.clusters, r.localPref = from, -1, nil, 0 // the next hop stays the client's
			out[uint32(from*64)+id+1] = r
		}
	}
	return out
}

// offerRS is the route route server rs sends client j in obgp-paper, as
// gobgpd's that admits: of the paths of the others not through j's AS, the
// worst admitted, then j's export filter, which leaves j without a route if
// it rejects that path. The route goes on as the client sent it.
func (n *network) offerRS(rs, j int) *route {
	var known []*table.Path
	for _, q := range n.routers[rs].dest.GetAllKnownPathList() {
		from := n.source(rs, q)
		if from != j && !slices.Contains(q.GetAsList(), n.asn(j)) {
			known = append(known, q)
		}
	}
	u := &table.Update{KnownPathList: known}
	var p *table.Path
	if n.mode == BGP {
		p, _, _ = u.GetChanges(table.GLOBAL_RIB_NAME, 0, false)
	} else {
		p, _ = u.GetExportChanges(table.GLOBAL_RIB_NAME, 0)
	}
	if p == nil || p.IsWithdraw || p.IsLocal() {
		return nil
	}
	from := n.source(rs, p)
	r := n.received[session{from, rs}][p.RemoteID()]
	if pol := n.policy[session{rs, j}]; pol != nil && (pol.DenyExport || pol.DenyVia != 0 && slices.Contains(r.path, pol.DenyVia)) {
		return nil
	}
	if withheld(r.communities, false, false, n.asn(j)) {
		return nil
	}
	r.nexthop, r.originator, r.clusters, r.localPref = from, -1, nil, 0 // the next hop stays the client's
	return &r
}

func (n *network) apply(e Event) {
	s := session{e.From, e.To}
	set := func(change func(*Session)) {
		if n.policy[s] == nil {
			n.policy[s] = &Session{From: e.From, To: e.To}
		}
		change(n.policy[s])
	}
	switch e.Kind {
	case "withdraw":
		n.originate(false)
	case "announce":
		n.originate(true)
	case "down":
		for _, d := range []session{s, {e.To, e.From}} {
			n.up[d] = false
			n.queues[d] = nil
			ids := []uint32{0}
			for id := range n.received[d] {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			delete(n.received, d)
			delete(n.routers[d.from].sent, d)
			for _, id := range slices.Compact(ids) {
				n.importPath(d, id, true)
			}
		}
		n.syncTables(e.From)
		n.syncTables(e.To)
	case "up":
		n.up[s], n.up[session{e.To, e.From}] = true, true
		n.syncTables(e.From)
		n.syncTables(e.To)
		n.advertise(e.From)
		n.advertise(e.To)
	case "prepend":
		set(func(p *Session) { p.Prepend = e.Value })
		n.advertise(e.From)
	case "prepend-all": // towards every neighbor in another AS at once, as the lab's prepend step
		for _, j := range n.peers(e.From) {
			if !n.internal(e.From, j) && !n.confedPeers(e.From, j) { // as the lab: towards other ASes, not members
				s := session{e.From, j}
				if n.policy[s] == nil {
					n.policy[s] = &Session{From: e.From, To: j}
				}
				n.policy[s].Prepend = e.Value
			}
		}
		n.advertise(e.From)
	case "local-pref": // at To for the routes of From, as the lab's set_preference step
		set(func(p *Session) { p.LocalPref = uint32(e.Value) })
		ids := []uint32{}
		for id := range n.received[s] {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			n.importPath(s, id, false)
		}
	case "expect":
		n.checks = append(n.checks, n.expect(e))
	case "igp": // a link inside an AS gets cost Value, 0 takes it away, as the lab's igp step
		for k, l := range n.inst.Links {
			if (l == [2]int{e.From, e.To} || l == [2]int{e.To, e.From}) && n.internal(e.From, e.To) {
				n.costs[k] = e.Value
				n.igp = nil
			}
		}
	case "deny-export":
		set(func(p *Session) { p.DenyExport = e.Value != 0 })
		n.syncTables(e.From)
		n.advertise(e.From)
	case "deny-import":
		set(func(p *Session) { p.DenyImport = e.Value != 0 })
		ids := []uint32{}
		for id := range n.received[s] {
			ids = append(ids, id)
		}
		if len(ids) == 0 && e.Value == 0 {
			ids = []uint32{0}
		}
		slices.Sort(ids)
		for _, id := range ids {
			n.importPath(s, id, false) // soft reconfiguration inbound, from the Adj-RIB-In
		}
	default:
		panic(fmt.Sprintf("unknown event %q", e.Kind))
	}
}

func (n *network) result(converged bool, steps int) Result {
	r := n.snapshot()
	r.Converged, r.Steps, r.Checks, r.Transient = converged, steps, n.checks, n.transient
	r.Looped, r.Blocked, r.Holes = n.looped, waiting(n.waits), passing(n.losses, r)
	return r
}

// expect checks the best routes as the lab's expect step does: a route
// held or not, from the neighbor via, not through the AS of avoid, and
// forwarding without loops or black holes from the routers.
func (n *network) expect(e Event) Verdict {
	r := n.snapshot()
	var problems []string
	for _, i := range e.Routers {
		held := r.Best[i] != nil
		switch {
		case (e.Prefixes == "" || e.Prefixes == "all") && !held:
			problems = append(problems, fmt.Sprintf("router %d misses the prefix", i))
		case e.Prefixes == "none" && held:
			problems = append(problems, fmt.Sprintf("router %d holds the prefix", i))
		}
		if !held {
			continue
		}
		best := n.best(i)
		if e.Via != nil && n.source(i, best) != *e.Via {
			problems = append(problems, fmt.Sprintf("router %d routes via %d, not %d", i, n.source(i, best), *e.Via))
		}
		if e.Avoid != nil && slices.Contains(r.Best[i], n.asn(*e.Avoid)) {
			problems = append(problems, fmt.Sprintf("router %d routes through %d", i, *e.Avoid))
		}
	}
	if e.Forwarding {
		for _, f := range forwardingFrom(n.inst, n.mode, r, e.Routers) {
			problems = append(problems, f.Detail)
		}
	}
	if e.Consistent {
		for _, f := range exportConsistency(n.inst, n.mode, r) {
			problems = append(problems, f.Detail)
		}
	}
	return Verdict{Passed: len(problems) == 0, Problems: problems}
}

func (n *network) snapshot() Result {
	r := Result{Mode: n.mode, Costs: slices.Clone(n.costs)}
	for i := range n.routers {
		best := n.best(i)
		if best == nil || best.IsWithdraw {
			r.Best, r.NextHop = append(r.Best, nil), append(r.NextHop, -1)
		} else {
			hop := n.nexthop(i, best)
			r.Best, r.NextHop = append(r.Best, flat(best)), append(r.NextHop, hop)
		}
		var exported []uint32
		if p := n.exportPath(i); p != nil {
			exported = p.GetAsList()
		}
		r.Exported = append(r.Exported, exported)
		var offered [][]uint32
		for _, j := range n.peers(i) {
			if n.internal(i, j) || n.routeServer(i) { // a route server is no AS on the path
				continue
			}
			if o := n.offerEBGP(i, j, n.exportTo(i, j)); o != nil {
				path := slices.Concat(o.confed, o.path, o.set)
				for len(path) > 0 && (path[0] == n.asn(i) || path[0] == n.localAS(i, j)) {
					path = path[1:] // as the lab compares: without the own AS and its prepends
				}
				if !slices.ContainsFunc(offered, func(x []uint32) bool { return slices.Equal(x, path) }) {
					offered = append(offered, path)
				}
			}
		}
		r.Offered = append(r.Offered, offered)
	}
	return r
}
