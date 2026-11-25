package obgpsim

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"reflect"
	"slices"
	"sync"
	"time"
)

// An order of messages without end: the network returns to a state it was
// in, so the same choices repeat forever. Where a run stops at MaxSteps
// without one, it is undecided: it was not looked for in every state, or
// not at all in large networks.

// Cycle is where a run returned to an earlier state: the state after
// message From recurred after message From+Length. Every session that held
// messages in it delivered at least one, and at least one second passed,
// so repeating it forever is a fair order of messages that never rests.
type Cycle struct {
	From   int `json:"from"`
	Length int `json:"length"`
}

// CycleFrom is the message from which a run looks for a cycle, so that
// runs that come to rest soon cost nothing: after every message for
// CycleDense messages, then after every eighth. CycleRouters bounds the
// networks it looks in, CycleBytes the state: the state of a large network,
// or of one whose queues grow, rarely recurs and costs much to compare.
const (
	CycleFrom    = 500
	CycleDense   = 500
	CycleRouters = 12
	CycleBytes   = 64 << 10
)

// looks tells whether a run looks for a cycle after message step.
func looks(step int) bool {
	return step >= CycleFrom && (step < CycleFrom+CycleDense || step%8 == 0)
}

// cycles remembers the states of a run after the messages it looks at, by a
// hash of each, and every message from start on: which session delivered
// it and whether a second passed before it.
type cycles struct {
	seed      maphash.Seed
	seen      map[uint64]int // hash of a state, the message after which it was
	start     int            // the message the log begins after
	delivered []session      // per message after start
	ticked    []bool         // per message after start
}

func newCycles(start int) *cycles {
	return &cycles{seed: maphash.MakeSeed(), seen: map[uint64]int{}, start: start}
}

// log records which session delivered message start+k and whether a
// second passed before it.
func (c *cycles) log(s session, ticked bool) {
	c.delivered = append(c.delivered, s)
	c.ticked = append(c.ticked, ticked)
}

// after records the state after message step and returns the earlier message
// after which the network was in the same state, if repeating what came
// since is a fair order: every session with messages delivered, a second
// passed. -1 for none. The hash only proposes a cycle, the caller confirms
// it on the state itself.
func (c *cycles) after(step int, state []byte, pending []session) int {
	h := maphash.Bytes(c.seed, state)
	from, ok := c.seen[h]
	c.seen[h] = step
	if !ok {
		return -1
	}
	// The messages after from, up to this one.
	since := c.delivered[from+1-c.start : step+1-c.start]
	if !slices.Contains(c.ticked[from+1-c.start:step+1-c.start], true) {
		return -1 // no time passed: no order of real messages
	}
	for _, p := range pending { // the state is the same, so are its sessions with messages
		if !slices.Contains(since, p) {
			return -1
		}
	}
	return from
}

// state is everything of the network that decides what comes next, in a
// canonical form: the routers' tables with their OBGP state, what each
// session carries and holds, the refreshes asked, the origins' paths, the
// routes kept stale and the End-of-RIBs a restarting router waits for. Times
// count only in their order: gobgpd compares the age of paths in whole
// seconds, and every new path is younger than all others. ok is false where
// the tables hold something it cannot compare, a function or a channel.
func (n *network) state() (out []byte, ok bool) {
	w := &walker{seen: map[uintptr]int{}, names: map[uint64]int{}}
	sessions := func(m map[session]bool) []session {
		var l []session
		for s := range m {
			l = append(l, s)
		}
		slices.SortFunc(l, func(a, b session) int { return cmp.Or(a.from-b.from, a.to-b.to) })
		return l
	}
	for i, r := range n.routers {
		fmt.Fprintf(&w.buf, "router %d\n", i)
		w.walk(reflect.ValueOf(r.dest))
		keys := map[session]bool{}
		for s := range r.sent {
			keys[s] = true
		}
		for _, s := range sessions(keys) {
			ids := r.sent[s]
			fmt.Fprintf(&w.buf, "sent %v", s)
			for _, id := range slices.Sorted(mapKeys(ids)) {
				fmt.Fprintf(&w.buf, " %d=%q", id, ids[id])
			}
			w.buf.WriteByte('\n')
		}
	}
	keys := map[session]bool{}
	for s, q := range n.queues {
		if len(q) > 0 {
			keys[s] = true
		}
	}
	for s := range n.received {
		keys[s] = true
	}
	for s := range n.asked {
		keys[s] = true
	}
	for _, s := range sessions(keys) {
		fmt.Fprintf(&w.buf, "session %d %d asked %v queue ", s.from, s.to, n.asked[s])
		w.walk(reflect.ValueOf(n.queues[s]))
		routes := n.received[s]
		for _, id := range slices.Sorted(mapKeys(routes)) {
			fmt.Fprintf(&w.buf, " received %d ", id)
			w.walk(reflect.ValueOf(routes[id]))
			if t, ok := n.stamps[s][id]; ok {
				w.time(t.Unix())
			}
		}
		w.buf.WriteByte('\n')
	}
	for _, i := range slices.Sorted(mapKeys(n.origins)) {
		fmt.Fprintf(&w.buf, "origin %d ", i)
		w.walk(reflect.ValueOf(n.origins[i]))
	}
	// Graceful restart: the routes kept stale and the End-of-RIBs a restarting router waits for, where there are any.
	stale := map[session]bool{}
	for s, ids := range n.stale {
		if len(ids) > 0 {
			stale[s] = true
		}
	}
	for _, s := range sessions(stale) {
		fmt.Fprintf(&w.buf, "stale %d %d %v\n", s.from, s.to, slices.Sorted(mapKeys(n.stale[s])))
	}
	for _, r := range slices.Sorted(mapKeys(n.restarting)) {
		fmt.Fprintf(&w.buf, "restarting %d %v\n", r, slices.Sorted(mapKeys(n.restarting[r])))
	}
	w.time(n.second())
	return w.finish(), !w.opaque
}

// second is the whole second the clock is in: a path made now gets it.
func (n *network) second() int64 { return time.Unix(1_700_000_000, n.clock).Unix() }

func mapKeys[K cmp.Ordered, V any](m map[K]V) func(func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// walker writes a value of the table package and all it points to, by
// reflection, so that no field is left out: pointers by the order they are
// first met, map entries sorted by key, times as placeholders that finish
// replaces by their rank.
type walker struct {
	buf     bytes.Buffer
	seen    map[uintptr]int
	times   []int64
	names   map[uint64]int
	opaque  bool
	scratch [binary.MaxVarintLen64]byte
}

func (w *walker) time(sec int64) {
	w.times = append(w.times, sec)
	w.buf.WriteString("@t")
}

// finish appends the rank of each time among all times, so that two states
// whose times stand in the same order are equal.
func (w *walker) finish() []byte {
	sorted := slices.Clone(w.times)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	w.buf.WriteString("\ntimes")
	for _, t := range w.times {
		i, _ := slices.BinarySearch(sorted, t)
		w.buf.WriteString(" ")
		w.buf.WriteString(fmt.Sprint(i))
	}
	return w.buf.Bytes()
}

func (w *walker) int(i int64) {
	w.buf.Write(binary.AppendVarint(w.scratch[:0], i))
}

// How the state treats a field of a struct of the table package.
const (
	fieldPlain = iota
	fieldTime  // gobgpd keeps a path's age in originInfo.timestamp, in Unix seconds
	// A path's local ID only names it: compared for equality, never ordered.
	// gobgpd frees one only when a session drops the path, so they grow with
	// every withdrawal: named by their first appearance.
	fieldName
	fieldSkip // the IDs in use, for handing out new ones: a new one is always unused
)

var kinds sync.Map // reflect.Type to []int

func fieldKinds(t reflect.Type) []int {
	if k, ok := kinds.Load(t); ok {
		return k.([]int)
	}
	k := make([]int, t.NumField())
	for i := range k {
		switch f := t.Field(i); {
		case t.Name() == "originInfo" && f.Name == "timestamp":
			k[i] = fieldTime
		case t.Name() == "Path" && f.Name == "localID":
			k[i] = fieldName
		case t.Name() == "Destination" && f.Name == "localIdMap":
			k[i] = fieldSkip
		}
	}
	kinds.Store(t, k)
	return k
}

func (w *walker) walk(v reflect.Value) {
	switch v.Kind() {
	case reflect.Invalid:
		w.buf.WriteString("~")
	case reflect.Bool:
		if v.Bool() {
			w.buf.WriteString("T")
		} else {
			w.buf.WriteString("F")
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.buf.WriteByte('i')
		w.int(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		w.buf.WriteByte('u')
		w.int(int64(v.Uint()))
	case reflect.Float32, reflect.Float64:
		fmt.Fprintf(&w.buf, "f%v", v.Float())
	case reflect.String:
		fmt.Fprintf(&w.buf, "s%d:%s", v.Len(), v.String())
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			w.buf.WriteString("[nil]")
			return
		}
		fmt.Fprintf(&w.buf, "[%d", v.Len())
		for i := range v.Len() {
			w.walk(v.Index(i))
		}
		w.buf.WriteString("]")
	case reflect.Map:
		if v.IsNil() {
			w.buf.WriteString("{nil}")
			return
		}
		type entry struct {
			key []byte
			val reflect.Value
		}
		var entries []entry
		it := v.MapRange()
		for it.Next() {
			k := &walker{seen: map[uintptr]int{}, names: map[uint64]int{}}
			k.walk(it.Key())
			if len(k.seen) > 0 || len(k.times) > 0 || k.opaque {
				w.opaque = true // keys with pointers or times: no canonical order
			}
			entries = append(entries, entry{k.buf.Bytes(), it.Value()})
		}
		slices.SortFunc(entries, func(a, b entry) int { return bytes.Compare(a.key, b.key) })
		fmt.Fprintf(&w.buf, "{%d", len(entries))
		for _, e := range entries {
			w.buf.Write(e.key)
			w.buf.WriteString(":")
			w.walk(e.val)
		}
		w.buf.WriteString("}")
	case reflect.Pointer:
		if v.IsNil() {
			w.buf.WriteString("*nil")
			return
		}
		if i, ok := w.seen[v.Pointer()]; ok {
			fmt.Fprintf(&w.buf, "*%d", i)
			return
		}
		w.seen[v.Pointer()] = len(w.seen)
		w.buf.WriteString("*")
		w.walk(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			w.buf.WriteString("I~")
			return
		}
		fmt.Fprintf(&w.buf, "I%s", v.Elem().Type())
		w.walk(v.Elem())
	case reflect.Struct:
		t := v.Type()
		w.buf.WriteByte('(')
		for i, kind := range fieldKinds(t) {
			switch kind {
			case fieldTime:
				w.time(v.Field(i).Int())
			case fieldName:
				id := v.Field(i).Uint()
				if _, ok := w.names[id]; !ok && id != 0 {
					w.names[id] = len(w.names) + 1
				}
				w.buf.WriteByte('#')
				w.int(int64(w.names[id]))
			case fieldPlain:
				w.walk(v.Field(i))
			}
		}
		w.buf.WriteByte(')')
	default: // functions, channels, unsafe pointers: nothing to compare by
		if !v.IsNil() {
			w.opaque = true
		}
	}
}
