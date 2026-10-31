//go:build obgpsim

package obgpsim

import (
	"slices"
	"testing"
)

// decode builds a network inside the model of OBGPHard from fuzz bytes: up to
// 12 routers, Gao-Rexford relations without cycles, failures of links and
// of the origin, an aggregate with an AS_SET, and a confederation of
// routers 1 to 3. Go's fuzzer shrinks a failing input on its own.
func decode(data []byte) (Instance, bool) {
	if len(data) < 4 {
		return Instance{}, false
	}
	inst := Instance{Routers: 2 + int(data[0])%11, Seed: int64(data[1])}
	flags := data[2]
	if flags&1 != 0 {
		inst.OriginSet = []uint32{64601, 64600} // out of order on purpose
	}
	var group []int
	if size := int(flags>>1) % 3; size > 0 && inst.Routers > size+1 {
		for i := 1; i <= size+1; i++ {
			group = append(group, i)
		}
	}
	data = data[3:]
	for len(data) >= 2 {
		a, b, kind := int(data[0])%inst.Routers, int(data[1])%inst.Routers, int(data[1]/16)%4
		data = data[2:]
		if a == b {
			continue
		}
		if a > b {
			a, b = b, a
		}
		link := [2]int{a, b}
		known := slices.Contains(inst.Links, link)
		switch {
		case kind == 3 && known:
			inst.Events = append(inst.Events, Event{After: len(inst.Events) * 3, Kind: "down", From: a, To: b})
		case !known:
			inst.Links = append(inst.Links, link)
			switch {
			case slices.Contains(group, a) && slices.Contains(group, b): // members: no relations among them
			case kind == 2:
				inst.Peers = append(inst.Peers, link)
			default:
				inst.Customers = append(inst.Customers, [2]int{a, b}) // the lower router is the provider: no cycles
			}
		}
	}
	if len(group) > 0 {
		var inside [][2]int
		for _, l := range inst.Links {
			if slices.Contains(group, l[0]) && slices.Contains(group, l[1]) {
				inside = append(inside, l)
			}
		}
		if connectedSet(group, inside) {
			inst.Confeds = []Confed{{Members: group, ID: 65500}}
		}
	}
	return inst, connected(inst.Routers, inst.Links)
}

// decodeSoft builds a network outside the model of pruning, without
// Gao-Rexford: filters towards and from single neighbors, prepending and
// Local Preference, set at the start and changed later.
func decodeSoft(data []byte) (Instance, bool) {
	if len(data) < 3 {
		return Instance{}, false
	}
	inst := Instance{Routers: 3 + int(data[0])%8, Seed: int64(data[1])}
	data = data[2:]
	for len(data) >= 3 {
		a, b, op := int(data[0])%inst.Routers, int(data[1])%inst.Routers, data[2]
		data = data[3:]
		if a == b {
			continue
		}
		link := [2]int{min(a, b), max(a, b)}
		if !slices.Contains(inst.Links, link) {
			inst.Links = append(inst.Links, link)
			continue
		}
		switch op % 5 {
		case 0:
			inst.Events = append(inst.Events, Event{After: 1 << 30, Kind: "deny-export", From: a, To: b, Value: 1})
		case 1:
			inst.Events = append(inst.Events, Event{After: 1 << 30, Kind: "deny-import", From: a, To: b, Value: 1})
		case 2:
			inst.Events = append(inst.Events, Event{After: 1 << 30, Kind: "prepend", From: a, To: b, Value: 1 + int(op/5)%3})
		case 3:
			inst.Sessions = append(inst.Sessions, Session{From: a, To: b, LocalPref: 50 + 50*uint32(op/5%4)})
		case 4:
			inst.Sessions = append(inst.Sessions, Session{From: a, To: b, DenyExport: true})
		}
	}
	return inst, connected(inst.Routers, inst.Links)
}

// FuzzInModel: inside the model, OBGPHard converges and forwards without loops
// or black holes, with and without pruning.
//
//	go test -tags obgpsim -run '^$' -fuzz FuzzInModel ./internal/pkg/obgpsim/
func FuzzInModel(f *testing.F) {
	f.Add([]byte{4, 1, 0, 0, 1, 1, 2, 2, 3, 0, 3, 1, 0x31})
	f.Add([]byte{9, 7, 0, 0, 1, 0, 2, 1, 3, 2, 4, 3, 5, 4, 6, 5, 7, 6, 8, 7, 0x28, 1, 0x34})
	f.Add([]byte{5, 3, 3, 0, 1, 1, 2, 2, 3, 0, 4, 1, 3})       // an aggregate, a confederation of 1 and 2
	f.Add([]byte{7, 2, 4, 0, 1, 1, 2, 2, 3, 3, 4, 0, 5, 1, 6}) // a confederation of 1 to 3
	f.Fuzz(func(t *testing.T, data []byte) {
		inst, ok := decode(data)
		if !ok {
			t.Skip()
		}
		_, findings := Check(&inst, OBGPHard, OBGPNP, OBGP)
		for _, fd := range findings {
			if fd.Kind != "unreachable" { // known inside the model: the order of Gao-Rexford routes
				t.Fatalf("%+v in %+v", fd, inst)
			}
		}
	})
}

// decodeIBGP builds a network with one AS of several routers: up to 10
// routers, of which 2 to 4 share an AS, linked by the IGP, iBGP in a full
// mesh or behind a route reflector.
func decodeIBGP(data []byte) (Instance, bool) {
	if len(data) < 4 {
		return Instance{}, false
	}
	inst := Instance{Routers: 4 + int(data[0])%7, Seed: int64(data[1])}
	size := 2 + int(data[2])%3
	inst.AS = make([]int, inst.Routers)
	for i := range inst.AS {
		inst.AS[i] = i
		if i >= 1 && i <= size {
			inst.AS[i] = 1
		}
	}
	if data[3]%2 == 1 {
		inst.IBGP = []IBGP{{AS: 1, Reflectors: []int{1 + int(data[3]/2)%size}}}
	}
	data = data[4:]
	for len(data) >= 2 {
		a, b := int(data[0])%inst.Routers, int(data[1])%inst.Routers
		data = data[2:]
		if a == b {
			continue
		}
		link := [2]int{min(a, b), max(a, b)}
		if !slices.Contains(inst.Links, link) {
			inst.Links = append(inst.Links, link)
			inst.Costs = append(inst.Costs, 1+int(data0(data))%10)
		}
	}
	var inside [][2]int
	for _, l := range inst.Links {
		if inst.AS[l[0]] == 1 && inst.AS[l[1]] == 1 {
			inside = append(inside, l)
		}
	}
	group := []int{}
	for i := 1; i <= size; i++ {
		group = append(group, i)
	}
	return inst, connected(inst.Routers, inst.Links) && connectedSet(group, inside)
}

func data0(d []byte) byte {
	if len(d) == 0 {
		return 0
	}
	return d[0]
}

// FuzzIBGP: with native iBGP, OBGPHard neither loops nor
// loses routers BGP reaches, and every AS exports one path. testdata keeps
// an AS of four routers that exported two, while a withdrawal over iBGP
// still pruned.
//
//	go test -tags obgpsim -run '^$' -fuzz FuzzIBGP ./internal/pkg/obgpsim/
func FuzzIBGP(f *testing.F) {
	f.Add([]byte{3, 1, 1, 0, 0, 1, 0, 2, 1, 2, 2, 3, 1, 4})
	f.Add([]byte{6, 4, 2, 5, 0, 1, 0, 3, 1, 2, 2, 3, 3, 4, 1, 5, 5, 6, 4, 7})
	f.Add([]byte{6, 4, 0x82, 5, 0, 1, 0, 3, 1, 2, 2, 3, 3, 4, 1, 5, 5, 6, 4, 7})
	f.Fuzz(func(t *testing.T, data []byte) {
		inst, ok := decodeIBGP(data)
		if !ok {
			t.Skip()
		}
		_, findings := Check(&inst, OBGPHard, OBGPNP, OBGP)
		for _, f := range findings {
			t.Fatalf("%+v in %+v", f, inst)
		}
	})
}

// FuzzSoft: outside the model of pruning, soft pruning keeps every router
// reachable that BGP reaches, and OBGPHard still converges and forwards without
// loops or black holes.
//
//	go test -tags obgpsim -run '^$' -fuzz FuzzSoft ./internal/pkg/obgpsim/
func FuzzSoft(f *testing.F) {
	f.Add([]byte{0, 1, 0, 1, 0, 0, 2, 0, 1, 2, 0, 0, 1, 0})                   // the triangle with an export filter
	f.Add([]byte{0, 1, 0, 1, 0, 0, 2, 0, 1, 2, 0, 1, 0, 1})                   // with an import filter
	f.Add([]byte{3, 5, 0, 1, 0, 1, 2, 0, 2, 3, 0, 3, 4, 0, 0, 1, 2, 1, 2, 3}) // prepending and a preference
	f.Fuzz(func(t *testing.T, data []byte) {
		inst, ok := decodeSoft(data)
		if !ok {
			t.Skip()
		}
		if _, findings := Check(&inst, OBGP); len(findings) > 0 {
			t.Fatalf("%+v in %+v", findings, inst)
		}
	})
}
