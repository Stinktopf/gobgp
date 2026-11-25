//go:build obgpsim

package obgpsim

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func disagree(seed int64) Instance {
	return Instance{Routers: 3, Links: [][2]int{{0, 1}, {0, 2}, {1, 2}}, Seed: seed,
		Sessions: []Session{{From: 1, To: 2, LocalPref: 200}, {From: 2, To: 1, LocalPref: 200}}}
}

// DISAGREE without rest returns to a state it was in: the run ends with an
// order without end, long before the bound, and the state really recurs.
func TestDisagreeWithoutRestIsAnOrderWithoutEnd(t *testing.T) {
	endless, rests := 0, 0
	for seed := int64(1); seed <= 40; seed++ {
		inst := disagree(seed)
		r := Run(&inst, BGP, MaxSteps)
		if r.Converged {
			rests++
			assert.Nil(t, r.Cycle)
			continue
		}
		if assert.NotNil(t, r.Cycle, seed) {
			endless++
			assert.Less(t, r.Steps, MaxSteps)
			assert.Equal(t, stateAfter(&inst, BGP, MaxSteps, r.Cycle.From), stateAfter(&inst, BGP, MaxSteps, r.Cycle.From+r.Cycle.Length))
		}
		for _, m := range []Mode{OBGPHard, OBGPNP, BGPPN} {
			assert.True(t, Run(&inst, m, MaxSteps).Converged, m)
		}
	}
	assert.Positive(t, endless)
	assert.Positive(t, rests)
}

// The state compares times by their order only: two runs whose clocks
// differ by a shift are in the same state.
func TestAStateKeepsTimesInTheirOrderOnly(t *testing.T) {
	w := &walker{seen: map[uintptr]int{}}
	w.time(10)
	w.time(12)
	w.time(10)
	v := &walker{seen: map[uintptr]int{}}
	v.time(110)
	v.time(250)
	v.time(110)
	assert.Equal(t, w.finish(), v.finish())
}

// A bounded step comes after a share of the messages: the state to confirm
// a cycle on is that of the same run, with the same bound.
func TestACycleAfterABoundedStepIsConfirmedOnTheSameRun(t *testing.T) {
	for seed := int64(1); seed <= 10; seed++ {
		inst := disagree(seed)
		inst.Events = []Event{{After: 1 << 30, Bounded: true, Kind: "prepend", From: 0, To: 1, Value: 1}}
		r := Run(&inst, BGP, MaxSteps)
		if r.Cycle == nil {
			continue
		}
		assert.True(t, bytes.Equal(stateAfter(&inst, BGP, MaxSteps, r.Cycle.From), stateAfter(&inst, BGP, MaxSteps, r.Cycle.From+r.Cycle.Length)), seed)
	}
}

// A replay of a run without end ends with the message that closed the cycle.
func TestARecordedRunWithoutEndHoldsEveryMessage(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		inst := disagree(seed)
		r, steps := Record(&inst, BGP)
		if r.Cycle == nil {
			continue
		}
		messages := 0
		for _, s := range steps {
			if s.Kind != "event" {
				messages++
			}
		}
		assert.Equal(t, r.Steps, messages, seed)
		return
	}
	t.Fatal("no run without end")
}

// With the way to rest checked, NS-BGP builds tables after a message: the
// replay takes its state after the same, or no cycle is ever confirmed and
// each look replays the run anew.
func TestACycleIsConfirmedAlsoWithTheWayToRest(t *testing.T) {
	defer func() { Transient = false }()
	Transient = true
	inst := Instance{Routers: 4, Links: [][2]int{{0, 1}, {0, 2}, {0, 3}, {1, 2}, {1, 3}, {2, 3}}, Seed: 1,
		Sessions: []Session{{From: 1, To: 2, LocalPref: 200}, {From: 3, To: 1, LocalPref: 200}, {From: 2, To: 3, LocalPref: 200}}}
	r := Run(&inst, BGPPN, MaxSteps)
	if assert.NotNil(t, r.Cycle) {
		assert.Less(t, r.Steps, 1000)
	}
}
