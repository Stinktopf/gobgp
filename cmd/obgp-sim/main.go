// obgp-sim searches for networks where OBGP deviates from BGP: every policy
// family on every connected topology up to a number of routers, each with
// a few seeds for the order of messages. It prints how often each mode
// deviates and writes the smallest example of each deviation per number of
// routers as JSON, so that a larger classic shows beside a smaller one.
//
// With -instance it plays one network instead, e.g. one the lab converted
// from a topology and scenario, in every mode with many orders of messages,
// and prints as JSON how often each mode converged, failed each expect and
// showed each deviation. With -trace it plays it once in one mode and prints
// every message and how each router forwards after it.
package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/osrg/gobgp/v4/internal/pkg/obgpsim"
)

type example struct {
	Instance obgpsim.Instance                `json:"instance"`
	Finding  obgpsim.Finding                 `json:"finding"`
	Results  map[obgpsim.Mode]obgpsim.Result `json:"results"`
	// Every finding of the network in every mode, so that the lab can tell
	// which modes show the deviation there, not only the one kept for it.
	Findings []obgpsim.Finding `json:"findings"`
	// How often the deviation showed: in Count of Of networks of its family,
	// at Affected routers in all, and whether the family is inside the
	// proof's model, where a deviation would be a counterexample.
	Count    int  `json:"count,omitempty"`
	Of       int  `json:"of,omitempty"`
	Affected int  `json:"affected,omitempty"`
	InModel  bool `json:"in_model"`
}

func size(e example) int { return e.Instance.Routers*100 + len(e.Instance.Links) }

func main() {
	routers := flag.Int("routers", 4, "largest number of routers, all connected topologies up to it")
	seeds := flag.Int("seeds", 3, "orders of messages per network")
	only := flag.String("family", "", "only this policy family")
	out := flag.String("out", "", "write the smallest example of each deviation per number of routers to this JSON file")
	instance := flag.String("instance", "", "play this network, a JSON file of an instance, - for stdin")
	asJSON = flag.Bool("json", false, "with -trace: write every step as JSON, for the lab's Simulation")
	transient := flag.Bool("transient", false, "also report the way: forwarding loops, routers blocked waiting for a refresh, routers without a route; BGP included")
	tunnel := flag.Bool("tunnel", false, "forward inside an AS over tunnels to the exit, as MPLS")
	perNeighbor := flag.Bool("per-neighbor", false, "OBGP with a table per eBGP neighbor, as GOBGP_OPERA_EXPORT=neighbor")
	trace := flag.String("trace", "", "with -instance: play it once in this mode, its own seed, and print every message")
	progress := flag.Bool("progress", false, "report on stderr how far the search is: \"progress done total\", networks weighed by their routers squared")
	flag.Parse()
	obgpsim.Transient = *transient
	obgpsim.Tunnel = *tunnel
	obgpsim.PerNeighbor = *perNeighbor
	if *trace != "" {
		if err := traceOne(*instance, obgpsim.Mode(*trace)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *instance != "" {
		if err := play(*instance, *seeds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	var seedList []int64
	for s := range *seeds {
		seedList = append(seedList, int64(s+1))
	}
	smallest := map[string]map[int]example{} // by deviation, then by number of routers
	counts, affected := map[string]int{}, map[string]int{}
	totals := map[string]int{}
	// Every network first, so that the progress knows its total: a network
	// weighs its routers squared, about what it costs to play.
	type batch struct {
		n     int
		insts []obgpsim.Instance
	}
	var batches []batch
	total, done, told := 0, 0, -1
	for _, f := range obgpsim.Families {
		if *only != "" && f.Name != *only {
			continue
		}
		for n := 2; n <= *routers; n++ {
			insts := obgpsim.Instances(f, n, seedList)
			batches = append(batches, batch{n, insts})
			total += len(insts) * n * n
		}
	}
	for _, b := range batches {
		n := b.n
		{
			for _, inst := range b.insts {
				if *progress {
					done += n * n
					if pct := 1000 * done / max(1, total); pct != told {
						told = pct
						fmt.Fprintf(os.Stderr, "progress %d %d\n", done, total)
					}
				}
				totals[inst.Family]++
				results, findings := obgpsim.Check(&inst)
				for _, fd := range findings {
					key := fmt.Sprintf("%s\t%s\t%s", inst.Family, fd.Mode, fd.Kind)
					counts[key]++
					affected[key] += len(fd.Routers)
					e := example{Instance: inst, Finding: fd, Results: results, Findings: findings}
					if smallest[key] == nil {
						smallest[key] = map[int]example{}
					}
					if old, ok := smallest[key][n]; !ok || size(e) < size(old) {
						smallest[key][n] = e
					}
				}
			}
		}
	}

	fmt.Printf("%-16s %-9s %-19s %8s %8s %8s  %s\n", "family", "mode", "deviation", "networks", "of", "routers", "in model")
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return cmp.Compare(a, b) })
	inModel := map[string]bool{}
	for _, f := range obgpsim.Families {
		inModel[f.Name] = f.InModel
	}
	labels := make([]string, 0, len(totals))
	for l := range totals {
		labels = append(labels, l)
	}
	slices.Sort(labels)
	for _, l := range labels {
		if !slices.ContainsFunc(keys, func(k string) bool { return strings.HasPrefix(k, l+"\t") }) {
			fmt.Printf("%-16s %-9s %-19s %8d %8d %8d  %v\n", l, "all", "none", 0, totals[l], 0, inModel[l])
		}
	}
	for _, k := range keys {
		parts := strings.Split(k, "\t")
		fmt.Printf("%-16s %-9s %-19s %8d %8d %8d  %v\n", parts[0], parts[1], parts[2], counts[k], totals[parts[0]], affected[k], inModel[parts[0]])
	}
	if *out != "" {
		list := make([]example, 0, len(smallest))
		for _, k := range keys {
			family := strings.Split(k, "\t")[0]
			for n := 2; n <= *routers; n++ {
				if e, ok := smallest[k][n]; ok {
					e.Count, e.Of, e.Affected, e.InModel = counts[k], totals[family], affected[k], inModel[family]
					list = append(list, e)
				}
			}
		}
		data, _ := json.MarshalIndent(list, "", "  ")
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

// outcome is how one mode played an instance over all orders of messages.
type outcome struct {
	Runs      int             `json:"runs"`
	Converged int             `json:"converged"`
	Failed    []int           `json:"failed"`            // per expect, the runs in which it failed
	Findings  map[string]int  `json:"findings"`          // per deviation, the runs that showed it
	Example   *obgpsim.Result `json:"example,omitempty"` // the first run with a failed expect
}

func load(file string) (obgpsim.Instance, error) {
	var inst obgpsim.Instance
	var data []byte
	var err error
	if file == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(file)
	}
	if err != nil {
		return inst, err
	}
	return inst, json.Unmarshal(data, &inst)
}

var asJSON *bool

// traceOne plays one instance once in one mode, with the seed it carries.
func traceOne(file string, mode obgpsim.Mode) error {
	if file == "" {
		return fmt.Errorf("-trace needs -instance")
	}
	if !slices.Contains(obgpsim.Modes, mode) {
		return fmt.Errorf("unknown mode %s, known: %v", mode, obgpsim.Modes)
	}
	inst, err := load(file)
	if err != nil {
		return err
	}
	obgpsim.Transient = true
	if *asJSON {
		r, steps := obgpsim.Record(&inst, mode)
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"instance": inst, "mode": mode, "steps": steps, "result": r})
	}
	r := obgpsim.Trace(&inst, mode, os.Stdout)
	fmt.Printf("converged %v after %d messages, first loop on the way %v\n", r.Converged, r.Steps, r.Transient)
	fmt.Printf("on the way, after messages: looped %d, blocked waiting for a refresh %d, without a route %d\n", r.Looped, r.Blocked, r.Holes)
	return nil
}

func play(file string, seeds int) error {
	inst, err := load(file)
	if err != nil {
		return err
	}
	out := map[obgpsim.Mode]*outcome{}
	for seed := 1; seed <= seeds; seed++ {
		inst.Seed = int64(seed)
		results, findings := obgpsim.Check(&inst)
		for m, r := range results {
			o := out[m]
			if o == nil {
				o = &outcome{Failed: make([]int, len(r.Checks)), Findings: map[string]int{}}
				out[m] = o
			}
			o.Runs++
			if r.Converged {
				o.Converged++
			}
			failed := false
			for i, c := range r.Checks {
				if !c.Passed {
					o.Failed[i]++
					failed = true
				}
			}
			if failed && o.Example == nil {
				example := r
				o.Example = &example
			}
		}
		seen := map[string]bool{}
		for _, f := range findings {
			if key := string(f.Mode) + "/" + f.Kind; !seen[key] {
				seen[key] = true
				out[f.Mode].Findings[f.Kind]++
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
