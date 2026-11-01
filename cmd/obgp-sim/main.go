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
	"bufio"
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

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
	perNeighbor := flag.Bool("per-neighbor", false, "OBGP with a table per eBGP neighbor, as GOBGP_OPERA_EXPORT=neighbor, bgp-pn (NS-BGP) always has them")
	trace := flag.String("trace", "", "with -instance: play it once in this mode, its own seed, and print every message")
	progress := flag.Bool("progress", false, "report on stderr how far the search is: \"progress done total\", networks weighed by their routers squared")
	workers := flag.Int("workers", 0, "processes that search at once, each every n-th network, 0 for half the cores, at most 32")
	shard := flag.String("shard", "", "internal: search only network i of every n, \"i/n\", and write what it found as JSON")
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
	// Every network first, so that the progress knows its total: a network
	// weighs its routers squared, about what it costs to play.
	var all []obgpsim.Instance
	total := 0
	for _, f := range obgpsim.Families {
		if *only != "" && f.Name != *only {
			continue
		}
		for n := 2; n <= *routers; n++ {
			insts := obgpsim.Instances(f, n, seedList)
			all = append(all, insts...)
			total += len(insts) * n * n
		}
	}
	var found part
	switch {
	case *shard != "":
		var i, of int
		if _, err := fmt.Sscanf(*shard, "%d/%d", &i, &of); err != nil || of < 1 || i < 0 || i >= of {
			fmt.Fprintln(os.Stderr, "-shard is i/n")
			os.Exit(2)
		}
		found = search(all, i, of, func(done int) { fmt.Fprintf(os.Stderr, "done %d\n", done) })
		if err := json.NewEncoder(os.Stdout).Encode(found); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	case processes(*workers) > 1 && len(all) > 1:
		var err error
		if found, err = inParallel(processes(*workers), total, *progress); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		told := -1
		found = search(all, 0, 1, func(done int) {
			if pct := 1000 * done / max(1, total); *progress && pct != told {
				told = pct
				fmt.Fprintf(os.Stderr, "progress %d %d\n", done, total)
			}
		})
	}
	smallest, counts, affected, totals := found.Smallest.examples(), found.Counts, found.Affected, found.Totals

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

// part is what a search found in its share of the networks: per deviation
// how often, at how many routers, and its smallest example per number of
// routers, each with its place in the order of all networks.
type part struct {
	Counts   map[string]int `json:"counts"`
	Affected map[string]int `json:"affected"`
	Totals   map[string]int `json:"totals"`
	Smallest smallestOf     `json:"smallest"`
}

type placedExample struct {
	Example example `json:"example"`
	Place   int     `json:"place"`
}

type smallestOf map[string]map[int]placedExample

func (s smallestOf) examples() map[string]map[int]example {
	out := map[string]map[int]example{}
	for k, byN := range s {
		out[k] = map[int]example{}
		for n, e := range byN {
			out[k][n] = e.Example
		}
	}
	return out
}

// keep takes e where it is smaller, or as small and earlier in the order of
// all networks, so that a search in several processes keeps what one would.
func keep(byN map[int]placedExample, n int, e placedExample) {
	old, ok := byN[n]
	if !ok || size(e.Example) < size(old.Example) || size(e.Example) == size(old.Example) && e.Place < old.Place {
		byN[n] = e
	}
}

// search plays network i, i+of, i+2of, ... of all and tells done, the weight
// of the networks played, after each.
func search(all []obgpsim.Instance, i, of int, tell func(done int)) part {
	p := part{Counts: map[string]int{}, Affected: map[string]int{}, Totals: map[string]int{}, Smallest: smallestOf{}}
	done := 0
	for place := i; place < len(all); place += of {
		inst := all[place]
		n := inst.Routers
		done += n * n
		tell(done)
		p.Totals[inst.Family]++
		results, findings := obgpsim.Check(&inst)
		for _, fd := range findings {
			key := fmt.Sprintf("%s\t%s\t%s", inst.Family, fd.Mode, fd.Kind)
			p.Counts[key]++
			p.Affected[key] += len(fd.Routers)
			if p.Smallest[key] == nil {
				p.Smallest[key] = map[int]placedExample{}
			}
			keep(p.Smallest[key], n, placedExample{example{Instance: inst, Finding: fd, Results: results, Findings: findings}, place})
		}
	}
	return p
}

// processes is how many processes search: half the cores of a host that is
// often shared, at most 32, unless asked for a number. The options of OBGP
// are global to the router's code, so a play has a process to itself.
func processes(asked int) int {
	if asked > 0 {
		return asked
	}
	return max(1, min(32, runtime.NumCPU()/2))
}

// inParallel runs this program again in n processes, each on its share of
// the networks, sums how far they are into one progress and merges what
// they found.
func inParallel(n, total int, progress bool) (part, error) {
	// The processes report "done", not progress, and write no file: -progress has no value, -out and -workers one.
	args := slices.DeleteFunc(withoutValue(os.Args[1:], "out", "workers"), func(a string) bool {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		return strings.HasPrefix(a, "-") && name == "progress"
	})
	merged := part{Counts: map[string]int{}, Affected: map[string]int{}, Totals: map[string]int{}, Smallest: smallestOf{}}
	var mu sync.Mutex
	done := make([]int, n)
	told := -1
	var wg sync.WaitGroup
	errs := make([]error, n)
	parts := make([]part, n)
	for i := range n {
		cmd := exec.Command(os.Args[0], append(append([]string{}, args...), "-shard", fmt.Sprintf("%d/%d", i, n))...)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return merged, err
		}
		var out strings.Builder
		cmd.Stdout = &out
		if err := cmd.Start(); err != nil {
			return merged, err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			lines := bufio.NewScanner(stderr)
			for lines.Scan() {
				if d, ok := strings.CutPrefix(lines.Text(), "done "); ok {
					v, _ := strconv.Atoi(d)
					mu.Lock()
					done[i] = v
					sum := 0
					for _, x := range done {
						sum += x
					}
					if pct := 1000 * sum / max(1, total); progress && pct != told {
						told = pct
						fmt.Fprintf(os.Stderr, "progress %d %d\n", sum, total)
					}
					mu.Unlock()
				} else {
					fmt.Fprintln(os.Stderr, lines.Text())
				}
			}
			if err := cmd.Wait(); err != nil {
				errs[i] = fmt.Errorf("search process %d of %d: %w", i, n, err)
				return
			}
			errs[i] = json.Unmarshal([]byte(out.String()), &parts[i])
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			return merged, errs[i]
		}
		p := parts[i]
		for k, v := range p.Counts {
			merged.Counts[k] += v
		}
		for k, v := range p.Affected {
			merged.Affected[k] += v
		}
		for k, v := range p.Totals {
			merged.Totals[k] += v
		}
		for k, byN := range p.Smallest {
			if merged.Smallest[k] == nil {
				merged.Smallest[k] = map[int]placedExample{}
			}
			for r, e := range byN {
				keep(merged.Smallest[k], r, e)
			}
		}
	}
	return merged, nil
}

// withoutValue is args without the flags named and their values, in both
// forms, -name value and -name=value.
func withoutValue(args []string, names ...string) []string {
	var out []string
	for k := 0; k < len(args); k++ {
		a := strings.TrimLeft(args[k], "-")
		name, _, inline := strings.Cut(a, "=")
		if slices.Contains(names, name) && strings.HasPrefix(args[k], "-") {
			if !inline && k+1 < len(args) {
				k++
			}
			continue
		}
		out = append(out, args[k])
	}
	return out
}
