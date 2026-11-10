// obgp-sim searches for networks where OBGP deviates from BGP: every policy
// family on every connected topology up to a number of routers, each in
// several orders of messages, one per seed. It prints in how many networks
// each mode deviates and writes the smallest example of each deviation per
// number of routers as JSON, so that a larger classic shows beside a smaller
// one, with the orders in which it showed.
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
	"time"

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
	// in some order of messages, at Affected routers in all, and whether the
	// family is inside the proof's model, where a deviation would be a
	// counterexample.
	Count    int  `json:"count,omitempty"`
	Of       int  `json:"of,omitempty"`
	Affected int  `json:"affected,omitempty"`
	InModel  bool `json:"in_model"`
	// In this network: per mode and deviation ("bgp/no-convergence") in how
	// many of Orders orders of messages it showed. The instance carries the
	// first order that showed the deviation kept.
	Shown  map[string]int `json:"shown,omitempty"`
	Orders int            `json:"orders,omitempty"`
}

func size(e example) int { return e.Instance.Routers*100 + len(e.Instance.Links) }

func main() {
	routers := flag.Int("routers", 4, "largest number of routers, all connected topologies up to it")
	seeds := flag.Int("seeds", 20, "orders of messages per network")
	only := flag.String("family", "", "only this policy family")
	out := flag.String("out", "", "write the smallest example of each deviation per number of routers to this JSON file")
	instance := flag.String("instance", "", "play this network, a JSON file of an instance, - for stdin")
	asJSON = flag.Bool("json", false, "with -trace: write every step as JSON, for the lab's Simulation")
	transient := flag.Bool("transient", false, "also report the way: forwarding loops, routers blocked waiting for a refresh, routers without a route; BGP included")
	tunnel := flag.Bool("tunnel", false, "forward inside an AS over tunnels to the exit, as MPLS")
	perNeighbor := flag.Bool("per-neighbor", false, "OBGP with a table per eBGP neighbor, as GOBGP_OPERA_EXPORT=neighbor, bgp-pn (NS-BGP) always has them")
	both := flag.Bool("both-tables", false, "play the OBGP modes with one table and, named -pn, with a table per eBGP neighbor, in one pass")
	trace := flag.String("trace", "", "with -instance: play it once in this mode, its own seed, and print every message")
	progress := flag.Bool("progress", false, "report on stderr how far the search is: \"progress done total\", networks weighed by their links")
	workers := flag.Int("workers", 0, "processes that search at once, each takes the next network once free, 0 for half the cores, at most 32")
	serve := flag.Bool("serve", false, "internal: play the networks that come on stdin, one JSON line each, and write what it found as JSON")
	flag.Parse()
	obgpsim.Transient = *transient
	obgpsim.Tunnel = *tunnel
	obgpsim.PerNeighbor = *perNeighbor
	if *both {
		modes = obgpsim.BothTables
	}
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
	// A process of a search in several plays the networks it is given.
	if *serve {
		s := newSearcher(seedList)
		in := bufio.NewScanner(os.Stdin)
		in.Buffer(make([]byte, 1<<20), 1<<24)
		for in.Scan() {
			var net placed
			if err := json.Unmarshal(in.Bytes(), &net); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			began := time.Now()
			s.play(net)
			// A network that takes long tells which it is, for the log of the search.
			if took := time.Since(began); took > SlowNetwork {
				line, _ := json.Marshal(net.Inst)
				fmt.Fprintf(os.Stderr, "slow %.0f s %s\n", took.Seconds(), line)
			}
			fmt.Fprintf(os.Stderr, "done %d\n", s.done)
		}
		if err := json.NewEncoder(os.Stdout).Encode(s.p); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	// Every network first, so that the progress knows its total: a network
	// weighs five plus its links, times its orders, about what it costs to
	// play: 1 to 3 ms per order, by its links more than by its routers.
	each := func(yield func(placed) bool) {
		place := 0
		for _, f := range obgpsim.Families {
			if *only != "" && f.Name != *only {
				continue
			}
			for n := 2; n <= *routers; n++ {
				for _, inst := range obgpsim.Instances(f, n, []int64{0}) {
					if !yield(placed{place, inst}) {
						return
					}
					place++
				}
			}
		}
	}
	total := 0
	for net := range each {
		total += weight(net.Inst) * len(seedList)
	}
	var found part
	if processes(*workers) > 1 {
		var err error
		if found, err = inParallel(processes(*workers), each, total, *progress); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		told := -1
		s := newSearcher(seedList)
		for net := range each {
			s.play(net)
			if pct := 1000 * s.done / max(1, total); *progress && pct != told {
				told = pct
				fmt.Fprintf(os.Stderr, "progress %d %d\n", s.done, total)
			}
		}
		found = s.p
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
	Settled   int             `json:"settled"`           // the runs at rest at every bounded event and at the end
	Endless   int             `json:"endless"`           // the runs without rest that returned to an earlier state: orders without end
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

// SlowNetwork is how long a network may take in a search before its process names it.
const SlowNetwork = 60 * time.Second

// modes are those a search or a play checks, every one by default, see -both-tables.
var modes []obgpsim.Mode

// traceOne plays one instance once in one mode, with the seed it carries.
func traceOne(file string, mode obgpsim.Mode) error {
	if file == "" {
		return fmt.Errorf("-trace needs -instance")
	}
	if !slices.Contains(obgpsim.BothTables, mode) {
		return fmt.Errorf("unknown mode %s, known: %v", mode, obgpsim.BothTables)
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

// play plays one instance with seeds 1 to seeds in every mode and writes per
// mode how often it converged, failed each check and showed each finding.
func play(file string, seeds int) error {
	inst, err := load(file)
	if err != nil {
		return err
	}
	out := map[obgpsim.Mode]*outcome{}
	for seed := 1; seed <= seeds; seed++ {
		inst.Seed = int64(seed)
		results, findings := obgpsim.Check(&inst, modes...)
		for m, r := range results {
			o := out[m]
			if o == nil {
				o = &outcome{Failed: make([]int, len(r.Checks)), Findings: map[string]int{}}
				out[m] = o
			}
			o.Runs++
			if !r.Converged && r.Cycle != nil {
				o.Endless++
			}
			if r.Converged {
				o.Converged++
				if r.Restless == 0 {
					o.Settled++
				}
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

// weight is about what a network costs to play once, see the progress.
func weight(inst obgpsim.Instance) int { return 5 + len(inst.Links) }

// placed is a network with its place in the order of all networks.
type placed struct {
	Place int              `json:"place"`
	Inst  obgpsim.Instance `json:"inst"`
}

// searcher plays networks in every order of seeds and keeps what they show:
// a deviation counts once per network, kept with the first order that
// showed it and in how many orders each deviation of the network showed.
// done is the weight of the networks played.
type searcher struct {
	seeds []int64
	p     part
	done  int
}

func newSearcher(seeds []int64) *searcher {
	return &searcher{seeds: seeds, p: part{Counts: map[string]int{}, Affected: map[string]int{}, Totals: map[string]int{}, Smallest: smallestOf{}}}
}

func (s *searcher) play(net placed) {
	p, seeds, place, n := s.p, s.seeds, net.Place, net.Inst.Routers
	s.done += weight(net.Inst) * len(seeds)
	p.Totals[net.Inst.Family]++
	shown := map[string]int{}
	first := map[string]example{}
	var keys []string
	for _, seed := range seeds {
		inst := net.Inst
		inst.Seed = seed
		results, findings := obgpsim.Check(&inst, modes...)
		// No rest counts in every order without it: Check reports it for OBGP only where BGP rested.
		for m, r := range results {
			if !r.Converged {
				shown[string(m)+"/no-rest"]++
			}
		}
		seen := map[string]bool{}
		for _, fd := range findings {
			key := fmt.Sprintf("%s\t%s\t%s", inst.Family, fd.Mode, fd.Kind)
			if seen[key] {
				continue
			}
			seen[key] = true
			if fd.Kind != "no-convergence" {
				shown[string(fd.Mode)+"/"+fd.Kind]++
			}
			if _, ok := first[key]; !ok {
				first[key] = example{Instance: inst, Finding: fd, Results: results, Findings: findings}
				keys = append(keys, key)
			}
		}
	}
	for m := range shown {
		if mode, ok := strings.CutSuffix(m, "/no-rest"); ok {
			shown[mode+"/no-convergence"] = shown[m]
			delete(shown, m)
		}
	}
	for _, key := range keys {
		e := first[key]
		e.Shown, e.Orders = shown, len(seeds)
		p.Counts[key]++
		p.Affected[key] += len(e.Finding.Routers)
		if p.Smallest[key] == nil {
			p.Smallest[key] = map[int]placedExample{}
		}
		keep(p.Smallest[key], n, placedExample{e, place})
	}
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

// inParallel runs this program again in n processes and hands each the
// next network of each as soon as it is done with its last, so that none
// waits while another still has a long share. It sums how far they are into
// one progress and merges what they found.
func inParallel(n int, each func(func(placed) bool), total int, progress bool) (part, error) {
	// This process only makes, hands out and merges: two threads, so that the search keeps to the
	// processes it was given, as the lab counts them against its share of the host.
	runtime.GOMAXPROCS(2)
	// The processes report "done", not progress, and write no file: -progress has no value, -out and -workers one.
	args := slices.DeleteFunc(withoutValue(os.Args[1:], "out", "workers"), func(a string) bool {
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		return strings.HasPrefix(a, "-") && name == "progress"
	})
	merged := part{Counts: map[string]int{}, Affected: map[string]int{}, Totals: map[string]int{}, Smallest: smallestOf{}}
	networks := make(chan placed, n)
	go func() {
		for net := range each {
			networks <- net
		}
		close(networks)
	}()
	var mu sync.Mutex
	done := make([]int, n)
	told := -1
	var wg sync.WaitGroup
	errs := make([]error, n)
	parts := make([]part, n)
	for i := range n {
		cmd := exec.Command(os.Args[0], append(append([]string{}, args...), "-serve")...)
		cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return merged, err
		}
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
			// One network ahead, so that a process never waits for the next.
			enc, closed := json.NewEncoder(stdin), false
			give := func() {
				if closed {
					return
				}
				if net, ok := <-networks; ok && enc.Encode(net) == nil {
					return
				}
				closed = true
				stdin.Close() // no network left: the process writes what it found and ends
			}
			give()
			give()
			lines := bufio.NewScanner(stderr)
			for lines.Scan() {
				if d, ok := strings.CutPrefix(lines.Text(), "done "); ok {
					v, _ := strconv.Atoi(d)
					give()
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
