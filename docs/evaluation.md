# Evaluation

How the lab answers each question: what a run is, what it measures, when it counts as a problem, and
how far the numbers go.

## Questions

One experiment per question.

| Question | Experiment |
|---|---|
| Does OBGP converge where BGP oscillates, in every mode? | [`behaviour-oscillation`](../experiments/behaviour-oscillation.yaml) |
| Does OBGP on a share of the routers stop oscillation, in every mode? | [`behaviour-deployment`](../experiments/behaviour-deployment.yaml) |
| Does it still converge, and how fast, with an MRAI of 30 s? | [`behaviour-mrai`](../experiments/behaviour-mrai.yaml) |
| Does it come to rest after failures? | [`behaviour-failures`](../experiments/behaviour-failures.yaml) |
| Do Gao-Rexford policies hold, also in partial deployment, and does every router keep what BGP reaches? | [`semantics-gao-rexford`](../experiments/semantics-gao-rexford.yaml) |
| Does it keep BGP's semantics in the cases of the Go tests? | [`semantics-adversarial`](../experiments/semantics-adversarial.yaml) |
| Where does it fail outside its model or inside an AS? | [`semantics-limits`](../experiments/semantics-limits.yaml) |
| Does it scale to 128 networks of the Internet's core? | [`internet-scale`](../experiments/internet-scale.yaml) |
| Does it hold full tables? | [`internet-dfz`](../experiments/internet-dfz.yaml) |
| Where does a router spend its CPU in each mode, and what limits the busiest one? | [`performance-scale`](../experiments/performance-scale.yaml) |
| Does the lab work? | [`lab-smoke`](../experiments/lab-smoke.yaml) |
| Does it run every feature? | [`lab-features`](../experiments/lab-features.yaml) |
| Does it measure right? | [`lab-calibration`](../experiments/lab-calibration.yaml) |
| Does sampling change what it measures? | [`lab-sampling`](../experiments/lab-sampling.yaml) |
| Does a link delay bring it to the orders of messages the simulator finds? | [`lab-orders`](../experiments/lab-orders.yaml) |

The paper's experiment `ifip-networking-2026` stays as it was published.

## A run

- **Experiment:** topologies × scenarios × variants × runs. A variant is a [mode](router.md#modes)
  with its settings. One topology and scenario is a cell.
- **Router:** one Kubernetes pod per router, gobgpd and a controller beside it. The controller runs
  the scenario's steps and samples each router at 10 Hz, the Internet runs at 1 Hz. With
  `sampling: {profile_s: 120, profile_routers: 3}` the three routers with the most neighbors take CPU
  profiles in chunks of 5 s from the start of the first announcing step until rest and its quiet time,
  alike in every mode, at most 120 s. A profile cut before rest, or of a run without rest, is kept but
  gives no profile metrics, so that no mode gains by a shorter window. Each chunk is kept beside the run as `cpu-<router>-<t>.pb.gz`, t its start in the run's
  seconds, the allocations at start and end as `allocs-<router>-start.pb.gz` and `-end`, for `go tool pprof`.
- **Recording:** with `sampling: {record_routers: 3}` the three routers with the most neighbors record
  every UPDATE they receive from the first announcing step on, kept beside the run as
  `updates-<router>.mrt.gz` (MRT, whole seconds).
- **Feed:** a scenario of one `feed` step runs one router of a recorded run alone. Each of its neighbors
  is a feeder (`cmd/obgp-replay`) that sends it the UPDATEs that neighbor sent it in the recording, as
  fast as it takes them (`flood`) or at the recorded seconds (`paced`), and answers a route refresh with
  what it sent so far. The variants are the modes or commits compared, on the same input. The final
  check keeps what the router sent each feeder and a digest of it, equal when two runs sent the same.
  A feed names a recorded result, so its scenario and experiment are saved in the lab for each comparison.
- **Benchmark:** `benchmark: {baseline: <ref>, candidates: [<ref>], modes: [obgp-rp-pn]}` (Experiments, New benchmark)
  makes one result: per mode the baseline, its A/A twin and each candidate run the workload on the whole network,
  the busiest router profiled. With `feed: true` the baseline first records what that router receives, once per
  mode, and the others get it fed to that router alone. The variants, the speed rule and the profiles follow. The
  Benchmark area shows the verdict per mode and compares a chosen pair, Reference and Compared with, on one radar.
- **Changes for speed:** see Benchmark, and the speed rule under Statistics, which the lab judges (MCP `speed`).
  With `sampling: {paths: false}` the routers read no paths while they sample, so their CPU is their own:
  loops and black holes on the way and path lengths are then not measured.
- **Scenario:** steps that announce, withdraw, fail links, restart routers and change policies.
- **Seed:** fixes a scenario's random choices and the order of the variants in a round. Variants of
  one run share it, so they are paired.
- **Rest:** no route changes and no updates for the quiet time, 3 s by default, 5 s in the Internet runs,
  with an MRAI at least one and a half MRAI. A router that samples rarely stands by its latest sample
  while its next one shows no change.
- **Reference:** the BGP run of the same seed, where it came to rest.

## Metrics

A *path* is one AS path to a prefix from one neighbor. A *route* is the path a router selected for a prefix.

**Time**

| Metric | Unit | Until |
|---|---|---|
| Full reach | s | every router holds every prefix, routes may still change |
| Settle | s | no router changes anything and no update is sent |
| Settle after the last step | s | the same, from the last step: for a series of steps, such as flaps, rest after all of them |

**End state**

| Metric | Unit | Counts |
|---|---|---|
| Never at rest | runs | runs whose routes still change in the last of three quiet times after the last step |
| Not reached | routes | router and prefix pairs without a route |
| Loops, black holes | prefixes | prefixes whose packets loop, or end at a router without a route |
| Withdrawn kept | routes | router and prefix pairs still held after their withdrawal |
| Updates at rest | updates/s | per router in the longest pause between steps, from settle on, zero when routes stand still |
| Updates per neighbor | per prefix | the most a router received from one neighbor from the first announcement to the next step, per announced prefix |

**On the way**

| Metric | Unit | Counts |
|---|---|---|
| Loops on the way | s | time in which packets to some prefix looped |
| Black holes on the way | s | time in which packets to some prefix ended without a route |
| Blocked | s | time in which a router set aside a valid path and had no route |
| Blocked | prefixes | the most at one router at once |
| Session drops | drops | sessions that fell from established, both ends count |
| Drops no step explains | drops | of sessions no step touched |

Loops and black holes on the way follow the next hops each router samples on every change, each from
when it was read, not from the time of its sample. The routers read one after another, so a loop or black
hole shorter than two sampling intervals may be no more than that. The problems count only longer ones. Above 256 prefixes every router follows the same
sample of 256. With a table per neighbor, `bgp-pn` and `-pn` alike, packets from an eBGP
neighbor follow the route sent to it, see [DESIGN.md](../DESIGN.md#a-table-per-neighbor). A
stopped router forwards nothing. Back up, it counts as neither loop nor black hole until it has told
its routes again, as its old ones went with the restart.

**Tables and resources**

| Metric | Unit | Counts |
|---|---|---|
| Routes | prefixes | with a selected route, the Loc-RIB of RFC 4271 |
| Known | prefixes | with a path admitted or set aside |
| Adj-RIB-In | paths | received from all neighbors |
| Admitted | paths | admitted by the import, the Loc-RIB of the paper |
| Set aside | paths | kept by OBGP without admitting them |
| Memory | MiB | resident memory of the daemon |

## Problems

Every run is checked at its end against its reference, whatever its scenario checks.

| Problem | When |
|---|---|
| Routes still change at the end | updates go on after the rest |
| A step found no rest in time | a step waited for rest in vain |
| No rest before the final check | the final check waited for rest in vain |
| Loops at rest | packets to a prefix loop at the end |
| Fewer routes than BGP | a router holds fewer prefixes than in the reference, the prefixes named where at most three are missing |
| No BGP run at rest to compare with | a run misses prefixes and the reference never came to rest |
| More black holes than BGP | more than in the reference, or any where it never came to rest |
| More withdrawn routes kept than BGP | more than in the reference, or any where it never came to rest |
| Paths against the relations, more than BGP | more than in the reference. Paths with an `AS_SET` are not judged |
| Loops on the way, longer than BGP | longer than in every BGP run of the cell by more than two sampling intervals |
| Black holes on the way, longer than BGP | the same for black holes |
| Routers wait without a route | blocked longer than two sampling intervals, under refresh pruning longer than the wait for a route refresh plus two sampling intervals |
| Sessions dropped without a step | drops no step explains |
| At rest where the simulator never rests | a run comes to rest where the simulator never did |
| No final check | skipped, for tables above 2000 prefixes or a router that does not answer twice within 120 s |
| Routes at rest worse or better than the baseline's | a commit-only variant chooses routes of another quality at rest than the baseline of the same seed (AS path length and neighbor relation, in a feed the path length a feeder gets). Routers that also differ in the A/A variant do not count. Where they differ there too, as OBGP's may, the routes of all routers added up compare instead: prefixes held, path lengths summed and routes from customers, peers and providers, beyond what the A/A variant deviates in any seed |
| No routes at rest to compare with the baseline | such a variant or its baseline was not at rest or had no final check, so the comparison above could not be made, or its routes vary as the baseline's own runs do and their totals stay within them |

As a result begins, the [simulator](simulator.md) plays every cell it can, 20 message orders per mode,
and every run of a cell whose scenario chooses targets or whose variant chooses its OBGP routers at random.
Each failed check and broken property is judged against it:

- **Predicted:** the simulator showed it for that mode in some order, e.g. BGP without rest on BAD GADGET.
  BAD GADGET has a stable state: BGP comes to rest there in some orders and runs, not in all.
- **Not predicted:** the simulator played the mode and scenario and did not show it. This fails a result.
  Where a run contradicts the prediction, the simulator plays that cell in 1,000 orders first: rest, a failed
  check, a loop, black hole or block on the way.
- **No answer:** the simulator can play the mode and scenario but failed, timed out, reached no order up to the
  check, or answered before it judged this. This fails a result as well: predict again.
- **Not predictable:** the simulator cannot play the mode or scenario, e.g. prefixes of the Internet,
  or was never asked. Told, not judged. A run without problems there is done but not predictable, never a plain pass.
  A pure OBGP mode must still come to rest: a run of it without rest counts as not predicted. Its way to rest is not judged.

A check is matched to the simulator's by its scenario step, not by its place in time: the checks of a parallel
step end in any order. A check the scenario allows a mode to fail counts as predicted only where the simulator
failed it as well. A calibration result passes only where `lab calibrate` finds the known values. Its bounds of the time until
every router has the withdrawal come from the link delays and one TCP round trip per hop. They are derived,
not measured.

With an MRAI, rest is not predictable. The simulator plays the MRAI as coalescing, without its timer
([details](simulator.md#lab-steps-in-the-simulator)). A run without rest is then
predicted where the simulator showed it and not judged otherwise, and a run at rest where the simulator never rests is
not a problem. Checks, lost routes and loops stay judged.

- **Error:** a run without samples.
- **Not measured:** a completed run without a rest value, e.g. when its samples after the last step span
  less than the quiet time.
- **Passed:** a finished result without errors, runs not measured, or failed checks and problems the
  simulator did not predict or gave no answer for. The verdict rests on the result alone.

## Statistics

- **Interval:** the median of each cell with its exact confidence interval.
- **Paired variants:** Wilcoxon signed-rank tests on runs of the same seed.
- **Primary comparison:** each behaviour and Internet experiment names one, e.g. `primary: {metric: hold_churn, baseline: bgp}`.
  Every other variant is tested against the baseline, Holm-corrected across its cells. An experiment
  whose runs cannot reach 5 % after Holm is refused.
- **Never pooled:** modes are compared, never combined.
- **Speed rule:** `speed: {baseline: <ref>, metric: cpu_s_mean, margin_pct: 5, guards: [settle_s, rss_mean, flaps], guard_pct: 10}`.
  The baseline ref is the same commit in every mode and stands twice in each mode it compares, the second time as its
  A/A variant. Every other ref of that mode and settings is a candidate. The experiment is refused when its runs
  cannot reach the corrected level for all its comparisons, e.g. 7 runs for two. A candidate is *faster* in a cell where its Hodges-Lehmann interval, at a level Bonferroni-corrected
  for all candidate cells, lies below minus the margin of the baseline's median, Holm's p is below 5 %, it chooses
  and sends what the baseline does at rest, and no guard gets worse beyond its percent, times also by their
  resolution. The margin comes from earlier A/A pairs. Where the A/A variant shifts beyond the margin itself,
  the lab moved and no verdict is given. Other verdicts: slower, slower within the margin, no change shown, faster but
  worse elsewhere, faster with a guard unmeasured, behaves differently, too few runs. With few runs, faster
  needs every paired difference beyond the margin: the exact interval then spans the smallest and largest difference.
  Where the routes at rest vary between runs of the baseline itself, as OBGP's may, they are not compared route by
  route: the verdict stands on the speed, the guards and their totals at rest, and says so. The properties every run is checked for still hold for it.

## Threats to validity

- **One host:** all routers share its CPUs. Each result marks the runs where the host or a router's sampling was at its limit.
- **Unbound before November 2026:** results until then ran on any CPU of the host. Rates of oscillating
  modes, such as updates at rest, depend on the CPUs there and compare only within one result. Oscillating
  routers grew large there, as GoBGP queues updates to each neighbor without bound. A router past 1 GiB
  now leaves a heap profile with its run.
- **Metrics before 14 November 2026:** gobgpd counted the routes advertised to each neighbor at every
  read of its metrics, about once a second, and held back BGP messages meanwhile. On large routers,
  above all with a table per neighbor, that slowed the router and its sampling. The lab now reads no such count.
- **Resolution:** times are exact to two sampling intervals, 0.2 s at 10 Hz, 2 s for the Internet runs.
  A run whose slowest router sampled below 90 % of the rate set samples at its limit: its resolution is two
  of that router's intervals, and a settle time below it shows as such.
- **Few runs:** ten per cell in the behaviour and semantics experiments, eight in `internet-scale`, six in
  `internet-dfz`, so the interval of a median
  reaches 97.9, 99.2 or 96.9 %.
- **Exploratory tests:** all but the primary comparison are uncorrected.
- **CAIDA:** its relations are inferred, and some are wrong.
- **Simulator:** one prefix, no timers, an MRAI only as coalescing, small networks enumerated rather than the Internet sampled.
- **Feed:** the feeders send what the neighbors sent in the recorded run, not what they would send in
  answer to the router's own updates, so a feed measures a router on a fixed input, not a network.
  Recording costs the recording router time, so a run that records measures it less exactly. A recording
  holds what the neighbors sent in answer to the recorded mode's own updates and refreshes, so it feeds
  only variants of that mode and settings.
- **Simulator and lab:** the lab cannot replay the simulator's message orders, so a case found in few orders may not show in the lab.
  Its orders are drawn without timing, the lab's come from real timing: only whether a deviation never, sometimes or always shows
  compares, not how often. Both run gobgpd's route selection, so a fault in it shows on both sides alike.
  This holds for rest and for deviations at rest: lost routes against BGP of the same order or seed, loops, black holes, and leaks
  where routers leak by policy. Deviations on the way do not compare: the lab sees them only beyond two sampling intervals.
  Packets against the relations at rest, a forward valley, only the simulator checks: the lab checks paths, not packets.
