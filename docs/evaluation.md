# Evaluation

How the lab answers each question: what a run is, what it measures, when it counts as a problem, and
how far the numbers go.

## Questions

One experiment per question.

| Question | Experiment |
|---|---|
| Does OBGP converge where BGP oscillates, in every mode? | [`behaviour-oscillation`](../experiments/behaviour-oscillation.yaml) |
| Does it still converge, and how fast, with an MRAI of 30 s? | [`behaviour-mrai`](../experiments/behaviour-mrai.yaml) |
| Does it stay stable under failures? | [`behaviour-failures`](../experiments/behaviour-failures.yaml) |
| Do Gao-Rexford policies hold, also in partial deployment, and does every router keep what BGP reaches? | [`semantics-gao-rexford`](../experiments/semantics-gao-rexford.yaml) |
| Does it keep BGP's semantics in the cases of the Go tests? | [`semantics-adversarial`](../experiments/semantics-adversarial.yaml) |
| Where does it fail outside its model or inside an AS? | [`semantics-limits`](../experiments/semantics-limits.yaml) |
| Does it scale to 256 networks of the Internet's core? | [`internet-scale`](../experiments/internet-scale.yaml) |
| Does it hold full tables? | [`internet-dfz`](../experiments/internet-dfz.yaml) |
| Does the lab work? | [`lab-smoke`](../experiments/lab-smoke.yaml) |
| Does it run every feature? | [`lab-features`](../experiments/lab-features.yaml) |
| Does it measure right? | [`lab-calibration`](../experiments/lab-calibration.yaml) |
| Does sampling change what it measures? | [`lab-sampling`](../experiments/lab-sampling.yaml) |

The paper's experiment `ifip-networking-2026` stays as it was published.

## A run

- **Experiment:** topologies × scenarios × variants × runs. A variant is a [mode](router.md#modes)
  with its settings. One topology and scenario is a cell.
- **Router:** one Kubernetes pod per router, gobgpd and a controller beside it. The controller runs
  the scenario's steps and samples each router at 10 Hz, the Internet runs at 1 Hz.
- **Scenario:** steps that announce, withdraw, fail links, restart routers and change policies.
- **Seed:** fixes a scenario's random choices and the order of the variants in a round. Variants of
  one run share it, so they are paired.
- **Rest:** a state counts once it holds 3 s, with an MRAI one and a half MRAI.
- **Reference:** the BGP run of the same seed, where it came to rest.

## Metrics

A path is one AS path to a prefix from one neighbor, a route the path selected for a prefix.

**Time**

| Metric | Unit | Until |
|---|---|---|
| Full reach | s | every router holds every prefix, routes may still change |
| Settle | s | no router changes anything and no update is sent |

**End state**

| Metric | Unit | Counts |
|---|---|---|
| Never at rest | runs | runs whose routes still change at the end |
| Not reached | routes | router and prefix pairs without a route |
| Loops, black holes | prefixes | prefixes whose packets loop, or end at a router without a route |
| Withdrawn kept | routes | router and prefix pairs still held after their withdrawal |
| Updates at rest | updates/s | per router after the last step, zero when routes stand still |

**On the way**

| Metric | Unit | Counts |
|---|---|---|
| Loops on the way | s | time in which packets to some prefix looped |
| Black holes on the way | s | time in which packets to some prefix ended without a route |
| Blocked | s | time in which a router set aside a valid path and had no route |
| Blocked | prefixes | the most at one router at once |
| Session drops | drops | sessions that fell from established, both ends count |
| Drops no step explains | drops | of sessions no step touched |

Loops and black holes on the way follow the next hops each router samples on every change. Above 256
prefixes every router follows the same sample of 256 (Followed). Under `bgp-pn` packets from an eBGP
neighbor follow the route sent to it, see [DESIGN.md](../DESIGN.md#ns-bgp-as-the-yardstick).

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
| No rest in time | a step or the final check waited for rest in vain |
| Loops at rest | packets to a prefix loop at the end |
| Fewer routes than BGP | a router holds fewer prefixes than in the reference |
| No BGP run at rest to compare with | a run misses prefixes and the reference never came to rest |
| Black holes, withdrawn routes BGP has not | more than in the reference |
| Paths against the relations | more valley paths than in the reference, or an `AS_SET` left out |
| Loops or black holes on the way, longer than BGP | longer than in the reference by more than two sampling intervals |
| Routers wait without a route | blocked longer than two sampling intervals, or than the wait for a route refresh |
| Sessions fell without a step for it | drops no step explains |
| At rest, the simulator never is | lab and simulator disagree |
| No final check | skipped, for tables above 2000 prefixes |

As a result begins, the [simulator](simulator.md) plays every cell it can, 20 message orders per mode.
A problem it foresees for that mode is expected, e.g. BGP without rest on BAD GADGET. Every other
problem is reported.

## Statistics

- **Interval:** the median of each cell with its exact confidence interval.
- **Paired variants:** Wilcoxon signed-rank tests on runs of the same seed.
- **Primary comparison:** each experiment names one, e.g. `primary: {metric: hold_churn, baseline: bgp}`.
  Every other variant is tested against the baseline, Holm-corrected across its cells. An experiment
  whose runs cannot reach 5 % after Holm is refused.
- **Never pooled:** modes are compared, never combined.

## Threats to validity

- **One host:** all routers share its CPUs. Each result marks the runs where the host or a router's sampling was at its limit.
- **Resolution:** times are exact to two sampling intervals, 0.2 s at 10 Hz, 2 s for the Internet runs.
- **Few runs:** ten per cell, six for the Internet runs, so the interval of a median reaches 97.9 or 96.9 %.
- **Exploratory tests:** all but the primary comparison are uncorrected.
- **CAIDA:** its relations are inferred, and some are wrong.
- **Simulator:** one prefix, no timers, small networks enumerated rather than the Internet sampled.
- **Simulator and lab:** the lab cannot replay the simulator's message orders, so a case found in few orders may not show in the lab.
