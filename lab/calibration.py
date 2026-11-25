"""Checks the measurements of the lab against a run whose values are known
before: twenty prefixes along a line of routers (experiments/lab-calibration).

On a line every router selects every prefix and admits exactly one path to
it, as the path back would hold its own AS; OBGP suppresses none. Every link
delays by 500 ms each way, so a withdrawal reaches the last of three hops
after 1.5 s at the earliest: a time the sampling must resolve. BGP runs over
TCP, which sends no more than its congestion window before an acknowledgement
comes back. After the idle time before the withdrawal the window is small
again, so that some of the twenty withdrawals may wait one round trip of
1 s at a hop, at most one at each, as the window doubles. At rest nothing
changes: no updates, no oscillation, and the routers sample at the set rate.
A measurement that deviates is a fault of the lab, not of the protocol.
"""

from . import analysis
from .results import Dataset

PROCESSING_S = 1.0  # what the routers and the controller may add along the line


def applies(dataset: Dataset) -> bool:
    """Whether a result calibrates the lab: its scenarios include calibration."""
    return "calibration" in dataset.experiment.scenarios


def reach_bounds(run: dict, set_hz: float) -> tuple[float, float] | None:
    """The earliest and the latest time until the withdrawal reaches every
    router, from the delayed links of the run: one delay per hop, and at most
    one round trip of TCP per hop on top, the processing and one sampling
    interval, as its end shows at the next sample. None without delays."""
    delayed = [e for e in run.get("events", []) if e["name"] == "degrade" and e.get("delay_ms")]
    if not delayed:
        return None
    hops = len({tuple(link) for e in delayed for link in e.get("links", [])}) or len(delayed)
    delay = max(e["delay_ms"] for e in delayed) / 1000
    return hops * delay, hops * delay + hops * 2 * delay + PROCESSING_S + 1 / set_hz


def checks(dataset: Dataset) -> list[dict]:
    """Every check of every finished run: what was measured, what was expected, and whether it holds."""
    out = []
    for key in dataset.keys():
        if not dataset.is_done(key) or (run := dataset.run(key))["status"] == "error":
            continue
        set_hz = 1 / dataset.experiment.sampling_of(key.variant).interval
        if (bounds := reach_bounds(run, set_hz)) is None:
            continue  # an older calibration, without delays on its links
        m = analysis.run_metrics(dataset, key, run)
        prefixes = next((e["expected"] for e in run["events"] if e["name"] == "announced"), None)
        low, high = bounds
        expected = [
            ("selected routes per router", m["selected_mean"], prefixes, lambda v, x: v == x),
            ("admitted paths per router", m["rib_mean"], prefixes, lambda v, x: v == x),
            ("admitted paths, largest router", m["rib_max"], prefixes, lambda v, x: v == x),
            ("suppressed paths", m["suppressed_mean"], 0, lambda v, x: v in (None, 0)),
            ("updates at rest per second", m["hold_churn"], 0, lambda v, x: v is not None and v < 0.05),
            ("oscillates", m["oscillates"], 0, lambda v, x: v == x),
            ("withdrawn from all, s", m["convergence_s"], f"{low:g} to {high:g}, derived from the link delays", lambda v, x: v is not None and low <= v <= high),
            ("slowest router samples, Hz", m["sample_hz_min"], 0.9 * set_hz, lambda v, x: v is not None and v >= x),
        ]
        for what, value, want, holds in expected:
            out.append({"run": str(key), "key": key, "what": what, "value": value, "expected": want, "ok": bool(holds(value, want))})
    return out
