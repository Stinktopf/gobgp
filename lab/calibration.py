"""Checks the measurements of the lab against a run whose values are known
before: twenty prefixes along a line of routers (experiments/lab-calibration).

On a line every router selects every prefix and admits exactly one path to
it, as the path back would hold its own AS; OBGP suppresses none. Every link
delays by 500 ms, so a withdrawal reaches the last of three hops after 1.5 s
and some processing: a time the sampling must resolve. At rest nothing changes: no
updates, no oscillation, and the routers sample at the set rate. A measurement that deviates is a fault of
the lab, not of the protocol.
"""

from . import analysis
from .results import Dataset


def checks(dataset: Dataset) -> list[dict]:
    """Every check of every finished run: what was measured, what was expected, and whether it holds."""
    set_hz = 1 / dataset.experiment.sampling.interval
    out = []
    for key in dataset.keys():
        if not dataset.is_done(key) or (run := dataset.run(key))["status"] == "error":
            continue
        m = analysis.run_metrics(dataset, key, run)
        prefixes = next((e["expected"] for e in run["events"] if e["name"] == "announced"), None)
        if not any(e["name"] == "degrade" for e in run["events"]):
            continue  # an older calibration, without delays on its links
        expected = [
            ("selected routes per router", m["selected_mean"], prefixes, lambda v, x: v == x),
            ("admitted paths per router", m["rib_mean"], prefixes, lambda v, x: v == x),
            ("admitted paths, largest router", m["rib_max"], prefixes, lambda v, x: v == x),
            ("suppressed paths", m["suppressed_mean"], 0, lambda v, x: v in (None, 0)),
            ("updates at rest per second", m["hold_churn"], 0, lambda v, x: v is not None and v < 0.05),
            ("oscillates", m["oscillates"], 0, lambda v, x: v == x),
            ("withdrawn from all, s", m["convergence_s"], "1.5 to 2.5", lambda v, x: v is not None and 1.5 <= v <= 2.5),
            ("slowest router samples, Hz", m["sample_hz_min"], f"≥ {0.9 * set_hz:g}", lambda v, x: v is not None and v >= 0.9 * set_hz),
        ]
        for what, value, want, holds in expected:
            out.append({"run": str(key), "what": what, "value": value, "expected": want, "ok": bool(holds(value, want))})
    return out
