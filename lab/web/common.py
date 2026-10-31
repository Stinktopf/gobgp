"""What the pages of the web interface share: templates, the queue, small helpers and the filters of the templates."""

import hashlib
import math
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from pydantic import ValidationError

from .. import (
    analysis,
    scenario,
)
from .. import host as hostload
from ..results import Dataset
from .jobs import Jobs

HERE = Path(__file__).parent


COUNT = "A count of paths, not the memory they take"


GARBAGE = "Includes garbage until the next collection"


METRICS = {  # label, unit, what it measures in a few words, group, caveat
    "checks": ("Checks", "runs", "runs whose expect steps all passed", "Outcome", None),
    "convergence_s": ("Full reach", "s", "until every router reaches every prefix, routes may still change", "Outcome", None),
    "settle_s": ("Settle", "s", "until no router changes anything, no more updates", "Outcome", None),
    "oscillates": ("Never at rest", "runs", "routes still change at the end of the rest", "Outcome", None),
    "unreached": ("Not reached", "routes", "router and prefix pairs without a route at the end", "Outcome", None),
    "stale_end": ("Withdrawn kept", "routes", "router and prefix pairs still held after their withdrawal", "Outcome", None),
    "loops_end": ("Loops", "prefixes", "whose packets loop at the end", "Outcome", None),
    "holes_end": ("Black holes", "prefixes", "whose packets end at a router without a route at the end", "Outcome", None),
    "loops_s": ("Loops on the way", "s", "in which packets to some prefix looped", "Outcome", None),
    "loops_max": ("Looping", "prefixes", "the most looping at once on the way", "Outcome", None),
    "holes_s": ("Black holes on the way", "s", "in which packets to some prefix ended at a router without a route", "Outcome", None),
    "holes_max": ("Holed", "prefixes", "the most ending at a router without a route at once on the way", "Outcome", None),
    "flaps": ("Session drops", "drops", "sessions that fell from established, both ends count", "Outcome", None),
    "flaps_unplanned": ("Drops no step explains", "drops", "of sessions no down, degrade or restart touched", "Outcome", None),
    "down_unplanned": ("Down, no step", "sessions", "not established at the end, no step touched them", "Outcome", None),
    "sessions_down_end": ("Sessions down", "sessions", "not established at the end, both ends count", "Outcome", None),
    "hops_sampled": ("Followed", "prefixes", "the sample loops and black holes on the way are counted on, large tables only", "Outcome", None),
    "blocked_s": ("Blocked", "s", "in which a router had a prefix with a valid path set aside and no route", "Outcome", None),
    "blocked_max": ("Blocked", "prefixes", "the most at one router at once", "Outcome", None),
    "hold_churn": ("Updates at rest", "updates/s", "per router at rest, zero when routes stand still", "Outcome", None),
    "adj_in_mean": ("Adj-RIB-In", "paths", "received from all peers, peak of the mean over the routers", "Resources", None),
    "rib_mean": ("Admitted", "paths", "the import admits, the Loc-RIB size of the paper", "Resources", COUNT),
    "suppressed_mean": ("Set aside", "paths", "OBGP keeps without admitting them", "Resources", None),
    "selected_mean": ("Routes", "prefixes", "with a selected route, the Loc-RIB of RFC 4271", "Resources", None),
    "known_mean": ("Known", "prefixes", "with a path admitted or set aside", "Resources", None),
    "path_len_avg": ("Path length", "AS hops", "mean of the admitted paths", "Resources", None),
    "rss_mean": ("Memory", "MiB", "resident memory of the daemon", "Resources", "The Go runtime returns freed memory late"),
    "heap_mean": ("Heap", "MiB", "heap in use of the daemon", "Resources", GARBAGE),
    "objects_mean": ("Heap objects", "objects", "of the daemon", "Resources", GARBAGE),
    "cpu_s_mean": ("CPU", "s", "per router while measured", "Resources", "The whole daemon, with its API and the sampling"),
}


templates = Jinja2Templates(HERE / "templates")


jobs = Jobs()


def with_error(page: str, error: str) -> str:
    """A page to go back to, with a problem to show; one shown before is replaced."""
    url = urlparse(page)
    query = [(k, v) for k, v in parse_qsl(url.query) if k != "error"] + [("error", error)]
    return f"{url.path}?{urlencode(query)}"


def gone() -> Response:
    """The answer to the polling of a result deleted meanwhile: back to the list, no more polling."""
    return Response(status_code=286, headers={"HX-Redirect": "/results"})


def still(dataset: Dataset, response: HTMLResponse) -> HTMLResponse:
    """Ends the polling of a page on a result that no longer runs (htmx stops at 286)."""
    if dataset.status.get("state") not in ("running", "queued") and dataset.name not in jobs.queue():
        response.status_code = 286
    return response


def find(name: str) -> Dataset:
    dataset = Dataset.find(name)
    if not dataset:
        raise HTTPException(404, f"No result {name}.")
    return dataset


def readable(error: ValidationError) -> list[str]:
    """Validation errors as short lines, with the step positions counted from 1."""
    lines = []
    for e in error.errors()[:5]:
        loc = [x + 1 if isinstance(x, int) else x for x in e["loc"] if x not in ("args",)]
        where = " ".join(f"step {x}" if isinstance(x, int) else str(x) for x in loc if x != "steps")
        message = "needs steps" if e["type"] == "too_short" else e["msg"].removeprefix("Value error, ")
        lines.append(f"{where}: {message}" if where else message)
    return lines


def load_problem(error: Exception) -> str:
    """Why a file does not load, in one line: for a validation error what is
    wrong where, not only how many errors there are."""
    if isinstance(error, ValidationError):
        lines = readable(error)
        return "; ".join(lines) + (f" and {error.error_count() - len(lines)} more" if error.error_count() > len(lines) else "")
    return str(error).splitlines()[0]


def problems(found: list[str]) -> list[str]:
    """Problems of a check, those of routers that differ only in their router
    as one: "r1 misses 1 of 1 prefixes" and "r2 …" as "r1, r2 miss 1 of 1 prefixes"."""
    plural = {"misses": "miss", "holds": "hold", "routes": "route"}
    routers = defaultdict(list)
    for p in found:
        router, _, rest = p.partition(" ")
        if rest.partition(" ")[0] in plural:
            routers[rest].append(router)
        else:
            routers[p] = []
    out = []
    for rest, names in routers.items():
        if len(names) > 1:
            verb, _, tail = rest.partition(" ")
            rest = f"{plural[verb]} {tail}"
        out.append(f"{', '.join(names)} {rest}" if names else rest)
    return out


def download(text: str, filename: str, media_type: str) -> Response:
    return Response(text, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def metrics_of(dataset: Dataset) -> dict:
    """The metrics of a result, Checks first if its scenarios have expect steps."""
    checked = any(step.kind == "expect" for s in dataset.experiment.scenarios
                  for step in scenario.each_step(dataset.scenario(s).steps))
    return METRICS if checked else {k: v for k, v in METRICS.items() if k != "checks"}


def back(request: Request, default: str) -> str:
    """The page a form was posted from, to return to it."""
    referer = urlparse(request.headers.get("referer", ""))
    return referer.path + (f"?{referer.query}" if referer.query else "") if referer.path.startswith("/") else default


def duration(seconds: float | None) -> str:
    if seconds is None:
        return "–"
    seconds = int(seconds)
    if seconds >= 3600:
        return f"{seconds // 3600} h {seconds % 3600 // 60:02d} min"
    if seconds >= 600:
        return f"{seconds // 60} min"
    if seconds >= 60:  # as the timeline of a scenario
        return f"{seconds // 60} min {seconds % 60:02d} s"
    return f"{seconds} s"


def clock(when: datetime | None) -> Markup | str:
    """A time of day, with the weekday when it is not today. The page shows
    it in the reader's time zone, see ui.js, the server's stands until then."""
    if when is None:
        return "–"
    when = when.astimezone()
    shown = f"{when:%H:%M}" if when.date() == datetime.now().astimezone().date() else f"{when:%a %H:%M}"
    return Markup(f'<time datetime="{when.isoformat(timespec="seconds")}" data-clock>{shown}</time>')


def created(stamp: str | None) -> str:
    """When a result was made: the time today, the date before."""
    try:
        when = datetime.fromisoformat(stamp).astimezone()
    except (TypeError, ValueError):
        return (stamp or "")[:10]
    return f"{when:%H:%M}" if when.date() == datetime.now().date() else f"{when:%Y-%m-%d}"


def sparkline(values: list[float], top: float, width: int = 320, height: int = 64) -> str:
    """SVG polyline points for a small live chart scaled to top."""
    if len(values) < 2:
        return ""
    step = width / (len(values) - 1)
    return " ".join(f"{i * step:.1f},{height - 4 - (v / top) * (height - 8):.1f}" for i, v in enumerate(values))


def area(lower: list[float], upper: list[float], top: float, width: int = 320, height: int = 64) -> str:
    """SVG polygon points of the band between two series scaled to top."""
    if len(upper) < 2:
        return ""
    step = width / (len(upper) - 1)
    y = lambda v: f"{height - (v / top) * height:.1f}"
    edge = [f"{i * step:.1f},{y(v)}" for i, v in enumerate(upper)]
    base = [f"{i * step:.1f},{y(v)}" for i, v in reversed(list(enumerate(lower)))]
    return " ".join(edge + base)


def line(values: list[float], top: float, width: int = 320, height: int = 64) -> str:
    """SVG polyline points of a series scaled to top, edge to edge, to draw
    on the edge of an area()."""
    if len(values) < 2:
        return ""
    step = width / (len(values) - 1)
    return " ".join(f"{i * step:.1f},{height - (v / top) * height:.1f}" for i, v in enumerate(values))


def ceiling(values: list[float], limit: float, floor: float, unit: float = 1) -> float:
    """The top of a chart axis: the next of 1, 2, 5 times a power of ten
    units above the largest value, at least floor and at most limit."""
    want = max([floor, *values]) / unit
    step = 10 ** math.floor(math.log10(want))
    top = next(m * step for m in (1, 2, 5, 10) if m * step >= want * (1 - 1e-9))
    return min(top * unit, limit)


def metric_digits(metric: str, time_digits: int = 1) -> int:
    return {"convergence_s": time_digits, "settle_s": time_digits, "path_len_avg": 2, "rss_mean": 1, "heap_mean": 1, "cpu_s_mean": 2}.get(metric, 0)


def metric_value(value: float | None, metric: str, time_digits: int = 1) -> str:
    """A metric as text; times with the decimals their sampling allows."""
    if value is None:
        return "–"
    return f"{value:,.{metric_digits(metric, time_digits)}f}"


def shown(value: float | None, metric: str, time_digits: int = 1) -> float | None:
    """A metric as the table shows it, for comparing: values that look the same are the same."""
    return None if value is None else round(value, metric_digits(metric, time_digits))


def size(n: float) -> str:
    """Bytes as text: 812 KB, 1.4 GB."""
    units = ["B", "KB", "MB", "GB", "TB"]
    while n >= 1000 and len(units) > 1:
        n /= 1000
        units.pop(0)
    unit = units[0]
    return f"{n:.0f} {unit}" if unit in ("B", "KB") or n >= 100 else f"{n:.1f} {unit}"


def listing(items, width: int = 28) -> str:
    """Names joined by commas; whole names only, then ", …" once they do not
    fit. A first name longer than the width is cut."""
    items = [str(item) for item in items]
    if items and len(items[0]) > width:
        return items[0][:width - 1] + "…"
    out = ""
    for item in items:
        text = f"{out}, {item}" if out else item
        if len(text) > width and out:
            return f"{out}, …"
        out = text
    return out


_versions: dict[str, tuple[float, str]] = {}


def static(path: str) -> str:
    """The URL of a static file with a version from its content, so that a
    browser loads it again once it changed instead of from its cache."""
    file = HERE / "static" / path
    mtime = file.stat().st_mtime
    if (hit := _versions.get(path)) is None or hit[0] != mtime:
        hit = _versions[path] = (mtime, hashlib.sha256(file.read_bytes()).hexdigest()[:8])
    return f"/static/{path}?v={hit[1]}"


templates.env.filters["listing"] = listing
templates.env.filters["problems"] = problems
# The case of the Simulation an experiment was made from, as its description names it.
def _case_seen(path: str | None) -> str:
    from .. import simulation  # the Simulation only where a result names a case of it

    return simulation.seen(path) if path else ""


templates.env.filters["case_seen"] = _case_seen
templates.env.filters["case_of"] = lambda text: (m.group(0) if (m := re.search(r"/simulation/\d+/\d+", text or "")) else None)
templates.env.globals["busy_host"] = analysis.BUSY_HOST
templates.env.filters["size"] = size
templates.env.filters["duration"] = duration
templates.env.filters["clock"] = clock
templates.env.filters["shown"] = shown
templates.env.globals["size_series"] = analysis.size_series
templates.env.globals["router_metrics"] = analysis.ROUTER_METRICS
# The level the interval of a median reaches with n runs, in percent; None below 3.
templates.env.filters["interval_level"] = lambda n: round(100 * ci["level"], 1) if (ci := analysis.median_ci(list(range(int(n or 0))))) else None
templates.env.filters["created"] = created
templates.env.filters["metric_value"] = metric_value
templates.env.filters["compact"] = lambda n: f"{n:,.0f}" if abs(n) < 1e6 else f"{n / 1e6:,.1f}M"
templates.env.globals["sparkline"] = sparkline
templates.env.globals["area"] = area
templates.env.globals["line"] = line
templates.env.globals["ceiling"] = ceiling
templates.env.globals["host_series"] = hostload.series
templates.env.globals["static"] = static
