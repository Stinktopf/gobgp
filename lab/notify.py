"""A Discord message when a result ends: finished, failed or stopped.

Sent to a Discord webhook, as configured in the settings of the web
interface or with `lab notify`, in ~/.config/obgp-lab/notify.json:

    {"discord": "https://discord.com/api/webhooks/<id>/<token>",
     "lab": "https://lab.example.org:8443"}

The webhook URL is a secret: whoever has it can post to the channel. The
optional address of the lab links the message to the result. A message
that cannot be sent is logged; it never stops an experiment.
"""

import json
import logging
import platform
import re
import time
from datetime import UTC, datetime, timedelta

import requests

from . import config

log = logging.getLogger("lab")
WEBHOOK = re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")
# The colours of the states in the interface: emerald, rose and amber.
COLORS = {"finished": 0x059669, "failed": 0xE11D48, "stopped": 0xD97706}
STARTED = 0x1E3765  # U of T Blue


def file():
    return config.SETTINGS / "notify.json"


def load() -> dict:
    try:
        return json.loads(file().read_text())
    except (OSError, ValueError):
        return {}


def save(settings: dict) -> None:
    if (url := settings.get("discord")) and not WEBHOOK.fullmatch(url):
        raise ValueError("That is not the URL of a Discord webhook.")
    file().parent.mkdir(parents=True, exist_ok=True)
    file().touch(mode=0o600)
    file().chmod(0o600)
    file().write_text(json.dumps(settings, indent=2))


def masked(url: str | None) -> str:
    """A webhook URL without its token, to show."""
    return re.sub(r"/[\w-]+$", "/…", url) if url else ""


def send(embed: dict, mention: bool = False, settings: dict | None = None) -> list[str]:
    """Posts an embed to the webhook; returns the problems."""
    settings = load() if settings is None else settings
    if not (url := settings.get("discord")):
        return []
    body = {
        "username": "OBGP Lab",
        "embeds": [{"footer": {"text": platform.node()}, "timestamp": datetime.now(UTC).isoformat(), **embed}],
        **({"content": "@here", "allowed_mentions": {"parse": ["everyone"]}} if mention else {"allowed_mentions": {"parse": []}}),
    }
    problem = "Discord: rate limited"
    for _ in range(2):  # once more after a rate limit
        try:
            response = requests.post(url, json=body, timeout=10)
            if response.status_code == 429:
                time.sleep(min(float(response.json().get("retry_after", 1)), 10))
                continue
            response.raise_for_status()
            return []
        # Only the kind of error: the messages of requests contain the URL, and with it the token.
        except requests.HTTPError as e:
            problem = f"Discord answered {e.response.status_code}"
        except (requests.RequestException, ValueError) as e:
            problem = f"Discord not reachable ({type(e).__name__})"
        break
    log.warning("notification not sent: %s", problem)
    return [problem]


def test(settings: dict | None = None) -> list[str]:
    settings = load() if settings is None else settings
    if not settings.get("discord"):
        return ["No webhook to send to."]
    return send({"title": "OBGP Lab", "description": "Notifications arrive here.", "color": 0x1E3765}, settings=settings)


def result_started(dataset) -> None:
    """Tells that a result started or resumed: what runs, and when it ends."""
    from . import estimate

    s = dataset.status
    done, total = s.get("done", 0), s.get("total", 0)
    try:
        e = dataset.experiment
    except (ValueError, KeyError):
        e = None
    fields = [{"name": "Runs", "value": f"{done} of {total} done, {total - done} to go" if done else str(total), "inline": True}]
    try:
        left = estimate.remaining_s(dataset, estimate.history())
    except Exception as error:  # the message goes out anyway
        log.warning("no estimate in the notification: %s", error)
        left = None
    if left:
        ends = datetime.now().astimezone() + timedelta(seconds=left)
        fields.append({"name": "Takes", "value": f"about {_duration(left)}, until {ends:%H:%M}", "inline": True})
    if e:
        fields += _setup(dataset, e)
    embed = {"title": f"{dataset.name} {'resumed' if done else 'started'}", "color": STARTED, "fields": fields}
    if e and e.description:
        embed["description"] = e.description
    if lab := load().get("lab"):
        embed["url"] = f"{lab.rstrip('/')}/results/{dataset.name}"
    send(embed)


def _setup(dataset, e) -> list[dict]:
    """The fields of what a result runs: experiment, topologies, scenarios and variants."""
    commits = dataset.meta.get("commits", {})
    variants = [f"`{v.name}` {v.summary()} · {v.ref} {commits.get(v.name, '')[:7]}".rstrip() for v in e.variants]
    return [
        {"name": "Experiment", "value": f"`{e.name}`", "inline": True},
        {"name": "Topologies", "value": _listing(e.topologies), "inline": True},
        {"name": "Scenarios", "value": _listing(e.scenarios), "inline": True},
        {"name": "Variants", "value": "\n".join(variants)},
    ]


def result_ended(dataset) -> None:
    """Tells how a result ended, unless it is still queued or running: what
    ran, how long it took, what went wrong, and how the variants compare."""
    s = dataset.status
    state = s.get("state")
    if state not in COLORS:
        return
    try:
        e = dataset.experiment
    except (ValueError, KeyError):
        e = None
    done, total = s.get("done", 0), s.get("total", 0)
    fields = [{"name": "Runs", "value": f"{done} of {total}" + (" done" if done < total else ""), "inline": True}]
    try:
        began = datetime.fromisoformat(s.get("began") or s["started"])
        ended = datetime.fromisoformat(s["updated"]) if s.get("updated") else datetime.now(UTC)
        if state == "finished":
            fields.append({"name": "Took", "value": _duration((ended - began).total_seconds()), "inline": True})
        else:  # pauses between stops and resumes would count as running
            fields.append({"name": "Since", "value": f"{began.astimezone():%d %b, %H:%M}", "inline": True})
    except (KeyError, ValueError):
        pass
    if n := s.get("errors"):
        fields.append({"name": "Errors", "value": f"{n} run{'s' * (n != 1)}", "inline": True})
    if e:
        fields += _setup(dataset, e)
        # Medians of a part of the runs would mislead.
        if state == "finished" and (table := _comparison(dataset, e)):
            fields.append({"name": "Medians", "value": table})
        if failed := _failed_checks(dataset, e):
            fields.append({"name": "Failed checks", "value": failed})
    embed = {"title": f"{dataset.name} {state}", "color": COLORS[state], "fields": fields}
    description = [s["error"][:900]] if state == "failed" and s.get("error") else []
    if state == "stopped":
        description.append("Stopped by hand, not by an error. It continues where it stopped once resumed.")
    if e and e.description:
        description.append(e.description)
    if description:
        embed["description"] = "\n\n".join(description)
    if lab := load().get("lab"):
        embed["url"] = f"{lab.rstrip('/')}/results/{dataset.name}"
    send(embed, mention=state == "failed")


def _duration(seconds: float) -> str:
    minutes = round(seconds / 60)
    return f"{minutes // 60} h {minutes % 60:02d} min" if minutes >= 60 else f"{max(1, minutes)} min"


def _listing(names: list[str], most: int = 4) -> str:
    shown = ", ".join(names[:most])
    return f"{shown}, … ({len(names)})" if len(names) > most else shown


def _failed_checks(dataset, experiment) -> str | None:
    """Per variant, the runs in which a check failed, and the first problem."""
    from . import analysis

    try:
        failed = analysis.failed_checks(dataset)
    except Exception:
        return None
    lines = []
    for v in experiment.variants:
        mine = [f for f in failed if f["variant"] == v.name]
        if mine:
            runs = len({(f["topology"], f["scenario"], f["run"]) for f in mine})
            first = mine[0]
            lines.append(f"`{v.name}` {runs} run{'s' * (runs != 1)}, first in {first['scenario']}: {'; '.join(first['problems'])[:120]}")
    return "\n".join(lines)[:1000] or None


def _comparison(dataset, experiment) -> str | None:
    """Per variant over its groups: runs that timed out, and the medians of
    convergence, admitted paths, suppressed paths and updates at rest, as a small table."""
    from statistics import mean, median

    from . import analysis

    try:
        groups = analysis.summary(dataset)
    except Exception as error:  # the message goes out anyway
        log.warning("no comparison in the notification: %s", error)
        return None
    digits = experiment.sampling.digits()
    rows = []
    for v in experiment.variants:
        mine = [g for g in groups if g["variant"] == v.name and g["runs"]]
        if not mine:
            continue
        values = lambda metric, mine=mine: [g["metrics"][metric]["median"] for g in mine if g["metrics"][metric]]
        timeouts = sum(g["statuses"].get("timeout", 0) for g in mine)
        runs = sum(g["runs"] for g in mine)
        conv, rib, sup, osc = values("convergence_s"), values("rib_mean"), values("suppressed_mean"), values("hold_churn")
        # Medians of convergence leave out the runs that did not converge.
        converged = sum(g["metrics"]["convergence_s"]["n"] for g in mine if g["metrics"]["convergence_s"])
        measurable = sum(g["runs"] for g in mine if g.get("measurable"))
        rows.append((v.name, f"{median(conv):.{digits}f}" if conv else "–", f"{converged}/{measurable}" if measurable else "–",
                     f"{mean(rib):.1f}" if rib else "–", f"{mean(sup):.1f}" if sup else "–", f"{median(osc):.1f}" if osc else "–", f"{timeouts}/{runs}"))
    if not rows:
        return None
    head = ("", "conv. s", "conv.", "admitted", "suppr.", "at rest/s", "timeouts")
    widths = [max(len(r[i]) for r in [head, *rows]) for i in range(len(head))]
    line = lambda r: "  ".join(c.ljust(widths[0]) if i == 0 else c.rjust(widths[i]) for i, c in enumerate(r))
    return "```\n" + "\n".join(line(r) for r in [head, *rows]) + "\n```"
