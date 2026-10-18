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
    """Tells that a result started or resumed: its runs, when it ends, and
    when the queue behind it does."""
    from . import estimate

    s = dataset.status
    # A new result has no status yet: the runner writes it once it starts.
    done, total = s.get("done", 0), s.get("total") or dataset.experiment.runs_total()
    past = _past()
    left = _remaining(dataset, estimate, past)
    lines = [f"{done} of {total} runs done, {total - done} to go" if done else f"{total} runs"]
    if left:
        lines[0] += f", about {_duration(left)}, until {_at(left)}"
    if queue := _queue(dataset, left or 0, past):
        lines.append(queue)
    embed = {"title": f"{dataset.name} {'resumed' if done else 'started'}", "color": STARTED, "description": "\n".join(lines)}
    if lab := load().get("lab"):
        embed["url"] = f"{lab.rstrip('/')}/results/{dataset.name}"
    send(embed)


def _past():
    from . import estimate

    try:
        return estimate.history()
    except Exception as error:  # the message goes out anyway
        log.warning("no estimate in the notification: %s", error)
        return None


def _remaining(dataset, estimate, past) -> float | None:
    try:
        return estimate.remaining_s(dataset, past) if past is not None else None
    except Exception as error:
        log.warning("no estimate in the notification: %s", error)
        return None


def _at(seconds: float) -> str:
    return f"{datetime.now().astimezone() + timedelta(seconds=seconds):%H:%M}"


def _queue(dataset, before: float, past) -> str | None:
    """The results waiting behind this one: how many, how long, and when
    the last is likely done, after before seconds of this one."""
    from . import estimate
    from .results import Dataset, queued

    rest = [n for n in queued() if n != dataset.name]
    if not rest:
        return None
    total = 0.0
    for name in rest:
        try:
            total += _remaining(Dataset.find(name), estimate, past) or 0
        except (OSError, ValueError, KeyError):
            pass
    more = f"{len(rest)} more in the queue, next {rest[0]}"
    return f"{more}, about {_duration(total)}, all done around {_at(before + total)}" if total else more


def lab_restarted(reboot: bool, waiting: list[str], error: str | None = None) -> None:
    """Tells that the watchdog started the lab again, why, and what it does now."""
    text = ("The host rebooted. " if reboot else "The web server had ended. ") + "The watchdog started it again"
    text += f" and resumes {_listing(waiting)}." if waiting else ". Nothing was queued."
    fields = [{"name": "Last log line", "value": f"`{error}`"}] if error else []
    send({"title": "Lab started again", "description": text, "color": COLORS["stopped"], "fields": fields})


def watchdog_gave_up(reason: str, error: str) -> None:
    """Tells that the lab stays off because its web server kept ending."""
    fields = [{"name": "Last log line", "value": f"`{error}`"}] if error else []
    text = (f"{reason} Look at {config.SETTINGS / 'serve.log'} on the host, then start the lab again there with "
            f"`{config.ROOT / 'scripts' / 'start.sh'}`. The watchdog then watches again.")
    send({"title": "Lab stays off", "description": text, "color": COLORS["failed"], "fields": fields}, mention=True)


def result_ended(dataset) -> None:
    """Tells how a result ended, unless it is still queued or running: its
    runs and how they ended, what went wrong, and what the queue does next."""
    s = dataset.status
    state = s.get("state")
    if state not in COLORS:
        return
    done, total = s.get("done", 0), s.get("total", 0)
    lines = []
    if state == "failed" and s.get("error"):
        lines.append(s["error"][:500])
    took = ""
    try:
        began = datetime.fromisoformat(s.get("began") or s["started"])
        ended = datetime.fromisoformat(s["updated"]) if s.get("updated") else datetime.now(UTC)
        if state == "finished":  # pauses between stops and resumes would count otherwise
            took = f" in {_duration((ended - began).total_seconds())}"
    except (KeyError, ValueError):
        pass
    lines.append(f"{done} of {total} runs{took}" + (", stopped by hand, it continues once resumed" if state == "stopped" else ""))
    if runs := _statuses(dataset):
        lines.append(runs)
    try:
        e = dataset.experiment
    except (ValueError, KeyError):
        e = None
    if e and (failed := _failed_checks(dataset, e)):
        lines.append(f"Failed checks: {failed}")
    if limit := _host_limit(dataset):
        lines.append(f"Host at its limit: {limit}")
    if queue := _queue(dataset, 0, _past()):
        lines.append(queue)
    embed = {"title": f"{dataset.name} {state}", "color": COLORS[state], "description": "\n".join(lines)[:4000]}
    if lab := load().get("lab"):
        embed["url"] = f"{lab.rstrip('/')}/results/{dataset.name}"
    send(embed, mention=state == "failed")


def _statuses(dataset) -> str | None:
    """How the runs ended, as the run grid marks them, only what occurred."""
    from . import analysis

    try:
        statuses = dataset.statuses()
        metrics = analysis.run_summary(dataset) if any(v == "completed" for v in statuses.values()) else {}
    except Exception:
        return None
    count = {"done": 0, "did not come to rest": 0, "failed a check": 0, "ended in an error": 0}
    for key, status in statuses.items():
        if status == "completed":
            count["did not come to rest" if metrics.get(str(key), {}).get("oscillates") == 1 else "done"] += 1
        elif status == "timeout":
            count["did not come to rest"] += 1
        elif status == "failed":
            count["failed a check"] += 1
        elif status == "error":
            count["ended in an error"] += 1
    return " · ".join(f"{n} {what}" for what, n in count.items() if n) or None


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
            lines.append(f"`{v.name}` {runs} run{'s' * (runs != 1)}, {first['problems'][0][:80]}")
    return ", ".join(lines)[:600] or None


def _host_limit(dataset) -> str | None:
    """As the result page says it: where the host was at its limit or the
    routers sampled far less often than set, and whether oscillation caused it."""
    from . import analysis

    try:
        m = analysis.integrity(dataset)
    except Exception:
        return None
    lines = []
    if m["busy"]:
        w = m["busy"][0]
        lines.append(f"Up to {100 * w['cpu']:.0f} % of the CPUs in {w['topology']} · {w['scenario']} · `{w['variant']}`.")
    if m["slow"]:
        w = m["slow"][0]
        lines.append(f"Sampled down to {w['hz']:g} of {m['set']:g} Hz in {w['topology']} · {w['scenario']} · `{w['variant']}`, "
                     f"times there exact to about {1 / w['hz']:.1f} s.")
    if not lines:
        return None
    if cause := sorted({x["variant"] for x in m["busy"] + m["slow"] if x["oscillating"]}):
        lines.append(f"{', '.join(f'`{v}`' for v in cause)} oscillated there.")
    return " ".join(lines)[:600]
