"""Usage as the status line saw it last. Stale or missing values are unknown, never 0."""
import json, os, time

BASE = os.path.expanduser("~/.claude/usage")
STALE_S = 600
WINDOW_S = {"five_hour": 5 * 3600, "seven_day": 7 * 86400}
BLOCK = 95  # % of the 5 h or 7 d window: tool calls are denied


def load():
    try:
        u = json.load(open(f"{BASE}/last.json"))
    except (OSError, ValueError):
        return None
    return u if time.time() - u.get("t", 0) <= STALE_S else {**u, "stale": True}


def pct(u, k, bound=False):
    """The share of a window. With bound, also from stale data until the window resets: use within a
    window only grows, so the last value is a lower bound."""
    if not u or (u.get("stale") and not bound):
        return None
    w = u.get(k) or {}
    if u.get("stale") and not (w.get("resets") and time.time() < w["resets"]):
        return None
    return w.get("pct")


def allowed(u, k):
    """Whether the user allowed work past the block in the current window, by touching allow."""
    try:
        at = os.path.getmtime(f"{BASE}/allow")
    except OSError:
        return False
    resets = (u.get(k) or {}).get("resets")
    return bool(resets) and at >= resets - WINDOW_S[k]


RULES = {"five_hour": [(80, "pause large work until the reset")],
         "seven_day": [(80, "keep capacity for urgent fixes this week"),
                       (90, "ask the user before any further nontrivial work")]}


def warnings(u):
    """The usage in a few words, and the thresholds crossed that were not told yet in this session or
    window. Those are kept as told, so that the prompt hook and the hook after each tool tell each once."""
    try:
        told = json.load(open(f"{BASE}/warned.json"))
    except (OSError, ValueError):
        told = {}
    parts, new = [], []
    ctx = u.get("ctx")
    parts.append("context " + ("n/a" if ctx is None else f"{ctx:.0f} %"))
    if ctx is not None and ctx >= 60 and told.get("context") != u.get("session"):
        told["context"] = u.get("session")
        new.append(f"context at {ctx:.0f} %: suggest a checkpoint or fresh session at the next task boundary")
    for k, name in (("five_hour", "5h"), ("seven_day", "7d")):
        p = pct(u, k)
        at = (u.get(k) or {}).get("resets")
        parts.append(f"{name} " + ("n/a" if p is None else f"{p:.0f} %") + (f" (resets {time.strftime('%a %H:%M', time.localtime(at))})" if at else ""))
        if p is None:
            continue
        for limit, advice in RULES[k] + [(BLOCK, "tool calls are blocked until the reset or until the user runs touch ~/.claude/usage/allow")]:
            key = f"{name}-{limit}"
            if p >= limit and told.get(key) != str(at) and not (limit == BLOCK and allowed(u, k)):
                told[key] = str(at)
                new.append(f"{name} at {p:.0f} %: {advice}")
    if new:
        with open(f"{BASE}/warned.json", "w") as f:
            json.dump(told, f)
    return parts, new
