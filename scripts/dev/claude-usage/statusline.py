#!/usr/bin/env python3
"""Status line: context, 5 h and 7 d use. Also keeps them in last.json for the prompt hook."""
import json, os, sys, time

d = json.load(sys.stdin)
ctx = (d.get("context_window") or {}).get("used_percentage")
limits = d.get("rate_limits") or {}
out = {"t": time.time(), "ctx": ctx, "session": d.get("session_id")}
for k in ("five_hour", "seven_day"):
    w = limits.get(k) or {}
    out[k] = {"pct": w.get("used_percentage"), "resets": w.get("resets_at")}
path = os.path.expanduser("~/.claude/usage/last.json")
with open(path + ".tmp", "w") as f:
    json.dump(out, f)
os.replace(path + ".tmp", path)


GREEN, YELLOW, RED, DIM, END = "\033[32m", "\033[33m", "\033[31m", "", "\033[0m"  # labels in the terminal's own colour


def show(name, pct, at, warn):
    """A share in green, yellow within 15 points of its warning, red from it on, with its reset time."""
    if pct is None:
        return f"{DIM}{name} n/a{END}"
    colour = RED if pct >= warn else YELLOW if pct >= warn - 15 else GREEN
    when = ""
    if at:
        fmt = "%H:%M" if at - time.time() < 86400 else "%a %H:%M"
        when = f" {DIM}until {time.strftime(fmt, time.localtime(at))}{END}"
    return f"{DIM}{name}{END} {colour}{pct:.0f} %{END}{when}"


print("   ".join([show("context", ctx, None, 60), show("5 h", out["five_hour"]["pct"], out["five_hour"]["resets"], 80),
                  show("7 d", out["seven_day"]["pct"], out["seven_day"]["resets"], 80)]))
