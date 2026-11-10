#!/usr/bin/env python3
"""PreToolUse: denies every tool call from 95 % of the 5 h or 7 d window, unless the user allowed it for this window.
Unknown usage does not block, stale usage does until its window resets. Not a spending limit: a running turn ends, other sessions go on."""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import BLOCK, allowed, load, pct

u = load()
for k, name in (("five_hour", "5 h"), ("seven_day", "7 d")):
    p = pct(u, k, bound=True)
    if p is not None and p >= BLOCK and not allowed(u, k):
        print(f"Blocked: {name} usage at {p:.0f} %. Stop and tell the user. They can allow this window with "
              "touch ~/.claude/usage/allow.", file=sys.stderr)
        sys.exit(2)
