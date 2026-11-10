#!/usr/bin/env python3
"""UserPromptSubmit: one line of usage for Claude. Each threshold is told once per session or window."""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load, warnings

u = load()
if u is None:
    print("Usage unknown: the status line has written nothing yet.")
    sys.exit(0)
if u.get("stale"):
    print(f"Usage unknown: the status line last wrote {int((time.time() - u['t']) / 60)} min ago.")
    sys.exit(0)
parts, new = warnings(u)
print("Usage: " + ", ".join(parts) + "." + (" Tell the user once: " + "; ".join(new) + "." if new else ""))
