#!/usr/bin/env python3
"""PostToolUse: a threshold crossed during a long turn reaches Claude at once, not only with the next
prompt. Silent unless something new is to be told, each once, as by the prompt hook."""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load, warnings

u = load()
if u and not u.get("stale"):
    _, new = warnings(u)
    if new:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                 "additionalContext": "Usage. Tell the user now: " + "; ".join(new) + "."}}))
