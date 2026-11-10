#!/bin/sh
# Installs the usage display for Claude Code in the user's own profile: copies
# the scripts to ~/.claude/usage and adds the status line and its hooks to
# ~/.claude/settings.json, after a backup. Settings someone else set stay.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HOME/.claude/usage"
cp "$here"/common.py "$here"/guard.py "$here"/hook.py "$here"/statusline.py "$here"/warn.py "$HOME/.claude/usage/"
python3 -I - "$HOME/.claude/settings.json" <<'EOF'
import json, shutil, sys
from pathlib import Path

path = Path(sys.argv[1])
settings = json.loads(path.read_text()) if path.exists() else {}
if path.exists():
    shutil.copy(path, path.with_suffix(".json.bak"))
command = lambda name: f"python3 ~/.claude/usage/{name}.py"
line = {"type": "command", "command": command("statusline")}
if settings.get("statusLine") not in (None, line):
    print(f"Kept the status line {settings['statusLine']}. Set it to {line} to see usage.")
else:
    settings["statusLine"] = line
hooks = settings.setdefault("hooks", {})
for event, name, matcher in (("UserPromptSubmit", "hook", None), ("PreToolUse", "guard", "*"), ("PostToolUse", "warn", "*")):
    entries = hooks.setdefault(event, [])
    if any(h.get("command") == command(name) for e in entries for h in e.get("hooks", [])):
        continue
    entries.append({**({"matcher": matcher} if matcher else {}), "hooks": [{"type": "command", "command": command(name)}]})
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(settings, indent=2) + "\n")
print(f"Installed. Restart Claude Code. Backup: {path.with_suffix('.json.bak')}" if path.with_suffix(".json.bak").exists() else "Installed. Restart Claude Code.")
EOF
