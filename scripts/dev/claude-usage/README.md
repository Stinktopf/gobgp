# Usage display for Claude Code

Opt-in, for your own profile. Nothing in the repository turns it on.

```bash
scripts/dev/claude-usage/install.sh
```

| Part | Does |
|---|---|
| `statusline.py` | shows context, 5 h and 7 d use with their reset times, and keeps them for the hooks |
| `hook.py` | gives Claude one line of usage with every prompt, and each warning once |
| `warn.py` | gives a warning crossed during a long answer at once, after the tool call that saw it |
| `guard.py` | denies every tool call from 95 % of the 5 h or 7 d window |

- **Warnings:** context from 60 %, 5 h from 80 %, 7 d from 80 % and 90 %.
- **Unknown usage:** never counts as 0. Usage older than 10 minutes still blocks until its window resets.
- **Past the block:** `touch ~/.claude/usage/allow` allows the current window.
- **Removal:** delete `~/.claude/usage` and the entries that name it in `~/.claude/settings.json`.

The guard is no spending limit: a running turn ends, other sessions go on.
