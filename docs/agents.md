# Agents

An agent operates the lab over MCP (`/mcp`) or HTTP (`/api/v1`), with a token from Settings › Agents.

| Scope | May |
|---|---|
| read | read status, results, single runs with their samples and loops on the way, logs, experiments, scenarios, topologies, the simulator's searches, and stars and notes |
| control | also change experiments and scenarios, run the queue and put a result before the running one, start a simulator search, let the simulator play a topology and scenario, star and note results, searches and cases, and update the lab |

The MCP server describes its tools itself. The simulator's are `simulation_*`, `start_simulation`, `stop_simulation`, `predict`, `predict_again` and `agreement`. Its searches
are also over HTTP, under `/api/v1/simulation/searches`.

Stars and notes are the lab's own, for everyone and without an author, the same whether a person or an agent
set them: `marks`, `star`, `add_note`, `edit_note`, `delete_note`. They stay out of downloads and public results.

## Approval

- **Default:** a control token asks first, and each change waits under Settings › Agents. A token made to act
  at once skips this, except for updates and changes beyond the budget.
- **Shown:** the runs and hours of an experiment, the file it saves, or the commits of an update.
- **Updates:** always wait, also with a token that acts at once.
- **Budget:** queueing waits once the queue would run longer than agents may fill, 24 h by default.

## Claude Code

The settings show a token once, with this block for the terminal:

```bash
curl -fsSk https://LAB:8443/certificate -o ~/.obgp-lab.crt
echo 'export NODE_EXTRA_CA_CERTS=~/.obgp-lab.crt' >> ~/.bashrc
export NODE_EXTRA_CA_CERTS=~/.obgp-lab.crt
claude mcp add --transport http obgp-lab https://LAB:8443/mcp --header "Authorization: Bearer obgp_…"
```

- **Certificate:** self-signed, its SHA-256 fingerprint is in the settings.
- **Trust:** the block trusts it for every Node.js program of the user.

## Results on another machine

The tool `download` gives the address of a whole result or search, a token that only downloads and the
fingerprint of the certificate. The agent fetches it onto its own machine, for figures or the local web interface:

```bash
uv run lab pull URL --fingerprint FINGERPRINT < token-file
```

- **Token:** fetches results and searches only. Each `download` replaces the agent's previous one, and it goes with the agent's token.
- **Certificate:** pinned by the fingerprint.
- **Existing:** a result or search of the same name stays unless `--force`.

## What no agent can do

| An agent tries to | It gets |
|---|---|
| act without a valid token | 401 |
| use a download token for anything but a download | 403 |
| change anything with a read token | 403 |
| approve its own change | the sign-in page |
| change the paper's experiment or scenarios | a refusal with the reason |
| save an invalid experiment | the editor's refusal |
| delete a scenario in use | a refusal |
| fill the queue beyond its budget | a change that waits |
| run a change whose file changed since | a failed approval |

Each row is tested in [`tests/test_agent.py`](../tests/test_agent.py) or [`tests/test_remote.py`](../tests/test_remote.py).

- **Never:** settings, passwords, tokens, or deleting results.
- **Log:** every action, with the token's name.
- **Revoke:** a token stops at once.
- **Storage:** tokens only as hashes.
