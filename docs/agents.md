# Agents

An agent operates the lab over MCP (`/mcp`) or HTTP (`/api/v1`), with a token from Settings › Agents.

| Scope | May |
|---|---|
| read | read status, results, logs, experiments, scenarios, topologies and the simulator's searches |
| control | also change experiments and scenarios, run the queue, start a simulator search and update the lab |

The MCP server describes its tools itself. The simulator's are `simulation_*`, over HTTP under
`/api/v1/simulation/searches`.

## Approval

- **Default:** a control token asks first. Each change waits under Settings › Agents.
- **Shown:** the runs and hours of an experiment, the file it saves, or the commits of an update.
- **Updates:** always wait, also with a token that acts at once.
- **Budget:** queueing waits once the queue would run longer than agents may fill, 24 h by default.
- **Changed files:** an approval fails if the file changed since the agent asked.

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

## What no agent can do

| An agent tries to | It gets |
|---|---|
| act without a valid token | 401 |
| change anything with a read token | 403 |
| approve its own change | the sign-in page |
| change the paper's experiment or scenarios | a refusal with the reason |
| save an invalid experiment | the editor's refusal |
| delete a scenario in use | a refusal |
| fill the queue beyond its budget | a change that waits |
| run a change whose file changed since | a failed approval |

Each row is tested in [`tests/test_agent.py`](../tests/test_agent.py).

- **Never:** settings, passwords, tokens, or deleting results.
- **Log:** every action, with the token's name.
- **Revoke:** a token stops at once.
- **Storage:** tokens only as hashes.
