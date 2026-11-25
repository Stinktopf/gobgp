"""MCP for agents, under /mcp, with a token of the settings as bearer. A
token of scope read reaches a server with the read tools only, one of
scope control a server that also starts, pauses and stops experiments."""

import functools
from contextlib import AsyncExitStack, asynccontextmanager

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse

from . import agent, tokens

INSTRUCTIONS = """The OBGP lab runs BGP and OBGP on real routers and measures them.
An experiment file runs as a result: topologies x scenarios x variants x runs.
Start with status and results, then result for the setup and the verdict, metrics for what
the metrics mean, summary for medians with their interval, runs for every run,
primary for the comparison an experiment is about, paired for any other, problems for what went wrong, log for
the details. Never pool variants: compare them, and state n and the resolution
(two sampling intervals) with every claim about times.
To build an experiment, read topologies, scenarios, vocabulary and an example
with experiment or scenario, then save_experiment or save_scenario and
start_experiment. A change may wait for a person: then action tells its state.
Before the lab, the simulator plays one prefix on every small network with the router's own
decision code: simulation_searches lists its searches, simulation_search the findings of one,
simulation_case plays a finding step by step, a page at a time, predict plays one topology and scenario of
the lab, start_simulation starts a search,
stop_simulation stops it and simulation_to_lab makes a finding an experiment to start.
marks reads the stars and notes people and agents left on results, searches and cases, star and add_note set them.
predict_again judges a result that does not run against a new answer of the simulator,
agreement sets simulator and lab side by side per cell, on rest and on deviations at rest: only never, sometimes and always compare.
The paper's experiment and its scenarios stay as they are, results are never deleted."""

READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
CONTROL = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)
DELETE = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=False)


def with_reasons(fn):
    """A tool whose expected failures reach the agent with their reason, e.g. a
    scenario still in use. Others the SDK reports without detail."""
    @functools.wraps(fn)
    def tool(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (ValueError, LookupError) as e:
            raise ToolError(str(e)) from e
    return tool


def server(control: bool) -> MCPServer:
    s = MCPServer("obgp-lab", instructions=INSTRUCTIONS)
    for fn in (agent.status, agent.version, agent.experiments, agent.results, agent.result, agent.metrics, agent.summary,
               agent.runs, agent.run_events, agent.run_samples, agent.run_forwarding, agent.paired, agent.primary, agent.agreement, agent.problems,
               agent.log, agent.topologies, agent.scenarios, agent.vocabulary,
               agent.simulation_searches, agent.simulation_search, agent.simulation_case, agent.download):
        s.tool(annotations=READ)(with_reasons(fn))
    s.tool(name="marks", annotations=READ)(with_reasons(agent.marks_of))
    for name, fn in (("experiment", agent.experiment_of), ("scenario", agent.scenario_of), ("topology", agent.topology_of)):
        s.tool(name=name, annotations=READ)(with_reasons(fn))
    if control:
        s.tool(annotations=READ)(with_reasons(agent.action))
        for name, fn in (("start_experiment", agent.start), ("stop_result", agent.stop), ("resume_result", agent.resume),
                         ("pause_queue", agent.pause), ("resume_queue", agent.unpause), ("run_next", agent.run_next), ("update_lab", agent.update_lab),
                         ("save_experiment", agent.save_experiment), ("save_scenario", agent.save_scenario),
                         ("start_simulation", agent.start_simulation), ("stop_simulation", agent.stop_simulation),
                         ("simulation_to_lab", agent.simulation_to_lab), ("predict_again", agent.predict_again),
                         ("star", agent.star), ("add_note", agent.add_note), ("edit_note", agent.edit_note)):
            s.tool(name=name, annotations=CONTROL)(with_reasons(fn))
        s.tool(annotations=CONTROL)(with_reasons(agent.predict))  # changes nothing, but takes CPU: no approval, refused beside a result
        for fn in (agent.delete_experiment, agent.delete_scenario, agent.delete_note):
            s.tool(annotations=DELETE)(with_reasons(fn))
    return s


class Endpoint:
    """The ASGI app of /mcp: checks the token and hands the request to the server of its scope."""

    def __init__(self) -> None:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)  # the token guards it
        self.servers = {scope: server(scope == "control") for scope in tokens.SCOPES}
        self.apps = {scope: s.streamable_http_app(streamable_http_path="/mcp", stateless_http=True, json_response=True,
                                                  transport_security=security)
                     for scope, s in self.servers.items()}

    @asynccontextmanager
    async def running(self):
        async with AsyncExitStack() as stack:
            for s in self.servers.values():
                await stack.enter_async_context(s.session_manager.run())
            yield

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if not (token := tokens.check(headers.get("authorization"))):
            response = JSONResponse({"error": "A valid token is needed: Authorization: Bearer obgp_…"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
            return await response(scope, receive, send)
        if token["scope"] not in self.apps:  # a download token fetches files only
            response = JSONResponse({"error": "This token only downloads."}, status_code=403)
            return await response(scope, receive, send)
        tokens.caller.set(token)
        host = headers.get("host", "")
        agent.origin.set(f"{scope.get('scheme', 'https')}://{host}" if host else "")
        await self.apps[token["scope"]](scope, receive, send)
