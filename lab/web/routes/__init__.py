"""The pages of the web interface, one module per area."""

from . import (
    experiments,
    groups,
    login,
    queue,
    results,
    scenarios,
    settings,
    topologies,
)

routers = [m.router for m in (login, settings, queue, experiments, results, groups, scenarios, topologies)]
