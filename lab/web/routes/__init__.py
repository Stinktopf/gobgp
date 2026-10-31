"""The pages of the web interface, one module per area."""

from . import (
    api,
    experiments,
    groups,
    login,
    queue,
    results,
    scenarios,
    settings,
    simulation,
    topologies,
)

routers = [m.router for m in (api, login, settings, queue, experiments, results, groups, scenarios, topologies, simulation)]
