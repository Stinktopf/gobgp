"""The API for agents and scripts, under /api/v1, with a token of the
settings as bearer: GET reads, POST controls with a token of scope control."""

from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from starlette.background import BackgroundTask

from ... import remote, results as datasets, simulation
from .. import agent, tokens

router = APIRouter(prefix="/api/v1")


def downloader(request: Request) -> dict:
    if not (token := tokens.check(request.headers.get("authorization"))):
        raise HTTPException(401, "A valid token is needed: Authorization: Bearer obgp_…", headers={"WWW-Authenticate": "Bearer"})
    return token


def reader(token: Annotated[dict, Depends(downloader)]) -> dict:
    if token["scope"] == tokens.DOWNLOAD:
        raise HTTPException(403, "This token only downloads.")
    return token


def controller(token: Annotated[dict, Depends(reader)]) -> dict:
    if token["scope"] != "control":
        raise HTTPException(403, "This token only reads.")
    return token


Controller = Annotated[dict, Depends(controller)]  # the token of an agent that may control


def control(token: dict, call, *args):
    """Runs a control action as the token's agent, for the activity log."""
    tokens.caller.set(token)
    return answer(call, *args)


def answer(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except LookupError as e:
        raise HTTPException(404, str(e)) from None
    except RuntimeError as e:
        raise HTTPException(502, str(e)) from None
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


def split(items: str) -> list[str] | None:
    return [m for m in items.split(",") if m] or None


@router.get("/status", dependencies=[Depends(reader)])
def status():
    return agent.status()


@router.get("/version", dependencies=[Depends(reader)])
def version():
    return agent.version()


@router.get("/metrics", dependencies=[Depends(reader)])
def metrics():
    return agent.metrics()


@router.get("/experiments", dependencies=[Depends(reader)])
def experiments():
    return agent.experiments()


@router.get("/experiments/{name}", dependencies=[Depends(reader)])
def experiment(name: str):
    return answer(agent.experiment_of, name)


@router.get("/scenarios", dependencies=[Depends(reader)])
def scenarios():
    return agent.scenarios()


@router.get("/scenarios/{name}", dependencies=[Depends(reader)])
def scenario(name: str):
    return answer(agent.scenario_of, name)


@router.get("/topologies", dependencies=[Depends(reader)])
def topologies():
    return agent.topologies()


@router.get("/topologies/{name}", dependencies=[Depends(reader)])
def topology(name: str):
    return answer(agent.topology_of, name)


@router.get("/vocabulary", dependencies=[Depends(reader)])
def vocabulary():
    return agent.vocabulary()


@router.get("/actions/{action_id}", dependencies=[Depends(reader)])
def action(action_id: str):
    return answer(agent.action, action_id)


@router.get("/results", dependencies=[Depends(reader)])
def results():
    return agent.results()


@router.get("/results/{name}", dependencies=[Depends(reader)])
def result(name: str):
    return answer(agent.result, name)


@router.get("/results/{name}/summary", dependencies=[Depends(reader)])
def summary(name: str, topology: str = "", scenario: str = "", variant: str = "", metrics: str = ""):
    return answer(agent.summary, name, topology, scenario, variant, split(metrics))


@router.get("/results/{name}/runs", dependencies=[Depends(reader)])
def runs(name: str, topology: str = "", scenario: str = "", variant: str = "", metrics: str = ""):
    return answer(agent.runs, name, topology, scenario, variant, split(metrics))


@router.get("/results/{name}/paired", dependencies=[Depends(reader)])
def paired(name: str, topology: str, scenario: str, metric: str, variant: str, baseline: str):
    return answer(agent.paired, name, topology, scenario, metric, variant, baseline)


@router.get("/results/{name}/primary", dependencies=[Depends(reader)])
def primary(name: str):
    return answer(agent.primary, name)


@router.get("/results/{name}/problems", dependencies=[Depends(reader)])
def problems(name: str):
    return answer(agent.problems, name)


@router.get("/results/{name}/runs/{topology}/{variant}/{scenario}/{run}/events", dependencies=[Depends(reader)])
def run_events(name: str, topology: str, variant: str, scenario: str, run: int):
    return answer(agent.run_events, name, topology, variant, scenario, run)


@router.get("/results/{name}/runs/{topology}/{variant}/{scenario}/{run}/samples", dependencies=[Depends(reader)])
def run_samples(name: str, topology: str, variant: str, scenario: str, run: int, routers: str = "", from_s: float = 0.0,
                to_s: float = 1e9, fields: str = "", limit: int = 500):
    return answer(agent.run_samples, name, topology, variant, scenario, run, split(routers), from_s, to_s, split(fields), limit)


@router.get("/results/{name}/runs/{topology}/{variant}/{scenario}/{run}/forwarding", dependencies=[Depends(reader)])
def run_forwarding(name: str, topology: str, variant: str, scenario: str, run: int, prefix: str = "", from_s: float = 0.0, to_s: float = 1e9):
    return answer(agent.run_forwarding, name, topology, variant, scenario, run, prefix, from_s, to_s)


@router.get("/results/{name}/archive", dependencies=[Depends(downloader)])
def result_archive(name: str):
    """The whole result folder as a gzipped tar, for lab pull."""
    if not (dataset := datasets.Dataset.find(name)):
        raise HTTPException(404, f"No result {name}.")
    out = remote.archive(dataset.path)
    return StreamingResponse(iter(lambda: out.read(1 << 20), b""), media_type="application/gzip",
                             headers={"content-disposition": f'attachment; filename="{name}.tar.gz"'},
                             background=BackgroundTask(out.close))


@router.get("/results/{name}/log", dependencies=[Depends(reader)])
def log(name: str, tail: int = 200, grep: str = ""):
    return answer(agent.log, name, tail, grep)


@router.get("/simulation/searches", dependencies=[Depends(reader)])
def simulation_searches():
    return agent.simulation_searches()


@router.get("/simulation/searches/{search_id}", dependencies=[Depends(reader)])
def simulation_search(search_id: str):
    return answer(agent.simulation_search, search_id)


@router.get("/simulation/searches/{search_id}/file", dependencies=[Depends(downloader)])
def simulation_search_file(search_id: str):
    """A search as it is stored, for lab pull."""
    try:
        path = simulation._path(search_id)
    except LookupError as e:
        raise HTTPException(404, str(e)) from None
    if not path.exists():
        raise HTTPException(404, f"No search {search_id}.")
    return FileResponse(path, media_type="application/json")


@router.get("/simulation/searches/{search_id}/{finding}", dependencies=[Depends(reader)])
def simulation_case(search_id: str, finding: int, mode: str = "", start: int = 0, limit: int = 40):
    return answer(agent.simulation_case, search_id, finding, mode, start, limit)


@router.post("/simulation/predict")
def predict(token: Controller, topology: str, scenario: str, tables: bool = False, seeds: int = 20):
    """As MCP: changes nothing, but takes CPU, so a token of scope control."""
    return control(token, agent.predict, topology, scenario, tables, seeds)


@router.post("/simulation/searches")
def start_simulation(token: Controller):
    return control(token, agent.start_simulation)


@router.post("/simulation/searches/{search_id}/{finding}/lab")
def simulation_to_lab(search_id: str, finding: int, token: Controller):
    return control(token, agent.simulation_to_lab, search_id, finding)


@router.post("/simulation/searches/{search_id}/stop")
def stop_simulation(search_id: str, token: Controller):
    return control(token, agent.stop_simulation, search_id)


@router.post("/experiments/{name}/start")
def start(name: str, token: Controller):
    return control(token, agent.start, name)


@router.post("/results/{name}/stop")
def stop(name: str, token: Controller):
    return control(token, agent.stop, name)


@router.post("/results/{name}/resume")
def resume(name: str, token: Controller):
    return control(token, agent.resume, name)


@router.post("/queue/pause")
def pause(token: Controller):
    return control(token, agent.pause)


@router.post("/lab/update")
def update_lab(token: Controller, branch: str = ""):
    return control(token, agent.update_lab, branch)


@router.post("/queue/resume")
def unpause(token: Controller):
    return control(token, agent.unpause)


@router.put("/experiments/{name}")
def save_experiment(name: str, body: Annotated[dict, Body()], token: Controller):
    return control(token, agent.save_experiment, name, str(body.get("yaml", "")))


@router.delete("/experiments/{name}")
def delete_experiment(name: str, token: Controller):
    return control(token, agent.delete_experiment, name)


@router.put("/scenarios/{name}")
def save_scenario(name: str, body: Annotated[dict, Body()], token: Controller):
    return control(token, agent.save_scenario, name, str(body.get("yaml", "")))


@router.delete("/scenarios/{name}")
def delete_scenario(name: str, token: Controller):
    return control(token, agent.delete_scenario, name)
