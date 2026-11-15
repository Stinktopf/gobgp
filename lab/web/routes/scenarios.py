"""Scenarios: the list, the editor and its preview."""

from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError

from ... import (
    scenario,
)
from .. import groups
from ..common import load_problem, readable
from ..context import (
    check_rename,
    experiments,
    own_group,
    readable_topologies,
    render,
    step_kinds,
    thumb_stamps,
    users,
)

router = APIRouter()


def scenario_context() -> dict:
    """The topologies the preview of the scenario editor offers, by name and
    version: it loads the one it shows, as parts of the Internet are large."""
    loaded = readable_topologies()[0]
    return {"topologies": sorted(loaded), "versions": thumb_stamps(loaded)}


@router.get("/scenarios", response_class=HTMLResponse)
def scenarios_page(request: Request, error: str = ""):
    used = users("scenarios")
    items = []
    for n in scenario.names():
        try:
            sc = scenario.load(n)
        except (ValueError, OSError) as e:
            items.append({"name": n, "error": load_problem(e)})
            continue
        items.append({"name": n, "description": sc.description, "duration_s": sc.duration(), "used": used[n],
                      "kinds": step_kinds(sc.steps), "own": groups.of_scenario(used[n])})
    return render(request, "scenarios.html", nav="scenarios", groups=groups.arrange("scenarios", items, scenario.names()), error=error)


@router.get("/scenarios/new", response_class=HTMLResponse)
def scenario_new(request: Request, like: str = ""):
    data = {"name": "", "description": "", "steps": [{"announce": {"rate": 1, "for": 30}}, {"wait": 10},
                                                       {"withdraw": {}}, {"until_stable": {"timeout": 60}}]}
    if like:
        try:
            data = {**scenario.load(like).dump(), "name": f"{like}-copy"}
        except (ValueError, OSError):
            pass
    return render(request, "scenario.html", nav="scenarios", data=data, original="", used=[], **scenario_context())


@router.get("/scenarios/{name}", response_class=HTMLResponse)
def scenario_page(request: Request, name: str, error: str = ""):
    try:
        data = scenario.load(name).dump()
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, f"No scenario {name}.") from None
    used = users("scenarios")[name]
    # Preview on a topology of an experiment that plays the scenario.
    preview = next((t for x in experiments() if x.get("experiment") and name in x["experiment"].scenarios
                    for t in x["experiment"].topologies), "")
    return render(request, "scenario.html", nav="scenarios", data=data, original=name, used=used,
                  preview=preview, error=error, **scenario_context())


@router.post("/scenarios/preview")
async def scenario_preview(request: Request):
    body = await request.json()
    try:
        sc = scenario.parse({"name": "preview", "description": "", "params": body.get("params") or {}, "steps": body.get("steps") or []})
    except ValidationError as error:
        return JSONResponse({"problems": readable(error)})
    except ValueError as error:
        return JSONResponse({"problems": [str(error)]})
    return JSONResponse(await run_in_threadpool(preview, sc, body))


def preview(sc, body: dict) -> dict:
    out = {"problems": [], "timeline": scenario.timeline(sc.steps), "duration_s": sc.duration(), "targets": {}}
    if t := readable_topologies()[0].get(body.get("topology")):
        out["targets"] = scenario.preview_targets(sc.steps, scenario.Network(t["routers"], t["roles"]),
                                                  int(body.get("seed") or 42), int(body.get("run") or 1))
    return out


@router.post("/scenarios/save")
async def scenario_save(request: Request):
    body = await request.json()
    name, original = str(body.get("name", "")).strip(), str(body.get("original", ""))
    try:
        check_rename("scenario", name, original, body.get("mode"), scenario.path, "scenarios")
        sc = scenario.parse({"name": name, "description": str(body.get("description", "")).strip(),
                             "params": body.get("params") or {}, "steps": body.get("steps") or []})
    except ValidationError as error:
        return JSONResponse({"problems": readable(error)}, status_code=422)
    except ValueError as error:
        return JSONResponse({"problems": [str(error)]}, status_code=422)
    scenario.path(name).write_text(scenario.to_yaml(sc))
    if original and original != name and scenario.path(original).exists():
        groups.follow("scenarios", original, name, body.get("mode") == "rename", own_group("scenarios", name), own_group("scenarios", original))
    if original and original != name and body.get("mode") == "rename":
        scenario.path(original).unlink(missing_ok=True)
    return JSONResponse({"saved": name})


@router.post("/scenarios/{name}/delete")
def scenario_delete(name: str):
    try:
        file = scenario.path(name)
    except ValueError:
        raise HTTPException(404, f"No scenario {name}.") from None
    if used := users("scenarios")[name]:
        return RedirectResponse(f"/scenarios/{name}?{urlencode({'error': f'{name} is used by {', '.join(used)}.'})}", 303)
    file.unlink(missing_ok=True)
    groups.forget("scenarios", name)
    return RedirectResponse("/scenarios", 303)
