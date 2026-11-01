"""Simulation: searches of the simulator, their findings, and each finding
replayed step by step, every mode at hand."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ... import simulation
from ..common import jobs, with_error
from ..context import render

router = APIRouter()


@router.get("/simulation", response_class=HTMLResponse)
def area(request: Request, search: str = "", error: str = ""):
    every = [{**s, "left_s": simulation.left_s(s)} for s in simulation.searches()]
    shown = search or simulation.latest() or next((s["id"] for s in every), "")
    try:
        current = simulation.search(shown) if shown else None
        if current:
            current["left_s"] = simulation.left_s(current)
    except LookupError:
        raise HTTPException(404, f"No search {shown}.") from None
    groups = []
    for p in simulation.problems(current) if current else []:
        if not groups or groups[-1]["kind"] != p["kind"]:
            groups.append({"kind": p["kind"], "problems": []})
        groups[-1]["problems"].append({**p, "label": simulation.modes_label(p["modes"])})
    return render(request, "simulation.html", nav="simulation", searches=every, current=current, groups=groups, error=error)


@router.get("/simulation/{search_id}/state")
def state(request: Request, search_id: str):
    """Polled while a search waits or runs: how far it is, and a reload once it ended."""
    try:
        entry = simulation.search(search_id)
    except LookupError:
        entry = {"state": "gone"}
    if entry["state"] not in ("running", "queued"):
        return Response(headers={"HX-Refresh": "true"})
    return render(request, "partials/search-progress.html", s={**entry, "left_s": simulation.left_s(entry)})


@router.post("/simulation/searches")
def start():
    """A search that checks everything, queued beside the results: it runs when nothing runs before it."""
    try:
        search_id = simulation.start(by="web interface")
    except ValueError as e:
        return RedirectResponse(with_error("/simulation", str(e)), status_code=303)
    return RedirectResponse(f"/simulation?search={search_id}", status_code=303)


@router.post("/simulation/{search_id}/stop")
def stop(search_id: str):
    try:
        simulation.stop(search_id)
    except (LookupError, ValueError) as e:
        return RedirectResponse(with_error(f"/simulation?search={search_id}", str(e)), status_code=303)
    return RedirectResponse(f"/simulation?search={search_id}", status_code=303)


@router.post("/simulation/{search_id}/delete")
def delete(search_id: str):
    try:
        simulation.delete(search_id)
    except (LookupError, ValueError) as e:
        return RedirectResponse(with_error(f"/simulation?search={search_id}", str(e)), status_code=303)
    return RedirectResponse("/simulation", status_code=303)


@router.get("/simulation/{search_id}/{finding_id}", response_class=HTMLResponse)
def case(request: Request, search_id: str, finding_id: int, error: str = ""):
    try:
        entry = simulation.search(search_id)
    except LookupError as e:
        raise HTTPException(404, str(e)) from None
    found = simulation.case_of(entry, finding_id)
    if found is None:
        raise HTTPException(404, f"No case {finding_id} in search {search_id}.")
    if found["case"]["id"] != finding_id:  # a finding of the case, as agents and older links name it
        return RedirectResponse(f"/simulation/{search_id}/{found['case']['id']}", status_code=307)
    example = next(e for e in entry["findings"] if e["id"] == finding_id)
    obgp = [m for m in found["modes"] if m != "bgp"]
    # Large the first OBGP mode that shows the problem, BGP beside it. When only BGP shows it, BGP large, beside it the default mode.
    right, left = (obgp[0], "bgp") if obgp else ("bgp", "obgp-rp")
    lab = simulation.played(search_id, finding_id, found["case"]["kind"])
    return render(request, "simulation-case.html", nav="simulation", search_id=search_id, finding_id=finding_id, example=example, lab=lab,
                  shown=found["modes"], per_mode=found["case"]["per_mode"], label=simulation.modes_label(found["modes"]),
                  proof=found["case"]["proof"], examples=found["examples"], modes=simulation.MODES, left=left, right=right, error=error)


@router.post("/simulation/{search_id}/{finding_id}/lab")
def to_lab(search_id: str, finding_id: int):
    """Makes the case an experiment of the lab and opens it, to start it there."""
    try:
        name = simulation.to_lab(search_id, finding_id)
    except (LookupError, ValueError) as e:
        return RedirectResponse(with_error(f"/simulation/{search_id}/{finding_id}", str(e)), status_code=303)
    return RedirectResponse(f"/experiments/{name}", status_code=303)


@router.get("/simulation/{search_id}/{finding_id}/trace")
async def case_trace(search_id: str, finding_id: int, mode: str):
    try:
        return JSONResponse(await run_in_threadpool(simulation.trace, search_id, finding_id, mode, not jobs.active()))
    except LookupError as e:
        raise HTTPException(404, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    except RuntimeError as e:
        raise HTTPException(502, str(e)) from None
