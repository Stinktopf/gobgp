"""Simulation: searches of the simulator, their findings, and each finding
replayed step by step, every mode at hand."""

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from ... import marks, simulation
from ..common import with_error
from ..context import render

router = APIRouter()


@router.get("/simulation", response_class=HTMLResponse)
def area(request: Request, search: str = "", error: str = ""):
    marked = marks.starred("search")
    every = sorted(({**s, "left_s": simulation.left_s(s), "starred": s["id"] in marked} for s in simulation.searches()),
                   key=lambda s: not s["starred"])  # starred first, each part newest first
    shown = search or simulation.latest() or next((s["id"] for s in every), "")
    try:
        current = simulation.search(shown) if shown else None
        if current:
            current["left_s"] = simulation.left_s(current)
    except LookupError:
        raise HTTPException(404, f"No search {shown}.") from None
    groups = []
    starred = simulation.stars(current["id"]) if current else set()
    found = [{**p, "label": simulation.modes_label(p["modes"]), "starred": p["id"] in starred} for p in (simulation.problems(current) if current else [])]
    if marked := [p for p in found if p["starred"]]:  # first, out of their own groups
        groups.append({"kind": "starred", "problems": marked})
    for p in found:
        if p["starred"]:
            continue
        if not groups or groups[-1]["kind"] != p["kind"]:
            groups.append({"kind": p["kind"], "problems": []})
        groups[-1]["problems"].append(p)
    return render(request, "simulation.html", nav="simulation", searches=every, current=current, groups=groups, error=error,
                  search_notes=marks.counts("search"), case_notes=marks.counts("case"),
                  marks_on={"kind": "search", "name": current["id"]} if current else None)


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
    return RedirectResponse("/simulation", status_code=303)  # a stopped search is gone


@router.post("/simulation/delete")
def delete_picked(request: Request):
    """The searches picked in the list, as Results deletes them."""
    problems = []
    for search_id in request.query_params.getlist("ids"):
        try:
            simulation.delete(search_id)
        except (LookupError, ValueError) as e:
            problems.append(f"{search_id}: {e}")
    return RedirectResponse(with_error("/simulation", "Not deleted: " + " ".join(problems)) if problems else "/simulation", status_code=303)


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
    obgp = [m for m in found["modes"] if m.startswith("obgp")]
    # Large the first OBGP mode that shows the problem, BGP beside it. When only BGP or NS-BGP shows it, that one, beside it the default mode.
    right, left = (obgp[0], "bgp") if obgp else (found["modes"][0], "obgp-rp")
    lab = simulation.played(search_id, finding_id, found["case"]["kind"])
    starred = finding_id in simulation.stars(search_id)
    return render(request, "simulation-case.html", nav="simulation", search_id=search_id, finding_id=finding_id, example=example, lab=lab,
                  shown=found["modes"], per_mode=found["case"]["per_mode"], label=simulation.modes_label(found["modes"]),
                  proof=found["case"]["proof"], examples=found["examples"], modes=simulation.MODES, left=left, right=right, error=error,
                  starred=starred, marks_on={"kind": "case", "name": f"{search_id}/{finding_id}"})


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
        return JSONResponse(await run_in_threadpool(simulation.trace, search_id, finding_id, mode))
    except LookupError as e:
        raise HTTPException(404, str(e)) from None
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    except RuntimeError as e:
        raise HTTPException(502, str(e)) from None
