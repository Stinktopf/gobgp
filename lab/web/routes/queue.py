"""The dock, the overview of the lab and the queue."""

from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ... import (
    cluster,
)
from ...results import Dataset
from ..common import back, jobs, templates
from ..context import parts, render

router = APIRouter()


@router.get("/")
def home():
    return RedirectResponse("/experiments", 303)


@router.get("/partials/dock", response_class=HTMLResponse)
def dock_partial(request: Request):
    return render(request, "partials/dock.html")


@router.get("/partials/dock/parts/{name}", response_class=HTMLResponse)
def dock_parts(request: Request, name: str):
    """The sub-jobs of a waiting result, when it is opened in the dock."""
    dataset = Dataset.find(name)
    return templates.TemplateResponse(request, "partials/dock-parts.html", {"parts": parts(dataset) if dataset else [], "name": name})


@router.get("/partials/lab", response_class=HTMLResponse)
def lab_partial(request: Request):
    return render(request, "partials/lab.html", cluster_state=jobs.cluster_control.snapshot(), max_routers=cluster.max_routers(), limits=cluster.limits())


@router.post("/queue")
async def queue_order(request: Request):
    names = (await request.json()).get("order")
    if not isinstance(names, list):
        raise HTTPException(422)
    jobs.reorder([str(n) for n in names])
    return JSONResponse({"queue": jobs.queue()})


@router.post("/queue/pause")
def queue_pause(request: Request):
    jobs.pause()
    return RedirectResponse(back(request, "/results"), 303)


@router.post("/queue/resume")
def queue_resume(request: Request):
    if cluster.manually_stopped():
        return RedirectResponse(f"/settings?{urlencode({'error': 'The cluster is switched off. Start it before resuming jobs.'})}#cluster", 303)
    jobs.resume_queue()
    return RedirectResponse(back(request, "/results"), 303)


@router.post("/queue/stop")
def queue_stop(request: Request):
    jobs.stop_all()
    return RedirectResponse(back(request, "/results"), 303)
