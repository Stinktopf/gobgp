"""The web interface: manage, monitor and compare experiments. This module puts its parts together,
the pages are in routes/, what they share in common.py."""

import logging
import threading
import time

from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import (
    analysis,
    wrapped,
)
from ..config import ROOT
from ..results import Dataset
from . import auth
from .cluster_control import ClusterControl
from .common import HERE, jobs
from .context import experiments, render
from .routes import routers
from .routes.settings import watch_updates

PUBLIC_PATHS = ("/login", "/static/", "/assets/")

def warm_up() -> None:
    """Analyses every result once in the background, so that no page waits
    for it, e.g. after a new version of the metrics. Runs of a result that
    runs are left to its runner."""
    log = logging.getLogger("uvicorn.error")
    began = time.monotonic()
    experiments()  # parses every experiment, scenario and topology once, the large ones take seconds
    for dataset in Dataset.all():
        try:
            analysis.summary(dataset)
            for key in dataset.keys():
                if dataset.is_done(key):
                    analysis.run_bins(dataset, key, dataset.run(key))
        except (ValueError, OSError, KeyError) as e:
            log.warning("warming up %s: %s", dataset.name, e)
    try:
        wrapped.overview()
    except (ValueError, OSError, KeyError) as e:
        log.warning("warming up Wrapped: %s", e)
    log.info("analysed every result in %.0f s", time.monotonic() - began)


def create_app() -> FastAPI:
    cluster_control = ClusterControl(jobs)
    jobs.cluster_control = cluster_control
    app = FastAPI(title="OBGP Lab", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.cluster_control = cluster_control
    app.add_middleware(GZipMiddleware)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")  # one copy of logos and icons
    threading.Thread(target=jobs.supervise, daemon=True).start()
    threading.Thread(target=warm_up, daemon=True).start()
    threading.Thread(target=watch_updates, daemon=True).start()
    cluster_control.prime()
    if file := auth.initialize():
        logging.getLogger("uvicorn.error").warning("No password was set: the initial password is in %s", file)
    @app.middleware("http")
    async def require_login(request: Request, call_next):
        settings = auth.load()
        if not request.url.path.startswith(PUBLIC_PATHS):
            if not settings or not auth.valid(request.cookies.get(auth.COOKIE), settings):
                if request.headers.get("HX-Request"):
                    return Response(status_code=401, headers={"HX-Redirect": "/login"})
                return RedirectResponse("/login", 303)
            # Forms may only be posted from the lab itself.
            origin = request.headers.get("origin")
            if request.method == "POST" and origin and origin.split("://")[-1] != request.url.netloc:
                return Response("Cross-origin request.", status_code=403)
            # The initial password is changed before anything else.
            if auth.must_change(settings) and request.url.path not in ("/settings", "/settings/password", "/logout"):
                if request.headers.get("HX-Request"):  # e.g. the dock refreshing: nothing to swap in
                    return Response(status_code=204)
                return RedirectResponse("/settings", 303)
        return await call_next(request)
    @app.exception_handler(StarletteHTTPException)
    async def not_found(request: Request, error: StarletteHTTPException):
        # Pages get a page, requests of scripts the plain answer.
        if "text/html" not in request.headers.get("accept", "") or request.headers.get("HX-Request"):
            return JSONResponse({"detail": error.detail}, status_code=error.status_code)
        page = render(request, "error.html", status=error.status_code, detail=error.detail, nav="")
        page.status_code = error.status_code
        return page
    for router in routers:
        app.include_router(router)
    return app
