"""The web interface: manage, monitor and compare experiments. This module puts its parts together,
the pages are in routes/, what they share in common.py."""

import logging
import subprocess
import sys
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Route

from .. import config as lab_config
from . import auth, common
from .cluster_control import ClusterControl
from .common import jobs
from .context import experiments, render
from .mcp_server import Endpoint
from .routes import routers
from .routes.settings import watch_updates

PUBLIC_PATHS = ("/login", "/healthz", "/static/", "/assets/", "/certificate")  # the certificate is in every TLS handshake anyway
TOKEN_PATHS = ("/api/", "/mcp")  # agents, with a token instead of the login

def warm_up() -> None:
    """Analyses every result once, in a process of its own at the lowest
    priority, so that no page waits for it, e.g. after a new version of the
    metrics, and the web server keeps its CPU. Runs of a result that runs
    are left to its runner."""
    experiments()  # parses every experiment, scenario and topology once for the pages, the large ones take seconds
    try:
        subprocess.run([sys.executable, "-m", "lab.cli", "analyse", "--all"], stdout=subprocess.DEVNULL)
    except OSError as e:
        logging.getLogger("uvicorn.error").warning("warming up: %s", e)


def create_app() -> FastAPI:
    cluster_control = ClusterControl(jobs)
    jobs.cluster_control = cluster_control
    mcp = Endpoint()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with mcp.running():
            yield

    app = FastAPI(title="OBGP Lab", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.cluster_control = cluster_control
    app.add_middleware(GZipMiddleware)
    app.mount("/static", StaticFiles(directory=common.STATIC), name="static")  # the copy of a frozen server
    app.mount("/assets", StaticFiles(directory=lab_config.ROOT / "assets"), name="assets")  # one copy of logos and icons
    threading.Thread(target=jobs.supervise, daemon=True).start()
    threading.Thread(target=warm_up, daemon=True).start()
    threading.Thread(target=watch_updates, daemon=True).start()
    cluster_control.prime()
    if file := auth.initialize():
        logging.getLogger("uvicorn.error").warning("No password was set: the initial password is in %s", file)
    @app.middleware("http")
    async def require_login(request: Request, call_next):
        settings = auth.load()
        if not request.url.path.startswith(PUBLIC_PATHS + TOKEN_PATHS):
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
    @app.get("/healthz")
    def healthz():
        """Whether the server answers, for the watchdog: no page, no login, no state of the lab."""
        return Response("ok", media_type="text/plain")
    for router in routers:
        app.include_router(router)
    app.router.routes.append(Route("/mcp", mcp, methods=["GET", "POST", "DELETE"]))
    return app
