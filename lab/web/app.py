"""The web interface: manage, monitor and compare experiments."""

import csv
import hashlib
import io
import logging
import platform
import re
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from html import escape
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse

import yaml
from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import (
    analysis,
    caida,
    cluster,
    config,
    estimate,
    generate,
    notify,
    scenario,
    sndlib,
    topology,
    update,
    wrapped,
)
from .. import host as hostload
from ..config import ROOT, Experiment, Variant
from ..modes import MODES
from ..results import Dataset, RunKey, folder_size, storage
from . import auth
from .jobs import Jobs

HERE = Path(__file__).parent
EXPERIMENTS = ROOT / "experiments"
PUBLIC_PATHS = ("/login", "/static/", "/assets/")
# From what ran to the numbers, over time, a single run, and how it was set up.
TABS = {"runs": "Runs", "table": "Table", "charts": "Charts", "replay": "Replay", "details": "Details"}
OLD_TABS = {"overview": "table"}  # links from before
SERIES_CACHE: dict = {}  # (result, topology, scenario, done runs) -> series of every variant
COUNT = "A count of paths, not the memory they take"
GARBAGE = "Includes garbage until the next collection"
METRICS = {  # label, unit, what it measures in a few words, group, caveat
    "checks": ("Checks", "runs", "runs whose expect steps all passed", "Outcome", None),
    "convergence_s": ("Convergence", "s", "until every router reaches every prefix", "Outcome", None),
    "settle_s": ("Settle", "s", "until no router changes anything, no more updates", "Outcome", None),
    "hold_churn": ("Updates at rest", "updates/s", "per router at rest, zero when routes stand still", "Outcome", None),
    "adj_in_mean": ("Adj-RIB-In", "paths", "received from all peers, peak of the mean over the routers", "Resources", None),
    "rib_mean": ("Admitted", "paths", "the import admits, the Loc-RIB size of the paper", "Resources", COUNT),
    "suppressed_mean": ("Suppressed", "paths", "OBGP keeps without admitting them", "Resources", None),
    "selected_mean": ("Selected", "routes", "one per prefix, the Loc-RIB of RFC 4271", "Resources", None),
    "path_len_avg": ("Path length", "AS hops", "mean of the admitted paths", "Resources", None),
    "rss_mean": ("Memory", "MB", "resident memory of the daemon", "Resources", "The Go runtime returns freed memory late"),
    "heap_mean": ("Heap", "MB", "heap in use of the daemon", "Resources", GARBAGE),
    "objects_mean": ("Heap objects", "objects", "of the daemon", "Resources", GARBAGE),
    "cpu_s_mean": ("CPU", "s", "per router while measured", "Resources", "The whole daemon, with its API and the sampling"),
}

templates = Jinja2Templates(HERE / "templates")
jobs = Jobs()


def create_app() -> FastAPI:
    app = FastAPI(title="OBGP Lab", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(GZipMiddleware)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    app.mount("/assets", StaticFiles(directory=ROOT / "assets"), name="assets")  # one copy of logos and icons
    threading.Thread(target=jobs.supervise, daemon=True).start()
    threading.Thread(target=warm_up, daemon=True).start()
    threading.Thread(target=watch_updates, daemon=True).start()
    throttle = auth.Throttle()
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

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, error: str = ""):
        return render(request, "login.html", error=error, initial=auth.must_change(auth.load()),
                      initial_file=auth.initial_file())

    @app.post("/login")
    def login(request: Request, password: str = Form()):
        client = request.client.host if request.client else "?"
        settings = auth.load()
        if wait := throttle.locked(client):
            return RedirectResponse(f"/login?error=Too many attempts, wait {int(wait) + 1} s", 303)
        if not settings or not auth.check_password(password, settings):
            throttle.failed(client)
            return RedirectResponse("/login?error=Wrong password", 303)
        throttle.succeeded(client)
        response = RedirectResponse("/", 303)
        sign_in(request, response)
        return response

    @app.post("/logout")
    def logout():
        response = RedirectResponse("/login", 303)
        response.delete_cookie(auth.COOKIE)
        return response

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, saved: str = "", error: str = ""):
        return render(request, "settings.html", nav="settings", webhook=notify.masked(notify.load().get("discord")),
                      initial=auth.must_change(auth.load()), saved=saved, error=error,
                      host_settings=config.host_settings(), machine_host=cluster.host(), limits=cluster.limits(), max_routers=cluster.max_routers(),
                      version=UPDATES or update.status(fetch=False), running=jobs.active())

    @app.post("/settings/update/check")
    def settings_update_check():
        UPDATES.update(update.status(fetch=True))
        return RedirectResponse("/settings#version", 303)

    @app.post("/settings/update")
    def settings_update():
        """Takes the new commits and starts the server again, only while no result runs."""
        if active := jobs.active():
            return RedirectResponse(f"/settings?{urlencode({'error': f'{active.name} runs. Pause the queue or wait until it ends, then update.'})}#version", 303)
        try:
            commit = update.update()
        except update.UpdateError as e:
            return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#version", 303)
        threading.Timer(1.0, update.restart).start()  # after this answer is sent
        return RedirectResponse(f"/settings?{urlencode({'saved': f'Updated to {commit}. The lab starts again, reload in a few seconds.'})}#version", 303)

    @app.post("/settings/host")
    async def settings_host(request: Request):
        """What the lab may take of the host, what it keeps free, and the routers per thread."""
        form, machine = await request.form(), cluster.host()
        try:
            number = lambda key, scale=1: round(float(str(form.get(key)).replace(",", ".")) * scale) if str(form.get(key) or "").strip() else None
            values = {"cpus": number("cpus"), "memory_mb": number("memory_gb", 1024), "keep_cpus": number("keep_cpus"),
                      "keep_mb": number("keep_gb", 1024), "routers_per_cpu": number("routers_per_cpu")}
        except ValueError:
            return RedirectResponse(f"/settings?{urlencode({'error': 'Host: numbers only.'})}", 303)
        values = {k: v for k, v in values.items() if v is not None}
        cpus, memory = values.get("cpus", machine["cpus"]), values.get("memory_mb", machine["memory_mb"])
        keep_cpus, keep_mb = values.get("keep_cpus", config.HOST_DEFAULTS["keep_cpus"]), values.get("keep_mb", config.HOST_DEFAULTS["keep_mb"])
        problem = ("Threads for the lab: from 1 to the " + str(machine["cpus"]) + " of the host." if not 1 <= cpus <= machine["cpus"]
                   else f"Memory for the lab: at most the {machine['memory_mb'] / 1024:.0f} GB of the host." if not 1024 <= memory <= machine["memory_mb"]
                   else "Keep at least 4 threads free for the host." if keep_cpus < config.HOST_KEEP_AT_LEAST["keep_cpus"]
                   else "Keep at least 4 GB free for the host." if keep_mb < config.HOST_KEEP_AT_LEAST["keep_mb"]
                   else "Keep fewer threads free than the lab may take." if keep_cpus >= cpus
                   else "Keep less memory free than the lab may take." if keep_mb >= memory
                   else "Routers per thread: from 1 to 32." if not 1 <= values.get("routers_per_cpu", 4) <= 32 else None)
        if problem:
            return RedirectResponse(f"/settings?{urlencode({'error': problem})}", 303)
        # All of a resource counts as no cap: the lab follows the host if it grows.
        values = {k: v for k, v in values.items() if not (k == "cpus" and v == machine["cpus"]) and not (k == "memory_mb" and v == machine["memory_mb"])}
        config.save_host(values)
        return RedirectResponse(f"/settings?{urlencode({'saved': f'Host saved. The lab now runs up to {cluster.max_routers()} routers.'})}", 303)

    @app.post("/settings/notify")
    def settings_notify(request: Request, discord: str = Form(""), action: str = Form("save")):
        # The saved webhook is never shown; an empty field keeps it.
        url = "" if action == "off" else discord.strip() or notify.load().get("discord", "")
        settings = {"discord": url, "lab": str(request.base_url).rstrip("/")} if url else {}
        try:
            notify.save(settings)
        except ValueError as e:
            return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}", 303)
        if action == "test":
            problems = notify.test(settings)
            query = {"error": " ".join(problems)} if problems else {"saved": "A test message is on its way."}
        else:
            query = {"saved": "Notifications off." if action == "off" else "Saved."}
        return RedirectResponse(f"/settings?{urlencode(query)}", 303)

    @app.post("/settings/password")
    def settings_password(request: Request, current: str = Form(""), new: str = Form(""), repeat: str = Form("")):
        if not auth.check_password(current, auth.load()):
            return RedirectResponse(f"/settings?{urlencode({'error': 'The current password is wrong.'})}", 303)
        if len(new) < 10 or new != repeat:
            error = "The new password needs 10 characters or more, twice the same."
            return RedirectResponse(f"/settings?{urlencode({'error': error})}", 303)
        # The change signs out every other session; this one gets a new cookie.
        auth.set_password(new)
        response = RedirectResponse(f"/settings?{urlencode({'saved': 'Password changed. Other sessions are signed out.'})}", 303)
        sign_in(request, response)
        return response

    @app.get("/")
    def home():
        return RedirectResponse("/experiments", 303)

    @app.get("/partials/dock", response_class=HTMLResponse)
    def dock_partial(request: Request):
        return render(request, "partials/dock.html")

    @app.get("/partials/dock/parts/{name}", response_class=HTMLResponse)
    def dock_parts(request: Request, name: str):
        """The sub-jobs of a waiting result, when it is opened in the dock."""
        dataset = Dataset.find(name)
        return templates.TemplateResponse(request, "partials/dock-parts.html", {"parts": parts(dataset) if dataset else [], "name": name})

    @app.get("/partials/lab", response_class=HTMLResponse)
    def lab_partial(request: Request):
        return render(request, "partials/lab.html", max_routers=cluster.max_routers(), limits=cluster.limits())

    @app.get("/experiments", response_class=HTMLResponse)
    def experiments_page(request: Request, error: str = ""):
        listed = experiments()
        choices = {which: run_all(listed, which) for which in RUN_ALL}
        return render(request, "experiments.html", nav="experiments", experiments=listed, error=error,
                      run_all=[{"which": w, "label": RUN_ALL[w], "count": len(c), "s": sum(x["estimate_s"] or 0 for x in c)} for w, (c, _) in choices.items()],
                      all_left=choices["all"][1], left_counts=(sum(" / " not in n for n, _ in choices["all"][1]), sum(" / " in n for n, _ in choices["all"][1])), max_routers=cluster.max_routers(), limits=cluster.limits())

    @app.post("/experiments/run-all")
    def experiments_run_all(which: str = Form("all")):
        problems = []
        for x in run_all(experiments(), which if which in RUN_ALL else "all")[0]:
            try:
                result = Dataset.new_name(x["experiment"])
                Dataset.create(x["experiment"], result)
                jobs.enqueue(result)
            except ValueError as error:
                problems.append(f"{x['name']}: {error}")
        return RedirectResponse("/experiments" + (f"?{urlencode({'error': ' '.join(problems)})}" if problems else ""), 303)

    @app.post("/experiments/{name}/start")
    def experiment_start(name: str):
        try:
            result = start(name)
        except ValueError as error:
            return RedirectResponse(f"/experiments?{urlencode({'error': str(error)})}", 303)
        return RedirectResponse(f"/results/{result}", 303)

    @app.get("/experiments/new", response_class=HTMLResponse)
    def experiment_new(request: Request, like: str = ""):
        base, _ = read_experiment(like) if like else (None, "")
        values = builder_values(base.model_copy(update={"name": f"{base.name}-copy"}) if base else None)
        return render(request, "experiment.html", nav="experiments", values=values, new=True, **builder_context())

    @app.get("/experiments/{name}", response_class=HTMLResponse)
    def experiment_page(request: Request, name: str):
        e, error = read_experiment(name)
        if not e:
            raise HTTPException(404, error)
        values = {**builder_values(e, original=name), "error": error}
        made = [d for d in Dataset.all() if d.experiment.name == name]  # newest first
        return render(request, "experiment.html", nav="experiments", values=values, new=False, made=made,
                      **builder_context())

    @app.post("/experiments/estimate", response_class=HTMLResponse)
    async def experiment_estimate(request: Request):
        try:
            e = parse_builder(await request.form())
        except ValueError as error:
            return HTMLResponse(f'<span class="error">{escape(str(error))}</span>')
        how = (f"{len(e.topologies)} × {len(e.cases())} × {len(e.variants)} × {e.runs}: topologies, scenarios with the values of their sweeps, variants, runs"
               if e.sweeps else f"{len(e.topologies)} × {len(e.scenarios)} × {len(e.variants)} × {e.runs}: topologies, scenarios, variants, runs")
        notes = "".join(f"<li>{escape(n)}</li>" for n in mixed_notes(e))
        return HTMLResponse(f'<span data-tip="{how}">{e.runs_total()} runs · ≈ {duration(estimate.experiment_s(e))}</span>'
                            f'<ul id="variant-notes" hx-swap-oob="true" class="muted space-y-0.5 px-5 pb-3 text-xs">{notes}</ul>'
                            + host_notes(e))

    @app.post("/experiments/save")
    async def experiment_save(request: Request):
        form = await request.form()
        original, mode = str(form.get("original", "")), form.get("mode") or None
        try:
            e = parse_builder(form)
            check_rename("experiment", e.name, original, mode, config.path)
            e.check_files()
            cluster.check_modes(e)
            config.save(e)
        except ValueError as error:
            return JSONResponse({"problems": str(error).split("; ")}, status_code=422)
        if original and original != e.name and mode == "rename":
            config.path(original).unlink(missing_ok=True)
        if form.get("action") != "start":
            return JSONResponse({"saved": e.name})
        result = Dataset.new_name(e)
        Dataset.create(e, result)
        jobs.enqueue(result)
        return JSONResponse({"saved": e.name, "result": result})

    @app.post("/experiments/{name}/delete")
    def experiment_delete(name: str):
        try:
            config.path(name).unlink(missing_ok=True)
        except ValueError:
            raise HTTPException(404, f"No experiment {name}.")
        return RedirectResponse("/experiments", 303)

    @app.post("/queue")
    async def queue_order(request: Request):
        names = (await request.json()).get("order")
        if not isinstance(names, list):
            raise HTTPException(422)
        jobs.reorder([str(n) for n in names])
        return JSONResponse({"queue": jobs.queue()})

    @app.post("/queue/pause")
    def queue_pause(request: Request):
        jobs.pause()
        return RedirectResponse(back(request, "/results"), 303)

    @app.post("/queue/resume")
    def queue_resume(request: Request):
        jobs.resume_queue()
        return RedirectResponse(back(request, "/results"), 303)

    @app.post("/queue/stop")
    def queue_stop(request: Request):
        jobs.stop_all()
        return RedirectResponse(back(request, "/results"), 303)

    @app.get("/results", response_class=HTMLResponse)
    def results(request: Request, show: str = "all", error: str = ""):
        every, older = Dataset.all(), Dataset.older()
        sizes = {d.name: folder_size(d.path) for d in every + older}
        used = {public: sum(sizes[d.name] for d in every + older if d.public == public) for public in (True, False)}
        pick = lambda datasets: [d for d in datasets if show == "all" or d.public == (show == "public")]
        failed = {d.name: failed_checks(d) for d in every}
        return render(request, "results.html", nav="results", results=pick(every), older=pick(older), show=show, failed=failed,
                      sizes=sizes, storage=storage(used), error=error)

    @app.get("/wrapped", response_class=HTMLResponse)
    def wrapped_page(request: Request):
        """The claims to fame of all results."""
        return render(request, "wrapped.html", nav="wrapped", wrapped=wrapped.overview())

    @app.get("/results/compare", response_class=HTMLResponse)
    def results_compare(request: Request, a: str, b: str, topology: str = "", metric: str = ""):
        """Two results side by side: what differs in their setup, and every
        metric of the scenarios and variants they share, the first one at first."""
        first, second = find(a), find(b)
        metrics = {k: m for k, m in METRICS.items() if k != "checks"}
        return render(request, "compare.html", nav="results", metrics=metrics,
                      **comparison(first, second, topology, metric if metric in metrics else next(iter(metrics))))

    @app.get("/results/{name}", response_class=HTMLResponse)
    def result(request: Request, name: str, tab: str = "runs", metric: str = "",
               topology: str = "", scenario: str = "", error: str = ""):
        tab = OLD_TABS.get(tab, tab)
        tab = tab if tab in TABS else "runs"
        dataset = find(name)
        metrics = metrics_of(dataset)
        metric = metric if metric in metrics else next(iter(metrics))
        return render(request, "result.html", nav="results", tab=tab, metric=metric, tabs=TABS, metrics=metrics,
                      error=error, **result_context(dataset, tab, topology, scenario))

    @app.get("/results/{name}/partials/header", response_class=HTMLResponse)
    def result_header(request: Request, name: str):
        if not (dataset := Dataset.find(name)):
            return gone()
        return still(dataset, render(request, "partials/result-header.html", **result_context(dataset, "")))

    @app.get("/results/{name}/partials/{tab}", response_class=HTMLResponse)
    def result_partial(request: Request, name: str, tab: str, metric: str = "",
                       topology: str = "", scenario: str = ""):
        tab = OLD_TABS.get(tab, tab)
        if tab not in TABS:
            raise HTTPException(404)
        if not (dataset := Dataset.find(name)):
            return gone()
        metrics = metrics_of(dataset)
        metric = metric if metric in metrics else next(iter(metrics))
        return still(dataset, render(request, f"partials/tab-{tab}.html", tab=tab, metric=metric, metrics=metrics,
                                     **result_context(dataset, tab, topology, scenario)))

    @app.get("/results/{name}/replay")
    def result_replay(name: str, topology: str, scenario: str, variant: str, run: int = 1):
        dataset = find(name)
        key = RunKey(topology, variant, scenario, run)
        e = dataset.experiment
        if topology not in e.topologies or scenario not in e.cases() or variant not in [v.name for v in e.variants]:
            raise HTTPException(404)
        if not dataset.is_done(key) or dataset.run(key)["status"] == "error":
            return JSONResponse({"missing": True})
        t = dataset.topology(topology)
        # The modes of a mixed run mark its OBGP routers; other runs mark none.
        topology = {"routers": t["routers"], "roles": t["roles"], "modes": dataset.run(key).get("modes")}
        return JSONResponse({**analysis.replay(dataset, key), "topology": topology})

    # Exports, for papers and plots of one's own.

    @app.get("/results/{name}/summary.csv")
    def result_summary_csv(name: str):
        """Every metric of every topology, scenario and variant: median, range and runs."""
        dataset = find(name)
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["topology", "scenario", "variant", "runs", "checks_passed", "checks_runs",
                         *[f"{m}_{k}" for m in analysis.METRICS for k in ("median", "min", "max", "n", "ci_low", "ci_high", "ci_level", "router_min", "router_max")]])
        for g in analysis.summary(dataset):
            checks = g.get("checks") or {}
            row = [g["topology"], g["scenario"], g["variant"], g["runs"], checks.get("passed", ""), checks.get("runs", "")]
            for m in analysis.METRICS:
                v = g["metrics"].get(m) or {}
                row += [v.get(k, "") for k in ("median", "min", "max", "n", "ci_low", "ci_high", "ci_level", "router_min", "router_max")]
            writer.writerow(row)
        return download(out.getvalue(), f"{name}-summary.csv", "text/csv")

    @app.get("/results/{name}/series.csv")
    def result_series_csv(name: str, topology: str, scenario: str):
        """The time series of one scenario, one row per second, variant and metric."""
        dataset = find(name)
        e = dataset.experiment
        if topology not in e.topologies or scenario not in e.cases():
            raise HTTPException(404)
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["t_s", "variant", "metric", "median", "ci_low", "ci_high", "ci_level", "router_min", "router_max"])
        for v, s in series_of(dataset, topology, scenario).items():
            for m in analysis.SERIES:
                for i, t in enumerate(s["t"]):
                    values = [s["metrics"][m][k][i] for k in ("median", "ci_low", "ci_high", "ci_level", "min", "max")]
                    if values[0] is not None:
                        writer.writerow([t, v, m, *values])
        return download(out.getvalue(), f"{name}-{topology}-{scenario}-series.csv", "text/csv")

    @app.get("/results/{name}/curve")
    def result_curve(name: str, topology: str, scenario: str, metric: str):
        dataset = find(name)
        e = dataset.experiment
        if topology not in e.topologies or scenario not in e.cases() or metric not in METRICS or metric == "checks" \
                or not (e.sweep_of(scenario) or analysis.size_series(e.topologies)):
            raise HTTPException(404)
        return JSONResponse(analysis.curve(dataset, topology, scenario, metric))

    @app.get("/results/{name}/progress")
    def result_progress(name: str):
        """How many runs are done, for pages that tell when new ones are."""
        s = find(name).status
        return JSONResponse({"done": s.get("done", 0), "state": s.get("state")})

    @app.get("/results/{name}/series")
    def result_series(name: str, topology: str, scenario: str):
        """Time series of every variant for the charts, on a common time axis."""
        dataset = find(name)
        experiment = dataset.experiment
        if topology not in experiment.topologies or scenario not in experiment.cases():
            raise HTTPException(404)
        variants = [v.name for v in experiment.variants]
        per_variant = series_of(dataset, topology, scenario)
        t = sorted({x for s in per_variant.values() for x in s["t"]})
        metrics = {m: {} for m in analysis.SERIES}
        for v, s in per_variant.items():
            index = {x: i for i, x in enumerate(s["t"])}
            for m in analysis.SERIES:
                metrics[m][v] = {k: [s["metrics"][m][k][index[x]] if x in index else None for x in t] for k in ("median", "ci_low", "ci_high", "ci_level", "min", "max")}
        # Events per variant: until_stable lets the variants take different times.
        events = {v: s["events"] for v, s in per_variant.items()}
        return JSONResponse({"t": t, "variants": variants, "metrics": metrics, "events": events})

    @app.post("/results/{name}/stop")
    def stop(request: Request, name: str):
        jobs.stop(find(name).name)
        return RedirectResponse(back(request, f"/results/{name}"), 303)

    @app.post("/results/{name}/resume")
    def resume(name: str):
        jobs.enqueue(find(name).name)
        return RedirectResponse(f"/results/{name}", 303)

    # Picked results: their names in the query, as the confirmation posts nothing else.
    @app.post("/results/delete")
    def results_delete(request: Request):
        problems = []
        for name in request.query_params.getlist("names"):
            try:
                find(name).delete()
            except (ValueError, OSError, HTTPException) as error:
                problems.append(f"{name}: {getattr(error, 'detail', error)}")
        return RedirectResponse("/results" + (f"?{urlencode({'error': 'Not deleted: ' + ' '.join(problems)})}" if problems else ""), 303)

    @app.post("/results/run-again")
    def results_run_again(request: Request):
        problems, started = [], set()
        for name in request.query_params.getlist("names"):
            dataset = Dataset.find(name)
            experiment = dataset.experiment.name if dataset else None
            if experiment in started:  # once for every experiment
                continue
            try:
                if not experiment or not config.path_ok(experiment) or not config.path(experiment).exists():
                    raise ValueError("its experiment file is gone")
                start(experiment)
                started.add(experiment)
            except ValueError as error:
                problems.append(f"{name}: {error}")
        return RedirectResponse("/results" + (f"?{urlencode({'error': 'Not started: ' + ' '.join(problems)})}" if problems else ""), 303)

    @app.post("/results/{name}/delete")
    def result_delete(request: Request, name: str):
        dataset = find(name)
        try:
            dataset.delete()
        except (ValueError, OSError) as error:
            return RedirectResponse(with_error(back(request, f"/results/{name}"), str(error)), 303)
        return RedirectResponse("/results", 303)

    @app.post("/results/{name}/visibility")
    def visibility(request: Request, name: str, public: bool = Form()):
        dataset = find(name)
        page = back(request, f"/results/{name}?tab=details")
        try:
            dataset.publish(public)
        except (ValueError, FileExistsError) as error:
            text = str(error) if isinstance(error, ValueError) else f"{name} exists in results/{'public' if public else 'private'} already."
            return RedirectResponse(with_error(page, text), 303)
        return RedirectResponse(page, 303)

    @app.get("/scenarios", response_class=HTMLResponse)
    def scenarios_page(request: Request, error: str = ""):
        used = users("scenarios")
        items = []
        for n in scenario.names():
            try:
                sc = scenario.load(n)
            except (ValueError, OSError) as e:
                items.append({"name": n, "error": str(e).splitlines()[0]})
                continue
            items.append({"name": n, "description": sc.description, "duration_s": sc.duration(), "used": used[n],
                          "kinds": step_kinds(sc.steps)})
        return render(request, "scenarios.html", nav="scenarios", scenarios=items, error=error)

    @app.get("/scenarios/new", response_class=HTMLResponse)
    def scenario_new(request: Request, like: str = ""):
        data = {"name": "", "description": "", "steps": [{"announce": {"rate": 1, "for": 30}}, {"wait": 10},
                                                           {"withdraw": {}}, {"until_stable": {"timeout": 60}}]}
        if like:
            try:
                data = {**scenario.load(like).dump(), "name": f"{like}-copy"}
            except (ValueError, OSError):
                pass
        return render(request, "scenario.html", nav="scenarios", data=data, original="", used=[], **scenario_context())

    @app.get("/scenarios/{name}", response_class=HTMLResponse)
    def scenario_page(request: Request, name: str, error: str = ""):
        try:
            data = scenario.load(name).dump()
        except (ValueError, FileNotFoundError):
            raise HTTPException(404, f"No scenario {name}.")
        used = users("scenarios")[name]
        # Preview on a topology of an experiment that plays the scenario.
        preview = next((t for x in experiments() if x.get("experiment") and name in x["experiment"].scenarios
                        for t in x["experiment"].topologies), "")
        return render(request, "scenario.html", nav="scenarios", data=data, original=name, used=used,
                      preview=preview, error=error, **scenario_context())

    @app.post("/scenarios/preview")
    async def scenario_preview(request: Request):
        body = await request.json()
        try:
            sc = scenario.parse({"name": "preview", "description": "", "params": body.get("params") or {}, "steps": body.get("steps") or []})
        except ValidationError as error:
            return JSONResponse({"problems": readable(error)})
        except ValueError as error:
            return JSONResponse({"problems": [str(error)]})
        out = {"problems": [], "timeline": scenario.timeline(sc.steps), "duration_s": sc.duration(), "targets": {}}
        if t := readable_topologies()[0].get(body.get("topology")):
            out["targets"] = scenario.preview_targets(sc.steps, scenario.Network(t["routers"], t["roles"]),
                                                      int(body.get("seed") or 42), int(body.get("run") or 1))
        return JSONResponse(out)

    @app.post("/scenarios/save")
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
        if original and original != name and body.get("mode") == "rename":
            scenario.path(original).unlink(missing_ok=True)
        return JSONResponse({"saved": name})

    @app.post("/scenarios/{name}/delete")
    def scenario_delete(name: str):
        try:
            file = scenario.path(name)
        except ValueError:
            raise HTTPException(404, f"No scenario {name}.")
        if used := users("scenarios")[name]:
            return RedirectResponse(f"/scenarios/{name}?{urlencode({'error': f'{name} is used by {', '.join(used)}.'})}", 303)
        file.unlink(missing_ok=True)
        return RedirectResponse("/scenarios", 303)

    @app.get("/topologies", response_class=HTMLResponse)
    def topologies(request: Request, error: str = ""):
        used = users("topologies")
        loaded, broken = readable_topologies()
        items = [{"name": n, **topology_summary(t), "used": used[n], "source": t["source"]} for n, t in loaded.items()]
        return render(request, "topologies.html", nav="topologies", topologies=items, broken=broken, models=generate.MODELS,
                      thumbs=thumb_stamps(loaded), error=error)

    @app.get("/topologies/sndlib", response_class=HTMLResponse)
    def sndlib_list(request: Request):
        try:
            networks = sndlib.summary()
        except OSError as e:
            return HTMLResponse(f'<p class="error py-6">SNDlib is not reachable: {escape(str(e))}</p>')
        return render(request, "partials/sndlib.html", networks=networks)

    @app.post("/topologies/generate")
    async def topologies_generate(request: Request):
        form = await request.form()
        try:
            sizes = [int(x) for x in str(form.get("sizes", "")).replace(" ", "").split(",") if x]
            names = generate.generate(str(form.get("model", "")), sizes, int(form.get("seed") or 1), str(form.get("name", "")),
                                      **{k: v for k, v in form.items() if k not in ("model", "sizes", "seed", "name")})
        except (ValueError, FileExistsError) as e:
            return RedirectResponse(f"/topologies?{urlencode({'error': str(e)})}", 303)
        return RedirectResponse(f"/topologies/{names[0]}" if len(names) == 1 else "/topologies", 303)

    @app.post("/topologies/sndlib")
    async def sndlib_import(network: str = Form(""), name: str = Form(""), file: UploadFile | None = None):
        # Native files of SNDlib are small; a limit keeps uploads from filling the memory.
        text = (await file.read(5_000_000)).decode(errors="replace") if file and file.filename else None
        network = Path(file.filename).stem if text else network
        if not network:
            return RedirectResponse(f"/topologies?{urlencode({'error': 'Pick a network or a file to import.'})}", 303)
        try:
            created = sndlib.import_network(network, name.strip() or sndlib.slug(network), text)
        except (ValueError, FileExistsError, OSError) as e:
            return RedirectResponse(f"/topologies?{urlencode({'error': str(e)})}", 303)
        return RedirectResponse(f"/topologies/{created}", 303)

    @app.get("/topologies/caida", response_class=HTMLResponse)
    def caida_form(request: Request):
        try:
            months, online = caida.months(), True
        except OSError as e:
            logging.getLogger("uvicorn.error").warning("CAIDA months: %s", e)
            months, online = caida.cached(), False  # what was downloaded before
        if not months:
            return HTMLResponse('<p class="error py-6">CAIDA is not reachable, and nothing was downloaded before.</p>')
        month = lambda m: f"{m[:4]}-{m[4:6]}"
        return render(request, "partials/caida.html", newest=month(months[0]), oldest=month(months[-1]), online=online,
                      max=caida.max_routers(), month_names=caida.MONTHS)

    @app.get("/topologies/caida/search", response_class=HTMLResponse)
    def caida_search(request: Request, q: str = "", month: str = ""):
        if not q.strip() or q.startswith("AS") and " " in q:  # empty, or the chosen AS shown again
            return HTMLResponse("")
        try:
            hits = caida.relations(caida.nearest(month)[0]).search(q)
        except (ValueError, OSError) as e:
            return render(request, "partials/caida-hits.html", error=str(e), hits=None)
        return render(request, "partials/caida-hits.html", hits=hits, max=caida.max_routers())

    @app.get("/topologies/caida/countries")
    def caida_countries(month: str = ""):
        """The countries of a month, each with how many of its ASes connect; the browser names them."""
        try:
            countries = caida.relations(caida.nearest(month)[0]).countries()
        except (ValueError, OSError):
            return JSONResponse([])
        return JSONResponse([[cc, n] for cc, n in countries if n >= 3])

    @app.get("/topologies/caida/members", response_class=HTMLResponse)
    def caida_members(request: Request, part: str = "core", asn: str = "", country: str = "", size: str = "32", month: str = "",
                      member: str = "", offset: int = 0):
        """A page of the ASes of a part, those that match the search, with the trigger for the next."""
        try:
            found, total = caida.members(*caida.read_form(part, asn, country, size), month, member, offset)
        except (ValueError, OSError) as e:
            return HTMLResponse(f'<li class="px-3 py-1 text-xs text-rose-700 dark:text-rose-300">{escape(str(e))}</li>')
        return render(request, "partials/caida-members.html", found=found, total=total, offset=offset,
                      next=urlencode({"part": part, "asn": asn, "country": country, "size": size, "month": month,
                                      "member": member, "offset": offset + len(found)}))

    @app.get("/topologies/caida/preview", response_class=HTMLResponse)
    def caida_preview(request: Request, part: str = "core", asn: str = "", country: str = "", size: str = "32", month: str = ""):
        try:
            p = caida.preview(*caida.read_form(part, asn, country, size), month)
        except ValueError as e:
            return render(request, "partials/caida-preview.html", error=str(e))
        except OSError as e:
            return render(request, "partials/caida-preview.html", error=f"CAIDA is not reachable: {e}")
        return render(request, "partials/caida-preview.html", p=p)

    @app.post("/topologies/caida")
    def caida_import(part: str = Form("core"), asn: str = Form(""), country: str = Form(""), size: str = Form("32"), month: str = Form(""),
                     name: str = Form("")):
        try:
            created = caida.import_part(*caida.read_form(part, asn, country, size), name.strip(), month)
        except (ValueError, FileExistsError, OSError) as e:
            return RedirectResponse(f"/topologies?{urlencode({'error': str(e)})}", 303)
        return RedirectResponse(f"/topologies/{created}", 303)

    @app.get("/topologies/new", response_class=HTMLResponse)
    def topology_new(request: Request, like: str = ""):
        t, copy = {"routers": {}, "roles": {}}, ""
        if like:
            try:
                t, copy = topology.load(like), f"{like}-copy"
            except (ValueError, OSError, KeyError, yaml.YAMLError):
                pass
        return render(request, "topology.html", nav="topologies", name="", copy=copy, topology=t, used=[])

    @app.get("/topologies/{name}/data")
    def topology_data(name: str):
        """Routers and roles of a topology, for the preview of the scenario editor, kept by the browser per version."""
        try:
            t = topology.load(name, shared=True)
        except (ValueError, OSError):
            raise HTTPException(404) from None
        return JSONResponse({"routers": t["routers"], "roles": t["roles"]}, headers={"Cache-Control": "private, max-age=86400"})

    @app.get("/topologies/{name}/thumb")
    def topology_thumb(name: str):
        """What the small drawing of a topology needs, fetched once per version by the browser."""
        try:
            t = topology.load(name, shared=True)
        except (ValueError, OSError):
            raise HTTPException(404) from None
        return JSONResponse(thumbnails({name: t})[name], headers={"Cache-Control": "private, max-age=86400"})

    @app.get("/topologies/{name}", response_class=HTMLResponse)
    def topology_page(request: Request, name: str, error: str = ""):
        try:
            t = topology.load(name)
        except (ValueError, FileNotFoundError):
            raise HTTPException(404, f"No topology {name}.")
        source = t.get("source") or ""
        names = caida.names(source, {r.get("asn") for r in t["routers"].values()}) if source.startswith("caida/") else {}
        return render(request, "topology.html", nav="topologies", name=name, topology=t, error=error,
                      used=users("topologies")[name], as_names=names)

    @app.post("/topologies/{name}/delete")
    def topology_delete(name: str):
        try:
            file = topology.path(name)
        except ValueError:
            raise HTTPException(404, f"No topology {name}.")
        if used := users("topologies")[name]:
            error = f"{name} is used by {', '.join(used)}."
            return RedirectResponse(f"/topologies/{name}?{urlencode({'error': error})}", 303)
        file.unlink(missing_ok=True)
        return RedirectResponse("/topologies", 303)

    @app.post("/topologies/save")
    async def topology_save(request: Request):
        body = await request.json()
        name, original = str(body.get("name", "")).strip(), str(body.get("original", ""))
        try:
            check_rename("topology", name, original, body.get("mode"), topology.path, "topologies")
            roles = {role: list(members) for role, members in (body.get("roles") or {}).items() if members}
            topology.save(name, body["routers"], roles, body.get("source") or None)
        except (ValueError, KeyError, TypeError) as e:
            return JSONResponse({"problems": str(e).split("; ")}, status_code=422)
        if original and original != name and body.get("mode") == "rename":
            topology.path(original).unlink(missing_ok=True)
        return JSONResponse({"saved": name})

    return app


def start(name: str) -> str:
    """Queues a new result of an experiment, as its file is now, and returns its name; ValueError if it cannot."""
    try:
        e = Experiment.load(config.path(name))
    except FileNotFoundError as error:
        raise ValueError(str(error)) from None
    if problem := cluster.too_large(e):
        raise ValueError(f"Not started: {problem}.")
    result = Dataset.new_name(e)
    Dataset.create(e, result)
    jobs.enqueue(result)
    return result


def with_error(page: str, error: str) -> str:
    """A page to go back to, with a problem to show; one shown before is replaced."""
    url = urlparse(page)
    query = [(k, v) for k, v in parse_qsl(url.query) if k != "error"] + [("error", error)]
    return f"{url.path}?{urlencode(query)}"


def sign_in(request: Request, response: Response) -> None:
    response.set_cookie(auth.COOKIE, auth.issue(auth.load()), max_age=auth.MAX_AGE, httponly=True,
                        secure=request.url.scheme == "https", samesite="strict")


def gone() -> Response:
    """The answer to the polling of a result deleted meanwhile: back to the list, no more polling."""
    return Response(status_code=286, headers={"HX-Redirect": "/results"})


def still(dataset: Dataset, response: HTMLResponse) -> HTMLResponse:
    """Ends the polling of a page on a result that no longer runs (htmx stops at 286)."""
    if dataset.status.get("state") not in ("running", "queued") and dataset.name not in jobs.queue():
        response.status_code = 286
    return response


def find(name: str) -> Dataset:
    dataset = Dataset.find(name)
    if not dataset:
        raise HTTPException(404, f"No result {name}.")
    return dataset


def check_rename(kind: str, name: str, original: str, mode, path, used_in: str = "") -> None:
    """Checks saving under a new name: mode rename moves the original, copy keeps it."""
    if not config.path_ok(name):
        raise ValueError("Names use lowercase letters, digits and dashes.")
    if name == original:
        return
    if path(name).exists():
        raise ValueError(f"A {kind} named {name} exists already.")
    if original and mode == "rename" and used_in and (used := users(used_in)[original]):
        raise ValueError(f"{original} is used by {', '.join(used)}, so save a copy instead.")


def read_experiment(name: str) -> tuple[Experiment | None, str]:
    """An experiment file, also when its topologies or scenarios are missing: (experiment, problem)."""
    try:
        return Experiment.load(config.path(name)), ""  # checked, and kept so
    except (ValueError, OSError):
        pass
    try:
        data = config.load_yaml(config.path(name).read_text())
        e = Experiment.model_validate(data)
    except (ValueError, OSError, ValidationError):
        return None, f"No experiment {name}."
    try:
        e.check_files()
    except ValueError as error:
        return e, str(error)
    return e, ""


UPDATES: dict = {}  # the last check of GitHub for new commits of the branch
UPDATE_EVERY_S = 15 * 60


def watch_updates() -> None:
    """Asks GitHub every quarter hour whether the branch of the lab has new commits."""
    while True:
        try:
            UPDATES.update(update.status(fetch=True))
        except Exception:  # never stop watching for one failed check
            logging.getLogger("uvicorn.error").exception("checking for updates")
        time.sleep(UPDATE_EVERY_S)


def warm_up() -> None:
    """Analyses every result once in the background, so that no page waits
    for it, e.g. after a new version of the metrics. Runs of a result that
    runs are left to its runner."""
    log = logging.getLogger("uvicorn.error")
    began = time.monotonic()
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


def readable_topologies() -> tuple[dict[str, dict], dict[str, str]]:
    """The topologies that load, and the problems of those that do not."""
    loaded, broken = {}, {}
    for name in topology.names():
        try:
            loaded[name] = topology.load(name, shared=True)
        except (ValueError, OSError, KeyError, yaml.YAMLError) as error:
            broken[name] = str(error).splitlines()[0]
    return loaded, broken


def topology_summary(t: dict) -> dict:
    routers = t["routers"]
    return {
        "routers": len(routers),
        "links": sum(len(r.get("neighbors", [])) for r in routers.values()) // 2,
        "preferences": sum(1 for r in routers.values() for n in r.get("neighbors", []) if n.get("localPref", 100) != 100),
    }


def thumb_stamps(loaded: dict[str, dict]) -> dict[str, str]:
    """A version of each topology, by its file: the browser keeps a drawing until it changes."""
    out = {}
    for name in loaded:
        try:
            stat = topology.path(name).stat()
            out[name] = f"{stat.st_mtime_ns:x}-{stat.st_size:x}"
        except OSError:
            pass
    return out


def thumbnails(loaded: dict[str, dict]) -> dict[str, dict]:
    """What the small drawings of the topologies need, and no more: each
    session once, by name, and positions to the pixel. Parts of the Internet
    hold thousands of sessions."""
    def router(n: str, r: dict) -> dict:
        out = {"neighbors": [{"name": m["name"]} for m in r.get("neighbors", []) if n < m["name"]]}
        if p := r.get("position"):
            out["position"] = {"x": round(p["x"]), "y": round(p["y"])}
        if loc := r.get("location"):
            out["location"] = loc
        return out
    return {name: {"roles": {"origins": t["roles"].get("origins", [])}, "routers": {n: router(n, r) for n, r in t["routers"].items()}}
            for name, t in loaded.items()}


def users(kind: str) -> dict[str, list[str]]:
    """The experiments that use each topology or scenario (kind: "topologies" or "scenarios")."""
    used = defaultdict(list)
    for x in experiments():
        if e := x.get("experiment"):
            for n in getattr(e, kind):
                used[n].append(e.name)
    return used


def step_kinds(steps) -> list[str]:
    """The building blocks a scenario uses, in order, without the flow."""
    def walk(items):
        for step in items:
            yield step.kind
            if step.kind == "parallel":
                yield from walk(step.args)
            elif step.kind == "repeat":
                yield from walk(step.args.steps)
    return list(dict.fromkeys(k for k in walk(steps) if k not in ("wait", "until_stable", "parallel", "repeat")))


def readable(error: ValidationError) -> list[str]:
    """Validation errors as short lines, with the step positions counted from 1."""
    lines = []
    for e in error.errors()[:5]:
        loc = [x + 1 if isinstance(x, int) else x for x in e["loc"] if x not in ("args",)]
        where = " ".join(f"step {x}" if isinstance(x, int) else str(x) for x in loc if x != "steps")
        message = "needs steps" if e["type"] == "too_short" else e["msg"].removeprefix("Value error, ")
        lines.append(f"{where}: {message}" if where else message)
    return lines


def scenario_context() -> dict:
    """The topologies the preview of the scenario editor offers, by name and
    version: it loads the one it shows, as parts of the Internet are large."""
    loaded = readable_topologies()[0]
    return {"topologies": sorted(loaded), "versions": thumb_stamps(loaded)}


def experiments() -> list[dict]:
    """The experiment files; one that does not load is listed with its problem."""
    out, past = [], estimate.history()
    for path in sorted(EXPERIMENTS.glob("*.yaml")):
        try:
            e = Experiment.load(path)
        except (ValueError, OSError) as error:
            out.append({"name": path.stem, "error": str(error).splitlines()[0]})
            continue
        out.append({"name": path.stem, "experiment": e, "runs": e.runs_total(), "estimate_s": estimate.experiment_s(e, past),
                    "too_large": cluster.too_large(e), "skips": cluster.oversized(e), "limit": cluster.limit(e)})
    return out


# Run all queues the checks of the lab first, smoke and calibration before the others.
ALL_FIRST = ["lab-smoke", "lab-calibration"]
RUN_ALL = {"all": "Everything", "experiments": "Experiments only", "lab": "Lab checks only"}


def run_all(listed: list[dict], which: str = "all") -> tuple[list[dict], list[tuple[str, str]]]:
    """The experiments Run all queues, in order, and what it leaves out, with why:
    whole experiments, and topologies larger than this host."""
    chosen, left = [], []
    for x in listed:
        lab = x["name"].startswith(wrapped.LAB)
        if (which == "lab" and not lab) or (which == "experiments" and lab):
            continue
        if "error" in x:
            left.append((x["name"], "does not load"))
        else:
            skips = cluster.oversized(x["experiment"])
            whole = len(skips) == len(x["experiment"].topologies)
            if not whole:
                chosen.append(x)
            for t, why in skips.items():
                left.append((x["name"] if whole and len(skips) == 1 else f"{x['name']} / {t}",
                             f"needs {', '.join(why)} (host: up to {cluster.limit(x['experiment']).removeprefix('at most ')})"))
    first = {n: i for i, n in enumerate(ALL_FIRST)}
    return sorted(chosen, key=lambda x: (not x["name"].startswith(wrapped.LAB), first.get(x["name"], len(first)), x["name"])), left


def git_refs() -> list[str]:
    try:
        out = cluster.git("for-each-ref", "--format=%(refname:short)", "refs/heads", "refs/tags")
    except Exception:
        return []
    return ["HEAD", *out.split()]


def builder_context() -> dict:
    loaded = readable_topologies()[0]
    scenarios = []
    for n in scenario.names():
        try:
            sc = scenario.load(n)
        except (ValueError, OSError):
            continue
        scenarios.append({"name": n, "duration_s": sc.duration(), "description": sc.description, "kinds": step_kinds(sc.steps), "params": sc.params})
    return {
        "topologies": [{"name": n, **topology_summary(t)} for n, t in loaded.items()],
        "thumbs": thumb_stamps(loaded),
        "scenarios": scenarios,
        "refs": git_refs(),
        "modes": list(MODES.values()),
        "intervals": [1.0, 0.5, 0.2, 0.1, 0.05],
        # The numbers a sweep can set, by kind of step.
        # The parameters each scenario offers for sweeps, with the values it gives them.
        "params": {x["name"]: x["params"] for x in scenarios if x["params"]},
    }


def builder_values(e: Experiment | None, original: str = "") -> dict:
    """The fields of the experiment builder; original is the file it edits."""
    e = e or Experiment(name="", variants=[Variant(name="bgp", mode="bgp"), Variant(name="obgp", mode="obgp")],
                        topologies=["bad-gadget"], scenarios=["full-drain-60"])
    return {
        "original": original,
        "name": e.name, "description": e.description, "runs": e.runs, "seed": e.seed,
        "variants": [v.model_dump() for v in e.variants],
        "topologies": e.topologies, "scenarios": e.scenarios,
        "cpus": e.cluster.cpus, "memory_mb": e.cluster.memory_mb,
        "hold_time": e.bgp.hold_time, "keepalive": e.bgp.keepalive, "connect_retry": e.bgp.connect_retry,
        "graceful_restart": e.bgp.graceful_restart,
        "interval": e.sampling.interval, "stable_s": e.sampling.stable_s, "error": "",
        "sweeps": [{"scenario": w.scenario, "param": w.param, "values": ", ".join(f"{v:g}" for v in w.values)} for w in e.sweeps],
    }


def _variants(form) -> list[dict]:
    rows = sorted({int(k[1:].split("_")[0]) for k in form.keys() if re.fullmatch(r"v\d+_name", k)})
    return [{"name": str(form.get(f"v{i}_name", "")).strip(), "ref": str(form.get(f"v{i}_ref", "")).strip() or "HEAD",
             "mode": (mode := str(form.get(f"v{i}_mode", ""))),
             "share": float(form.get(f"v{i}_share") or 0) / 100 if MODES.get(mode) and MODES[mode].pick == "random" else None}
            for i in rows if str(form.get(f"v{i}_name", "")).strip()]


def _sweeps(form) -> list[dict]:
    """The sweeps of the builder form, a row each, those without a scenario left out."""
    rows = sorted({int(k[1:].split("_")[0]) for k in form.keys() if re.fullmatch(r"s\d+_scenario", k)})
    out = []
    for i in rows:
        if not (name := str(form.get(f"s{i}_scenario", ""))):
            continue
        raw = str(form.get(f"s{i}_values", "")).replace(" ", "")
        try:  # by commas, or by semicolons for decimal commas: 0,5; 1
            values = [float(v.replace(",", ".")) for v in (raw.split(";") if ";" in raw else raw.split(",")) if v]
        except ValueError:
            raise ValueError(f"Sweep of {name}: values are numbers, separated by commas.") from None
        out.append({"scenario": name, "param": str(form.get(f"s{i}_param", "")), "values": values})
    return out


def parse_builder(form) -> Experiment:
    """The experiment of the builder form; ValueError with a readable message if it is invalid."""
    name = str(form.get("name", "")).strip()
    number = lambda key, kind=int: kind(str(form.get(key) or 0).replace(",", "."))
    try:
        e = Experiment(
            name=name, description=str(form.get("description", "")).strip(), runs=number("runs"), seed=number("seed"),
            variants=_variants(form), topologies=form.getlist("topologies"), scenarios=form.getlist("scenarios"),
            cluster={"cpus": number("cpus"), "memory_mb": number("memory_mb")},
            bgp={"hold_time": number("hold_time"), "keepalive": number("keepalive"), "connect_retry": number("connect_retry"),
                 "graceful_restart": form.get("graceful_restart") == "on"},
            sampling={"interval": number("interval", float), "stable_s": number("stable_s", float)},
            sweeps=_sweeps(form),
        )
        e.check_files()
    except ValidationError as error:
        first = error.errors()[0]
        field = ".".join(str(x) for x in first["loc"]) or "experiment"
        if first["loc"][:1] == ("sweeps",) and len(first["loc"]) > 1:
            name = _sweeps(form)[first["loc"][1]]["scenario"]
            if first["type"] == "too_short":
                raise ValueError(f"Give the sweep of {name} at least two values.") from None
            raise ValueError(f"Sweep of {name}: {first['msg'].removeprefix('Value error, ')}.") from None
        if first["type"] == "too_short":
            raise ValueError(f"Pick at least one of the {field}.") from None
        raise ValueError(f"{field}: {first['msg'].removeprefix('Value error, ')}") from None
    return e


def overview() -> dict:
    """The running result and the waiting ones, each with how long it takes and when it ends."""
    active = jobs.active()
    names = [n for n in jobs.queue() if not active or n != active.name]
    paused = jobs.paused()
    if not active and not names:
        return {"active": None, "queue": [], "paused": paused}
    past = estimate.history()
    clock = datetime.now()
    left = estimate.remaining_s(active, past) if active else None
    ends = clock + timedelta(seconds=left or 0)
    queue = []
    for name in names:
        dataset = Dataset.find(name)
        takes = waiting_s(dataset, past) if dataset else None
        if takes is not None:
            ends += timedelta(seconds=estimate.STARTUP_S + takes)
        # Its sub-jobs come when it is opened, from /partials/dock/parts.
        queue.append({"name": name, "takes_s": takes, "ends": ends if takes is not None else None})
    # The whole of it: the running result and every waiting one that can be estimated.
    return {"active": active, "active_parts": parts(active, running=True) if active else [], "left_s": left, "active_ends": clock + timedelta(seconds=left) if left is not None else None,
            "queue": queue, "paused": paused, "all_ends": ends if queue and ends > clock and not paused else None, "all_s": (ends - clock).total_seconds()}


WAITING_S: dict = {}  # result -> (what it was estimated from, seconds)


def waiting_s(dataset: Dataset, past: dict) -> float | None:
    """How long a waiting result takes, estimated again only when it or the history changes."""
    try:  # the runner writes its status after every run
        stamp = ((dataset.path / "status.json").stat().st_mtime_ns, len(past))
    except OSError:
        stamp = (0, len(past))
    if (kept := WAITING_S.get(dataset.path)) is None or kept[0] != stamp:
        kept = WAITING_S[dataset.path] = (stamp, estimate.remaining_s(dataset, past))
    return kept[1]


def parts(dataset: Dataset, running: bool = False) -> list[dict]:
    """The sub-jobs of a result: its runs by topology and scenario, each
    running, pending or as it ended (completed, timeout, failed, error).
    The running one first, then those to come, the finished ones last, so
    that a long list shows what matters at its top."""
    try:
        keys = dataset.keys()
    except (ValueError, OSError):
        return []
    current = dataset.status.get("current") if running else None
    done = dataset.statuses()
    out: dict[tuple, dict] = {}
    for key in keys:
        part = out.setdefault((key.topology, key.scenario), {"topology": key.topology, "scenario": key.scenario, "runs": []})
        state = "running" if str(key) == current else done.get(key, "pending")
        part["runs"].append({"variant": key.variant, "index": key.index, "state": state})
    for part in out.values():
        part["done"] = sum(r["state"] not in ("running", "pending") for r in part["runs"])
    order = lambda p: 0 if any(r["state"] == "running" for r in p["runs"]) else 2 if p["done"] == len(p["runs"]) else 1
    return sorted(out.values(), key=order)


def result_context(dataset: Dataset, tab: str, topology: str = "", scenario: str = "") -> dict:
    experiment = dataset.experiment
    status = dataset.status
    topologies = experiment.topologies
    scenarios = experiment.cases()
    topology = topology if topology in topologies else topologies[0]
    context = {
        "result": dataset,
        "experiment": experiment,
        "status": status,
        "queued": dataset.name in jobs.queue(),
        # The experiment file it was made from, if it is still there.
        "source": experiment.name if config.path_ok(experiment.name) and config.path(experiment.name).exists() else None,
        "topology": topology,
        "scenario": scenario if scenario in scenarios else "",
        "integrity": integrity(dataset),
        "failed": failed_by_topology(dataset),
    }
    if tab == "table":
        context["running"] = status.get("current") if status.get("state") == "running" else None
        groups = {(g["scenario"], g["variant"]): g for g in analysis.summary(dataset) if g["topology"] == topology}
        context["table"] = [
            {"scenario": s, "cells": [groups.get((s, v.name)) for v in experiment.variants]}
            for s in experiment.cases()
        ]
        context["paired"] = lambda s, variant, metric, baseline: analysis.paired(dataset, topology, s, metric, variant, baseline)
        context["failed_checks"] = lambda: analysis.failed_checks(dataset, topology)  # read only for the checks
    if tab == "charts":
        # The chosen scenario, by default the first that has runs.
        done = {k.scenario for k in dataset.keys() if k.topology == topology and dataset.is_done(k)}
        context["scenario"] = scenario if scenario in scenarios else next((s for s in scenarios if s in done), scenarios[0])
    if tab == "runs":
        log = dataset.path / "lab.log"
        lines = log.read_text().splitlines()[-300:] if log.exists() else []
        # "2026-09-30 11:04:08,590 INFO message" as (time, level, message)
        context["log"] = [(m[2], m[3], m[4]) if (m := re.match(r"(\S+) (\S+?)(?:,\d+)? (\w+) (.*)", line)) else ("", "", line)
                          for line in lines]
        # topology -> variant -> scenario -> the state of every run
        def state(key: RunKey) -> str:
            if dataset.is_done(key):
                return dataset.run(key)["status"]
            return "running" if str(key) == status.get("current") and status.get("state") == "running" else "pending"
        context["grid"] = {t: {v.name: {s: [state(RunKey(t, v.name, s, i)) for i in range(1, experiment.runs + 1)]
                                        for s in experiment.cases()} for v in experiment.variants} for t in experiment.topologies}
    if tab == "replay":
        context["scenario"] = scenario if scenario in scenarios else scenarios[0]
        context["runs"] = list(range(1, experiment.runs + 1))
    return context


# Settings of an experiment as people read them.
SETTING_NAMES = {"hold_time": "hold time, s", "keepalive": "keepalive, s", "connect_retry": "connect retry, s",
                 "graceful_restart": "graceful restart", "interval": "interval, s", "stable_s": "stable after, s",
                 "cpus": "CPUs", "memory_mb": "memory, MB", "router_limit_mb": "memory per router, MB"}


def comparison(first: Dataset, second: Dataset, topology: str, metric: str) -> dict:
    """What two results share, how their setup differs, and one metric of both."""
    ea, eb = first.experiment, second.experiment
    topologies = [t for t in ea.topologies if t in eb.topologies]
    scenarios = [s for s in ea.cases() if s in eb.cases()]  # with the values of their sweeps
    shared = [v.name for v in ea.variants if v.name in {w.name for w in eb.variants}]
    topology = topology if topology in topologies else (topologies or [""])[0]
    differences = []

    def differ(label: str, x, y) -> None:
        if isinstance(x, dict) and isinstance(y, dict):  # setting by setting
            for k in dict.fromkeys([*x, *y]):
                differ(f"{label} {SETTING_NAMES.get(k, k.replace('_', ' '))}", x.get(k, "–"), y.get(k, "–"))
        elif x != y:
            differences.append((label, str(x), str(y)))

    va, vb = {v.name: v for v in ea.variants}, {v.name: v for v in eb.variants}
    for v in shared:
        differ(f"{v}: code", first.commits.get(v, "")[:8], second.commits.get(v, "")[:8])
        differ(f"{v}: mode", va[v].summary(), vb[v].summary())
    only = lambda xs, ys: ", ".join(x for x in xs if x not in ys) or "–"
    differ("Variants only in one", only(va, vb), only(vb, va))
    differ("Topologies only in one", only(ea.topologies, eb.topologies), only(eb.topologies, ea.topologies))
    differ("Scenarios only in one", only(ea.cases(), eb.cases()), only(eb.cases(), ea.cases()))
    differ("BGP", ea.bgp.model_dump(), eb.bgp.model_dump())
    differ("Sampling", ea.sampling.model_dump(), eb.sampling.model_dump())
    differ("Runs per combination", ea.runs, eb.runs)
    differ("Seed", ea.seed, eb.seed)
    # The cluster as set, overlaid with what a result recorded of it: older ones record nothing, newer ones CPUs and memory.
    differ("Cluster", {**ea.cluster.model_dump(), **(first.meta.get("cluster") or {})}, {**eb.cluster.model_dump(), **(second.meta.get("cluster") or {})})
    changed = [t for t in topologies if first.topology(t) != second.topology(t)]
    changed += [s for s in scenarios if first.scenario(s) != second.scenario(s)]
    differ("Changed since", "–", ", ".join(changed) or "–")
    groups = [{(g["scenario"], g["variant"]): g for g in analysis.summary(d) if g["topology"] == topology} for d in (first, second)]
    rows = [{"scenario": s, "cells": [[(groups[i].get((s, v)) or {}).get("metrics", {}).get(metric) for i in (0, 1)] for v in shared]}
            for s in scenarios]
    return {"first": first, "second": second, "topologies": topologies, "topology": topology, "variants": shared,
            "rows": rows, "differences": differences, "metric": metric, "digits": ea.sampling.digits()}


def host_notes(e: Experiment) -> str:
    """For the builder, as on a result: the topologies this host leaves out, and why."""
    skips = cluster.oversized(e)
    if not skips:
        return '<ul id="host-notes" hx-swap-oob="true" class="hidden"></ul>'
    limit = cluster.limit(e).removeprefix("at most ").replace(", ", " and ")
    lines = [f"{t} needs {' and '.join(why)}." for t, why in skips.items()]
    whole = len(skips) == len(e.topologies)
    lines.append(f"This host runs at most {limit}, " + ("so the experiment cannot start here." if whole else "so the experiment runs without them."))
    items = "".join(f"<li>{escape(line)}</li>" for line in lines)
    return ('<ul id="host-notes" hx-swap-oob="true" class="mb-6 space-y-1 rounded-lg bg-amber-50 px-4 py-2.5 text-sm text-amber-900 '
            f'dark:bg-amber-950/40 dark:text-amber-200" aria-label="Limits of this host">{items}</ul>')


def mixed_notes(e: Experiment) -> list[str]:
    """For the builder: how many routers of each topology run OBGP in each mixed variant."""
    notes = []
    for v in e.variants:
        mode = MODES[v.mode]
        if mode.inner is None:
            continue
        parts = []
        for t in e.topologies:
            routers = topology.load(t, shared=True)["routers"]
            chosen = sum(m != "bgp" for m in v.modes_of(routers, seed=e.seed * 1000 + 1).values())
            parts.append(f"{chosen} of {len(routers)} on {t}")
        drawn = ", drawn anew for every run" if mode.pick == "random" else ", as the topology marks them"
        notes.append(f"{v.name}: {MODES[mode.inner].label} on {'; '.join(parts)}{drawn}")
    return notes


BUSY_HOST = 0.9  # a larger share of the CPUs in use, and a run may measure the host
SHIFTING_HOST = 0.2  # the load of others on a shared host changed by more during a run


def integrity(dataset: Dataset) -> dict:
    """What limits the measurements of a result: routers that sampled far
    less often than set, so that times are only as exact as their samples;
    a host that was nearly saturated, or whose load by others changed much;
    runs of different images of a variant."""
    set_hz = 1 / dataset.experiment.sampling.interval
    out = {"set": set_hz, "low": None, "high": None, "slow": [], "busy": [], "shifting": [], "images": {},
           "skipped": dataset.status.get("skipped") or {}, "limit": dataset.status.get("limit")}
    try:
        groups = analysis.summary(dataset)
    except (OSError, ValueError, KeyError):
        return out
    medians = [m["min"] for g in groups if (m := g["metrics"].get("sample_hz"))]
    slowest = [(g, m) for g in groups if (m := g["metrics"].get("sample_hz_min"))]
    where = lambda g: {"topology": g["topology"], "scenario": g["scenario"], "variant": g["variant"]}
    out.update(low=min((m["min"] for _, m in slowest), default=None), high=max(medians, default=None),
               slow=sorted(({**where(g), "hz": m["min"]} for g, m in slowest if m["min"] < set_hz / 2), key=lambda x: x["hz"]),
               busy=sorted(({**where(g), "cpu": m["max"]} for g in groups if (m := g["metrics"].get("host_cpu_max")) and m["max"] > BUSY_HOST),
                           key=lambda x: -x["cpu"]),
               shifting=sorted(({**where(g), "spread": m["max"]} for g in groups
                                if (m := g["metrics"].get("host_others_spread")) and m["max"] > SHIFTING_HOST),
                               key=lambda x: -x["spread"]))
    images = defaultdict(set)
    for key in dataset.keys():
        if dataset.is_done(key) and (image := dataset.run(key).get("image")):
            images[key.variant].add(image)
    out["images"] = {v: sorted(tags) for v, tags in images.items() if len(tags) > 1}
    return out


def failed_by_topology(dataset: Dataset) -> dict[str, int]:
    """The runs that failed a check, per topology, from the cached summary."""
    out = defaultdict(int)
    try:
        for g in analysis.summary(dataset):
            if n := g["statuses"].get("failed", 0):
                out[g["topology"]] += n
    except (OSError, ValueError, KeyError):
        return {}
    return dict(out)


def failed_checks(dataset: Dataset) -> int:
    """How many runs of a finished result failed a check, from its cached summary."""
    if dataset.status.get("state") != "finished":
        return 0
    try:
        return sum(g["statuses"].get("failed", 0) for g in analysis.summary(dataset))
    except (OSError, ValueError, KeyError):
        return 0


def series_of(dataset: Dataset, topology: str, scenario: str) -> dict:
    """The time series of every variant of a scenario. Reading every sample
    takes seconds for large results, so they are kept until another run of
    the scenario is done."""
    done = tuple(sorted((str(k), (dataset.path / k.path / "run.json").stat().st_mtime)
                        for k in dataset.keys() if k.topology == topology and k.scenario == scenario and dataset.is_done(k)))
    key = (str(dataset.path), topology, scenario, done)
    if (series := SERIES_CACHE.get(key)) is None:
        series = {v.name: analysis.series(dataset, topology, v.name, scenario) for v in dataset.experiment.variants}
        SERIES_CACHE[key] = series
        while len(SERIES_CACHE) > 32:
            SERIES_CACHE.pop(next(iter(SERIES_CACHE)))
    return series


def download(text: str, filename: str, media_type: str) -> Response:
    return Response(text, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def metrics_of(dataset: Dataset) -> dict:
    """The metrics of a result, Checks first if its scenarios have expect steps."""
    checked = any(step.kind == "expect" for s in dataset.experiment.scenarios
                  for step in scenario.each_step(dataset.scenario(s).steps))
    return METRICS if checked else {k: v for k, v in METRICS.items() if k != "checks"}


def render(request: Request, template: str, **context) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"host": platform.node(), "machine": hostload.now(), "update_ready": UPDATES.get("behind", 0) > 0,
                                                          **overview(), **context})


def back(request: Request, default: str) -> str:
    """The page a form was posted from, to return to it."""
    referer = urlparse(request.headers.get("referer", ""))
    return referer.path + (f"?{referer.query}" if referer.query else "") if referer.path.startswith("/") else default


def duration(seconds: float | None) -> str:
    if seconds is None:
        return "–"
    seconds = int(seconds)
    if seconds >= 3600:
        return f"{seconds // 3600} h {seconds % 3600 // 60:02d} min"
    if seconds >= 600:
        return f"{seconds // 60} min"
    if seconds >= 60:  # as the timeline of a scenario
        return f"{seconds // 60} min {seconds % 60:02d} s"
    return f"{seconds} s"


def clock(when: datetime | None) -> str:
    """A time of day to come, with the weekday when it is not today."""
    if when is None:
        return "–"
    today = datetime.now().date()
    return f"{when:%H:%M}" if when.date() == today else f"{when:%a %H:%M}"


def created(stamp: str | None) -> str:
    """When a result was made: the time today, the date before."""
    try:
        when = datetime.fromisoformat(stamp).astimezone()
    except (TypeError, ValueError):
        return (stamp or "")[:10]
    return f"{when:%H:%M}" if when.date() == datetime.now().date() else f"{when:%Y-%m-%d}"


def sparkline(values: list[float], top: float, width: int = 320, height: int = 64) -> str:
    """SVG polyline points for a small live chart scaled to top."""
    if len(values) < 2:
        return ""
    step = width / (len(values) - 1)
    return " ".join(f"{i * step:.1f},{height - 4 - (v / top) * (height - 8):.1f}" for i, v in enumerate(values))


def area(lower: list[float], upper: list[float], top: float, width: int = 320, height: int = 64) -> str:
    """SVG polygon points of the band between two series scaled to top."""
    if len(upper) < 2:
        return ""
    step = width / (len(upper) - 1)
    y = lambda v: f"{height - (v / top) * height:.1f}"
    edge = [f"{i * step:.1f},{y(v)}" for i, v in enumerate(upper)]
    base = [f"{i * step:.1f},{y(v)}" for i, v in reversed(list(enumerate(lower)))]
    return " ".join(edge + base)


def line(values: list[float], top: float, width: int = 320, height: int = 64) -> str:
    """SVG polyline points of a series scaled to top, edge to edge, to draw
    on the edge of an area()."""
    if len(values) < 2:
        return ""
    step = width / (len(values) - 1)
    return " ".join(f"{i * step:.1f},{height - (v / top) * height:.1f}" for i, v in enumerate(values))


def metric_digits(metric: str, time_digits: int = 1) -> int:
    return {"convergence_s": time_digits, "settle_s": time_digits, "path_len_avg": 2, "rss_mean": 1, "heap_mean": 1, "cpu_s_mean": 2}.get(metric, 0)


def metric_value(value: float | None, metric: str, time_digits: int = 1) -> str:
    """A metric as text; times with the decimals their sampling allows."""
    if value is None:
        return "–"
    return f"{value:,.{metric_digits(metric, time_digits)}f}"


def shown(value: float | None, metric: str, time_digits: int = 1) -> float | None:
    """A metric as the table shows it, for comparing: values that look the same are the same."""
    return None if value is None else round(value, metric_digits(metric, time_digits))


def size(n: float) -> str:
    """Bytes as text: 812 KB, 1.4 GB."""
    units = ["B", "KB", "MB", "GB", "TB"]
    while n >= 1000 and len(units) > 1:
        n /= 1000
        units.pop(0)
    unit = units[0]
    return f"{n:.0f} {unit}" if unit in ("B", "KB") or n >= 100 else f"{n:.1f} {unit}"


def listing(items, width: int = 28) -> str:
    """Names joined by commas; whole names only, then ", …" once they do not fit."""
    items = list(items)
    out = ""
    for item in items:
        text = f"{out}, {item}" if out else str(item)
        if len(text) > width and out:
            return f"{out}, …"
        out = text
    return out


_versions: dict[str, tuple[float, str]] = {}


def static(path: str) -> str:
    """The URL of a static file with a version from its content, so that a
    browser loads it again once it changed instead of from its cache."""
    file = HERE / "static" / path
    mtime = file.stat().st_mtime
    if (hit := _versions.get(path)) is None or hit[0] != mtime:
        hit = _versions[path] = (mtime, hashlib.sha256(file.read_bytes()).hexdigest()[:8])
    return f"/static/{path}?v={hit[1]}"


templates.env.filters["listing"] = listing
templates.env.filters["size"] = size
templates.env.filters["duration"] = duration
templates.env.filters["clock"] = clock
templates.env.filters["shown"] = shown
templates.env.globals["size_series"] = analysis.size_series
templates.env.globals["router_metrics"] = analysis.ROUTER_METRICS
# The level the interval of a median reaches with n runs, in percent; None below 3.
templates.env.filters["interval_level"] = lambda n: round(100 * ci["level"], 1) if (ci := analysis.median_ci(list(range(int(n or 0))))) else None
templates.env.filters["created"] = created
templates.env.filters["metric_value"] = metric_value
templates.env.filters["compact"] = lambda n: f"{n:,.0f}" if abs(n) < 1e6 else f"{n / 1e6:,.1f}M"
templates.env.globals["sparkline"] = sparkline
templates.env.globals["area"] = area
templates.env.globals["line"] = line
templates.env.globals["host_series"] = hostload.series
templates.env.globals["static"] = static
