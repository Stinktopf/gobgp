"""Settings: the cluster, updates from GitHub, the host, notifications and the password."""

import hashlib
import logging
import secrets
import ssl
import threading
import time
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from ... import (
    cluster,
    config,
    notify,
    update,
)
from .. import agent, approvals, auth, context, tokens
from ..cluster_control import save_gpu_quiet, save_idle
from ..common import back, jobs
from ..context import render
from .login import sign_in

router = APIRouter()


UPDATE_EVERY_S = 15 * 60
SHOWN_ONCE: dict[str, tuple[float, str]] = {}  # a new token until the page after its creation shows it, never in a URL
SHOWN_FOR_S = 120


def watch_updates() -> None:
    """Asks GitHub every quarter hour whether the branch of the lab has new commits."""
    while True:
        try:
            context.UPDATES.update(update.status(fetch=True))
        except Exception:  # never stop watching for one failed check
            logging.getLogger("uvicorn.error").exception("checking for updates")
        time.sleep(UPDATE_EVERY_S)


def token_rows() -> list[dict]:
    day = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d") if t else None
    return [{"id": t["id"], "name": t["name"], "scope": t["scope"], "created": day(t["created"]), "expires": day(t["expires"]),
             "used": datetime.fromtimestamp(t["used"]).strftime("%Y-%m-%d %H:%M") if t["used"] else None,
             "expired": bool(t["expires"] and t["expires"] < time.time()), "approval": t.get("approval", False)} for t in tokens.load()]


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, saved: str = "", error: str = "", shown: str = ""):
    made, new_token = SHOWN_ONCE.pop(shown, (0, None))
    new_token = new_token if time.monotonic() - made < SHOWN_FOR_S else None
    return render(request, "settings.html", nav="settings", webhook=notify.masked(notify.load().get("discord")),
                  waiting=approvals.waiting(), agent_limits=tokens.limits(), tokens=token_rows(), scopes=tokens.SCOPES, activity=[
                      {**a, "when": datetime.fromtimestamp(a["t"]).strftime("%m-%d %H:%M")} for a in tokens.activity()], new_token=new_token, base=str(request.base_url).rstrip("/"),
                  https=request.url.scheme == "https", fingerprint=certificate_fingerprint(),
                  initial=auth.must_change(auth.load()), saved=saved, error=error,
                  host_settings=config.host_settings(), machine_host=cluster.host(), limits=cluster.limits(), max_routers=cluster.max_routers(),
                  version=context.UPDATES or update.status(fetch=False), running=jobs.active(), cluster_state=jobs.cluster_control.snapshot())


@router.get("/partials/cluster", response_class=HTMLResponse)
def cluster_partial(request: Request):
    return render(request, "partials/cluster.html", cluster_state=jobs.cluster_control.snapshot(), running=jobs.active())


@router.post("/settings/cluster")
def settings_cluster(action: str = Form()):
    if action not in ("start", "stop", "idle", "apply"):
        raise HTTPException(400, "Unknown cluster action")
    try:
        jobs.cluster_control.request("idle-stop" if action == "idle" else action)
    except (cluster.Busy, ValueError, OSError) as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#cluster", 303)
    return RedirectResponse("/settings#cluster", 303)


@router.post("/settings/cluster/gpu")
def settings_cluster_gpu(minutes: int = Form()):
    try:
        save_gpu_quiet(minutes)
    except ValueError as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#cluster", 303)
    return RedirectResponse(f"/settings?{urlencode({'saved': 'GPU wait saved.'})}#cluster", 303)


@router.post("/settings/cluster/idle")
def settings_cluster_idle(minutes: int = Form()):
    try:
        save_idle(minutes)
        jobs.cluster_control.idle_since = time.monotonic()
    except ValueError as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#cluster", 303)
    return RedirectResponse(f"/settings?{urlencode({'saved': 'Idle timeout saved.'})}#cluster", 303)


@router.post("/settings/update/check")
def settings_update_check():
    context.UPDATES.update(update.status(fetch=True))
    return RedirectResponse("/settings#version", 303)


@router.post("/settings/update")
def settings_update():
    """Takes the new commits and starts the server again, only while no result runs."""
    if active := jobs.active():
        return RedirectResponse(f"/settings?{urlencode({'error': f'{active.name} runs. Pause the queue or wait until it ends, then update.'})}#version", 303)
    try:
        with cluster.claim("__maintenance__"):
            commit = update.update()
    except (update.UpdateError, cluster.Busy) as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#version", 303)
    threading.Timer(1.0, update.restart).start()  # after this answer is sent
    return RedirectResponse(f"/settings?{urlencode({'saved': f'Updated to {commit}. The lab starts again, reload in a few seconds.'})}#version", 303)


@router.post("/settings/update/switch")
def settings_update_switch(branch: str = Form("")):
    """Moves the lab to a branch on GitHub and starts the server again, only while no result runs."""
    if active := jobs.active():
        return RedirectResponse(f"/settings?{urlencode({'error': f'{active.name} runs. Pause the queue or wait until it ends, then switch.'})}#version", 303)
    try:
        with cluster.claim("__maintenance__"):
            commit = update.switch(branch or None)
    except (update.UpdateError, cluster.Busy) as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#version", 303)
    threading.Timer(1.0, update.restart).start()  # after this answer is sent
    message = f"Switched to {branch or 'the default branch'} at {commit}. The lab starts again, reload in a few seconds."
    return RedirectResponse(f"/settings?{urlencode({'saved': message})}#version", 303)


@router.post("/settings/host")
async def settings_host(request: Request):
    """What the lab may take of the host, what it keeps free, and the routers per thread."""
    form, machine = await request.form(), cluster.host()
    try:
        number = lambda key, scale=1: round(float(str(form.get(key)).replace(",", ".")) * scale) if str(form.get(key) or "").strip() else None
        values = {"cpus": number("cpus"), "memory_mb": number("memory_gb", 1024), "keep_cpus": number("keep_cpus"),
                  "keep_mb": number("keep_gb", 1024), "routers_per_cpu": number("routers_per_cpu")}
    except ValueError:
        return RedirectResponse(f"/settings?{urlencode({'error': 'Host: numbers only.'})}#budget", 303)
    values = {k: v for k, v in values.items() if v is not None}
    cpus, memory = values.get("cpus", machine["cpus"]), values.get("memory_mb", machine["memory_mb"])
    keep_cpus, keep_mb = values.get("keep_cpus", config.HOST_DEFAULTS["keep_cpus"]), values.get("keep_mb", config.HOST_DEFAULTS["keep_mb"])
    problem = ("Threads for the lab: from 1 to the " + str(machine["cpus"]) + " of the host." if not 1 <= cpus <= machine["cpus"]
               else f"Memory for the lab: at most the {machine['memory_mb'] / 1024:.0f} GiB of the host." if not 1024 <= memory <= machine["memory_mb"]
               else "Host CPU headroom cannot be negative." if keep_cpus < config.HOST_KEEP_AT_LEAST["keep_cpus"]
               else "Host memory headroom cannot be negative." if keep_mb < config.HOST_KEEP_AT_LEAST["keep_mb"]
               else "Keep fewer threads free: leave at least 2 for minikube." if keep_cpus > cpus - 2
               else "Keep less memory free: leave at least 2 GiB for minikube." if keep_mb > memory - 2048
               else "Routers per thread: from 1 to 32." if not 1 <= values.get("routers_per_cpu", 4) <= 32 else None)
    if problem:
        return RedirectResponse(f"/settings?{urlencode({'error': problem})}#budget", 303)
    # All of a resource counts as no cap: the lab follows the host if it grows.
    values = {k: v for k, v in values.items() if not (k == "cpus" and v == machine["cpus"]) and not (k == "memory_mb" and v == machine["memory_mb"])}
    action = str(form.get("action") or "save")
    if action not in ("save", "apply"):
        raise HTTPException(400, "Unknown settings action")
    try:
        jobs.cluster_control.request(action, values)
    except (cluster.Busy, ValueError, OSError) as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#budget", 303)
    message = "Host saved. Applying the new allocation in the background." if action == "apply" else "Host saved. Apply changes to update the cluster allocation."
    return RedirectResponse(f"/settings?{urlencode({'saved': message})}#budget", 303)


@router.post("/settings/tokens")
def settings_token_new(name: str = Form(""), scope: str = Form("read"), days: int = Form(90), approval: str = Form("")):
    try:
        token, _ = tokens.create(name, scope, days, approval == "on")
    except ValueError as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#agents", 303)
    now = time.monotonic()
    for key in [k for k, (t, _) in SHOWN_ONCE.items() if now - t > SHOWN_FOR_S]:
        del SHOWN_ONCE[key]
    shown = secrets.token_urlsafe(12)
    SHOWN_ONCE[shown] = (now, token)
    return RedirectResponse(f"/settings?shown={shown}#agents", 303)


@router.post("/settings/agents/limits")
def settings_agent_limits(queue_h: float = Form(24)):
    try:
        tokens.save_limits(queue_h)
    except ValueError as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#agents", 303)
    return RedirectResponse(f"/settings?{urlencode({'saved': 'Saved.'})}#agents", 303)


@router.post("/settings/actions/{action_id}/{decision}")
def settings_action(request: Request, action_id: str, decision: str):
    """A person approves or rejects what an agent asked to do."""
    if decision not in ("approve", "reject"):
        raise HTTPException(404)
    try:
        out = agent.decide(action_id, decision == "approve")
    except LookupError as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#agents", 303)
    message = {"done": "Done.", "rejected": "Rejected."}.get(out["state"], f"It failed: {out.get('outcome', '')}")
    key = "error" if out["state"] == "failed" else "saved"
    page = back(request, "/settings")
    if not page.startswith("/settings"):  # decided in the card of another page: back there
        return RedirectResponse(page, 303)
    return RedirectResponse(f"/settings?{urlencode({key: message})}#agents", 303)


@router.post("/settings/tokens/{token_id}/revoke")
def settings_token_revoke(token_id: str):
    tokens.revoke(token_id)
    return RedirectResponse(f"/settings?{urlencode({'saved': 'Token revoked.'})}#agents", 303)


def certificate_fingerprint() -> str | None:
    """SHA-256 of the HTTPS certificate, as openssl x509 -fingerprint prints it."""
    try:
        der = ssl.PEM_cert_to_DER_cert((config.SETTINGS / "tls.crt").read_text())
    except (OSError, ValueError):
        return None
    return ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())


@router.get("/certificate")
def certificate():
    """The self-signed certificate of HTTPS, for agents to trust it. Public, as every TLS handshake sends it."""
    cert = config.SETTINGS / "tls.crt"
    if not cert.exists():
        raise HTTPException(404, "The lab runs without HTTPS.")
    return FileResponse(cert, media_type="application/x-pem-file", filename="obgp-lab.crt")


@router.post("/settings/notify")
def settings_notify(request: Request, discord: str = Form(""), action: str = Form("save")):
    # The saved webhook is never shown; an empty field keeps it.
    url = "" if action == "off" else discord.strip() or notify.load().get("discord", "")
    settings = {"discord": url, "lab": str(request.base_url).rstrip("/")} if url else {}
    try:
        notify.save(settings)
    except ValueError as e:
        return RedirectResponse(f"/settings?{urlencode({'error': str(e)})}#notifications", 303)
    if action == "test":
        problems = notify.test(settings)
        query = {"error": " ".join(problems)} if problems else {"saved": "A test message is on its way."}
    else:
        query = {"saved": "Notifications off." if action == "off" else "Saved."}
    return RedirectResponse(f"/settings?{urlencode(query)}#notifications", 303)


@router.post("/settings/password")
def settings_password(request: Request, current: str = Form(""), new: str = Form(""), repeat: str = Form("")):
    if not auth.check_password(current, auth.load()):
        return RedirectResponse(f"/settings?{urlencode({'error': 'The current password is wrong.'})}#password", 303)
    if len(new) < 10 or new != repeat:
        error = "The new password needs 10 characters or more, twice the same."
        return RedirectResponse(f"/settings?{urlencode({'error': error})}#password", 303)
    # The change signs out every other session; this one gets a new cookie.
    auth.set_password(new)
    response = RedirectResponse(f"/settings?{urlencode({'saved': 'Password changed. Other sessions are signed out.'})}#password", 303)
    sign_in(request, response)
    return response
