"""Topologies: the list, the editor and the imports from SNDlib, CAIDA and generators."""

import logging
from html import escape
from pathlib import Path
from urllib.parse import urlencode

import yaml
from fastapi import APIRouter, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ... import (
    caida,
    generate,
    sndlib,
    topology,
)
from .. import groups
from ..context import (
    check_rename,
    own_group,
    readable_topologies,
    render,
    thumb_stamps,
    thumbnails,
    topology_summary,
    users,
)

router = APIRouter()


@router.get("/topologies", response_class=HTMLResponse)
def topologies(request: Request, error: str = ""):
    used = users("topologies")
    loaded, broken = readable_topologies()
    items = [{"name": n, **topology_summary(t), "used": used[n], "source": t["source"], "own": groups.of_topology(t["source"])}
             for n, t in loaded.items()]
    return render(request, "topologies.html", nav="topologies", groups=groups.arrange("topologies", items, topology.names()), broken=broken, models=generate.MODELS,
                  thumbs=thumb_stamps(loaded), error=error)


@router.get("/topologies/sndlib", response_class=HTMLResponse)
def sndlib_list(request: Request):
    try:
        networks = sndlib.summary()
    except OSError as e:
        return HTMLResponse(f'<p class="error py-6">SNDlib is not reachable: {escape(str(e))}</p>')
    return render(request, "partials/sndlib.html", networks=networks)


@router.post("/topologies/generate")
async def topologies_generate(request: Request):
    form = await request.form()
    try:
        sizes = [int(x) for x in str(form.get("sizes", "")).replace(" ", "").split(",") if x]
        names = generate.generate(str(form.get("model", "")), sizes, int(form.get("seed") or 1), str(form.get("name", "")),
                                  **{k: v for k, v in form.items() if k not in ("model", "sizes", "seed", "name")})
    except (ValueError, FileExistsError) as e:
        return RedirectResponse(f"/topologies?{urlencode({'error': str(e)})}", 303)
    return RedirectResponse(f"/topologies/{names[0]}" if len(names) == 1 else "/topologies", 303)


@router.post("/topologies/sndlib")
async def sndlib_import(network: str = Form(""), name: str = Form(""), structure: str = Form(""), externals: int = Form(4),
                        file: UploadFile | None = None):
    # Native files of SNDlib are small; a limit keeps uploads from filling the memory.
    text = (await file.read(5_000_000)).decode(errors="replace") if file and file.filename else None
    network = Path(file.filename).stem if text else network
    if not network:
        return RedirectResponse(f"/topologies?{urlencode({'error': 'Pick a network or a file to import.'})}", 303)
    try:
        if structure == "one-as" and not 1 <= externals <= 32:
            raise ValueError("Neighbors of the AS: from 1 to 32.")
        created = sndlib.import_network(network, name.strip() or sndlib.slug(network), text,
                                        externals if structure == "one-as" else None)
    except (ValueError, FileExistsError, OSError) as e:
        return RedirectResponse(f"/topologies?{urlencode({'error': str(e)})}", 303)
    return RedirectResponse(f"/topologies/{created}", 303)


@router.get("/topologies/caida", response_class=HTMLResponse)
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


@router.get("/topologies/caida/search", response_class=HTMLResponse)
def caida_search(request: Request, q: str = "", month: str = ""):
    if not q.strip() or q.startswith("AS") and " " in q:  # empty, or the chosen AS shown again
        return HTMLResponse("")
    try:
        hits = caida.relations(caida.nearest(month)[0]).search(q)
    except (ValueError, OSError) as e:
        return render(request, "partials/caida-hits.html", error=str(e), hits=None)
    return render(request, "partials/caida-hits.html", hits=hits, max=caida.max_routers())


@router.get("/topologies/caida/countries")
def caida_countries(month: str = ""):
    """The countries of a month, each with how many of its ASes connect; the browser names them."""
    try:
        countries = caida.relations(caida.nearest(month)[0]).countries()
    except (ValueError, OSError):
        return JSONResponse([])
    return JSONResponse([[cc, n] for cc, n in countries if n >= 3])


@router.get("/topologies/caida/members", response_class=HTMLResponse)
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


@router.get("/topologies/caida/preview", response_class=HTMLResponse)
def caida_preview(request: Request, part: str = "core", asn: str = "", country: str = "", size: str = "32", month: str = ""):
    try:
        p = caida.preview(*caida.read_form(part, asn, country, size), month)
    except ValueError as e:
        return render(request, "partials/caida-preview.html", error=str(e))
    except OSError as e:
        return render(request, "partials/caida-preview.html", error=f"CAIDA is not reachable: {e}")
    return render(request, "partials/caida-preview.html", p=p)


@router.post("/topologies/caida")
def caida_import(part: str = Form("core"), asn: str = Form(""), country: str = Form(""), size: str = Form("32"), month: str = Form(""),
                 name: str = Form("")):
    try:
        created = caida.import_part(*caida.read_form(part, asn, country, size), name.strip(), month)
    except (ValueError, FileExistsError, OSError) as e:
        return RedirectResponse(f"/topologies?{urlencode({'error': str(e)})}", 303)
    return RedirectResponse(f"/topologies/{created}", 303)


@router.get("/topologies/new", response_class=HTMLResponse)
def topology_new(request: Request, like: str = ""):
    t, copy = {"routers": {}, "roles": {}}, ""
    if like:
        try:
            t, copy = topology.load(like), f"{like}-copy"
        except (ValueError, OSError, KeyError, yaml.YAMLError):
            pass
    return render(request, "topology.html", nav="topologies", name="", copy=copy, topology=t, used=[])


@router.get("/topologies/{name}/data")
def topology_data(name: str):
    """Routers and roles of a topology, for the preview of the scenario editor, kept by the browser per version."""
    try:
        t = topology.load(name, shared=True)
    except (ValueError, OSError):
        raise HTTPException(404) from None
    return JSONResponse({"routers": t["routers"], "roles": t["roles"]}, headers={"Cache-Control": "private, max-age=86400"})


@router.get("/topologies/{name}/thumb")
def topology_thumb(name: str):
    """What the small drawing of a topology needs, fetched once per version by the browser."""
    try:
        t = topology.load(name, shared=True)
    except (ValueError, OSError):
        raise HTTPException(404) from None
    return JSONResponse(thumbnails({name: t})[name], headers={"Cache-Control": "private, max-age=86400"})


@router.get("/topologies/{name}", response_class=HTMLResponse)
def topology_page(request: Request, name: str, error: str = ""):
    try:
        t = topology.load(name)
    except (ValueError, FileNotFoundError):
        raise HTTPException(404, f"No topology {name}.") from None
    source = t.get("source") or ""
    names = caida.names(source, {r.get("asn") for r in t["routers"].values()}) if source.startswith("caida/") else {}
    return render(request, "topology.html", nav="topologies", name=name, topology=t, error=error,
                  used=users("topologies")[name], as_names=names)


@router.post("/topologies/{name}/delete")
def topology_delete(name: str):
    try:
        file = topology.path(name)
    except ValueError:
        raise HTTPException(404, f"No topology {name}.") from None
    if used := users("topologies")[name]:
        error = f"{name} is used by {', '.join(used)}."
        return RedirectResponse(f"/topologies/{name}?{urlencode({'error': error})}", 303)
    file.unlink(missing_ok=True)
    groups.forget("topologies", name)
    return RedirectResponse("/topologies", 303)


@router.post("/topologies/save")
async def topology_save(request: Request):
    body = await request.json()
    name, original = str(body.get("name", "")).strip(), str(body.get("original", ""))
    try:
        check_rename("topology", name, original, body.get("mode"), topology.path, "topologies")
        roles = {role: list(members) for role, members in (body.get("roles") or {}).items() if members}
        topology.save(name, body["routers"], roles, body.get("source") or None)
    except (ValueError, KeyError, TypeError) as e:
        return JSONResponse({"problems": str(e).split("; ")}, status_code=422)
    if original and original != name and topology.path(original).exists():
        groups.follow("topologies", original, name, body.get("mode") == "rename", own_group("topologies", name), own_group("topologies", original))
    if original and original != name and body.get("mode") == "rename":
        topology.path(original).unlink(missing_ok=True)
    return JSONResponse({"saved": name})
