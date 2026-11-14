"""Stars and notes on results, searches and cases, see lab/marks.py, and the panel of notes in the top bar.

Every form of the panel posts with the panel's state and gets the panel back, so that the page stays as it is.
Without the panel, e.g. a star in a list, a form returns to the page it came from."""

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from ... import marks, simulation
from ..common import with_error
from ..context import render

router = APIRouter()


def _back(back: str) -> str:
    """Where the page that sent a form is, only within the lab."""
    return back if back.startswith("/") and not back.startswith("//") else "/"


def where(kind: str, name: str, dates: dict | None = None) -> dict:
    """How an object is named and where it is, or no address once it is gone. dates: the days searches began, kept
    across the objects of one panel."""
    try:
        marks.resolve(kind, name)
    except (LookupError, ValueError):
        url = None
    else:
        url = {"result": f"/results/{name}", "search": f"/simulation?search={name}"}.get(kind) or f"/simulation/{name}"
    if kind == "page":
        return {"kind": kind, "name": name, "label": f"Page {name}", "url": name, "title": name}
    dates = {} if dates is None else dates
    search, _, case = name.partition("/")
    if kind != "result" and search not in dates:
        try:
            dates[search] = str(simulation.search(search).get("started", ""))[:10]
        except LookupError:
            dates[search] = ""
    of = f"search of {dates[search]}" if kind != "result" and dates[search] else f"search {search}"
    label = name if kind == "result" else of[0].upper() + of[1:] if kind == "search" else f"Case {case}, {of}"
    return {"kind": kind, "name": name, "label": label, "url": url, "title": name}


def panel(request: Request, kind: str = "", name: str = "", view: str = "", error: str = ""):
    """The notes of this page, or every note and star of the lab in one view: the open notes of each object
    first, its done ones after them, gone objects first of all, to tidy up."""
    dates: dict = {}
    here = where(kind, name, dates) if kind in marks.KINDS and name else None
    view = view if view in ("page", "all") and (view == "all" or here) else "page" if here else "all"
    objects = []
    for k, names in marks.everything().items():
        for n, m in sorted(names.items()):
            opened = sum(not x["done"] for x in m["notes"])
            objects.append({**where(k, n, dates), "star": m["star"], "notes": m["notes"], "open": opened, "done": len(m["notes"]) - opened})
    objects.sort(key=lambda o: (o["url"] is not None, -o["open"], not o["star"]))
    page = marks.of(here["kind"], here["name"]) if here else {"star": False, "notes": []}
    return render(request, "partials/notes-panel.html", here=here, view=view, page_notes=page["notes"],
                  page_star=page["star"], objects=objects, error=error, here_open=sum(not n["done"] for n in page["notes"]))


def answer(request: Request, form: dict, back: str, error: str = ""):
    """The panel again for a form of the panel, else back to the page."""
    if request.headers.get("x-notes-panel"):
        return panel(request, form.get("here_kind", ""), form.get("here_name", ""), form.get("view", ""), error)
    return RedirectResponse(with_error(_back(back), error) if error else _back(back), status_code=303)


@router.get("/marks/panel")
def show(request: Request, kind: str = "", name: str = "", view: str = ""):
    return panel(request, kind, name, view)


async def _form(request: Request) -> dict:
    return {k: v for k, v in (await request.form()).items() if isinstance(v, str)}


@router.post("/marks/{kind}/star")
async def star(request: Request, kind: str):
    """A star on an object, or none: starred objects come first in their list, for everyone."""
    form = await _form(request)
    try:
        marks.star(kind, marks.resolve(kind, form.get("name", "")), form.get("on") in ("true", "1", "on"))
    except (LookupError, ValueError) as e:
        if request.headers.get("x-notes-panel") and kind in marks.KINDS:  # a star of an object gone: taken all the same
            marks.star(kind, form.get("name", ""), form.get("on") in ("true", "1", "on"))
            return answer(request, form, form.get("back", ""))
        return answer(request, form, form.get("back", ""), str(e))
    return answer(request, form, form.get("back", ""))


@router.post("/marks/{kind}/notes")
async def add(request: Request, kind: str):
    """A note on an object, for everyone of the lab, without an author."""
    form = await _form(request)
    try:
        marks.add(kind, marks.resolve(kind, form.get("name", "")), form.get("text", ""), form.get("color"))
    except (LookupError, ValueError) as e:
        return answer(request, form, form.get("back", ""), str(e))
    return answer(request, form, form.get("back", ""))


@router.post("/marks/bulk")
async def bulk(request: Request):
    """One action on the notes and objects picked in the overview: done, open, unstar or delete."""
    form = await request.form()
    objects = [tuple(o.split(":", 1)) for o in form.getlist("object") if isinstance(o, str) and ":" in o]
    state = {k: v for k, v in form.items() if isinstance(v, str)}
    try:
        marks.bulk(state.get("action", ""), [n for n in form.getlist("note") if isinstance(n, str)], objects)
    except ValueError as e:
        return answer(request, state, state.get("back", ""), str(e))
    return answer(request, state, state.get("back", ""))


@router.post("/marks/notes/clear")
async def clear(request: Request):
    """Every done note of the lab is deleted."""
    form = await _form(request)
    marks.clear_done()
    return answer(request, form, form.get("back", ""))


@router.post("/marks/forget")
async def forget(request: Request):
    """The star and the notes of an object, e.g. one that is gone."""
    form = await _form(request)
    try:
        marks.forget(form.get("kind", ""), form.get("name", ""))
    except ValueError as e:
        return answer(request, form, form.get("back", ""), str(e))
    return answer(request, form, form.get("back", ""))


@router.post("/marks/notes/{note_id}")
async def edit(request: Request, note_id: str):
    """A note with a new text, or done, or open again."""
    form = await _form(request)
    done = {"true": True, "false": False}.get(form.get("done", ""))
    try:
        marks.edit(note_id, form.get("text"), done, form.get("color"))
    except (LookupError, ValueError) as e:
        return answer(request, form, form.get("back", ""), str(e))
    return answer(request, form, form.get("back", ""))


@router.post("/marks/notes/{note_id}/delete")
async def delete(request: Request, note_id: str):
    form = await _form(request)
    try:
        marks.delete(note_id)
    except LookupError as e:
        return answer(request, form, form.get("back", ""), str(e))
    return answer(request, form, form.get("back", ""))
