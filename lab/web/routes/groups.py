"""Groups of the main views: moving and renaming them."""


from fastapi import APIRouter, Form
from fastapi.responses import JSONResponse

from .. import groups
from ..context import own_group

router = APIRouter()


@router.post("/groups/{kind}")
def group_move(kind: str, name: str = Form(...), group: str = Form(...)):
    """Moves an experiment, scenario or topology to a group of the main view."""
    if (mine := own_group(kind, name)) is None:
        return JSONResponse({"problems": [f"No {kind.removesuffix('s')} {name}."]}, 404)
    try:
        return {"group": groups.move(kind, name, group, mine)}
    except ValueError as e:
        return JSONResponse({"problems": [str(e)]}, 400)


@router.post("/groups/{kind}/rename")
def group_rename(kind: str, old: str = Form(...), new: str = Form(...)):
    """Renames a group of a main view, into another one if that exists."""
    try:
        return {"group": groups.rename(kind, old, new)}
    except ValueError as e:
        return JSONResponse({"problems": [str(e)]}, 400)
