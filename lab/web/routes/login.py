"""Signing in and out."""


from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from .. import auth
from ..context import render

router = APIRouter()
throttle = auth.Throttle()  # slows down password guessing


def sign_in(request: Request, response: Response) -> None:
    response.set_cookie(auth.COOKIE, auth.issue(auth.load()), max_age=auth.MAX_AGE, httponly=True,
                        secure=request.url.scheme == "https", samesite="strict")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    return render(request, "login.html", error=error, initial=auth.must_change(auth.load()),
                  initial_file=auth.initial_file())


@router.post("/login")
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


@router.post("/logout")
def logout():
    response = RedirectResponse("/login", 303)
    response.delete_cookie(auth.COOKIE)
    return response
