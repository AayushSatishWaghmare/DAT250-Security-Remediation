from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app.auth import (
    clear_session,
    create_session,
    dummy_verify,
    get_user_from_session,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.database import run_query
from app.email_service import send_reset_email
from app.password_reset import (
    RESET_WINDOW_SECONDS,
    allow_reset_action,
    consume_reset_token,
    issue_reset_token,
    valid_reset_token,
)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def reset_response(request: Request, mode: str, message=None, token=None, status_code: int = 200):
    headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
    if status_code == 429:
        headers["Retry-After"] = str(RESET_WINDOW_SECONDS)
    return templates.TemplateResponse(
        "reset_password.html",
        {"request": request, "mode": mode, "message": message, "token": token},
        status_code=status_code,
        headers=headers,
    )


def reset_client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown-peer"


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = get_user_from_session(request)
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = run_query("SELECT * FROM users WHERE email=%s", (email,), fetchone=True)
    if not user:
        dummy_verify(password)
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Wrong email or password."}
        )
    if needs_rehash(user["password_hash"]):
        run_query(
            "UPDATE users SET password_hash=%s WHERE id=%s",
            (hash_password(password), user["id"]),
            commit=True,
        )

    token = create_session(user["id"])
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("session_token", token, secure=True, httponly=True, samesite="lax")
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@router.post("/register", response_class=HTMLResponse)
def register(request: Request, email: str = Form(...), full_name: str = Form(...), password: str = Form(...)):
    existing = run_query("SELECT id FROM users WHERE email=%s", (email,), fetchone=True)
    if existing:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Email already exists."}
        )
    run_query(
        """
        INSERT INTO users (email, full_name, password_hash, role)
        VALUES (%s, %s, %s, 'student')
        """,
        (email, full_name, hash_password(password)),
        commit=True,
    )
    return RedirectResponse("/login", status_code=302)


@router.get("/logout")
def logout(request: Request):
    token = request.cookies.get("session_token")
    if token:
        clear_session(token)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("session_token", secure=True, httponly=True, samesite="lax")
    return resp


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request):
    return reset_response(request, "request")


@router.post("/reset-password", response_class=HTMLResponse)
def reset_password_request(request: Request, email: str = Form(...)):
    email = email.strip()
    if not allow_reset_action(f"request:peer:{reset_client_key(request)}", 20) or not allow_reset_action(
        f"request:email:{email.casefold()}", 3
    ):
        return reset_response(
            request, "request", "Too many reset requests. Try again later.", status_code=429
        )

    token = issue_reset_token(email)
    if token is not None:
        send_reset_email(email, token)
    return reset_response(
        request, "request", "If an account exists for that email, a reset link has been sent."
    )


@router.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_token_page(request: Request, token: str):
    if not allow_reset_action(f"attempt:peer:{reset_client_key(request)}", 10):
        return reset_response(
            request, "invalid", "Too many reset attempts. Try again later.", status_code=429
        )
    if not valid_reset_token(token):
        return reset_response(
            request, "invalid", "This reset link is invalid or has expired.", status_code=400
        )
    return reset_response(request, "set", token=token)


@router.post("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_token(request: Request, token: str, new_password: str = Form(...)):
    if not allow_reset_action(f"attempt:peer:{reset_client_key(request)}", 10):
        return reset_response(
            request, "invalid", "Too many reset attempts. Try again later.", status_code=429
        )
    if not consume_reset_token(token, new_password):
        return reset_response(
            request, "invalid", "This reset link is invalid or has expired.", status_code=400
        )

    return RedirectResponse(
        "/login", status_code=302,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )
