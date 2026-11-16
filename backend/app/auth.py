import hashlib
import hmac
import re
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request
from app.database import run_query

# argon2-cffi's PasswordHasher uses Argon2id with a random per-hash salt.
_hasher = PasswordHasher()
_LEGACY_SHA256 = re.compile(r"[0-9a-f]{64}")
# Used to spend the same verification time when no account exists.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _is_legacy_hash(password_hash: str) -> bool:
    return bool(_LEGACY_SHA256.fullmatch(password_hash))


def verify_password(password: str, password_hash: str) -> bool:
    if _is_legacy_hash(password_hash):
        legacy = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy, password_hash)
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def dummy_verify(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def needs_rehash(password_hash: str) -> bool:
    return _is_legacy_hash(password_hash) or _hasher.check_needs_rehash(password_hash)


def create_session(user_id: int) -> str:
    token = secrets.token_hex(16)
    run_query(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, token),
        commit=True,
    )
    return token


def get_user_from_session(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None
    session = run_query(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token = %s
        """,
        (session_token,),
        fetchone=True,
    )
    return session


def clear_session(token: str):
    run_query("DELETE FROM sessions WHERE session_token = %s", (token,), commit=True)


def require_admin(request: Request):
    user = get_user_from_session(request)
    if not user:
        raise HTTPException(status_code=302, detail="Login required", headers={"Location": "/login"})
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user
