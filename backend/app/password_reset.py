import hashlib
import re
import secrets

from app.auth import hash_password
from app.database import get_conn, run_query

RESET_WINDOW_SECONDS = 900


def allow_reset_action(key: str, limit: int) -> bool:
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    row = run_query(
        """
        INSERT INTO password_reset_limits (key_hash, window_start, attempts)
        VALUES (%s, statement_timestamp(), 1)
        ON CONFLICT (key_hash) DO UPDATE SET
            attempts = CASE
                WHEN password_reset_limits.window_start <=
                     statement_timestamp() - (%s * INTERVAL '1 second')
                THEN 1 ELSE password_reset_limits.attempts + 1 END,
            window_start = CASE
                WHEN password_reset_limits.window_start <=
                     statement_timestamp() - (%s * INTERVAL '1 second')
                THEN statement_timestamp() ELSE password_reset_limits.window_start END
        RETURNING attempts
        """,
        (key_hash, RESET_WINDOW_SECONDS, RESET_WINDOW_SECONDS),
        fetchone=True,
        commit=True,
    )
    return row["attempts"] <= limit


def issue_reset_token(email: str) -> str | None:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # Issuance and consumption lock the same user to serialize replacement.
                cur.execute("SELECT id FROM users WHERE email=%s FOR UPDATE", (email,))
                user = cur.fetchone()
                if user is None:
                    return None
                cur.execute("DELETE FROM password_reset_tokens WHERE user_id=%s", (user[0],))
                cur.execute(
                    "INSERT INTO password_reset_tokens (user_id, token) VALUES (%s, %s)",
                    (user[0], token_hash),
                )
        return token
    finally:
        conn.close()


def _token_hash(token: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    return hashlib.sha256(token.encode()).hexdigest()


def valid_reset_token(token: str) -> bool:
    token_hash = _token_hash(token)
    if token_hash is None:
        return False
    return run_query(
        """
        SELECT id FROM password_reset_tokens
        WHERE token=%s AND created_at >
            clock_timestamp() - (%s * INTERVAL '1 second')
        """,
        (token_hash, RESET_WINDOW_SECONDS),
        fetchone=True,
    ) is not None


def consume_reset_token(token: str, new_password: str) -> bool:
    token_hash = _token_hash(token)
    if token_hash is None:
        return False
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT user_id FROM password_reset_tokens WHERE token=%s",
                    (token_hash,),
                )
                row = cur.fetchone()
                if row is None:
                    return False
                user_id = row[0]
                cur.execute("SELECT id FROM users WHERE id=%s FOR UPDATE", (user_id,))
                # Recheck after the lock: another request may have consumed/replaced it.
                cur.execute(
                    """
                    DELETE FROM password_reset_tokens
                    WHERE token=%s AND user_id=%s AND created_at >
                        clock_timestamp() - (%s * INTERVAL '1 second')
                    RETURNING user_id
                    """,
                    (token_hash, user_id, RESET_WINDOW_SECONDS),
                )
                if cur.fetchone() is None:
                    return False
                cur.execute(
                    "UPDATE users SET password_hash=%s WHERE id=%s",
                    (hash_password(new_password), user_id),
                )
                cur.execute("DELETE FROM password_reset_tokens WHERE user_id=%s", (user_id,))
                cur.execute("DELETE FROM sessions WHERE user_id=%s", (user_id,))
        return True
    finally:
        conn.close()
