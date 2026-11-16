import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.auth import verify_password
from app.database import get_conn, run_query
from app.main import app
from tests.support import SecurityTestCase


class PasswordResetTests(SecurityTestCase):
    def request_token(self, name="alice"):
        with patch("app.routes.auth_routes.send_reset_email") as send:
            response = self.client.post(
                "/reset-password", data={"email": self.users[name]["email"]}
            )
        self.assertEqual(response.status_code, 200)
        send.assert_called_once()
        return send.call_args.args[1]

    def test_random_hashed_token_and_successful_single_use(self):
        token = self.request_token()
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")
        row = run_query(
            "SELECT * FROM password_reset_tokens WHERE user_id=104", fetchone=True
        )
        self.assertNotEqual(row["token"], token)
        self.assertEqual(row["token"], hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(self.client.get(f"/reset-password/{token}").status_code, 200)
        self.sign_in("alice")
        response = self.client.post(
            f"/reset-password/{token}", data={"new_password": "Changed456"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/login")
        self.assertTrue(verify_password("Changed456", self.stored_user("alice")["password_hash"]))
        self.assertFalse(verify_password("Original123", self.stored_user("alice")["password_hash"]))
        self.assertTrue(verify_password("Original123", self.stored_user("bob")["password_hash"]))
        self.assertEqual(self.client.get("/grades/901").status_code, 302)
        response = self.client.post(
            f"/reset-password/{token}", data={"new_password": "Reused789"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue(verify_password("Changed456", self.stored_user("alice")["password_hash"]))
        self.client.cookies.clear()
        for password, succeeds in (("Original123", False), ("Changed456", True)):
            response = self.client.post(
                "/login", data={"email": self.users["alice"]["email"], "password": password}
            )
            self.assertEqual(response.status_code == 302, succeeds)

    def test_expired_replaced_and_malformed_tokens_cannot_change_passwords(self):
        old_token = self.request_token()
        fresh_token = self.request_token()
        self.assertNotEqual(old_token, fresh_token)
        self.assertEqual(
            run_query(
                "SELECT COUNT(*) AS n FROM password_reset_tokens WHERE user_id=104",
                fetchone=True,
            )["n"], 1
        )
        run_query(
            "UPDATE password_reset_tokens SET created_at=NOW() - INTERVAL '16 minutes'",
            commit=True,
        )
        for token in (old_token, fresh_token, "123456", secrets.token_urlsafe(32), "bad!token"):
            with self.subTest(token_kind=len(token)):
                response = self.client.post(
                    f"/reset-password/{token}", data={"new_password": "Rejected456"}
                )
                self.assertEqual(response.status_code, 400)
                response = self.client.get(f"/reset-password/{token}")
                self.assertEqual(response.status_code, 400)
        self.assertTrue(verify_password("Original123", self.stored_user("alice")["password_hash"]))

    def test_known_and_unknown_email_have_the_same_response(self):
        with patch("app.routes.auth_routes.send_reset_email") as send:
            known = self.client.post("/reset-password", data={"email": self.users["alice"]["email"]})
            unknown = self.client.post("/reset-password", data={"email": "missing@security.test"})
        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known.text, unknown.text)
        send.assert_called_once()

    def test_request_limits_apply_to_known_and_unknown_addresses(self):
        for email in (self.users["alice"]["email"], "missing@security.test"):
            with patch("app.routes.auth_routes.send_reset_email"):
                for _ in range(3):
                    self.assertEqual(
                        self.client.post("/reset-password", data={"email": email}).status_code, 200
                    )
                response = self.client.post("/reset-password", data={"email": email})
            self.assertEqual(response.status_code, 429)
            self.assertIn("retry-after", response.headers)
        run_query(
            "UPDATE password_reset_limits SET window_start=NOW() - INTERVAL '16 minutes'",
            commit=True,
        )
        self.request_token()

    def test_source_limit_cannot_be_bypassed_by_rotating_email(self):
        with patch("app.routes.auth_routes.send_reset_email"):
            for number in range(20):
                response = self.client.post(
                    "/reset-password",
                    data={"email": f"missing{number}@security.test"},
                    headers={"x-forwarded-for": f"192.0.2.{number}", "x-real-ip": f"192.0.2.{number}"},
                )
                self.assertEqual(response.status_code, 200)
            response = self.client.post(
                "/reset-password", data={"email": self.users["alice"]["email"]}
            )
        self.assertEqual(response.status_code, 429)

    def test_failed_attempt_limits_cover_get_and_post_and_survive_new_clients(self):
        for method in ("get", "post"):
            run_query("DELETE FROM password_reset_limits", commit=True)
            for _ in range(10):
                response = getattr(self.client, method)(
                    "/reset-password/not-valid",
                    **({"data": {"new_password": "Rejected456"}} if method == "post" else {}),
                )
                self.assertEqual(response.status_code, 400)
            with TestClient(app, follow_redirects=False) as other_client:
                response = other_client.get("/reset-password/not-valid")
            self.assertEqual(response.status_code, 429)
        self.assertTrue(verify_password("Original123", self.stored_user("alice")["password_hash"]))

    def test_only_one_concurrent_submission_can_consume_a_token(self):
        token = self.request_token()
        barrier = Barrier(2)

        def submit(password):
            with TestClient(app, follow_redirects=False) as client:
                barrier.wait(timeout=10)
                response = client.post(
                    f"/reset-password/{token}", data={"new_password": password}
                )
                return response.status_code, password

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, ("Concurrent123", "Concurrent456")))
        self.assertEqual(sorted(status for status, _ in results), [302, 400])
        winner = next(password for status, password in results if status == 302)
        self.assertTrue(verify_password(winner, self.stored_user("alice")["password_hash"]))

    def test_concurrent_requests_leave_only_one_active_link(self):
        barrier = Barrier(2)

        def request_reset(_):
            with TestClient(app, follow_redirects=False) as client:
                barrier.wait(timeout=10)
                return client.post(
                    "/reset-password", data={"email": self.users["alice"]["email"]}
                ).status_code

        with patch("app.routes.auth_routes.send_reset_email") as send:
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(list(pool.map(request_reset, range(2))), [200, 200])
        self.assertEqual(send.call_count, 2)
        statuses = [
            self.client.get(f"/reset-password/{call.args[1]}").status_code
            for call in send.call_args_list
        ]
        self.assertEqual(sorted(statuses), [200, 400])

    def test_password_update_failure_rolls_back_token_consumption(self):
        token = self.request_token()
        with patch("app.password_reset.hash_password", side_effect=RuntimeError("test rollback")):
            with TestClient(app, raise_server_exceptions=False) as client:
                response = client.post(
                    f"/reset-password/{token}", data={"new_password": "Changed456"}
                )
        self.assertEqual(response.status_code, 500)
        self.assertTrue(verify_password("Original123", self.stored_user("alice")["password_hash"]))
        response = self.client.post(
            f"/reset-password/{token}", data={"new_password": "Changed456"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(verify_password("Changed456", self.stored_user("alice")["password_hash"]))

    def test_mail_does_not_print_live_tokens(self):
        from app.email_service import send_reset_email

        token = secrets.token_urlsafe(32)
        with patch("app.email_service.smtplib.SMTP") as smtp, patch("builtins.print") as output:
            send_reset_email(self.users["alice"]["email"], token)
        self.assertNotIn(token, str(output.call_args_list))
        message = smtp.return_value.__enter__.return_value.sendmail.call_args.args[2]
        self.assertIn(f"/reset-password/{token}", message)

    def test_migration_invalidates_old_tokens_and_is_repeatable(self):
        run_query(
            "INSERT INTO password_reset_tokens (user_id, token) VALUES (104, '123456')",
            commit=True,
        )
        migration = Path("migrations/001_password_reset_security.sql").read_text()
        conn = get_conn()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(migration)
                    cur.execute(migration)
        finally:
            conn.close()
        self.assertEqual(
            run_query("SELECT COUNT(*) AS n FROM password_reset_tokens", fetchone=True)["n"], 0
        )
        self.assertEqual(self.stored_user("alice")["email"], self.users["alice"]["email"])
