import unittest
from urllib.parse import urlparse

from fastapi.testclient import TestClient

from app.auth import create_session, hash_password
from app.config import DATABASE_URL
from app.database import run_query
from app.main import app


class SecurityTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not urlparse(DATABASE_URL).path.endswith("_security_tests"):
            raise RuntimeError("Security tests require a dedicated *_security_tests database.")

    def setUp(self):
        self.client = self.enterContext(TestClient(app, follow_redirects=False))
        run_query("DELETE FROM sessions", commit=True)
        run_query("DELETE FROM password_reset_tokens", commit=True)
        if run_query("SELECT to_regclass('password_reset_limits') AS name", fetchone=True)["name"]:
            run_query("DELETE FROM password_reset_limits", commit=True)
        run_query("DELETE FROM course_comments", commit=True)
        self.users = {}
        for user_id, name, role in (
            (101, "admin", "admin"),
            (102, "teacher", "teacher"),
            (103, "ta", "ta"),
            (104, "alice", "student"),
            (105, "bob", "student"),
        ):
            email = f"{name}@security.test"
            run_query(
                """
                INSERT INTO users (id, email, full_name, password_hash, role)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET password_hash=EXCLUDED.password_hash,
                    role=EXCLUDED.role
                """,
                (user_id, email, name.title(), hash_password("Original123"), role),
                commit=True,
            )
            self.users[name] = {"id": user_id, "email": email, "role": role}
        run_query(
            """
            INSERT INTO courses (id, title, description)
            VALUES (901, 'Security Databases', 'Test course'),
                   (902, 'Web Development', 'Another test course')
            ON CONFLICT (id) DO NOTHING
            """,
            commit=True,
        )
        run_query(
            """
            INSERT INTO assignments (id, course_id, title)
            VALUES (901, 901, 'Security assignment')
            ON CONFLICT (id) DO NOTHING
            """,
            commit=True,
        )
        for grade_id, name, feedback in (
            (901, "alice", "Alice private feedback"),
            (902, "bob", "Bob private feedback"),
        ):
            run_query(
                """
                INSERT INTO grades (id, assignment_id, student_id, grade_value, feedback)
                VALUES (%s, 901, %s, 'A', %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (grade_id, self.users[name]["id"], feedback),
                commit=True,
            )

    def sign_in(self, name):
        self.client.cookies.set("session_token", create_session(self.users[name]["id"]))

    def stored_user(self, name):
        return run_query(
            "SELECT * FROM users WHERE id=%s", (self.users[name]["id"],), fetchone=True
        )
