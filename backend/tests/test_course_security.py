from unittest.mock import patch

import psycopg2
from fastapi.testclient import TestClient
from markupsafe import escape

from app.database import run_query
from app.main import app
from tests.support import SecurityTestCase


class CourseSecurityTests(SecurityTestCase):
    def test_existing_and_new_comments_are_plain_text(self):
        payload = '<script>alert("XSS")</script><img src=x onerror=alert(1)><b>HELLO</b>'
        run_query(
            "INSERT INTO course_comments (course_id, user_id, content) VALUES (901, 104, %s)",
            (payload,),
            commit=True,
        )
        self.sign_in("bob")
        response = self.client.post("/courses/901/comment", data={"content": payload})
        self.assertEqual(response.status_code, 302)
        response = self.client.get("/courses/901")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(payload, response.text)
        self.assertEqual(response.text.count(escape(payload)), 2)
        self.assertEqual(
            run_query("SELECT COUNT(*) AS n FROM course_comments", fetchone=True)["n"], 2
        )

    def test_search_treats_injection_and_quotes_as_data(self):
        self.sign_in("alice")
        for query in ("' OR TRUE -- ", "'", "'; SELECT pg_sleep(1); --"):
            with self.subTest(query=query):
                response = self.client.get("/courses/search", params={"q": query})
                self.assertEqual(response.status_code, 200)
                self.assertNotIn("Security Databases", response.text)
                self.assertNotIn("Web Development", response.text)
        response = self.client.get("/courses/search", params={"q": "dAtAbAs"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Security Databases", response.text)
        self.assertNotIn("Web Development", response.text)
        response = self.client.get("/courses/search", params={"q": ""})
        self.assertIn("Security Databases", response.text)
        self.assertIn("Web Development", response.text)

    def test_database_errors_do_not_expose_debug_details(self):
        self.sign_in("alice")
        with patch(
            "app.routes.course_routes.run_query",
            side_effect=psycopg2.OperationalError("private database detail"),
        ):
            with TestClient(
                app, raise_server_exceptions=False, cookies=self.client.cookies
            ) as client:
                response = client.get("/courses/search", params={"q": "test"})
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("private database detail", response.text)
        self.assertNotIn("Traceback", response.text)

    def test_anonymous_course_access_is_redirected(self):
        for path in ("/courses/search?q=test", "/courses/901"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["location"], "/login")
        response = self.client.post("/courses/901/comment", data={"content": "Not stored"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            run_query("SELECT COUNT(*) AS n FROM course_comments", fetchone=True)["n"], 0
        )
