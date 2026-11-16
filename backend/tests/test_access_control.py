from tests.support import SecurityTestCase


class AccessControlTests(SecurityTestCase):
    def test_students_can_only_view_their_own_grades(self):
        for name, own_id, other_id, other_feedback in (
            ("alice", 901, 902, "Bob private feedback"),
            ("bob", 902, 901, "Alice private feedback"),
        ):
            with self.subTest(user=name):
                self.sign_in(name)
                response = self.client.get(f"/grades/{own_id}")
                self.assertEqual(response.status_code, 200)
                self.assertIn(f"{name.title()} private feedback", response.text)
                for grade_id in (other_id, 999999):
                    response = self.client.get(f"/grades/{grade_id}")
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.headers["location"], "/grades")
                    self.assertNotIn(other_feedback, response.text)

    def test_grade_requires_authentication(self):
        response = self.client.get("/grades/901")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/login")

    def test_non_admin_roles_cannot_manage_or_search_users(self):
        for name in ("alice", "bob", "teacher", "ta"):
            self.sign_in(name)
            for path in ("/admin/users", "/admin/search-users?q=alice"):
                with self.subTest(user=name, path=path):
                    response = self.client.get(path, headers={"x-role": "admin"})
                    self.assertEqual(response.status_code, 403)
                    self.assertNotIn("alice@security.test", response.text)
            response = self.client.post(
                f"/admin/users/{self.users[name]['id']}/role",
                data={"role": "admin"},
                headers={"x-role": "admin"},
            )
            self.assertEqual(response.status_code, 403)
            self.assertEqual(self.stored_user(name)["role"], self.users[name]["role"])

    def test_anonymous_user_administration_is_redirected(self):
        for path in ("/admin/users", "/admin/search-users?q=alice"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["location"], "/login")
        response = self.client.post("/admin/users/104/role", data={"role": "admin"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/login")
        self.assertEqual(self.stored_user("alice")["role"], "student")

    def test_admin_can_list_search_and_assign_each_valid_role(self):
        self.sign_in("admin")
        response = self.client.get("/admin/users")
        self.assertEqual(response.status_code, 200)
        self.assertIn("alice@security.test", response.text)
        response = self.client.get("/admin/search-users", params={"q": "aLiCe"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("alice@security.test", response.text)
        self.assertNotIn("bob@security.test", response.text)
        response = self.client.get("/admin/search-users", params={"q": "' OR TRUE -- "})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("alice@security.test", response.text)
        for role in ("ta", "teacher", "admin", "student"):
            response = self.client.post("/admin/users/104/role", data={"role": role})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(self.stored_user("alice")["role"], role)
        response = self.client.post(
            "/admin/users/104/role", data={"role": "superuser"}, headers={"x-role": "admin"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.stored_user("alice")["role"], "student")

    def test_teacher_admin_panel_does_not_offer_user_management(self):
        self.sign_in("teacher")
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('href="/admin/users"', response.text)
        self.assertIn('href="/admin/grades"', response.text)
