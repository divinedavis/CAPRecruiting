"""Exercise the real app against a temporary database and in-memory storage.

Run with the app's virtualenv. Google responses are simulated; a real account's
consent step must still be checked in a browser. No production accounts or mail.
"""
import io
import os
import secrets
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi.testclient import TestClient
from PIL import Image


class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        root = Path(cls.tmp.name)
        repo = Path(__file__).resolve().parent
        (root / "static/.well-known").mkdir(parents=True)
        (root / "static/uploads").mkdir()
        (root / "templates").symlink_to(repo / "templates", target_is_directory=True)
        env = patch.dict(os.environ, {
            "SESSION_SECRET": secrets.token_hex(32), "SPACES_KEY": "test",
            "SPACES_SECRET": "test", "GOOGLE_CLIENT_ID": "test-client",
            "GOOGLE_CLIENT_SECRET": "test-client-secret", "SITE_URL": "https://testserver",
            "SMTP_USER": "", "SMTP_PASSWORD": "", "STRIPE_SECRET_KEY": "",
        })
        env.start()
        cls.addClassCleanup(env.stop)
        source = (repo / "main.py").read_text().replace("/home/recruiting/bearcats", str(root))
        cls.app = types.ModuleType("cap_test_app")
        cls.app.__file__ = str(root / "main.py")
        sys.modules[cls.app.__name__] = cls.app
        exec(compile(source, cls.app.__file__, "exec"), cls.app.__dict__)
        cls.addClassCleanup(cls.app.engine.dispose)
        cls.objects = {}

        def upload(file, bucket, key, **kwargs):
            cls.objects[key] = file.read()

        storage = types.SimpleNamespace(upload_fileobj=upload,
            delete_object=lambda **kw: cls.objects.pop(kw["Key"], None))
        cls.app.s3 = storage
        cls.password = "Regression!" + secrets.token_hex(8)
        with cls.app.SessionLocal() as db:
            for name, role in (("reg_player", "player"), ("reg_coach", "coach")):
                user = cls.app.User(username=name, email=name + "@example.invalid",
                    password_hash=cls.app.hash_password(cls.password), role=role,
                    subscription_tier="premium", public_id=secrets.token_hex(6))
                db.add(user)
                db.flush()
                if role == "player":
                    cls.player_id = user.id
                    db.add(cls.app.PlayerProfile(user_id=user.id, first_name="Regression", last_name="Player"))
                else:
                    cls.coach_id = user.id
                    db.add(cls.app.CoachProfile(user_id=user.id, college="Regression College"))
            lane = cls.app.ScoutBoardLane(college="Regression College", name="Watching")
            db.add(lane)
            db.flush()
            card = cls.app.ScoutBoardCard(college="Regression College", lane_id=lane.id,
                created_by=cls.coach_id, custom_first_name="Regression")
            db.add(card)
            db.commit()
            cls.card_id = card.id
        image = Image.frombytes("RGB", (800, 800), os.urandom(800 * 800 * 3))
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        cls.image = buf.getvalue()
        assert 1024 * 1024 < len(cls.image) < 5 * 1024 * 1024

    def setUp(self):
        self.client = TestClient(self.app.app, base_url="https://testserver", follow_redirects=False,
                                 headers={"Origin": "https://testserver"})
        self.addCleanup(self.client.close)
        # Lockout records are isolated and unrelated between cases.
        with self.app.SessionLocal() as db:
            db.query(self.app.LoginAttempt).delete()
            db.commit()

    def login(self, name="reg_player"):
        response = self.client.post("/login", data={"username": name, "password": self.password})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/dashboard")
        return response

    def test_password_login_cookie_and_authenticated_page(self):
        response = self.login()
        self.assertIn("secure", response.headers["set-cookie"].lower())
        page = self.client.get("/profile/edit")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Regression", page.text)

    def test_invalid_and_overlong_passwords_render_error_without_500(self):
        for password in ("wrong", "x" * 73, "😀" * 19):
            response = self.client.post("/login", data={"username": "reg_player", "password": password})
            self.assertEqual(response.status_code, 200)
            self.assertIn("Invalid username or password", response.text)
            self.assertNotIn("session", self.client.cookies)

    def test_oauth_errors_are_visible_and_unknown_query_is_not_reflected(self):
        page = self.client.get("/login?error=google_state")
        self.assertIn("Google sign-in failed (session expired)", page.text)
        self.assertNotIn("untrusted_marker", self.client.get("/login?error=untrusted_marker").text)

    def test_empty_google_callback_redirects_without_error_logging(self):
        with patch.object(self.app._logger, "error") as error_log:
            response = self.client.get("/auth/google/callback")
        self.assertEqual(response.headers["location"], "/login?error=google_state")
        error_log.assert_not_called()

    def google_start(self):
        response = self.client.get("/auth/google")
        self.assertEqual(response.status_code, 307)
        query = parse_qs(urlsplit(response.headers["location"]).query)
        self.assertEqual(query["redirect_uri"], ["https://testserver/auth/google/callback"])
        self.assertIn("session", self.client.cookies)
        return query["state"][0]

    def test_google_callback_rejects_wrong_state_without_token_exchange(self):
        self.google_start()
        with patch.object(self.app.httpx, "AsyncClient") as client:
            response = self.client.get("/auth/google/callback?state=wrong&code=test")
        self.assertEqual(response.headers["location"], "/login?error=google_state")
        client.assert_not_called()

    def test_google_existing_user_session_and_replay_rejection(self):
        state = self.google_start()
        calls = []

        def provider(request):
            calls.append(request.url.path)
            if request.url.path == "/token":
                return httpx.Response(200, json={"access_token": "test-token"})
            return httpx.Response(200, json={"email": "reg_player@example.invalid", "email_verified": True})

        factory = httpx.AsyncClient
        with patch.object(self.app.httpx, "AsyncClient",
                          side_effect=lambda: factory(transport=httpx.MockTransport(provider))):
            response = self.client.get("/auth/google/callback", params={"state": state, "code": "test-code"})
        self.assertEqual(calls, ["/token", "/oauth2/v2/userinfo"])
        self.assertEqual(response.headers["location"], "/dashboard")
        self.assertIn("Regression", self.client.get("/profile/edit").text)
        replay = self.client.get("/auth/google/callback", params={"state": state, "code": "test-code"})
        self.assertEqual(replay.headers["location"], "/login?error=google_state")

    def test_committed_logo_over_one_mb_is_stored_and_rendered(self):
        self.login()
        response = self.client.post("/profile/upload-committed-logo",
            files={"logo": ("logo.png", self.image, "image/png")})
        self.assertEqual(response.headers.get("location"), "/profile/edit")
        with self.app.SessionLocal() as db:
            url = db.query(self.app.PlayerProfile).filter_by(user_id=self.player_id).one().committed_school_logo
        key = url.removeprefix(self.app.SPACES_BASE_URL + "/")
        Image.open(io.BytesIO(self.objects[key])).verify()
        self.assertIn(url, self.client.get("/profile/edit").text)

    def test_scout_image_over_one_mb_is_stored_and_rendered(self):
        self.login("reg_coach")
        response = self.client.post(f"/dashboard/scout/card/{self.card_id}/image",
            files={"image": ("card.png", self.image, "image/png")})
        self.assertEqual(response.status_code, 200)
        url = response.json()["url"]
        self.assertEqual(self.objects[url.removeprefix(self.app.SPACES_BASE_URL + "/")], self.image)
        with self.app.SessionLocal() as db:
            self.assertEqual(db.get(self.app.ScoutBoardCard, self.card_id).tile_image_url, url)
        self.assertIn(url, self.client.get("/dashboard/scout").text)

    def test_upload_guards_and_non_upload_body_limit(self):
        response = self.client.post(f"/dashboard/scout/card/{self.card_id}/image",
            files={"image": ("card.png", self.image, "image/png")})
        self.assertEqual(response.status_code, 403)
        self.login()
        response = self.client.post("/profile/upload-committed-logo",
            files={"logo": ("logo.png", b"x" * (5 * 1024 * 1024 + 1), "image/png")})
        self.assertIn("logo_error=size", response.headers["location"])
        self.assertIn("school logo is too large", self.client.get(response.headers["location"]).text)
        response = self.client.post("/login", content=b"x" * (1024 * 1024 + 1))
        self.assertEqual(response.status_code, 413)

    def test_storage_failure_is_logged_and_shown_to_user(self):
        self.login()
        with patch.object(self.app.s3, "upload_fileobj", side_effect=OSError("storage unavailable")), \
             patch.object(self.app._logger, "exception") as log:
            response = self.client.post("/profile/upload-committed-logo",
                files={"logo": ("logo.png", self.image, "image/png")})
        log.assert_called_once()
        self.assertIn("logo_error=upload", response.headers["location"])
        self.assertIn("school logo could not be uploaded", self.client.get(response.headers["location"]).text)


if __name__ == "__main__":
    unittest.main()
