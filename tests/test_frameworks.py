import json

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from spur_monocle import GateConfig
from spur_monocle.asgi import MonocleMiddleware

from .helpers import assessment, encrypt, new_key

SECRET = "ab" * 32


@pytest.fixture
def fastapi_app():
    key, pem = new_key()
    app = FastAPI()

    @app.get("/")
    def index():
        return {"hello": "world"}

    @app.get("/healthz")
    def health():
        return {"ok": True}

    app.add_middleware(MonocleMiddleware, config=GateConfig(
        site_token="site-tok", cookie_secret=SECRET, mode="user-managed", private_key_pem=pem,
        exempt_paths=["/healthz"], secure_cookie=False, check_ip=True))
    return app, key


def test_fastapi_full_flow(fastapi_app):
    app, key = fastapi_app
    client = TestClient(app)  # peer address is "testclient"
    r = client.get("/")
    assert r.status_code == 200 and "mcl.spur.us/d/mcl.js?tk=site-tok" in r.text
    assert client.get("/healthz").json() == {"ok": True}

    token = encrypt(assessment(ip="testclient"), key.public_key())
    r = client.post("/verify-monocle", json={"captchaData": token})
    assert r.status_code == 200 and "MCLVALID" in r.cookies
    assert client.get("/").json() == {"hello": "world"}


def test_fastapi_denied_flow(fastapi_app):
    app, key = fastapi_app
    client = TestClient(app)
    token = encrypt(assessment(ip="testclient", anon=True, vpn=True, service="NORD_VPN"), key.public_key())
    r = client.post("/verify-monocle", json={"captchaData": token})
    assert r.status_code == 403 and r.json()["service"] == "NORD_VPN"
    assert "MCLVALID" not in r.cookies
    assert client.get("/").text.count("mcl.js") == 1  # still challenged
    d = client.get("/denied", params={"service": "NORD_VPN"})
    assert d.status_code == 403 and "NORD_VPN" in d.text


def test_fastapi_rejects_oversized_body(fastapi_app):
    app, _ = fastapi_app
    r = TestClient(app).post("/verify-monocle", content=b"x" * (70 * 1024),
                             headers={"content-type": "application/json"})
    assert r.status_code == 413



def _django_setup(pem):
    import django
    from django.conf import settings
    if not settings.configured:
        settings.configure(
            DEBUG=False, SECRET_KEY="x", ROOT_URLCONF=__name__, ALLOWED_HOSTS=["*"],
            MIDDLEWARE=["spur_monocle.django.MonocleMiddleware"],
            MONOCLE={"site_token": "dj-tok", "cookie_secret": SECRET, "mode": "user-managed",
                     "private_key_pem": pem, "secure_cookie": False},
        )
        django.setup()


def _index(request):
    from django.http import JsonResponse
    return JsonResponse({"hello": "django"})


urlpatterns = []


def test_django_full_flow():
    key, pem = new_key()
    _django_setup(pem)
    from django.test import Client
    from django.urls import path
    urlpatterns[:] = [path("", _index)]

    c = Client(REMOTE_ADDR="203.0.113.7")
    r = c.get("/")
    assert r.status_code == 200 and b"tk=dj-tok" in r.content
    token = encrypt(assessment(ip="203.0.113.7"), key.public_key())
    r = c.post("/verify-monocle", data=json.dumps({"captchaData": token}), content_type="application/json")
    assert r.status_code == 200 and "MCLVALID" in r.cookies
    assert c.get("/").json() == {"hello": "django"}
    # A different client IP replaying the cookie is challenged again.
    other = Client(REMOTE_ADDR="198.51.100.1")
    other.cookies["MCLVALID"] = r.cookies["MCLVALID"].value
    assert b"mcl.js" in other.get("/").content
