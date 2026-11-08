"""Django middleware.

settings.py::

    MIDDLEWARE = [..., "spur_monocle.django.MonocleMiddleware"]
    MONOCLE = {
        "site_token": os.environ["MONOCLE_SITE_TOKEN"],
        "secret_key": os.environ["MONOCLE_SECRET_KEY"],
        "cookie_secret": os.environ["MONOCLE_COOKIE_SECRET"],  # 64 hex chars
        "mode": "spur-managed",   # or "user-managed" / "policy"
        "exempt_paths": ["/healthz", "/static/"],
    }
"""
from __future__ import annotations

from http.cookies import SimpleCookie

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse

from .client import MonocleClient
from .cookie import COOKIE_NAME
from .errors import MonocleConfigError
from .gate import GateConfig, MonocleGate, Response, resolve_client_ip


def _to_django(resp: Response) -> HttpResponse:
    out = HttpResponse(resp.body, status=resp.status, content_type=resp.content_type)
    out["Cache-Control"] = "no-store"
    if resp.set_cookie:
        # Re-emit through Django's cookie API so other middleware and the test client see it.
        jar = SimpleCookie()
        jar.load(resp.set_cookie)
        morsel = jar[COOKIE_NAME]
        out.set_cookie(COOKIE_NAME, morsel.value, max_age=int(morsel["max-age"] or 0), path=morsel["path"] or "/",
                       secure=bool(morsel["secure"]), httponly=True, samesite="Strict")
    return out


class MonocleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        options = getattr(settings, "MONOCLE", None)
        if not options:
            raise ImproperlyConfigured("settings.MONOCLE is required for spur_monocle.django.MonocleMiddleware")
        try:
            self.gate = MonocleGate(GateConfig(**options))
        except MonocleConfigError as exc:
            raise ImproperlyConfigured(str(exc)) from exc
        key = self.gate.config.secret_key
        self.client = MonocleClient(key) if key and self.gate.config.mode != "user-managed" else None

    def __call__(self, request):
        try:
            ip = resolve_client_ip(request.META.get("REMOTE_ADDR"), request.META.get("HTTP_X_FORWARDED_FOR"),
                                   self.gate.config.trusted_proxies)
        except MonocleConfigError:
            return HttpResponse("client address unavailable", status=400)
        cookie = request.COOKIES.get(COOKIE_NAME)
        action = self.gate.route(request.path, request.method, cookie, ip)
        if action is None:
            return self.get_response(request)
        if action == "verify":
            token = MonocleGate.extract_token(request.body, request.content_type or "")
            return _to_django(self.gate.verify(token, ip, self.client))
        if action == "denied":
            return _to_django(self.gate.denied_response(request.GET.get("service", "")))
        return _to_django(self.gate.challenge_response(had_cookie=cookie is not None))
