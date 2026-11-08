"""Framework-agnostic Monocle gate: the logic shared by the ASGI and Django middleware.

Flow (same as Spur's Express middleware and Cloudflare worker):
1. A request without a valid ``MCLVALID`` cookie gets the challenge page, which loads
   Monocle's script and POSTs the encrypted assessment to ``verify_path``.
2. ``verify_path`` decrypts or policy-evaluates the assessment, checks freshness, IP
   binding and your deny rule, then sets an IP-bound, expiring ``MCLVALID`` cookie.
3. Later requests with a valid cookie pass straight through.
"""
from __future__ import annotations

import html
import ipaddress
import json
from dataclasses import dataclass, field
from importlib import resources
from string import Template
from typing import Callable, Optional, Sequence
from urllib.parse import quote

from .client import AsyncMonocleClient, MonocleClient, decrypt_assessment_locally
from .cookie import COOKIE_NAME, DEFAULT_TTL, cookie_is_valid, make_cookie_value, validate_cookie_secret
from .errors import MonocleAPIError, MonocleConfigError, MonocleDecryptionError, MonocleRequestError
from .types import MonocleAssessment

MODES = ("spur-managed", "user-managed", "policy")


def deny_anonymized(assessment: MonocleAssessment) -> bool:
    """Default deny rule: block traffic Monocle marks as anonymizing infrastructure."""
    return assessment.anon


def normalize_ip(ip: str) -> str:
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def resolve_client_ip(peer_ip: Optional[str], forwarded_for: Optional[str], trusted_proxies: int) -> str:
    """Client IP from the socket peer, honoring ``X-Forwarded-For`` only for ``trusted_proxies`` hops.

    With ``trusted_proxies=0`` (default) the header is ignored, so clients cannot spoof it.
    With N trusted proxies, the address N hops from the right of ``XFF + [peer]`` is used.
    """
    peer = normalize_ip(peer_ip or "")
    if trusted_proxies <= 0 or not forwarded_for:
        if not peer:
            raise MonocleConfigError("client IP address is not available")
        return peer
    chain = [normalize_ip(p) for p in forwarded_for.split(",") if p.strip()]
    if peer:
        chain.append(peer)
    index = max(0, len(chain) - 1 - trusted_proxies)
    return chain[index]


@dataclass
class GateConfig:
    site_token: str
    cookie_secret: str
    mode: str = "spur-managed"
    secret_key: Optional[str] = None
    private_key_pem: Optional[str] = None
    deny_if: Callable[[MonocleAssessment], bool] = deny_anonymized
    max_age_seconds: float = 5.0
    check_ip: bool = True
    fail_open: bool = True
    trusted_proxies: int = 0
    verify_path: str = "/verify-monocle"
    denied_path: str = "/denied"
    exempt_paths: Sequence[str] = field(default_factory=tuple)
    cookie_ttl: int = DEFAULT_TTL
    secure_cookie: bool = True
    challenge_status: int = 200

    def __post_init__(self):
        if not self.site_token:
            raise MonocleConfigError("site_token is required")
        validate_cookie_secret(self.cookie_secret)
        if self.mode not in MODES:
            raise MonocleConfigError(f"mode must be one of {MODES}")
        if self.mode in ("spur-managed", "policy") and not self.secret_key:
            raise MonocleConfigError(f"secret_key is required for mode {self.mode!r}")
        if self.mode == "user-managed" and not self.private_key_pem:
            raise MonocleConfigError("private_key_pem is required for mode 'user-managed'")


@dataclass
class Response:
    status: int
    body: bytes
    content_type: str
    set_cookie: Optional[str] = None


def _json(status: int, payload: dict) -> Response:
    return Response(status, json.dumps(payload).encode(), "application/json")


def _template(name: str) -> Template:
    return Template(resources.files("spur_monocle").joinpath("templates", name).read_text(encoding="utf-8"))


class MonocleGate:
    def __init__(self, config: GateConfig):
        self.config = config
        self._challenge = _template("challenge.html").substitute(
            site_token_url=quote(config.site_token, safe=""),
            verify_path=html.escape(json.dumps(config.verify_path)[1:-1]),
            denied_path=html.escape(json.dumps(config.denied_path)[1:-1]),
        ).encode()
        self._denied = _template("denied.html")

    # ---- routing -------------------------------------------------------------
    def is_exempt(self, path: str) -> bool:
        return any(path == p or (p.endswith("/") and path.startswith(p)) for p in self.config.exempt_paths)

    def route(self, path: str, method: str, cookie_value: Optional[str], client_ip: str) -> Optional[str]:
        """Return None to pass the request through, else one of "verify", "denied", "challenge"."""
        if self.is_exempt(path):
            return None
        if path == self.config.verify_path and method == "POST":
            return "verify"
        if path == self.config.denied_path:
            return "denied"
        if cookie_value and cookie_is_valid(cookie_value, client_ip, self.config.cookie_secret):
            return None
        return "challenge"

    def challenge_response(self, had_cookie: bool) -> Response:
        resp = Response(self.config.challenge_status, self._challenge, "text/html; charset=utf-8")
        if had_cookie:  # invalid or expired cookie: clear it
            resp.set_cookie = f"{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        return resp

    def denied_response(self, service: str = "") -> Response:
        body = self._denied.substitute(service=html.escape(service[:100] or "an anonymizing service"))
        return Response(403, body.encode(), "text/html; charset=utf-8")

    # ---- verification --------------------------------------------------------
    def _cookie_header(self, client_ip: str) -> str:
        value = make_cookie_value(client_ip, self.config.cookie_secret, ttl=self.config.cookie_ttl)
        secure = "; Secure" if self.config.secure_cookie else ""
        return f"{COOKIE_NAME}={value}; Path=/; Max-Age={self.config.cookie_ttl}; HttpOnly; SameSite=Strict{secure}"

    def _allow(self, client_ip: str) -> Response:
        resp = _json(200, {"ok": True})
        resp.set_cookie = self._cookie_header(client_ip)
        return resp

    def _judge(self, assessment: MonocleAssessment, client_ip: str, policy_allowed: Optional[bool] = None) -> Response:
        age = assessment.age_seconds()
        denied_body = {"vpn": assessment.vpn, "proxied": assessment.proxied, "service": assessment.service or ""}
        if age is None or age > self.config.max_age_seconds:
            return _json(403, {**denied_body, "reason": "stale_assessment"})
        if self.config.check_ip and client_ip not in {normalize_ip(assessment.ip), normalize_ip(assessment.ipv6)}:
            return _json(403, {**denied_body, "reason": "ip_mismatch"})
        if policy_allowed is False or (policy_allowed is None and self.config.deny_if(assessment)):
            return _json(403, {**denied_body, "reason": "denied"})
        return self._allow(client_ip)

    def _on_api_error(self, exc: Exception, client_ip: str) -> Response:
        if isinstance(exc, MonocleAPIError) and exc.status == 404 and self.config.mode == "policy":
            return self._allow(client_ip)  # no policy configured is a normal allow
        if self.config.fail_open:
            return self._allow(client_ip)
        return _json(503, {"reason": "monocle_unavailable"})

    @staticmethod
    def extract_token(body: bytes, content_type: str) -> Optional[str]:
        if not body:
            return None
        if "application/x-www-form-urlencoded" in (content_type or ""):
            from urllib.parse import parse_qs

            values = parse_qs(body.decode("utf-8", "replace")).get("captchaData")
            return values[0] if values else None
        try:
            data = json.loads(body)
        except ValueError:
            return None
        token = data.get("captchaData") if isinstance(data, dict) else None
        return token if isinstance(token, str) and token else None

    def verify(self, token: Optional[str], client_ip: str, client: Optional[MonocleClient] = None) -> Response:
        if not token:
            return _json(400, {"reason": "missing_captchaData"})
        cfg = self.config
        try:
            if cfg.mode == "user-managed":
                assert cfg.private_key_pem is not None
                return self._judge(decrypt_assessment_locally(token, cfg.private_key_pem), client_ip)
            assert client is not None
            if cfg.mode == "policy":
                decision = client.evaluate_assessment(token)
                return self._judge(decision.assessment, client_ip, policy_allowed=decision.allowed)
            return self._judge(client.decrypt_assessment(token), client_ip)
        except MonocleDecryptionError:
            return _json(403, {"reason": "invalid_assessment"})  # never fail open on a forged token
        except (MonocleAPIError, MonocleRequestError) as exc:
            return self._on_api_error(exc, client_ip)

    async def averify(self, token: Optional[str], client_ip: str,
                      client: Optional[AsyncMonocleClient] = None) -> Response:
        if not token:
            return _json(400, {"reason": "missing_captchaData"})
        cfg = self.config
        try:
            if cfg.mode == "user-managed":
                assert cfg.private_key_pem is not None
                return self._judge(decrypt_assessment_locally(token, cfg.private_key_pem), client_ip)
            assert client is not None
            if cfg.mode == "policy":
                decision = await client.evaluate_assessment(token)
                return self._judge(decision.assessment, client_ip, policy_allowed=decision.allowed)
            return self._judge(await client.decrypt_assessment(token), client_ip)
        except MonocleDecryptionError:
            return _json(403, {"reason": "invalid_assessment"})
        except (MonocleAPIError, MonocleRequestError) as exc:
            return self._on_api_error(exc, client_ip)
