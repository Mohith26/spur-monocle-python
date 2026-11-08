"""Pure ASGI middleware (FastAPI, Starlette, Quart, Litestar, Django ASGI...).

    app.add_middleware(MonocleMiddleware, config=GateConfig(...))   # FastAPI / Starlette
    app = MonocleMiddleware(app, config=GateConfig(...))              # any ASGI app
"""
from __future__ import annotations

from http.cookies import CookieError, SimpleCookie
from typing import Optional
from urllib.parse import parse_qs

from .client import AsyncMonocleClient
from .cookie import COOKIE_NAME
from .errors import MonocleConfigError
from .gate import GateConfig, MonocleGate, Response, resolve_client_ip

MAX_BODY = 64 * 1024


def _header(scope, name: bytes) -> Optional[str]:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return value.decode("latin-1")
    return None


def _cookie(scope) -> Optional[str]:
    raw = _header(scope, b"cookie")
    if not raw:
        return None
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except CookieError:
        return None
    morsel = jar.get(COOKIE_NAME)
    return morsel.value if morsel else None


class MonocleMiddleware:
    def __init__(self, app, config: GateConfig, client: Optional[AsyncMonocleClient] = None):
        self.app = app
        self.gate = MonocleGate(config)
        self.client = client
        if client is None and config.mode != "user-managed":
            assert config.secret_key is not None
            self.client = AsyncMonocleClient(config.secret_key)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        peer = (scope.get("client") or (None, None))[0]
        try:
            ip = resolve_client_ip(peer, _header(scope, b"x-forwarded-for"), self.gate.config.trusted_proxies)
        except MonocleConfigError:
            await self._send(send, Response(400, b"client address unavailable", "text/plain"))
            return
        cookie = _cookie(scope)
        action = self.gate.route(scope.get("path", "/"), scope.get("method", "GET"), cookie, ip)
        if action is None:
            await self.app(scope, receive, send)
        elif action == "verify":
            body = await self._read_body(receive)
            if body is None:
                await self._send(send, Response(413, b"body too large", "text/plain"))
                return
            token = MonocleGate.extract_token(body, _header(scope, b"content-type") or "")
            await self._send(send, await self.gate.averify(token, ip, self.client))
        elif action == "denied":
            qs = parse_qs(scope.get("query_string", b"").decode("latin-1"))
            await self._send(send, self.gate.denied_response((qs.get("service") or [""])[0]))
        else:
            await self._send(send, self.gate.challenge_response(had_cookie=cookie is not None))

    @staticmethod
    async def _read_body(receive) -> Optional[bytes]:
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            chunk = message.get("body", b"")
            size += len(chunk)
            if size > MAX_BODY:
                return None
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(chunks)

    @staticmethod
    async def _send(send, resp: Response) -> None:
        headers = [(b"content-type", resp.content_type.encode()), (b"content-length", str(len(resp.body)).encode()),
                   (b"cache-control", b"no-store")]
        if resp.set_cookie:
            headers.append((b"set-cookie", resp.set_cookie.encode("latin-1")))
        await send({"type": "http.response.start", "status": resp.status, "headers": headers})
        await send({"type": "http.response.body", "body": resp.body})
