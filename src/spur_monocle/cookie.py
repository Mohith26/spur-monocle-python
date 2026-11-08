"""The MCLVALID session cookie.

Format (compatible with Spur's Express middleware and Cloudflare worker):
``hex(iv) . hex(ciphertext) . hex(tag)``, AES-256-GCM over ``"<client ip>|<unix expiry>"``.
The cookie is bound to the client IP and expires (default one hour).
"""
from __future__ import annotations

import os
import time
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import MonocleConfigError

COOKIE_NAME = "MCLVALID"
DEFAULT_TTL = 3600


def _key(cookie_secret: str) -> bytes:
    try:
        key = bytes.fromhex(cookie_secret)
    except ValueError as exc:
        raise MonocleConfigError("cookie_secret must be hex (64 hex chars for AES-256)") from exc
    if len(key) != 32:
        raise MonocleConfigError("cookie_secret must decode to 32 bytes (64 hex chars)")
    return key


def validate_cookie_secret(cookie_secret: str) -> None:
    _key(cookie_secret)


def make_cookie_value(client_ip: str, cookie_secret: str, *, ttl: int = DEFAULT_TTL,
                      now: Optional[float] = None) -> str:
    expiry = int(now if now is not None else time.time()) + ttl
    iv = os.urandom(12)
    sealed = AESGCM(_key(cookie_secret)).encrypt(iv, f"{client_ip}|{expiry}".encode(), None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return f"{iv.hex()}.{ciphertext.hex()}.{tag.hex()}"


def cookie_is_valid(value: str, client_ip: str, cookie_secret: str, *, now: Optional[float] = None) -> bool:
    try:
        iv_hex, ct_hex, tag_hex = value.split(".")
        iv, ct, tag = bytes.fromhex(iv_hex), bytes.fromhex(ct_hex), bytes.fromhex(tag_hex)
        if len(iv) != 12 or len(tag) != 16:
            return False
        plain = AESGCM(_key(cookie_secret)).decrypt(iv, ct + tag, None).decode()
        cookie_ip, expiry = plain.rsplit("|", 1)
        expiry_ts = int(expiry)
    except (ValueError, InvalidTag, UnicodeDecodeError):
        return False
    current = now if now is not None else time.time()
    return cookie_ip == client_ip and current < expiry_ts
