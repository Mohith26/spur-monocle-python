"""Test helpers: generate Monocle-shaped JWEs (ECDH-ES + A256GCM) the way Spur's servers do."""
import base64
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from spur_monocle._jwe import _concat_kdf


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def new_key(curve=None):
    key = ec.generate_private_key(curve or ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    return key, pem


def public_pem(key) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def encrypt(payload: dict, public_key, alg="ECDH-ES", enc="A256GCM", apu=b"", apv=b""):
    eph = ec.generate_private_key(public_key.curve)
    nums = eph.public_key().public_numbers()
    size = (public_key.curve.key_size + 7) // 8
    header = {"alg": alg, "enc": enc,
              "epk": {"kty": "EC", "crv": {256: "P-256", 384: "P-384", 521: "P-521"}[public_key.curve.key_size],
                      "x": b64u(nums.x.to_bytes(size, "big")), "y": b64u(nums.y.to_bytes(size, "big"))}}
    if apu:
        header["apu"] = b64u(apu)
    if apv:
        header["apv"] = b64u(apv)
    header_b64 = b64u(json.dumps(header, separators=(",", ":")).encode())
    cek = _concat_kdf(eph.exchange(ec.ECDH(), public_key), enc, apu, apv, 256)
    iv = os.urandom(12)
    sealed = AESGCM(cek).encrypt(iv, json.dumps(payload).encode(), header_b64.encode())
    return ".".join([header_b64, "", b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])])


def assessment(**overrides):
    base = {"vpn": False, "proxied": False, "anon": False, "rdp": False, "dch": False, "cc": "US",
            "ip": "203.0.113.7", "ipv6": "", "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "complete": True, "id": "a1b2", "sid": "demo-app"}
    base.update(overrides)
    return base
