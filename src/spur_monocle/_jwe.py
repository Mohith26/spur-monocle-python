"""Compact JWE decryption for Monocle assessments (ECDH-ES + A256GCM, RFC 7516/7518).

Only the algorithm pair Monocle uses is accepted, so a token cannot downgrade the
key agreement or content encryption. Implemented on ``cryptography`` primitives.
"""
from __future__ import annotations

import base64
import json
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from .errors import MonocleDecryptionError

ALLOWED_ALG = "ECDH-ES"
ALLOWED_ENC = "A256GCM"
_CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def load_private_key(pem: str | bytes) -> ec.EllipticCurvePrivateKey:
    """Load a PKCS#8 (or SEC1) PEM EC private key."""
    if isinstance(pem, str):
        pem = pem.encode()
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise MonocleDecryptionError(f"invalid private key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise MonocleDecryptionError("private key must be an EC key")
    return key


def _lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _concat_kdf(z: bytes, enc: str, apu: bytes, apv: bytes, key_bits: int) -> bytes:
    other_info = _lp(enc.encode()) + _lp(apu) + _lp(apv) + struct.pack(">I", key_bits)
    return ConcatKDFHash(algorithm=hashes.SHA256(), length=key_bits // 8, otherinfo=other_info).derive(z)


def decrypt_compact(token: str, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Decrypt a compact-serialized JWE and return the plaintext bytes."""
    if not isinstance(token, str):
        raise MonocleDecryptionError("token must be a string")
    parts = token.strip().split(".")
    if len(parts) != 5:
        raise MonocleDecryptionError("not a compact JWE (expected 5 parts)")
    header_b64, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        iv = b64url_decode(iv_b64)
        ciphertext = b64url_decode(ciphertext_b64)
        tag = b64url_decode(tag_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise MonocleDecryptionError(f"malformed JWE: {exc}") from exc
    if not isinstance(header, dict):
        raise MonocleDecryptionError("malformed JWE header")
    if header.get("alg") != ALLOWED_ALG or header.get("enc") != ALLOWED_ENC:
        raise MonocleDecryptionError(
            f"unsupported JWE algorithms alg={header.get('alg')!r} enc={header.get('enc')!r}"
        )
    if encrypted_key_b64:
        raise MonocleDecryptionError("ECDH-ES (direct) tokens must have an empty encrypted key")
    if "zip" in header:
        raise MonocleDecryptionError("compressed JWE payloads are not supported")
    if len(iv) != 12 or len(tag) != 16:
        raise MonocleDecryptionError("invalid IV or tag length for A256GCM")

    epk = header.get("epk") or {}
    curve = _CURVES.get(epk.get("crv", ""))
    if epk.get("kty") != "EC" or curve is None:
        raise MonocleDecryptionError("missing or unsupported ephemeral public key")
    if curve.name != private_key.curve.name:
        raise MonocleDecryptionError("ephemeral key curve does not match the private key")
    try:
        x = int.from_bytes(b64url_decode(epk["x"]), "big")
        y = int.from_bytes(b64url_decode(epk["y"]), "big")
        # Construction validates that the point is on the curve (invalid-curve attack defense).
        peer = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
        z = private_key.exchange(ec.ECDH(), peer)
    except (KeyError, ValueError) as exc:
        raise MonocleDecryptionError(f"invalid ephemeral public key: {exc}") from exc

    apu = b64url_decode(header["apu"]) if header.get("apu") else b""
    apv = b64url_decode(header["apv"]) if header.get("apv") else b""
    cek = _concat_kdf(z, ALLOWED_ENC, apu, apv, 256)
    try:
        return AESGCM(cek).decrypt(iv, ciphertext + tag, header_b64.encode("ascii"))
    except InvalidTag as exc:
        raise MonocleDecryptionError("JWE authentication failed (wrong key or tampered token)") from exc
