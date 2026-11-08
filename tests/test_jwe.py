import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from spur_monocle import MonocleDecryptionError, decrypt_assessment_locally
from spur_monocle._jwe import decrypt_compact

from .helpers import assessment, b64u, encrypt, new_key


def test_roundtrip_p256():
    key, pem = new_key()
    token = encrypt(assessment(vpn=True, service="NORD_VPN"), key.public_key())
    a = decrypt_assessment_locally(token, pem)
    assert a.vpn and a.service == "NORD_VPN" and a.ip == "203.0.113.7"


@pytest.mark.parametrize("curve", [ec.SECP384R1(), ec.SECP521R1()])
def test_other_curves(curve):
    key, pem = new_key(curve)
    assert decrypt_assessment_locally(encrypt(assessment(), key.public_key()), pem).complete


def test_apu_apv_are_bound_into_kdf():
    key, _ = new_key()
    token = encrypt({"x": 1}, key.public_key(), apu=b"alice", apv=b"bob")
    assert json.loads(decrypt_compact(token, key)) == {"x": 1}


def test_wrong_key_fails_closed():
    key, _ = new_key()
    _, other_pem = new_key()
    with pytest.raises(MonocleDecryptionError, match="authentication failed"):
        decrypt_assessment_locally(encrypt(assessment(), key.public_key()), other_pem)


@pytest.mark.parametrize("alg,enc", [("ECDH-ES+A256KW", "A256GCM"), ("ECDH-ES", "A128GCM"), ("dir", "A256GCM"),
                                     ("none", "A256GCM")])
def test_disallowed_algorithms(alg, enc):
    key, pem = new_key()
    header = b64u(json.dumps({"alg": alg, "enc": enc}).encode())
    with pytest.raises(MonocleDecryptionError, match="unsupported"):
        decrypt_assessment_locally(f"{header}..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA", pem)


def test_tampered_ciphertext_and_header():
    key, pem = new_key()
    token = encrypt(assessment(), key.public_key())
    h, ek, iv, ct, tag = token.split(".")
    flipped = ct[:-2] + ("A" if ct[-2] != "A" else "B") + ct[-1]
    with pytest.raises(MonocleDecryptionError):
        decrypt_assessment_locally(".".join([h, ek, iv, flipped, tag]), pem)
    # Header is the AAD: re-encoding it (even with the same meaning) must fail authentication.
    hdr = json.loads(__import__("base64").urlsafe_b64decode(h + "=="))
    h2 = b64u(json.dumps(hdr, indent=1).encode())
    with pytest.raises(MonocleDecryptionError):
        decrypt_assessment_locally(".".join([h2, ek, iv, ct, tag]), pem)


def test_off_curve_ephemeral_key_rejected():
    key, pem = new_key()
    token = encrypt(assessment(), key.public_key())
    h, ek, iv, ct, tag = token.split(".")
    hdr = json.loads(__import__("base64").urlsafe_b64decode(h + "=="))
    hdr["epk"]["y"] = b64u((1).to_bytes(32, "big"))
    with pytest.raises(MonocleDecryptionError, match="ephemeral"):
        decrypt_assessment_locally(".".join([b64u(json.dumps(hdr).encode()), ek, iv, ct, tag]), pem)


def test_curve_mismatch_rejected():
    key384, _ = new_key(ec.SECP384R1())
    _, pem256 = new_key()
    with pytest.raises(MonocleDecryptionError, match="curve"):
        decrypt_assessment_locally(encrypt(assessment(), key384.public_key()), pem256)


@pytest.mark.parametrize("token", ["", "a.b.c", "!!!.x.y.z.w", 123])
def test_malformed(token):
    _, pem = new_key()
    with pytest.raises(MonocleDecryptionError):
        decrypt_assessment_locally(token, pem)


def test_bad_pem():
    with pytest.raises(MonocleDecryptionError, match="invalid private key"):
        decrypt_assessment_locally("x.y.z.w.v", "not a pem")


def test_non_object_payload():
    key, pem = new_key()
    from .helpers import encrypt as enc
    token = enc([1, 2, 3], key.public_key())
    with pytest.raises(MonocleDecryptionError, match="not an assessment"):
        decrypt_assessment_locally(token, pem)
