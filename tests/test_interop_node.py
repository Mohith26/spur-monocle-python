"""Cross-language checks against Spur's own stack (run `npm install` in tests/interop first).

* JWE: tokens produced by `jose` (the library @spur.us/monocle-backend uses for local decryption)
  must decrypt here, and tokens from this package's test helper must decrypt in `jose`.
* Cookie: MCLVALID values must be interchangeable with Spur's Express middleware format.
"""
import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from spur_monocle import decrypt_assessment_locally
from spur_monocle.cookie import cookie_is_valid, make_cookie_value

from .helpers import assessment, encrypt, new_key

HERE = Path(__file__).parent / "interop"
pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or not (HERE / "node_modules" / "jose").exists(),
    reason="node + `npm install` in tests/interop required",
)
SECRET = "5e" * 32


def node(*args) -> str:
    return subprocess.run(["node", str(HERE / "interop.mjs"), *args], check=True, capture_output=True,
                          text=True, cwd=HERE).stdout.strip()


@pytest.mark.parametrize("run", range(5))
def test_jose_tokens_decrypt_in_python(run):
    out = json.loads(node("jwe"))
    a = decrypt_assessment_locally(out["token"], out["pem"])
    assert a.id == "jose-1" and a.vpn and a.anon and a.service == "NORD_VPN" and a.ip == "203.0.113.7"


def test_python_tokens_decrypt_in_jose():
    key, pem = new_key()
    token = encrypt(assessment(id="py-1"), key.public_key())
    plain = node("jwe-decrypt", base64.b64encode(pem.encode()).decode(), token)
    assert json.loads(plain)["id"] == "py-1"


def test_cookie_python_to_node_and_back():
    value = make_cookie_value("203.0.113.7", SECRET)
    assert node("cookie-check", value, "203.0.113.7", SECRET) == "true"
    assert node("cookie-check", value, "198.51.100.1", SECRET) == "false"
    node_value = node("cookie-make", "203.0.113.7", SECRET)
    assert cookie_is_valid(node_value, "203.0.113.7", SECRET)
    assert not cookie_is_valid(node_value, "198.51.100.1", SECRET)
