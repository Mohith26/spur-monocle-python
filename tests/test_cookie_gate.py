import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx

from spur_monocle import GateConfig, MonocleClient, MonocleConfigError, MonocleGate
from spur_monocle.cookie import cookie_is_valid, make_cookie_value
from spur_monocle.gate import normalize_ip, resolve_client_ip

from .helpers import assessment, encrypt, new_key

SECRET = "11" * 32
API = "https://decrypt.mcl.spur.us"


def test_cookie_roundtrip_ip_binding_and_expiry():
    v = make_cookie_value("1.2.3.4", SECRET, ttl=60, now=1000)
    assert cookie_is_valid(v, "1.2.3.4", SECRET, now=1059)
    assert not cookie_is_valid(v, "1.2.3.4", SECRET, now=1060)
    assert not cookie_is_valid(v, "5.6.7.8", SECRET, now=1001)
    assert not cookie_is_valid(v, "1.2.3.4", "22" * 32, now=1001)


@pytest.mark.parametrize("bad", ["", "a.b", "zz.zz.zz", "00.00.00", "a.b.c.d"])
def test_cookie_garbage(bad):
    assert not cookie_is_valid(bad, "1.2.3.4", SECRET)


def test_cookie_secret_validation():
    with pytest.raises(MonocleConfigError):
        make_cookie_value("1.2.3.4", "abcd")
    with pytest.raises(MonocleConfigError):
        make_cookie_value("1.2.3.4", "zz" * 32)


def test_resolve_client_ip_ignores_xff_by_default():
    assert resolve_client_ip("10.0.0.1", "6.6.6.6", 0) == "10.0.0.1"
    assert resolve_client_ip("10.0.0.1", "203.0.113.7, 198.51.100.2", 1) == "198.51.100.2"
    assert resolve_client_ip("10.0.0.1", "spoofed, 203.0.113.7", 1) == "203.0.113.7"
    assert resolve_client_ip("10.0.0.1", "203.0.113.7, 198.51.100.2", 2) == "203.0.113.7"
    assert resolve_client_ip("10.0.0.1", "203.0.113.7", 5) == "203.0.113.7"
    assert normalize_ip("::ffff:203.0.113.7") == "203.0.113.7"
    with pytest.raises(MonocleConfigError):
        resolve_client_ip(None, None, 0)


def _cfg(**kw):
    base = dict(site_token="tok", cookie_secret=SECRET, mode="spur-managed", secret_key="sk")
    base.update(kw)
    return GateConfig(**base)


def test_config_validation():
    with pytest.raises(MonocleConfigError):
        _cfg(mode="nope")
    with pytest.raises(MonocleConfigError):
        _cfg(secret_key=None)
    with pytest.raises(MonocleConfigError):
        _cfg(mode="user-managed", private_key_pem=None)
    with pytest.raises(MonocleConfigError):
        _cfg(site_token="")


def test_routing():
    gate = MonocleGate(_cfg(exempt_paths=["/healthz", "/static/"]))
    assert gate.route("/healthz", "GET", None, "1.1.1.1") is None
    assert gate.route("/static/app.js", "GET", None, "1.1.1.1") is None
    assert gate.route("/verify-monocle", "POST", None, "1.1.1.1") == "verify"
    assert gate.route("/denied", "GET", None, "1.1.1.1") == "denied"
    assert gate.route("/", "GET", None, "1.1.1.1") == "challenge"
    good = make_cookie_value("1.1.1.1", SECRET)
    assert gate.route("/", "GET", good, "1.1.1.1") is None
    assert gate.route("/", "GET", good, "9.9.9.9") == "challenge"


def test_challenge_page_escapes_site_token_and_clears_bad_cookie():
    gate = MonocleGate(_cfg(site_token='a"b<c>&d'))
    resp = gate.challenge_response(had_cookie=True)
    assert b"tk=a%22b%3Cc%3E%26d" in resp.body
    assert b'a"b<c>' not in resp.body
    assert "Max-Age=0" in resp.set_cookie


def test_denied_page_escapes_service():
    body = MonocleGate(_cfg()).denied_response("<script>x</script>").body
    assert b"<script>x" not in body and b"&lt;script&gt;" in body


def _user_gate(**kw):
    key, pem = new_key()
    return key, MonocleGate(_cfg(mode="user-managed", secret_key=None, private_key_pem=pem, **kw))


def test_user_managed_allow_sets_cookie():
    key, gate = _user_gate()
    resp = gate.verify(encrypt(assessment(), key.public_key()), "203.0.113.7")
    assert resp.status == 200
    assert resp.set_cookie.startswith("MCLVALID=") and "HttpOnly" in resp.set_cookie and "Secure" in resp.set_cookie
    value = resp.set_cookie.split(";")[0].split("=", 1)[1]
    assert cookie_is_valid(value, "203.0.113.7", SECRET)


@pytest.mark.parametrize("overrides,reason", [
    ({"anon": True, "vpn": True, "service": "NORD_VPN"}, "denied"),
    ({"ip": "198.51.100.9"}, "ip_mismatch"),
    ({"ts": (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()}, "stale_assessment"),
    ({"ts": ""}, "stale_assessment"),
])
def test_user_managed_denials(overrides, reason):
    key, gate = _user_gate()
    resp = gate.verify(encrypt(assessment(**overrides), key.public_key()), "203.0.113.7")
    assert resp.status == 403 and resp.set_cookie is None
    body = json.loads(resp.body)
    assert body["reason"] == reason
    assert "ip" not in body  # the denial does not echo the full assessment back


def test_ipv6_assessment_matches():
    key, gate = _user_gate()
    resp = gate.verify(encrypt(assessment(ip="", ipv6="2001:db8::1"), key.public_key()), "2001:db8::1")
    assert resp.status == 200


def test_custom_deny_rule_and_ip_check_toggle():
    key, gate = _user_gate(deny_if=lambda a: a.vpn or a.dch, check_ip=False)
    assert gate.verify(encrypt(assessment(dch=True), key.public_key()), "1.1.1.1").status == 403
    assert gate.verify(encrypt(assessment(), key.public_key()), "1.1.1.1").status == 200


def test_forged_token_never_fails_open():
    _, gate = _user_gate(fail_open=True)
    other, _ = new_key()
    assert gate.verify(encrypt(assessment(), other.public_key()), "203.0.113.7").status == 403
    assert gate.verify(None, "203.0.113.7").status == 400


@respx.mock
def test_spur_managed_and_fail_open_semantics():
    gate = MonocleGate(_cfg())
    client = MonocleClient("sk")
    respx.post(f"{API}/api/v1/assessment").mock(return_value=httpx.Response(200, json=assessment()))
    assert gate.verify("ENC", "203.0.113.7", client).status == 200
    respx.post(f"{API}/api/v1/assessment").mock(return_value=httpx.Response(502))
    assert gate.verify("ENC", "203.0.113.7", client).status == 200  # fail open (Spur's worker default)
    closed = MonocleGate(_cfg(fail_open=False))
    assert closed.verify("ENC", "203.0.113.7", client).status == 503


@respx.mock
def test_policy_mode():
    gate = MonocleGate(_cfg(mode="policy", fail_open=False))
    client = MonocleClient("sk")
    respx.post(f"{API}/api/v1/policy").mock(return_value=httpx.Response(
        200, json={"allowed": False, "assessment": assessment(), "reason": "geo"}))
    assert gate.verify("ENC", "203.0.113.7", client).status == 403
    respx.post(f"{API}/api/v1/policy").mock(return_value=httpx.Response(
        200, json={"allowed": True, "assessment": assessment(anon=True)}))
    assert gate.verify("ENC", "203.0.113.7", client).status == 200  # policy decides, not deny_if
    respx.post(f"{API}/api/v1/policy").mock(return_value=httpx.Response(404))
    assert gate.verify("ENC", "203.0.113.7", client).status == 200  # no policy configured = allow


def test_extract_token():
    assert MonocleGate.extract_token(b'{"captchaData":"abc"}', "application/json") == "abc"
    assert MonocleGate.extract_token(b"captchaData=abc", "application/x-www-form-urlencoded") == "abc"
    assert MonocleGate.extract_token(b"not json", "application/json") is None
    assert MonocleGate.extract_token(b'{"captchaData": 5}', "application/json") is None
    assert MonocleGate.extract_token(b"", "") is None
