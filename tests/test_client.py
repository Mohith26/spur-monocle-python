import json

import httpx
import pytest
import respx

from spur_monocle import AsyncMonocleClient, MonocleAPIError, MonocleClient, MonocleConfigError, MonocleRequestError

from .helpers import assessment, encrypt, new_key

API = "https://decrypt.mcl.spur.us"


def test_requires_secret_key():
    with pytest.raises(MonocleConfigError):
        MonocleClient("")


@respx.mock
def test_decrypt_via_api_sends_token_header_and_raw_body():
    route = respx.post(f"{API}/api/v1/assessment").mock(return_value=httpx.Response(200, json=assessment(vpn=True)))
    with MonocleClient("sk_test") as c:
        a = c.decrypt_assessment("ENCRYPTED")
    req = route.calls.last.request
    assert req.headers["TOKEN"] == "sk_test"
    assert req.headers["content-type"].startswith("text/plain")
    assert req.headers["user-agent"].startswith("spur-monocle-python/")
    assert req.content == b"ENCRYPTED"
    assert a.vpn is True


@respx.mock
def test_policy_body_and_decision():
    route = respx.post(f"{API}/api/v1/policy").mock(return_value=httpx.Response(
        200, json={"allowed": False, "assessment": assessment(proxied=True), "decisionId": "d1", "reason": "proxy"}))
    d = MonocleClient("sk").evaluate_assessment("ENC", userId="u1")
    assert json.loads(route.calls.last.request.content) == {"assessment": "ENC", "userId": "u1"}
    assert d.allowed is False and d.decision_id == "d1" and d.assessment.proxied


@respx.mock
def test_api_error_status():
    respx.post(f"{API}/api/v1/assessment").mock(return_value=httpx.Response(401))
    with pytest.raises(MonocleAPIError) as e:
        MonocleClient("sk").decrypt_assessment("x")
    assert e.value.status == 401


@respx.mock
def test_network_error_and_bad_json():
    respx.post(f"{API}/api/v1/assessment").mock(side_effect=httpx.ConnectTimeout("t"))
    with pytest.raises(MonocleRequestError):
        MonocleClient("sk").decrypt_assessment("x")
    respx.post(f"{API}/api/v1/policy").mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(MonocleRequestError):
        MonocleClient("sk").evaluate_assessment("x")


@respx.mock
def test_custom_base_domain():
    url = "https://decrypt.example.test/api/v1/assessment"
    respx.post(url).mock(return_value=httpx.Response(200, json=assessment()))
    assert MonocleClient("sk", base_domain="example.test").decrypt_assessment("x").complete


def test_local_decrypt_makes_no_network_call():
    key, pem = new_key()
    with respx.mock(assert_all_called=False) as router:
        a = MonocleClient("sk").decrypt_assessment(encrypt(assessment(), key.public_key()), private_key_pem=pem)
        assert not router.calls
    assert a.sid == "demo-app"


def test_unknown_fields_kept_in_extra():
    from spur_monocle import MonocleAssessment
    a = MonocleAssessment.from_dict({**assessment(), "new_field": 1})
    assert a.extra == {"new_field": 1}


@respx.mock
async def test_async_client():
    respx.post(f"{API}/api/v1/assessment").mock(return_value=httpx.Response(200, json=assessment(anon=True)))
    respx.post(f"{API}/api/v1/policy").mock(return_value=httpx.Response(200, json={"allowed": True,
                                                                                   "assessment": assessment()}))
    async with AsyncMonocleClient("sk") as c:
        assert (await c.decrypt_assessment("x")).anon
        assert (await c.evaluate_assessment("x")).allowed
    respx.post(f"{API}/api/v1/assessment").mock(return_value=httpx.Response(500))
    with pytest.raises(MonocleAPIError):
        await AsyncMonocleClient("sk").decrypt_assessment("x")
