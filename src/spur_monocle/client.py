"""Monocle backend clients (sync and async), mirroring @spur.us/monocle-backend."""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Optional

import httpx

from . import __version__
from ._jwe import decrypt_compact, load_private_key
from .errors import MonocleAPIError, MonocleConfigError, MonocleDecryptionError, MonocleRequestError
from .types import MonocleAssessment, MonoclePolicyDecision

BASE_DOMAIN = "mcl.spur.us"
USER_AGENT = f"spur-monocle-python/{__version__}"
DEFAULT_TIMEOUT = 5.0


@lru_cache(maxsize=8)
def _cached_key(pem: str):
    # Parsing a PEM key costs more than the ECDH itself; cache it per process.
    return load_private_key(pem)


def decrypt_assessment_locally(encrypted_assessment: str, private_key_pem: str) -> MonocleAssessment:
    """Decrypt an assessment with your Monocle private key (Enterprise feature), no network call."""
    plaintext = decrypt_compact(encrypted_assessment, _cached_key(private_key_pem))
    try:
        return MonocleAssessment.from_dict(json.loads(plaintext))
    except (ValueError, TypeError) as exc:
        raise MonocleDecryptionError(f"decrypted payload is not an assessment: {exc}") from exc


class _Base:
    def __init__(self, secret_key: str, *, base_domain: str = BASE_DOMAIN, timeout: float = DEFAULT_TIMEOUT):
        if not secret_key:
            raise MonocleConfigError("Missing secret_key.")
        self._secret_key = secret_key
        self.decrypt_api_url = f"https://decrypt.{base_domain}"
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Content-Type": "text/plain; charset=utf-8", "User-Agent": USER_AGENT, "TOKEN": self._secret_key}

    @staticmethod
    def _policy_body(encrypted_assessment: str, options: dict) -> str:
        return json.dumps({"assessment": encrypted_assessment, **options})

    @staticmethod
    def _parse(response: httpx.Response) -> Any:
        if not response.is_success:
            raise MonocleAPIError(response.status_code, response.reason_phrase)
        try:
            return response.json()
        except ValueError as exc:
            raise MonocleRequestError("Monocle API returned invalid JSON") from exc


class MonocleClient(_Base):
    """Synchronous client.

    >>> client = MonocleClient(secret_key=os.environ["MONOCLE_SECRET_KEY"])
    >>> assessment = client.decrypt_assessment(token)
    """

    def __init__(self, secret_key: str, *, base_domain: str = BASE_DOMAIN, timeout: float = DEFAULT_TIMEOUT,
                 http_client: Optional[httpx.Client] = None):
        super().__init__(secret_key, base_domain=base_domain, timeout=timeout)
        self._http = http_client or httpx.Client(timeout=timeout)

    def decrypt_assessment(self, encrypted_assessment: str, *,
                           private_key_pem: Optional[str] = None) -> MonocleAssessment:
        if private_key_pem:
            return decrypt_assessment_locally(encrypted_assessment, private_key_pem)
        try:
            response = self._http.post(f"{self.decrypt_api_url}/api/v1/assessment",
                                       content=encrypted_assessment, headers=self._headers())
        except httpx.HTTPError as exc:
            raise MonocleRequestError(f"Failed to communicate with Monocle API: {exc}") from exc
        return MonocleAssessment.from_dict(self._parse(response))

    def evaluate_assessment(self, encrypted_assessment: str, **options: Any) -> MonoclePolicyDecision:
        try:
            response = self._http.post(f"{self.decrypt_api_url}/api/v1/policy",
                                       content=self._policy_body(encrypted_assessment, options),
                                       headers=self._headers())
        except httpx.HTTPError as exc:
            raise MonocleRequestError(f"Failed to communicate with Monocle API: {exc}") from exc
        return MonoclePolicyDecision.from_dict(self._parse(response))

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class AsyncMonocleClient(_Base):
    """asyncio client with the same API as :class:`MonocleClient`."""

    def __init__(self, secret_key: str, *, base_domain: str = BASE_DOMAIN, timeout: float = DEFAULT_TIMEOUT,
                 http_client: Optional[httpx.AsyncClient] = None):
        super().__init__(secret_key, base_domain=base_domain, timeout=timeout)
        self._http = http_client or httpx.AsyncClient(timeout=timeout)

    async def decrypt_assessment(self, encrypted_assessment: str, *,
                                 private_key_pem: Optional[str] = None) -> MonocleAssessment:
        if private_key_pem:
            return decrypt_assessment_locally(encrypted_assessment, private_key_pem)
        try:
            response = await self._http.post(f"{self.decrypt_api_url}/api/v1/assessment",
                                             content=encrypted_assessment, headers=self._headers())
        except httpx.HTTPError as exc:
            raise MonocleRequestError(f"Failed to communicate with Monocle API: {exc}") from exc
        return MonocleAssessment.from_dict(self._parse(response))

    async def evaluate_assessment(self, encrypted_assessment: str, **options: Any) -> MonoclePolicyDecision:
        try:
            response = await self._http.post(f"{self.decrypt_api_url}/api/v1/policy",
                                             content=self._policy_body(encrypted_assessment, options),
                                             headers=self._headers())
        except httpx.HTTPError as exc:
            raise MonocleRequestError(f"Failed to communicate with Monocle API: {exc}") from exc
        return MonoclePolicyDecision.from_dict(self._parse(response))

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
