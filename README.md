# spur-monocle (unofficial Python SDK for Spur Monocle)

[Spur Monocle](https://spur.us/monocle) detects VPNs, residential proxies and bots in the browser and hands your backend an encrypted assessment. Spur ships backend SDKs and middleware for Node (Express, Next.js), Go, Cloudflare Workers, NGINX, Android and iOS, but nothing for Python. I wrote this so FastAPI, Starlette and Django apps can use Monocle the same way.

This is a community project, not an official Spur SDK. It talks to the same public endpoints as `@spur.us/monocle-backend` and follows the same request contract.

## What's in it

- `MonocleClient` / `AsyncMonocleClient`: decrypt an assessment through Spur's decrypt API, decrypt it **locally** with your private key (Enterprise), or evaluate it against a **Monocle Policy**. Typed results (`MonocleAssessment`, `MonoclePolicyDecision`), explicit timeouts, and distinct errors for API status, network failures and bad tokens.
- Local decryption is a small, strict JWE implementation on top of `cryptography`: it accepts only `ECDH-ES` + `A256GCM` (what Monocle uses), validates the ephemeral key is on the curve, and authenticates the protected header. No network call; about 100 us per assessment on Apple Silicon (see `bench/`).
- `spur_monocle.asgi.MonocleMiddleware` (FastAPI, Starlette, any ASGI app) and `spur_monocle.django.MonocleMiddleware`: the same challenge flow as Spur's Express middleware and Cloudflare worker. Unverified visitors get a challenge page that loads Monocle, the assessment is verified at `/verify-monocle`, and a valid visitor gets an IP-bound, expiring `MCLVALID` cookie.

## Install

```bash
pip install git+https://github.com/Mohith26/spur-monocle-python
```

## Client

```python
from spur_monocle import MonocleClient

client = MonocleClient(secret_key=os.environ["MONOCLE_SECRET_KEY"])

assessment = client.decrypt_assessment(token)                      # via Spur's decrypt API
assessment = client.decrypt_assessment(token, private_key_pem=pem)  # locally (Enterprise)
decision = client.evaluate_assessment(token)                       # Monocle Policy API

if assessment.is_anonymized:
    ...
```

`AsyncMonocleClient` has the same methods as coroutines.

## FastAPI / Starlette

```python
from spur_monocle import GateConfig
from spur_monocle.asgi import MonocleMiddleware

app.add_middleware(MonocleMiddleware, config=GateConfig(
    site_token=os.environ["MONOCLE_SITE_TOKEN"],
    secret_key=os.environ["MONOCLE_SECRET_KEY"],
    cookie_secret=os.environ["MONOCLE_COOKIE_SECRET"],   # 64 hex chars
    mode="spur-managed",            # or "user-managed" (local key) or "policy"
    exempt_paths=["/healthz", "/static/"],
))
```

## Django

```python
MIDDLEWARE = [..., "spur_monocle.django.MonocleMiddleware"]
MONOCLE = {"site_token": ..., "secret_key": ..., "cookie_secret": ..., "mode": "spur-managed"}
```

## Behavior and defaults

| Setting | Default | Notes |
|---|---|---|
| `deny_if` | `assessment.anon` | Any callable on `MonocleAssessment`, e.g. `lambda a: a.vpn or a.dch`. Ignored in `policy` mode, where the Policy decides. |
| `max_age_seconds` | 5 | Rejects replayed or stale assessments. |
| `check_ip` | True | The assessment's IPv4 or IPv6 must match the requesting client. |
| `trusted_proxies` | 0 | `X-Forwarded-For` is ignored unless you say how many proxy hops to trust, so clients cannot spoof their IP. |
| `fail_open` | True | If Spur's API is unreachable or errors, let the visitor through (matches Spur's Cloudflare worker). A token that fails decryption or authentication is always rejected. In `policy` mode a 404 (no policy configured) is an allow. |
| `cookie_ttl` | 3600 | `MCLVALID` is HttpOnly, SameSite=Strict, Secure by default, and bound to the client IP. |

Denials return only `vpn`, `proxied`, `service` and a reason code, not the full assessment.

## How I tested it

```bash
pip install -e ".[dev]" && pytest          # 61 tests
cd tests/interop && npm install && cd ../.. && pytest tests/test_interop_node.py
```

- JWE: round trips on P-256/384/521, wrong key, tampered ciphertext and header, off-curve ephemeral keys, curve mismatch, and disallowed `alg`/`enc` values.
- Interop with Spur's own stack: tokens produced by `jose` (the library `@spur.us/monocle-backend` uses for local decryption) decrypt here, and tokens from this package decrypt in `jose`. `MCLVALID` cookies made here validate with the Express middleware's cookie format and vice versa.
- Client: request shape (`TOKEN` header, raw body, policy JSON body), API errors, timeouts, invalid JSON, custom base domain, and that local decryption makes no network call.
- Middleware: full challenge, verify and pass-through flows in FastAPI and Django, IP-bound cookie replay from another IP, denials, oversized bodies, HTML escaping of the site token and the denied-page service name.

What I have **not** done: run it against a live Monocle application. I don't have a Spur account, so the API paths are tested against the documented contract (mirrored from `@spur.us/monocle-backend`), not real responses.

## License

MIT
