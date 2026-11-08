"""Minimal FastAPI app protected by Monocle.

    export MONOCLE_SITE_TOKEN=...   MONOCLE_SECRET_KEY=...
    export MONOCLE_COOKIE_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
    uvicorn examples.fastapi_app:app
"""
import os

from fastapi import FastAPI

from spur_monocle import GateConfig
from spur_monocle.asgi import MonocleMiddleware

app = FastAPI()


@app.get("/")
def index():
    return {"message": "you passed the Monocle check"}


@app.get("/healthz")
def health():
    return {"ok": True}


app.add_middleware(
    MonocleMiddleware,
    config=GateConfig(
        site_token=os.environ["MONOCLE_SITE_TOKEN"],
        secret_key=os.environ["MONOCLE_SECRET_KEY"],
        cookie_secret=os.environ["MONOCLE_COOKIE_SECRET"],
        mode="spur-managed",
        exempt_paths=["/healthz"],
        trusted_proxies=int(os.environ.get("TRUSTED_PROXIES", "0")),
    ),
)
