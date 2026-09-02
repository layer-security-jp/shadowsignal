"""Authenticated HTTPS client for the ShadowSignal classifier."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

import certifi


DEFAULT_API = "https://shadowsignal-api.layersecurity.jp"


class ShadowSignalAPIError(RuntimeError):
    pass


def configured_api_key() -> str:
    key = os.getenv("SHADOWSIGNAL_API_KEY", "").strip()
    if not key:
        raise ShadowSignalAPIError("SHADOWSIGNAL_API_KEY is required; do not pass API keys on the command line")
    return key


def analyze(payload: dict, *, api_url: str = DEFAULT_API, api_key: str | None = None) -> dict:
    key = api_key or configured_api_key()
    request = urllib.request.Request(
        api_url.rstrip("/") + "/v1/shape-analyses",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "layersecurity-shadowsignal/1.2.0",
        },
        method="POST",
    )
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(request, timeout=20, context=context) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        message = exc.read().decode("utf-8", "replace")[:500]
        raise ShadowSignalAPIError(f"ShadowSignal API returned HTTP {exc.code}: {message}") from exc
    except urllib.error.URLError as exc:
        raise ShadowSignalAPIError(f"ShadowSignal API connection failed: {exc.reason}") from exc
