"""Authenticated HTTPS client for the ShadowSignal classifier."""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

import certifi

from . import __version__


DEFAULT_API = "https://shadowsignal-api.layersecurity.jp"
MAX_RESPONSE_BYTES = 64 * 1024
RETRYABLE_STATUS = {429, 502, 503, 504}
VALID_VERDICTS = {"likely_llm", "indeterminate", "unlikely_llm"}
VALID_CONFIDENCE = {"high", "medium", "low"}


class ShadowSignalAPIError(RuntimeError):
    pass


def configured_api_key() -> str:
    key = os.getenv("SHADOWSIGNAL_API_KEY", "").strip()
    if not key:
        raise ShadowSignalAPIError("SHADOWSIGNAL_API_KEY is required; do not pass API keys on the command line")
    return key


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validated_api_base(api_url: str) -> str:
    value = api_url.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ShadowSignalAPIError("API URL must use HTTPS; HTTP is allowed only for loopback testing")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ShadowSignalAPIError("API URL must be a plain HTTPS origin or loopback URL")
    return value


def _open_request(request: urllib.request.Request, *, context: ssl.SSLContext, timeout: float):
    opener = urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirect(),
    )
    return opener.open(request, timeout=timeout)


def _validated_response(raw: bytes, *, observation_id: str) -> dict:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ShadowSignalAPIError("ShadowSignal API returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ShadowSignalAPIError("ShadowSignal API returned an invalid response object")
    if value.get("schema_version") != "shadowsignal-shape-result/v2":
        raise ShadowSignalAPIError("ShadowSignal API returned an unsupported result schema")
    if value.get("observation_id") != observation_id:
        raise ShadowSignalAPIError("ShadowSignal API returned a mismatched observation_id")
    if value.get("verdict") not in VALID_VERDICTS:
        raise ShadowSignalAPIError("ShadowSignal API returned an invalid verdict")
    if value.get("confidence") not in VALID_CONFIDENCE:
        raise ShadowSignalAPIError("ShadowSignal API returned an invalid confidence")
    for field in ("evidence_class", "model_version"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise ShadowSignalAPIError(f"ShadowSignal API returned an invalid {field}")
    for field in ("interaction_count", "analyzed_flows"):
        if not isinstance(value.get(field), int) or isinstance(value.get(field), bool) or value[field] < 0:
            raise ShadowSignalAPIError(f"ShadowSignal API returned an invalid {field}")
    return value


def analyze(
    payload: dict,
    *,
    api_url: str = DEFAULT_API,
    api_key: str | None = None,
    timeout: float = 20,
    retries: int = 2,
) -> dict:
    if payload.get("schema_version") != "shadowsignal-shape/v2":
        raise ShadowSignalAPIError("only shadowsignal-shape/v2 payloads are supported")
    observation_id = payload.get("observation_id")
    if not isinstance(observation_id, str):
        raise ShadowSignalAPIError("payload observation_id is required")
    if not 1 <= timeout <= 120:
        raise ShadowSignalAPIError("timeout must be between 1 and 120 seconds")
    if not 0 <= retries <= 4:
        raise ShadowSignalAPIError("retries must be between 0 and 4")
    key = api_key or configured_api_key()
    base = _validated_api_base(api_url)
    request = urllib.request.Request(
        base + "/v2/shape-analyses",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": f"layersecurity-shadowsignal/{__version__}",
        },
        method="POST",
    )
    context = ssl.create_default_context(cafile=certifi.where())
    for attempt in range(retries + 1):
        try:
            with _open_request(request, timeout=timeout, context=context) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ShadowSignalAPIError("ShadowSignal API response is too large")
                return _validated_response(raw, observation_id=observation_id)
        except urllib.error.HTTPError as exc:
            message = exc.read(501).decode("utf-8", "replace")[:500]
            if exc.code not in RETRYABLE_STATUS or attempt >= retries:
                raise ShadowSignalAPIError(
                    f"ShadowSignal API returned HTTP {exc.code}: {message}"
                ) from exc
            retry_after = exc.headers.get("Retry-After", "1") if exc.headers else "1"
            try:
                delay = max(0.0, min(float(retry_after), 5.0))
            except ValueError:
                delay = 1.0
            time.sleep(delay)
        except urllib.error.URLError as exc:
            if attempt >= retries:
                raise ShadowSignalAPIError(
                    f"ShadowSignal API connection failed: {exc.reason}"
                ) from exc
            time.sleep(min(0.5 * (2**attempt), 2.0))
    raise ShadowSignalAPIError("ShadowSignal API request failed")
