"""Local-only destination intelligence and split-decision result joining."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnownDestination:
    suffix: str
    vendor: str
    product: str
    category: str


KNOWN_DESTINATIONS = (
    KnownDestination("api.anthropic.com", "Anthropic", "anthropic-api", "api_endpoint"),
    KnownDestination("claude.ai", "Anthropic", "claude", "chat_ui"),
    KnownDestination("api.openai.com", "OpenAI", "openai-api", "api_endpoint"),
    KnownDestination("chatgpt.com", "OpenAI", "chatgpt", "chat_ui"),
    KnownDestination("api.deepseek.com", "DeepSeek", "deepseek-api", "api_endpoint"),
    KnownDestination("generativelanguage.googleapis.com", "Google", "gemini-api", "api_endpoint"),
    KnownDestination("gemini.google.com", "Google", "gemini", "chat_ui"),
)


def _basename(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.replace("\\", "/").rsplit("/", 1)[-1].strip()
    return normalized[:128] or None


def lookup_destination(hostname: str) -> KnownDestination | None:
    normalized = hostname.lower().rstrip(".")
    for destination in KNOWN_DESTINATIONS:
        if normalized == destination.suffix or normalized.endswith("." + destination.suffix):
            return destination
    return None


def _local_product(destination: KnownDestination | None, process_name: str | None) -> str | None:
    process = (_basename(process_name) or "").lower()
    if "claude" in process:
        return "claude-code"
    if "codex" in process:
        return "codex"
    return destination.product if destination else None


def final_verdict(
    *, known_ai: bool, shape_verdict: str, sustained_stream: bool = False
) -> str:
    if known_ai:
        if sustained_stream:
            return "confirmed_ai_usage"
        return {
            "likely_llm": "confirmed_ai_usage",
            "indeterminate": "known_ai_access",
            "unlikely_llm": "known_ai_background",
        }.get(shape_verdict, "unclassified")
    return {
        "likely_llm": "suspected_shadow_ai",
        "indeterminate": "unclassified",
        "unlikely_llm": "not_detected",
    }.get(shape_verdict, "unclassified")


def describe_local_context(
    *, destination_host: str, process_name: str | None, parent_process: str | None
) -> dict:
    destination = lookup_destination(destination_host)
    return {
        "known_ai_destination": destination is not None,
        "destination_host": destination_host.lower().rstrip("."),
        "vendor": destination.vendor if destination else None,
        "product": _local_product(destination, process_name),
        "process_name": _basename(process_name),
        "parent_process": _basename(parent_process),
    }


def join_local_result(
    api_result: dict,
    *,
    destination_host: str,
    process_name: str | None,
    parent_process: str | None,
) -> dict:
    context = describe_local_context(
        destination_host=destination_host,
        process_name=process_name,
        parent_process=parent_process,
    )
    shape_verdict = str(api_result.get("shape_verdict", "indeterminate"))
    sustained_stream = api_result.get("sustained_stream") is True
    return {
        "observation_id": api_result.get("observation_id"),
        "final_verdict": final_verdict(
            known_ai=bool(context["known_ai_destination"]),
            shape_verdict=shape_verdict,
            sustained_stream=sustained_stream,
        ),
        "shape_verdict": shape_verdict,
        "confidence": api_result.get("confidence_bucket"),
        "evidence_class": api_result.get("evidence_class"),
        "sustained_stream": sustained_stream,
        **context,
        "model_version": api_result.get("model_version"),
    }
