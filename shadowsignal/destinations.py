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

_BROWSER_MARKERS = (
    "chrome",
    "chromium",
    "edge",
    "firefox",
    "safari",
    "webkit",
    "brave",
    "vivaldi",
    "opera",
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


def _attribution_context(
    destination: KnownDestination | None,
    process_name: str | None,
    parent_process: str | None,
) -> tuple[bool, bool]:
    """Return (attribution_confident, trusted_agent_process)."""
    if destination is None:
        return (False, False)
    process = " ".join(
        part.lower() for part in (process_name or "", parent_process or "") if part
    )
    if destination.category == "chat_ui":
        names = {
            (_basename(part) or "").lower()
            for part in (process_name, parent_process)
            if part
        }
        is_arc = any(name == "arc" or name.startswith("arc ") for name in names)
        return (is_arc or any(marker in process for marker in _BROWSER_MARKERS), False)

    trusted_agent = (
        destination.vendor == "Anthropic" and "claude" in process
    ) or (
        destination.vendor == "OpenAI" and "codex" in process
    ) or (
        destination.vendor == "Google" and "gemini" in process
    ) or (
        destination.vendor == "DeepSeek" and "deepseek" in process
    )
    return (trusted_agent, trusted_agent)


def prefer_attributable_flows(flows: list, *, destination_host: str) -> list:
    """Prefer owners compatible with the locally known destination.

    If process attribution is unavailable, retain the original flows so the
    caller can still report access or an inconclusive shape result.
    """
    destination = lookup_destination(destination_host)
    attributable = [
        flow
        for flow in flows
        if _attribution_context(
            destination,
            getattr(flow, "process_name", None),
            getattr(flow, "parent_process", None),
        )[0]
    ]
    return attributable or flows


def final_verdict(
    *,
    known_ai: bool,
    shape_verdict: str,
    sustained_stream: bool = False,
    interaction_triggered: bool = False,
    attribution_confident: bool = False,
    trusted_agent_process: bool = False,
) -> str:
    if known_ai:
        if trusted_agent_process and (
            sustained_stream or shape_verdict == "likely_llm"
        ):
            return "confirmed_ai_usage"
        if attribution_confident and interaction_triggered and (
            sustained_stream or shape_verdict == "likely_llm"
        ):
            return "confirmed_ai_usage"
        if not attribution_confident:
            return "attribution_ambiguous"
        return {
            "likely_llm": "known_ai_access",
            "indeterminate": "known_ai_access",
            "unlikely_llm": "known_ai_background",
        }.get(shape_verdict, "unclassified")
    return {
        "likely_llm": "suspected_shadow_ai" if interaction_triggered else "unclassified",
        "indeterminate": "unclassified",
        "unlikely_llm": "not_detected",
    }.get(shape_verdict, "unclassified")


def describe_local_context(
    *, destination_host: str, process_name: str | None, parent_process: str | None
) -> dict:
    destination = lookup_destination(destination_host)
    attribution_confident, trusted_agent_process = _attribution_context(
        destination, process_name, parent_process
    )
    return {
        "known_ai_destination": destination is not None,
        "destination_host": destination_host.lower().rstrip("."),
        "vendor": destination.vendor if destination else None,
        "product": _local_product(destination, process_name),
        "process_name": _basename(process_name),
        "parent_process": _basename(parent_process),
        "attribution_confident": attribution_confident,
        "trusted_agent_process": trusted_agent_process,
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
    interaction_triggered = api_result.get("interaction_triggered") is True
    return {
        "observation_id": api_result.get("observation_id"),
        "final_verdict": final_verdict(
            known_ai=bool(context["known_ai_destination"]),
            shape_verdict=shape_verdict,
            sustained_stream=sustained_stream,
            interaction_triggered=interaction_triggered,
            attribution_confident=bool(context["attribution_confident"]),
            trusted_agent_process=bool(context["trusted_agent_process"]),
        ),
        "shape_verdict": shape_verdict,
        "confidence": api_result.get("confidence_bucket"),
        "evidence_class": api_result.get("evidence_class"),
        "sustained_stream": sustained_stream,
        "interaction_triggered": interaction_triggered,
        **context,
        "model_version": api_result.get("model_version"),
    }
