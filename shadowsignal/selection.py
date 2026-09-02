"""Choose capture flows that best represent interactive encrypted sessions."""

from __future__ import annotations

from .models import CapturedFlow


def _activity_key(flow: CapturedFlow) -> tuple[int, int, int, int, int]:
    if not flow.events:
        return (0, 0, 0, 0, 0)
    inbound = sum(event.direction == "in" for event in flow.events)
    outbound = len(flow.events) - inbound
    offsets = [event.offset_ms for event in flow.events]
    span_ms = max(offsets) - min(offsets)
    interactive = inbound >= 8 and outbound >= 1 and span_ms >= 1_000
    return (
        int(interactive),
        min(inbound, 64),
        min(span_ms, 120_000),
        int(outbound > 0),
        len(flow.events),
    )


def select_candidate_flows(flows: list[CapturedFlow], *, limit: int) -> list[CapturedFlow]:
    """Prioritize sustained bidirectional flows over short connection bursts."""
    eligible = [flow for flow in flows if flow.events]
    return sorted(eligible, key=_activity_key, reverse=True)[:limit]
