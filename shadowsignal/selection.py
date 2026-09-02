"""Choose capture flows that best represent interactive encrypted sessions."""

from __future__ import annotations

from .models import CapturedFlow


def _request_hint(flow: CapturedFlow) -> bool:
    """Return a loose local hint that a request preceded a response.

    The server remains responsible for the actual shape decision.  This hint
    only prevents a receive-only background flow from outranking the flow that
    contains the user's request.
    """
    ordered = sorted(flow.events, key=lambda event: event.offset_ms)
    for index, event in enumerate(ordered):
        if event.direction != "out" or event.size < 256:
            continue
        following = [
            candidate
            for candidate in ordered[index + 1 :]
            if candidate.offset_ms - event.offset_ms <= 5_000
            and candidate.direction == "in"
        ]
        if len(following) >= 4 and sum(candidate.size for candidate in following) >= 1_024:
            return True
    return False


def _activity_key(flow: CapturedFlow) -> tuple[int, int, int, int, int, int]:
    if not flow.events:
        return (0, 0, 0, 0, 0, 0)
    inbound = sum(event.direction == "in" for event in flow.events)
    outbound = len(flow.events) - inbound
    offsets = [event.offset_ms for event in flow.events]
    span_ms = max(offsets) - min(offsets)
    interactive = inbound >= 8 and outbound >= 1 and span_ms >= 1_000
    return (
        int(_request_hint(flow)),
        int(interactive),
        min(inbound, 64),
        min(span_ms, 120_000),
        int(outbound > 0),
        len(flow.events),
    )


def _owner_key(flow: CapturedFlow) -> tuple[str, str]:
    if flow.process_id is not None:
        return ("pid", str(flow.process_id))
    process = (flow.process_name or "").strip().lower()
    parent = (flow.parent_process or "").strip().lower()
    if process or parent:
        return (process, parent)
    return ("unknown", flow.remote_ip)


def select_candidate_flows(flows: list[CapturedFlow], *, limit: int) -> list[CapturedFlow]:
    """Choose one process owner, then its strongest destination flows.

    DNS-derived CDN addresses are commonly shared by unrelated applications.
    Combining flows from different owners can therefore manufacture an LLM-like
    session that never existed in any one process.
    """
    eligible = [flow for flow in flows if flow.events]
    if not eligible:
        return []
    groups: dict[tuple[str, str], list[CapturedFlow]] = {}
    for flow in eligible:
        groups.setdefault(_owner_key(flow), []).append(flow)
    selected_group = max(
        groups.values(),
        key=lambda group: max(_activity_key(flow) for flow in group),
    )
    return sorted(selected_group, key=_activity_key, reverse=True)[:limit]
