"""Build the strictly allowlisted shape-only API payload."""

from __future__ import annotations

import uuid

from .models import CapturedFlow, PacketEvent


SCHEMA_VERSION = "shadowsignal-shape/v2"
MAX_EVENTS_PER_FLOW = 512
MAX_TOTAL_EVENTS = 2_048
MAX_FLOWS = 16
MAX_WINDOW_MS = 180_000
TIME_QUANTUM_MS = 10
SIZE_QUANTUM_BYTES = 32
MAX_SIZE_BYTES = 1_536


def _quantize_time(offset_ms: int) -> int:
    return ((offset_ms + TIME_QUANTUM_MS // 2) // TIME_QUANTUM_MS) * TIME_QUANTUM_MS


def _quantize_size(size: int) -> int:
    rounded_up = ((max(1, size) + SIZE_QUANTUM_BYTES - 1) // SIZE_QUANTUM_BYTES) * SIZE_QUANTUM_BYTES
    return min(MAX_SIZE_BYTES, rounded_up)


def _uniform_sample(events: list[PacketEvent], limit: int) -> list[PacketEvent]:
    if limit <= 0:
        return []
    if len(events) <= limit:
        return events
    if limit == 1:
        return [events[0]]
    last = len(events) - 1
    indexes = [round(index * last / (limit - 1)) for index in range(limit)]
    return [events[index] for index in indexes]


def _sample_events_to_limit(events: list[PacketEvent], limit: int) -> list[PacketEvent]:
    """Limit volume without erasing the less frequent request direction."""
    if len(events) <= limit:
        return events
    outbound = [event for event in events if event.direction == "out"]
    inbound = [event for event in events if event.direction == "in"]
    outbound_limit = min(len(outbound), limit // 4)
    inbound_limit = min(len(inbound), limit - outbound_limit)
    remaining = limit - outbound_limit - inbound_limit
    outbound_limit = min(len(outbound), outbound_limit + remaining)
    remaining = limit - outbound_limit - inbound_limit
    inbound_limit = min(len(inbound), inbound_limit + remaining)
    selected_outbound = _uniform_sample(outbound, outbound_limit)
    selected_inbound = _uniform_sample(inbound, inbound_limit)
    return sorted([*selected_outbound, *selected_inbound], key=lambda event: event.offset_ms)


def build_shape_payload(flow: CapturedFlow, *, observation_id: str | None = None) -> dict:
    return build_session_payload([flow], observation_id=observation_id)


def build_session_payload(
    flows: list[CapturedFlow], *, observation_id: str | None = None
) -> dict:
    """Build one anonymous observation while preserving flow boundaries."""
    populated = [flow for flow in flows if flow.events][:MAX_FLOWS]
    if not populated:
        raise ValueError("at least one packet event is required")
    started_at = min(event.offset_ms for flow in populated for event in flow.events)
    per_flow_limit = min(
        MAX_EVENTS_PER_FLOW,
        max(1, MAX_TOTAL_EVENTS // len(populated)),
    )
    anonymous_flows = []
    for flow in populated:
        ordered = sorted(flow.events, key=lambda event: event.offset_ms)
        selected = [
            event
            for event in ordered
            if 0 <= event.offset_ms - started_at <= MAX_WINDOW_MS
        ]
        if not selected:
            continue
        selected = _sample_events_to_limit(selected, per_flow_limit)
        anonymous_flows.append(
            {
                "transport": "quic" if flow.transport == "quic" else "tcp",
                "events": [
                    {
                        "offset_ms": _quantize_time(event.offset_ms - started_at),
                        "direction": event.direction,
                        "size": _quantize_size(event.size),
                    }
                    for event in selected
                ],
            }
        )
    if not anonymous_flows:
        raise ValueError("at least one packet event is required")
    return {
        "schema_version": SCHEMA_VERSION,
        "observation_id": observation_id or "obs_" + uuid.uuid4().hex,
        "granularity": "l4_segment",
        "grouping": "single_flow" if len(anonymous_flows) == 1 else "flow_set",
        "flows": anonymous_flows,
    }
