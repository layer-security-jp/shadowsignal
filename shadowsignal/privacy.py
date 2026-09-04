"""Build the strictly allowlisted shape-only API payload."""

from __future__ import annotations

from bisect import bisect_right
import math
import uuid

from .models import CapturedFlow, PacketEvent


SCHEMA_VERSION = "shadowsignal-shape/v2"
FLOW_STATS_SCHEMA_VERSION = "shadowsignal-flow-stats/v2"
MAX_EVENTS_PER_FLOW = 512
MAX_TOTAL_EVENTS = 2_048
MAX_FLOWS = 16
MAX_WINDOW_MS = 180_000
TIME_QUANTUM_MS = 10
SIZE_QUANTUM_BYTES = 32
MAX_SIZE_BYTES = 1_536
REQUEST_BURST_GAP_MS = 400
REQUEST_BURST_MIN_BYTES = 256
RESPONSE_PRESERVATION_MS = 60_000
MAX_EVENTS_PER_RESPONSE_WINDOW = 128
FLOW_COALESCE_MS = 3


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


def _response_sample(events: list[PacketEvent], limit: int) -> list[PacketEvent]:
    """Keep the beginning of a response intact and retain later coverage."""
    if len(events) <= limit:
        return events
    head_limit = max(8, limit // 2)
    head = events[:head_limit]
    return [*head, *_uniform_sample(events[head_limit:], limit - head_limit)]


def _response_windows(
    events: list[PacketEvent],
) -> list[tuple[tuple[int, int, int], list[PacketEvent], list[PacketEvent]]]:
    """Find broad request-followed-by-response regions for loss-aware sampling.

    This is capture preservation, not an LLM decision. It keeps a bounded
    portion of bidirectional activity intact so the server can make that
    decision after long-lived flows are reduced to the API limits.
    """
    outbound = [event for event in events if event.direction == "out"]
    bursts: list[list[PacketEvent]] = []
    for event in outbound:
        if bursts and event.offset_ms - bursts[-1][-1].offset_ms <= REQUEST_BURST_GAP_MS:
            bursts[-1].append(event)
        else:
            bursts.append([event])

    substantial = [
        burst
        for burst in bursts
        if sum(event.size for event in burst) >= REQUEST_BURST_MIN_BYTES
    ]
    inbound = [event for event in events if event.direction == "in"]
    inbound_offsets = [event.offset_ms for event in inbound]
    windows = []
    for index, burst in enumerate(substantial):
        ended_at = burst[-1].offset_ms
        next_request = (
            substantial[index + 1][0].offset_ms
            if index + 1 < len(substantial)
            else ended_at + RESPONSE_PRESERVATION_MS
        )
        deadline = min(ended_at + RESPONSE_PRESERVATION_MS, next_request)
        first = bisect_right(inbound_offsets, ended_at)
        last = bisect_right(inbound_offsets, deadline)
        response = inbound[first:last]
        span = (
            response[-1].offset_ms - response[0].offset_ms
            if len(response) > 1
            else 0
        )
        rank = (
            int(len(response) >= 8 and span >= 1_000),
            min(len(response), 128),
            span,
        )
        windows.append((rank, burst, response))
    return sorted(windows, key=lambda item: item[0], reverse=True)


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
    selected_outbound: list[PacketEvent] = []
    selected_inbound: list[PacketEvent] = []
    selected_ids: set[int] = set()

    for _rank, request, response in _response_windows(events):
        request_remaining = outbound_limit - len(selected_outbound)
        response_remaining = inbound_limit - len(selected_inbound)
        if request_remaining <= 0 or response_remaining <= 0:
            break
        request_additions = [event for event in request if id(event) not in selected_ids]
        if len(request_additions) > request_remaining:
            request_additions = _uniform_sample(request_additions, request_remaining)
        response_additions = [event for event in response if id(event) not in selected_ids]
        response_additions = _response_sample(
            response_additions,
            min(len(response_additions), response_remaining, MAX_EVENTS_PER_RESPONSE_WINDOW),
        )
        for event in [*request_additions, *response_additions]:
            selected_ids.add(id(event))
        selected_outbound.extend(request_additions)
        selected_inbound.extend(response_additions)

    remaining_outbound = [event for event in outbound if id(event) not in selected_ids]
    additions = _uniform_sample(
        remaining_outbound,
        outbound_limit - len(selected_outbound),
    )
    selected_outbound.extend(additions)
    selected_ids.update(id(event) for event in additions)

    remaining_inbound = [event for event in inbound if id(event) not in selected_ids]
    additions = _uniform_sample(
        remaining_inbound,
        inbound_limit - len(selected_inbound),
    )
    selected_inbound.extend(additions)

    original_order = {id(event): index for index, event in enumerate(events)}
    return sorted(
        [*selected_outbound, *selected_inbound],
        key=lambda event: original_order[id(event)],
    )


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


def _bounded_round(value: float, low: int, high: int) -> int:
    return max(low, min(high, int(round(value))))


def _percentile(values: list[int], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    if lower + 1 >= len(ordered):
        return float(ordered[lower])
    return ordered[lower] + (position - lower) * (
        ordered[lower + 1] - ordered[lower]
    )


def _coalesced_inbound(flow: CapturedFlow) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for event in sorted(flow.events, key=lambda item: item.offset_ms):
        if event.direction != "in":
            continue
        if merged and event.offset_ms - merged[-1][0] <= FLOW_COALESCE_MS:
            merged[-1] = (merged[-1][0], merged[-1][1] + event.size)
        else:
            merged.append((event.offset_ms, event.size))
    return merged


def build_flow_stats_payload(
    flow: CapturedFlow, *, observation_id: str | None = None
) -> dict:
    """Reduce one flow to quantized aggregate statistics with no event series."""
    inbound = _coalesced_inbound(flow)
    if len(inbound) < 2:
        raise ValueError("at least two inbound packet events are required")
    timestamps = [timestamp for timestamp, _size in inbound]
    sizes = [size for _timestamp, size in inbound]
    duration_ms = timestamps[-1] - timestamps[0]
    if duration_ms <= 0:
        raise ValueError("inbound packet events must span a positive duration")
    intervals = [
        timestamps[index + 1] - timestamps[index]
        for index in range(len(timestamps) - 1)
    ]
    mean_size = sum(sizes) / len(sizes)
    mean_interval = sum(intervals) / len(intervals)
    size_deviation = math.sqrt(
        sum((size - mean_size) ** 2 for size in sizes) / len(sizes)
    )
    interval_deviation = math.sqrt(
        sum((interval - mean_interval) ** 2 for interval in intervals)
        / len(intervals)
    )
    dribble_run = current_run = 1
    for interval in intervals:
        current_run = current_run + 1 if interval < 1_000 else 1
        dribble_run = max(dribble_run, current_run)
    outbound_bytes = sum(
        event.size for event in flow.events if event.direction == "out"
    )
    inbound_bytes = sum(sizes)
    median_interval_ms = sorted(intervals)[len(intervals) // 2]
    return {
        "schema_version": FLOW_STATS_SCHEMA_VERSION,
        "observation_id": observation_id or "obs_" + uuid.uuid4().hex,
        "transport": "quic" if flow.transport == "quic" else "tcp",
        "inbound_packets": _bounded_round(len(inbound), 1, 10_000),
        "duration_ms": _bounded_round(
            round(duration_ms / 100) * 100, 100, 600_000
        ),
        "median_inbound_size": _bounded_round(
            round(_percentile(sizes, 0.5) / 32) * 32, 32, 65_536
        ),
        "small_packet_ratio_milli": _bounded_round(
            sum(size < 400 for size in sizes) / len(sizes) * 1_000, 0, 1_000
        ),
        "size_cv_milli": _bounded_round(
            (size_deviation / mean_size if mean_size else 0) * 1_000,
            0,
            20_000,
        ),
        "iat_cv_milli": _bounded_round(
            (interval_deviation / mean_interval if mean_interval else 0) * 1_000,
            0,
            20_000,
        ),
        "median_iat_ms": _bounded_round(
            round(median_interval_ms / 10) * 10, 0, 600_000
        ),
        "density_milli": _bounded_round(
            len(inbound) / (duration_ms / 1_000) * 1_000, 0, 500_000
        ),
        "kib_per_second_milli": _bounded_round(
            inbound_bytes / (duration_ms / 1_000) / 1_024 * 1_000,
            0,
            10_000_000,
        ),
        "inbound_outbound_ratio_milli": _bounded_round(
            inbound_bytes / max(outbound_bytes, 200) * 1_000,
            0,
            1_000_000,
        ),
        "dribble_run": _bounded_round(dribble_run, 1, 10_000),
    }
