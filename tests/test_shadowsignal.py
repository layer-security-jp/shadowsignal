from __future__ import annotations

import ipaddress
import io
import signal
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from shadowsignal import api, capture, dashboard
from shadowsignal.cli import synthetic_flow
from shadowsignal.destinations import final_verdict, join_local_result, prefer_attributable_flows
from shadowsignal.models import CapturedFlow, PacketEvent
from shadowsignal.pcapng import _tls_server_name, parse_pcapng
from shadowsignal.pcap import parse_pcap
from shadowsignal.privacy import build_session_payload, build_shape_payload
from shadowsignal.selection import select_candidate_flows


FORBIDDEN_FIELDS = {
    "payload",
    "prompt",
    "response",
    "content",
    "source_ip",
    "source_port",
    "username",
    "file_path",
    "destination_host",
    "destination_ip",
    "destination_port",
    "process_name",
    "parent_process",
    "device_id",
    "flow_id",
    "known_ai_match",
    "server_name",
    "sni",
}


def test_payload_contains_only_allowlisted_top_level_fields() -> None:
    payload = build_shape_payload(
        synthetic_flow(), observation_id="obs_0123456789abcdef0123456789abcdef"
    )
    assert set(payload) == {
        "schema_version",
        "observation_id",
        "granularity",
        "grouping",
        "flows",
    }
    assert not (set(payload) & FORBIDDEN_FIELDS)
    assert payload["schema_version"] == "shadowsignal-shape/v2"
    assert set(payload["flows"][0]) == {"transport", "events"}


def test_v2_payload_is_sent_to_v2_endpoint(monkeypatch) -> None:
    requested_urls = []

    def fake_urlopen(request, **_kwargs):
        requested_urls.append(request.full_url)
        return io.BytesIO(b'{"verdict":"indeterminate"}')

    monkeypatch.setattr(api.urllib.request, "urlopen", fake_urlopen)
    result = api.analyze(
        build_shape_payload(synthetic_flow()),
        api_url="https://example.invalid",
        api_key="test-key",
    )

    assert requested_urls == ["https://example.invalid/v2/shape-analyses"]
    assert result["verdict"] == "indeterminate"


def test_process_and_destination_stay_in_local_join_only() -> None:
    flow = CapturedFlow("tcp", 1, "203.0.113.10", 443)
    flow.process_name = r"C:\\Users\\alice\\AppData\\claude.exe"
    flow.parent_process = "/Applications/Visual Studio Code.app/Code.exe"
    flow.events = [PacketEvent(0, "in", 100)]
    payload = build_shape_payload(flow)
    joined = join_local_result(
        {
            "observation_id": payload["observation_id"],
            "shape_verdict": "likely_llm",
            "confidence_bucket": "high",
        },
        destination_host="api.anthropic.com",
        process_name=flow.process_name,
        parent_process=flow.parent_process,
    )
    assert joined["process_name"] == "claude.exe"
    assert joined["parent_process"] == "Code.exe"
    assert joined["destination_host"] == "api.anthropic.com"
    assert joined["final_verdict"] == "confirmed_ai_usage"
    assert not (set(payload) & FORBIDDEN_FIELDS)
    assert "alice" not in str(payload)


def test_shared_cdn_flow_requires_compatible_local_process() -> None:
    api_result = {
        "observation_id": "obs_0123456789abcdef0123456789abcdef",
        "shape_verdict": "indeterminate",
        "confidence_bucket": "medium",
        "sustained_stream": True,
        "interaction_triggered": True,
    }

    contaminated = join_local_result(
        api_result,
        destination_host="chatgpt.com",
        process_name="codex",
        parent_process="ChatGPT",
    )
    browser = join_local_result(
        api_result,
        destination_host="chatgpt.com",
        process_name="Google Chrome Helper",
        parent_process="Google Chrome",
    )

    assert contaminated["attribution_confident"] is False
    assert contaminated["final_verdict"] == "attribution_ambiguous"
    assert browser["attribution_confident"] is True
    assert browser["final_verdict"] == "confirmed_ai_usage"


def test_tls_server_name_can_attribute_generic_local_process() -> None:
    result = join_local_result(
        {
            "shape_verdict": "indeterminate",
            "confidence_bucket": "medium",
            "sustained_stream": True,
            "interaction_triggered": True,
        },
        destination_host="api.anthropic.com",
        process_name="python",
        parent_process="Terminal",
        observed_server_name="api.anthropic.com",
    )

    assert result["observed_server_name"] == "api.anthropic.com"
    assert result["attribution_confident"] is True
    assert result["final_verdict"] == "confirmed_ai_usage"


def test_short_browser_name_does_not_match_unrelated_process_substring() -> None:
    result = join_local_result(
        {
            "shape_verdict": "indeterminate",
            "confidence_bucket": "medium",
            "sustained_stream": True,
            "interaction_triggered": True,
        },
        destination_host="chatgpt.com",
        process_name="SearchHost.exe",
        parent_process="explorer.exe",
    )

    assert result["attribution_confident"] is False
    assert result["final_verdict"] == "attribution_ambiguous"


def test_events_are_sorted_and_limited() -> None:
    flow = CapturedFlow("tcp", 1, "203.0.113.10", 443)
    flow.events = [PacketEvent(offset, "in", 100) for offset in range(700, -1, -1)]
    payload = build_shape_payload(flow)
    events = payload["flows"][0]["events"]
    offsets = [event["offset_ms"] for event in events]
    assert len(offsets) == 512
    assert offsets == sorted(offsets)
    assert offsets[-1] == 700
    assert all(offset % 10 == 0 for offset in offsets)
    assert all(event["size"] == 128 for event in events)


def test_event_limit_preserves_sparse_outbound_direction() -> None:
    flow = CapturedFlow("tcp", 1, "203.0.113.10", 443)
    flow.events = [PacketEvent(index * 10, "in", 100) for index in range(900)]
    flow.events.extend(PacketEvent(index * 400, "out", 320) for index in range(20))

    payload = build_shape_payload(flow)

    events = payload["flows"][0]["events"]
    assert len(events) == 512
    assert sum(event["direction"] == "out" for event in events) == 20


def test_event_limit_uses_full_budget_for_outbound_dominant_flow() -> None:
    flow = CapturedFlow("tcp", 1, "203.0.113.10", 443)
    flow.events = [PacketEvent(index * 10, "out", 100) for index in range(900)]
    flow.events.extend(PacketEvent(index * 400, "in", 320) for index in range(20))

    payload = build_shape_payload(flow)

    events = payload["flows"][0]["events"]
    assert len(events) == 512
    assert sum(event["direction"] == "in" for event in events) == 20


def test_session_payload_preserves_concurrent_flow_boundaries_without_context() -> None:
    first = CapturedFlow("tcp", 51001, "203.0.113.10", 443)
    first.events = [PacketEvent(0, "out", 310), PacketEvent(500, "in", 121)]
    second = CapturedFlow("tcp", 51002, "203.0.113.10", 443)
    second.events = [PacketEvent(250, "out", 90), PacketEvent(900, "in", 1400)]

    payload = build_session_payload(
        [first, second], observation_id="obs_0123456789abcdef0123456789abcdef"
    )

    assert payload["grouping"] == "flow_set"
    assert [event["offset_ms"] for event in payload["flows"][0]["events"]] == [0, 500]
    assert [event["offset_ms"] for event in payload["flows"][1]["events"]] == [250, 900]
    assert payload["observation_id"] == "obs_0123456789abcdef0123456789abcdef"
    assert "destination_host" not in payload
    assert "process_name" not in payload


def test_interactive_flow_is_selected_before_short_burst() -> None:
    burst = CapturedFlow("tcp", 51001, "203.0.113.10", 443)
    burst.events = [PacketEvent(offset, "in", 1400) for offset in range(100)]

    interactive = CapturedFlow("tcp", 51002, "203.0.113.10", 443)
    interactive.events = [PacketEvent(0, "out", 320)]
    interactive.events.extend(
        PacketEvent(index * 500, "in", 192) for index in range(1, 14)
    )

    assert select_candidate_flows([burst, interactive], limit=1) == [interactive]


def test_candidate_flows_never_mix_process_owners() -> None:
    browser = CapturedFlow("tcp", 51001, "203.0.113.10", 443, process_id=100)
    browser.events = [PacketEvent(0, "out", 600)]
    browser.events.extend(PacketEvent(index * 400, "in", 192) for index in range(1, 14))
    unrelated = CapturedFlow("tcp", 51002, "203.0.113.10", 443, process_id=200)
    unrelated.events = [PacketEvent(index * 100, "in", 192) for index in range(100)]

    selected = select_candidate_flows([unrelated, browser], limit=3)

    assert selected == [browser]
    assert {flow.process_id for flow in selected} == {100}


def test_known_chat_ui_prefers_browser_owner_over_shared_cdn_process() -> None:
    browser = CapturedFlow(
        "tcp", 51001, "203.0.113.10", 443, process_name="Google Chrome", process_id=100
    )
    browser.events = [PacketEvent(0, "out", 600), PacketEvent(500, "in", 1200)]
    codex = CapturedFlow(
        "tcp", 51002, "203.0.113.10", 443, process_name="codex", process_id=200
    )
    codex.events = [PacketEvent(index * 100, "in", 192) for index in range(100)]

    preferred = prefer_attributable_flows([codex, browser], destination_host="chatgpt.com")

    assert preferred == [browser]


def test_tls_server_name_beats_process_guess_on_shared_cdn() -> None:
    target = CapturedFlow(
        "tcp",
        51001,
        "203.0.113.10",
        443,
        process_name="python",
        process_id=100,
        server_name="chatgpt.com",
    )
    unrelated = CapturedFlow(
        "tcp",
        51002,
        "203.0.113.10",
        443,
        process_name="Google Chrome",
        process_id=200,
        server_name="example.com",
    )

    assert prefer_attributable_flows(
        [unrelated, target], destination_host="chatgpt.com"
    ) == [target]
    assert prefer_attributable_flows(
        [unrelated], destination_host="chatgpt.com"
    ) == []


def test_synthetic_flow_has_no_reserved_test_ip_in_payload() -> None:
    payload = build_shape_payload(synthetic_flow())
    assert "203.0.113.10" not in str(payload)


def test_split_decision_matrix() -> None:
    assert final_verdict(known_ai=True, shape_verdict="likely_llm") == "attribution_ambiguous"
    assert final_verdict(known_ai=True, shape_verdict="indeterminate") == "attribution_ambiguous"
    assert final_verdict(known_ai=True, shape_verdict="unlikely_llm") == "attribution_ambiguous"
    assert final_verdict(known_ai=False, shape_verdict="likely_llm") == "unclassified"
    assert final_verdict(known_ai=False, shape_verdict="indeterminate") == "unclassified"
    assert final_verdict(known_ai=False, shape_verdict="unlikely_llm") == "not_detected"
    assert (
        final_verdict(
            known_ai=True,
            shape_verdict="indeterminate",
            attribution_confident=True,
        )
        == "known_ai_access"
    )
    assert (
        final_verdict(
            known_ai=True,
            shape_verdict="unlikely_llm",
            attribution_confident=True,
        )
        == "known_ai_background"
    )
    assert (
        final_verdict(
            known_ai=True, shape_verdict="indeterminate", sustained_stream=True
        )
        == "attribution_ambiguous"
    )
    assert (
        final_verdict(
            known_ai=False, shape_verdict="indeterminate", sustained_stream=True
        )
        == "unclassified"
    )
    assert (
        final_verdict(
            known_ai=True,
            shape_verdict="indeterminate",
            sustained_stream=True,
            interaction_triggered=True,
            attribution_confident=True,
        )
        == "confirmed_ai_usage"
    )
    assert (
        final_verdict(
            known_ai=True,
            shape_verdict="indeterminate",
            sustained_stream=True,
            trusted_agent_process=True,
        )
        == "confirmed_ai_usage"
    )
    assert (
        final_verdict(
            known_ai=False,
            shape_verdict="likely_llm",
            interaction_triggered=True,
        )
        == "suspected_shadow_ai"
    )


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    body += b"\x00" * ((-len(body)) % 4)
    total_length = 12 + len(body)
    return struct.pack("<II", block_type, total_length) + body + struct.pack("<I", total_length)


def _tcp_frame_payload(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
) -> bytes:
    ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
    total_length = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        7,
        0x4000,
        64,
        6,
        0,
        ipaddress.ip_address(source_ip).packed,
        ipaddress.ip_address(destination_ip).packed,
    )
    tcp = struct.pack("!HHIIBBHHH", source_port, destination_port, 1, 0, 0x50, 0x18, 65535, 0, 0)
    return ethernet + ipv4 + tcp + payload


def _tcp_frame(source_ip: str, destination_ip: str, source_port: int, destination_port: int, size: int) -> bytes:
    return _tcp_frame_payload(
        source_ip, destination_ip, source_port, destination_port, b"x" * size
    )


def _tls_client_hello(hostname: str) -> bytes:
    encoded = hostname.encode("ascii")
    name = b"\x00" + struct.pack("!H", len(encoded)) + encoded
    server_names = struct.pack("!H", len(name)) + name
    extension = struct.pack("!HH", 0, len(server_names)) + server_names
    hello = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extension))
        + extension
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _enhanced_packet(frame: bytes, timestamp_microseconds: int) -> bytes:
    body = struct.pack(
        "<IIIII",
        0,
        timestamp_microseconds >> 32,
        timestamp_microseconds & 0xFFFFFFFF,
        len(frame),
        len(frame),
    )
    return _pcapng_block(6, body + frame)


def _sample_pcapng() -> bytes:
    section = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    timestamp_option = struct.pack("<HH", 9, 1) + b"\x06\x00\x00\x00" + struct.pack("<HH", 0, 0)
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535) + timestamp_option)
    outbound = _enhanced_packet(_tcp_frame("10.0.0.2", "203.0.113.10", 51001, 443, 32), 1_000_000)
    inbound = _enhanced_packet(_tcp_frame("203.0.113.10", "10.0.0.2", 443, 51001, 120), 1_500_000)
    duplicate = _enhanced_packet(_tcp_frame("203.0.113.10", "10.0.0.2", 443, 51001, 120), 1_500_000)
    return section + interface + outbound + inbound + duplicate


def _sample_pcap() -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 101)
    frames = [
        (_tcp_frame("10.0.0.2", "203.0.113.10", 51001, 443, 32)[14:], 1, 0),
        (_tcp_frame("203.0.113.10", "10.0.0.2", 443, 51001, 120)[14:], 1, 500_000),
    ]
    records = []
    for frame, seconds, microseconds in frames:
        captured = frame[:96]
        records.append(struct.pack("<IIII", seconds, microseconds, len(captured), len(frame)) + captured)
    return header + b"".join(records)


def _sample_null_pcap() -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 0)
    frames = [
        (struct.pack("<I", 2) + _tcp_frame("10.0.0.2", "203.0.113.10", 51001, 443, 32)[14:], 1, 0),
        (struct.pack("<I", 2) + _tcp_frame("203.0.113.10", "10.0.0.2", 443, 51001, 120)[14:], 1, 500_000),
    ]
    records = []
    for frame, seconds, microseconds in frames:
        captured = frame[:96]
        records.append(struct.pack("<IIII", seconds, microseconds, len(captured), len(frame)) + captured)
    return header + b"".join(records)


def _sample_sni_pcap(hostname: str) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 1536, 101)
    frame = _tcp_frame_payload(
        "10.0.0.2",
        "203.0.113.10",
        51001,
        443,
        _tls_client_hello(hostname),
    )[14:]
    record = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    return header + record


class _Resolver:
    def lookup(self, local_port: int) -> tuple[str | None, str | None, int | None]:
        assert local_port == 51001
        return "claude.exe", "Code.exe", 4321


def test_pktmon_pcapng_parser_extracts_only_flow_metadata(tmp_path) -> None:
    capture_file = tmp_path / "capture.pcapng"
    capture_file.write_bytes(_sample_pcapng())

    flows = parse_pcapng(capture_file, target_ips={"203.0.113.10"}, resolver=_Resolver())

    assert len(flows) == 1
    assert flows[0].process_name == "claude.exe"
    assert flows[0].parent_process == "Code.exe"
    assert flows[0].process_id == 4321
    assert [event.as_dict() for event in flows[0].events] == [
        {"offset_ms": 0, "direction": "out", "size": 32},
        {"offset_ms": 500, "direction": "in", "size": 120},
    ]


def test_macos_pcap_parser_extracts_sizes_from_truncated_raw_frames(tmp_path) -> None:
    capture_file = tmp_path / "capture.pcap"
    capture_file.write_bytes(_sample_pcap())

    flows = parse_pcap(capture_file, target_ips={"203.0.113.10"}, resolver=_Resolver())

    assert len(flows) == 1
    assert [event.as_dict() for event in flows[0].events] == [
        {"offset_ms": 0, "direction": "out", "size": 32},
        {"offset_ms": 500, "direction": "in", "size": 120},
    ]


def test_macos_pcap_parser_keeps_records_before_truncated_tail(tmp_path) -> None:
    capture_file = tmp_path / "truncated-tail.pcap"
    capture_file.write_bytes(_sample_pcap()[:-20])

    flows = parse_pcap(capture_file, target_ips={"203.0.113.10"}, resolver=_Resolver())

    assert len(flows) == 1
    assert len(flows[0].events) == 1


def test_macos_pcap_parser_supports_utun_null_link_type(tmp_path) -> None:
    capture_file = tmp_path / "utun.pcap"
    capture_file.write_bytes(_sample_null_pcap())

    flows = parse_pcap(capture_file, target_ips={"203.0.113.10"}, resolver=_Resolver())

    assert len(flows) == 1
    assert [event.size for event in flows[0].events] == [32, 120]


def test_tls_server_name_is_kept_local_and_never_added_to_api_payload(tmp_path) -> None:
    capture_file = tmp_path / "client-hello.pcap"
    capture_file.write_bytes(_sample_sni_pcap("chatgpt.com"))

    flows = parse_pcap(capture_file, target_ips={"203.0.113.10"}, resolver=_Resolver())
    payload = build_session_payload(flows)

    assert flows[0].server_name == "chatgpt.com"
    assert "chatgpt.com" not in str(payload)
    assert not (set(payload) & FORBIDDEN_FIELDS)


def test_tls_server_name_parser_rejects_truncated_and_non_tls_input() -> None:
    client_hello = _tls_client_hello("chatgpt.com")

    assert _tls_server_name(client_hello) == "chatgpt.com"
    assert _tls_server_name(b"not tls") is None
    assert _tls_server_name(client_hello[:40]) is None
    assert _tls_server_name(b"\x16\x02\x00" + client_hello[3:]) is None


def test_pktmon_filter_detection_is_language_independent() -> None:
    assert not capture._has_active_filters("Packet Filters:\n    None\n")
    assert not capture._has_active_filters("Paketfilter:\n    Keine\n")
    assert capture._has_active_filters(
        "Packet Filters:\n     # Name          IP Address Port\n     1 ExistingRule  10.0.0.1  443\n"
    )


def test_live_capture_rejects_unsupported_platform(monkeypatch) -> None:
    monkeypatch.setattr(capture.platform, "system", lambda: "Linux")
    with pytest.raises(capture.CaptureError, match="Windows 10/11 and macOS"):
        capture.capture_flows(target_host="api.anthropic.com", duration=5)


def test_macos_bpf_access_requires_readable_and_writable_device(monkeypatch) -> None:
    monkeypatch.setattr(capture.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(capture.Path, "glob", lambda _self, _pattern: [Path("/dev/bpf0")])
    monkeypatch.setattr(capture.os, "access", lambda _path, mode: mode == 6)

    assert capture.has_macos_bpf_access() is True


def test_macos_route_lookup_selects_real_interfaces(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        interface = "utun4" if "-inet6" in arguments else "en0"
        return SimpleNamespace(returncode=0, stdout=f"  interface: {interface}\n", stderr="")

    monkeypatch.setattr(capture.shutil, "which", lambda _name: "/sbin/route")
    monkeypatch.setattr(capture.subprocess, "run", fake_run)

    assert capture._route_interface("203.0.113.10") == "en0"
    assert capture._route_interface("2001:db8::10") == "utun4"
    assert "-inet6" not in calls[0]
    assert "-inet6" in calls[1]


def test_macos_route_group_skips_unroutable_address(monkeypatch) -> None:
    def fake_route(address: str) -> str:
        if ":" in address:
            raise capture.CaptureError("no IPv6 route")
        return "en0"

    monkeypatch.setattr(capture, "_route_interface", fake_route)
    assert capture._target_interfaces({"203.0.113.10", "2001:db8::10"}) == {
        "en0": {"203.0.113.10"}
    }


def test_pktmon_capture_owns_and_cleans_up_temporary_filters(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []
    resolver_state = {"started": False, "stopped": False}
    expected = [CapturedFlow("tcp", 51001, "203.0.113.10", 443)]

    class FakeResolver:
        def __init__(self, target_ips: set[str]):
            assert target_ips == {"203.0.113.10"}

        def start(self) -> None:
            resolver_state["started"] = True

        def stop(self) -> None:
            resolver_state["stopped"] = True

    def fake_run(_executable: str, *arguments: str, check: bool = True):
        del check
        calls.append(arguments)
        if arguments[:2] == ("filter", "list"):
            return SimpleNamespace(returncode=0, stdout="Packet Filters:\n    None\n", stderr="")
        if arguments[0] == "start":
            capture_path = Path(arguments[arguments.index("--file-name") + 1])
            capture_path.write_bytes(b"temporary etl")
        if arguments[0] == "etl2pcap":
            pcapng_path = Path(arguments[arguments.index("--out") + 1])
            pcapng_path.write_bytes(b"temporary pcapng")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(capture.platform, "system", lambda: "Windows")
    monkeypatch.setattr(capture, "_is_administrator", lambda: True)
    monkeypatch.setattr(capture.shutil, "which", lambda _name: "C:/Windows/System32/pktmon.exe")
    monkeypatch.setattr(capture, "resolve_target", lambda _host: {"203.0.113.10"})
    monkeypatch.setattr(capture, "ProcessResolver", FakeResolver)
    monkeypatch.setattr(capture, "_run_pktmon", fake_run)
    monkeypatch.setattr(capture.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(capture, "parse_pcapng", lambda *_args, **_kwargs: expected)

    assert capture.capture_flows(target_host="api.anthropic.com", duration=5) == expected
    assert resolver_state == {"started": True, "stopped": True}
    assert ("stop",) in calls
    assert ("filter", "remove") in calls
    assert calls.index(("stop",)) < calls.index(("filter", "remove"))
    start = next(call for call in calls if call[0] == "start")
    assert "--pkt-size" in start and str(capture.PKTMON_SNAPSHOT_BYTES) in start


def test_pktmon_filter_is_removed_when_start_fails(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    class FakeResolver:
        def __init__(self, _target_ips: set[str]):
            self.stopped = False

        def start(self) -> None:
            pass

        def stop(self) -> None:
            self.stopped = True

    def fake_run(_executable: str, *arguments: str, check: bool = True):
        del check
        calls.append(arguments)
        if arguments[:2] == ("filter", "list"):
            return SimpleNamespace(returncode=0, stdout="Packet Filters:\n    None\n", stderr="")
        if arguments[0] == "start":
            raise capture.CaptureError("start failed")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(capture.platform, "system", lambda: "Windows")
    monkeypatch.setattr(capture, "_is_administrator", lambda: True)
    monkeypatch.setattr(capture.shutil, "which", lambda _name: "pktmon.exe")
    monkeypatch.setattr(capture, "resolve_target", lambda _host: {"203.0.113.10"})
    monkeypatch.setattr(capture, "ProcessResolver", FakeResolver)
    monkeypatch.setattr(capture, "_run_pktmon", fake_run)

    with pytest.raises(capture.CaptureError, match="start failed"):
        capture.capture_flows(target_host="api.anthropic.com", duration=5)
    assert ("filter", "remove") in calls
    assert ("stop",) not in calls


def test_macos_tcpdump_capture_is_scoped_and_stopped(monkeypatch) -> None:
    state = {"resolver_started": False, "resolver_stopped": False}
    expected = [CapturedFlow("tcp", 51001, "203.0.113.10", 443)]
    process_instances = []

    class FakeResolver:
        def __init__(self, target_ips: set[str]):
            assert target_ips == {"203.0.113.10"}

        def start(self) -> None:
            state["resolver_started"] = True

        def stop(self) -> None:
            state["resolver_stopped"] = True

    class FakeProcess:
        def __init__(self, command, **kwargs):
            self.command = command
            self.returncode = None
            self.signal = None
            Path(command[command.index("-w") + 1]).write_bytes(_sample_pcap())
            process_instances.append(self)

        def poll(self):
            return self.returncode

        def send_signal(self, sent_signal):
            self.signal = sent_signal
            self.returncode = 0

        def communicate(self, timeout=None):
            del timeout
            return (None, "2 packets captured")

        def terminate(self):
            self.returncode = 0

        def kill(self):
            self.returncode = 0

    monkeypatch.setattr(capture.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(capture.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(capture.shutil, "which", lambda _name: "/usr/sbin/tcpdump")
    monkeypatch.setattr(capture, "resolve_target", lambda _host: {"203.0.113.10"})
    monkeypatch.setattr(capture, "ProcessResolver", FakeResolver)
    monkeypatch.setattr(capture.subprocess, "Popen", FakeProcess)
    monkeypatch.setattr(capture.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        capture, "_target_interfaces", lambda _target_ips: {"en0": {"203.0.113.10"}}
    )
    monkeypatch.setattr(capture, "parse_pcaps", lambda *_args, **_kwargs: expected)

    assert capture.capture_flows(target_host="api.anthropic.com", duration=0) == expected
    assert state == {"resolver_started": True, "resolver_stopped": True}
    process = process_instances[0]
    assert process.signal == signal.SIGINT
    assert process.command[process.command.index("-i") + 1] == "en0"
    assert "-y" not in process.command
    assert process.command[process.command.index("-s") + 1] == str(
        capture.TCPDUMP_SNAPSHOT_BYTES
    )
    assert process.command[-1] == "(host 203.0.113.10) and port 443"


def test_macos_tcpdump_forced_stop_is_controlled() -> None:
    class StuckProcess:
        def __init__(self) -> None:
            self.returncode = None
            self.signal = None
            self.killed = False
            self.communicate_calls = 0

        def poll(self):
            return self.returncode

        def send_signal(self, sent_signal):
            self.signal = sent_signal

        def communicate(self, timeout=None):
            self.communicate_calls += 1
            if self.communicate_calls <= 2:
                raise capture.subprocess.TimeoutExpired("tcpdump", timeout)
            self.returncode = -9
            return (None, "capture stopped after timeout")

        def kill(self):
            self.killed = True

    process = StuckProcess()
    diagnostic, controlled_stop = capture._stop_tcpdump(process)

    assert controlled_stop is True
    assert process.signal == signal.SIGINT
    assert process.killed is True
    assert process.returncode == -9
    assert diagnostic == "capture stopped after timeout"


def test_dashboard_filters_flows_and_returns_request_and_result(monkeypatch) -> None:
    matching = synthetic_flow()
    other = CapturedFlow("tcp", 51002, "203.0.113.11", 443, process_name="Safari")
    other.events = [PacketEvent(0, "out", 20)]
    monkeypatch.setattr(dashboard, "capture_flows", lambda **_kwargs: [matching, other])
    monkeypatch.setattr(
        dashboard,
        "analyze",
        lambda payload, api_url: {
            "schema_version": "shadowsignal-shape-result/v2",
            "observation_id": payload["observation_id"],
            "verdict": "likely_llm",
            "confidence": "high",
            "evidence_class": "interactive_generation",
            "interaction_count": 1,
            "analyzed_flows": 1,
            "model_version": "shadowsignal-shape-2026-09-r6",
            "api_url": api_url,
        },
    )

    result = dashboard._capture_request(
        {
            "target_host": "api.anthropic.com",
            "duration": 45,
            "max_flows": 3,
            "process": "code",
            "dry_run": False,
        },
        api_url="https://example.invalid",
    )

    assert result["captured_flows"] == 1
    item = result["items"][0]
    assert item["local_context"]["destination_host"] == "api.anthropic.com"
    assert item["local_result"]["final_verdict"] == "confirmed_ai_usage"
    assert item["api_result"]["verdict"] == "likely_llm"
    assert not (set(item["api_request"]) & FORBIDDEN_FIELDS)
