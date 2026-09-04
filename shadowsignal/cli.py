"""ShadowSignal command line interface."""

from __future__ import annotations

import argparse
import json
import sys

from .api import DEFAULT_API, ShadowSignalAPIError, analyze
from .capture import CaptureError, capture_flows
from .dashboard import serve_dashboard
from .destinations import join_local_result, prefer_attributable_flows
from .models import CapturedFlow, PacketEvent
from .privacy import build_flow_stats_payload
from .selection import select_candidate_flows


def synthetic_flow() -> CapturedFlow:
    flow = CapturedFlow("tcp", 51001, "203.0.113.10", 443, process_name="claude.exe", parent_process="Code.exe")
    flow.events.extend(PacketEvent(index * 3, "out", 1_500) for index in range(22))
    gaps = [0, 420, 760, 510, 930, 610, 470, 850, 560, 990, 650, 440, 780, 630]
    sizes = [120, 140, 160, 180, 130, 150, 170, 190, 110, 200, 155, 1_400, 1_500, 1_300]
    offset = 0
    for gap, size in zip(gaps, sizes):
        offset += gap
        flow.events.append(PacketEvent(offset, "in", size))
    return flow


def print_result(result: dict) -> None:
    summary = {
        "observation_id": result.get("observation_id"),
        "final_verdict": result.get("final_verdict"),
        "shape_verdict": result.get("shape_verdict"),
        "confidence": result.get("confidence"),
        "evidence_class": result.get("evidence_class"),
        "interaction_triggered": result.get("interaction_triggered"),
        "attribution_confident": result.get("attribution_confident"),
        "known_ai_destination": result.get("known_ai_destination"),
        "destination_host": result.get("destination_host"),
        "vendor": result.get("vendor"),
        "product": result.get("product"),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def run_self_test(args: argparse.Namespace) -> int:
    flow = synthetic_flow()
    payload = build_flow_stats_payload(
        flow, observation_id="obs_0123456789abcdef0123456789abcdef"
    )
    if args.dry_run:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print_result(
        join_local_result(
            analyze(payload, api_url=args.api),
            destination_host="api.anthropic.com",
            process_name=flow.process_name,
            parent_process=flow.parent_process,
        )
    )
    return 0


def run_capture(args: argparse.Namespace) -> int:
    if args.duration < 5 or args.duration > 300:
        raise SystemExit("--duration must be between 5 and 300 seconds")
    print(f"{args.target_host}の暗号化通信メタデータを{args.duration}秒間取得します...", file=sys.stderr)
    flows = capture_flows(target_host=args.target_host, duration=args.duration)
    if args.process:
        process_filter = args.process.lower()
        flows = [
            flow
            for flow in flows
            if process_filter in (flow.process_name or "").lower()
            or process_filter in (flow.parent_process or "").lower()
        ]
    flows = prefer_attributable_flows(flows, destination_host=args.target_host)
    flows = select_candidate_flows(flows, limit=args.max_flows)
    if not flows:
        print(
            "対象フローを取得できませんでした。計測開始後に対象の生成AIサービスを利用してください。",
            file=sys.stderr,
        )
        return 2

    candidates = []
    for flow in flows:
        try:
            candidates.append((flow, build_flow_stats_payload(flow)))
        except ValueError:
            continue
    if not candidates:
        print("判定に必要な受信イベントを取得できませんでした。", file=sys.stderr)
        return 2
    context_flow, payload = next(
        (item for item in candidates if item[0].process_name), candidates[0]
    )
    if args.dry_run:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_result(
            join_local_result(
                analyze(payload, api_url=args.api),
                destination_host=args.target_host,
                process_name=context_flow.process_name,
                parent_process=context_flow.parent_process,
                observed_server_name=context_flow.server_name,
            )
        )
    return 0


def run_dashboard(args: argparse.Namespace) -> int:
    serve_dashboard(api_url=args.api, port=args.port, open_browser=not args.no_browser)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shadowsignal", description="宛先情報を送らないLLM通信形状デモ")
    parser.add_argument("--api", default=DEFAULT_API, help="ShadowSignal APIのベースURL")
    subparsers = parser.add_subparsers(dest="command", required=True)

    self_test = subparsers.add_parser("self-test", help="合成した通信形状データでAPIを確認")
    self_test.add_argument("--dry-run", action="store_true", help="APIへ送るJSONを送信せず表示")
    self_test.set_defaults(handler=run_self_test)

    capture = subparsers.add_parser("capture", help="対象を限定して暗号化通信形状を取得")
    capture.add_argument("--target-host", required=True, help="対象ホスト名（例: api.anthropic.com）")
    capture.add_argument("--duration", type=int, default=45)
    capture.add_argument("--process", help="端末内でプロセス名が一致するフローだけを選択")
    capture.add_argument("--max-flows", type=int, default=3, choices=range(1, 11), metavar="1-10")
    capture.add_argument("--dry-run", action="store_true", help="取得後、APIへ送るJSONを送信せず表示")
    capture.set_defaults(handler=run_capture)

    dashboard = subparsers.add_parser("dashboard", help="ローカル専用デモダッシュボードを起動")
    dashboard.add_argument("--port", type=int, default=8765)
    dashboard.add_argument("--no-browser", action="store_true", help="ブラウザを開かずURLだけ表示")
    dashboard.set_defaults(handler=run_dashboard)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (ShadowSignalAPIError, CaptureError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except PermissionError:
        print("error: パケット取得にはAdministrator/root権限が必要です", file=sys.stderr)
        return 1
