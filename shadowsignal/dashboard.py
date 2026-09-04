"""Loopback-only demonstration dashboard for capture and classification."""

from __future__ import annotations

import json
import re
import secrets
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .api import ShadowSignalAPIError, analyze
from .capture import CaptureError, capture_flows
from .destinations import describe_local_context, join_local_result, prefer_attributable_flows
from .privacy import build_session_payload
from .selection import select_candidate_flows


_HOST_PATTERN = re.compile(
    r"(?=^.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


def _capture_request(data: dict, *, api_url: str) -> dict:
    target_host = str(data.get("target_host", "")).strip().lower().rstrip(".")
    if not _HOST_PATTERN.fullmatch(target_host):
        raise ValueError("対象ホストにはURLではなくホスト名を入力してください")
    try:
        duration = int(data.get("duration", 45))
        max_flows = int(data.get("max_flows", 3))
    except (TypeError, ValueError) as exc:
        raise ValueError("計測時間と最大フロー数は整数で入力してください") from exc
    if not 5 <= duration <= 300:
        raise ValueError("計測時間は5秒から300秒の範囲で指定してください")
    if not 1 <= max_flows <= 10:
        raise ValueError("最大フロー数は1から10の範囲で指定してください")

    process_filter = str(data.get("process", "")).strip().lower()
    if len(process_filter) > 128:
        raise ValueError("プロセス絞り込みは128文字以内で指定してください")
    dry_run = data.get("dry_run") is True

    flows = capture_flows(target_host=target_host, duration=duration)
    if process_filter:
        flows = [
            flow
            for flow in flows
            if process_filter in (flow.process_name or "").lower()
            or process_filter in (flow.parent_process or "").lower()
        ]
    flows = prefer_attributable_flows(flows, destination_host=target_host)
    flows = select_candidate_flows(flows, limit=max_flows)

    items = []
    if flows:
        payload = build_session_payload(flows)
        context_flow = next((flow for flow in flows if flow.process_name), flows[0])
        local_context = describe_local_context(
            destination_host=target_host,
            process_name=context_flow.process_name,
            parent_process=context_flow.parent_process,
            observed_server_name=context_flow.server_name,
        )
        item = {"api_request": payload, "local_context": local_context}
        if not dry_run:
            api_result = analyze(payload, api_url=api_url)
            item["api_result"] = api_result
            item["local_result"] = join_local_result(
                api_result,
                destination_host=target_host,
                process_name=context_flow.process_name,
                parent_process=context_flow.parent_process,
                observed_server_name=context_flow.server_name,
            )
        items.append(item)
    return {
        "dry_run": dry_run,
        "captured_flows": len(flows),
        "items": items,
        "message": (
            "対象フローを取得できませんでした。計測開始後に対象の生成AIサービスを利用してください。"
            if not items
            else None
        ),
    }


_HTML = r"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ShadowSignal by Layer Security</title>
  <style>
    :root { color-scheme: dark; --ink:#edf4ff; --muted:#8fa2bb; --line:#25384e; --panel:#101b29; --blue:#50a7ff; --cyan:#55e6c1; --bad:#ff7b87; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; color:var(--ink); background:radial-gradient(circle at 85% 0,#183a58 0,transparent 35%),#07111d; font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
    main { width:min(1180px,calc(100% - 48px)); margin:0 auto; padding:52px 0 72px; }
    header { display:flex; justify-content:space-between; align-items:end; gap:24px; margin-bottom:26px; }
    .eyebrow { color:var(--cyan); font-size:12px; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
    h1 { margin:5px 0 4px; font-size:clamp(34px,5vw,52px); letter-spacing:-.04em; }
    .subtitle,.note { color:var(--muted); }
    .privacy { max-width:430px; padding:14px 17px; border:1px solid var(--line); border-radius:12px; background:#0a1624cc; font-size:14px; }
    .grid { display:grid; grid-template-columns:minmax(330px,390px) 1fr; gap:22px; }
    .panel { border:1px solid var(--line); border-radius:18px; background:linear-gradient(145deg,#122033e8,#0c1725e8); box-shadow:0 20px 50px #0005; }
    form { padding:26px; }
    label { display:block; margin:0 0 17px; color:var(--muted); font-size:13px; font-weight:700; letter-spacing:.04em; }
    input { width:100%; margin-top:7px; padding:13px 14px; color:var(--ink); border:1px solid var(--line); border-radius:10px; outline:none; background:#07111d; font:inherit; }
    input:focus { border-color:var(--blue); box-shadow:0 0 0 3px #50a7ff22; }
    .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    .check { display:flex; align-items:center; gap:8px; }
    .check input { width:auto; margin:0; }
    button { width:100%; margin-top:10px; padding:14px 18px; border:0; border-radius:11px; color:#03111d; background:linear-gradient(100deg,var(--cyan),var(--blue)); font:inherit; font-weight:800; cursor:pointer; }
    button:disabled { filter:grayscale(.8); cursor:wait; opacity:.65; }
    .status { min-height:23px; margin:14px 0 0; font-variant-numeric:tabular-nums; }
    .results { min-height:550px; padding:26px; overflow:hidden; }
    .empty { display:grid; min-height:496px; place-content:center; color:var(--muted); text-align:center; }
    .badge { display:inline-flex; padding:5px 9px; border:1px solid #55e6c155; border-radius:999px; color:var(--cyan); background:#55e6c112; font-size:12px; font-weight:800; }
    .result-card { margin-bottom:15px; padding:17px; border:1px solid var(--line); border-radius:14px; background:#07111d99; }
    .result-card h2 { margin:8px 0 2px; font-size:24px; }
    .facts { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin:13px 0; }
    .fact { padding:10px; border-radius:9px; background:#142337; }
    .fact span { display:block; color:var(--muted); font-size:10px; text-transform:uppercase; }
    details { margin-top:12px; }
    summary { color:var(--blue); cursor:pointer; }
    pre { max-height:280px; overflow:auto; padding:12px; border-radius:9px; color:#cbd9e9; background:#030a12; font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap; word-break:break-word; }
    .error { color:var(--bad); }
    footer { margin-top:20px; color:var(--muted); font-size:13px; text-align:center; }
    @media (max-width:780px) { main { width:min(100% - 28px,620px); padding-top:30px; } header { display:block; } .privacy { margin-top:17px; } .grid { grid-template-columns:1fr; } .results { min-height:350px; } .empty { min-height:290px; } }
  </style>
</head>
<body>
<main>
  <header>
    <div><div class="eyebrow">Encrypted-flow intelligence</div><h1>ShadowSignal Demo</h1><div class="subtitle">通信内容を扱わず、生成AI利用の兆候を可視化</div></div>
    <div class="privacy">✓ 宛先・IP・プロセス・生パケットはAPIへ送信しません<br>✓ この端末内で宛先と判定結果を結合します</div>
  </header>
  <div class="grid">
    <section class="panel">
      <form id="capture-form">
        <label>対象ホスト<input name="target_host" value="api.anthropic.com" required></label>
        <div class="row">
          <label>計測時間（秒）<input name="duration" type="number" min="5" max="300" value="45" required></label>
          <label>最大フロー数<input name="max_flows" type="number" min="1" max="10" value="3" required></label>
        </div>
        <label>プロセス絞り込み（任意）<input name="process" placeholder="claude または code"></label>
        <label class="check"><input name="dry_run" type="checkbox"> APIへ送らずメタデータだけ確認</label>
        <button id="start" type="submit">キャプチャーを開始</button>
        <div class="status" id="status"></div>
        <p class="note">開始後、対象の生成AIサービスでプロンプトを1件送信してください。</p>
      </form>
    </section>
    <section class="panel results" id="results"><div class="empty">判定結果がここに表示されます</div></section>
  </div>
  <footer>この端末内だけで表示 · 生パケットはローカル解析後に削除 · API送信は通信形状のみ</footer>
</main>
<script nonce="__NONCE__">
const token = "__TOKEN__";
const form = document.getElementById("capture-form");
const button = document.getElementById("start");
const statusBox = document.getElementById("status");
const results = document.getElementById("results");
const esc = (value) => String(value ?? "—").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const verdictLabel = {confirmed_ai_usage:"生成AIの利用を検知",attribution_ambiguous:"通信の帰属を確認できません",known_ai_access:"生成AIサービスへの接続",known_ai_background:"バックグラウンド通信",suspected_shadow_ai:"生成AI利用の可能性",unclassified:"判定保留",not_detected:"検知なし",unknown:"判定不能"};
form.addEventListener("submit", async (event) => {
  event.preventDefault(); button.disabled = true; results.innerHTML = '<div class="empty">対象通信を計測しています…</div>';
  const values = Object.fromEntries(new FormData(form));
  const duration = Number(values.duration); values.max_flows = Number(values.max_flows); values.duration = duration; values.dry_run = Boolean(values.dry_run);
  const started = Date.now();
  const timer = setInterval(() => { const left = Math.max(0, duration - Math.floor((Date.now()-started)/1000)); statusBox.textContent = `キャプチャー中… 残り約 ${left} 秒`; }, 250);
  try {
    const response = await fetch("/api/capture", {method:"POST", headers:{"Content-Type":"application/json","X-ShadowSignal-Token":token}, body:JSON.stringify(values)});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    statusBox.textContent = body.dry_run ? "送信せずに計測完了" : "判定完了";
    if (!body.items.length) { results.innerHTML = `<div class="empty">${esc(body.message)}</div>`; return; }
    results.innerHTML = body.items.map((item, index) => {
      const r = item.local_result || {};
      const api = item.api_result || {};
      const verdict = r.final_verdict || "unknown";
      const title = body.dry_run ? "送信前確認" : (verdictLabel[verdict] || verdict);
      const eventCount = (item.api_request.flows || []).reduce((sum, flow) => sum + (flow.events?.length || 0), 0);
      return `<article class="result-card"><span class="badge">SESSION ${index+1}</span><h2>${esc(title)}</h2>
        <div class="facts"><div class="fact"><span>通信形状</span>${esc(api.verdict || api.shape_verdict || (body.dry_run ? "未送信" : null))}</div><div class="fact"><span>信頼度</span>${esc(api.confidence || api.confidence_bucket)}</div><div class="fact"><span>イベント数</span>${eventCount}</div></div>
        <div>${esc(item.local_context.vendor)} · ${esc(item.local_context.product)} · ${esc(item.local_context.destination_host)}</div>
        <details><summary>APIへ送信した通信形状データ</summary><pre>${esc(JSON.stringify(item.api_request,null,2))}</pre></details>
        ${item.api_result ? `<details><summary>APIレスポンス</summary><pre>${esc(JSON.stringify(item.api_result,null,2))}</pre></details>` : ""}
        <details><summary>この端末内だけの情報</summary><pre>${esc(JSON.stringify(item.local_context,null,2))}</pre></details></article>`;
    }).join("");
  } catch (error) { statusBox.textContent = "エラー"; results.innerHTML = `<div class="empty error">${esc(error.message)}</div>`; }
  finally { clearInterval(timer); button.disabled = false; }
});
</script>
</body></html>"""


def serve_dashboard(*, api_url: str, port: int = 8765, open_browser: bool = True) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("dashboard port must be between 1024 and 65535")
    token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(18)
    capture_lock = threading.Lock()
    html = _HTML.replace("__TOKEN__", token).replace("__NONCE__", nonce).encode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def _send_json(self, status: HTTPStatus, body: dict) -> None:
            encoded = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if self.path != "/":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", f"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(html)

        def do_POST(self) -> None:
            if self.path != "/api/capture":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            if not secrets.compare_digest(self.headers.get("X-ShadowSignal-Token", ""), token):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid dashboard session"})
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = 0
            if not 0 < content_length <= 8192:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid request size"})
                return
            if not capture_lock.acquire(blocking=False):
                self._send_json(HTTPStatus.CONFLICT, {"error": "a capture is already running"})
                return
            try:
                data = json.loads(self.rfile.read(content_length))
                if not isinstance(data, dict):
                    raise ValueError("request body must be an object")
                result = _capture_request(data, api_url=api_url)
                self._send_json(HTTPStatus.OK, result)
            except PermissionError:
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "パケット取得には管理者権限が必要です"})
            except (ShadowSignalAPIError, CaptureError, ValueError, UnicodeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            finally:
                capture_lock.release()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"ShadowSignal dashboard: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.35, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
