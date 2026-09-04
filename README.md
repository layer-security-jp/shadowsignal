# ShadowSignal

ShadowSignalは、通信内容を復号・送信せず、暗号化通信を端末内で集約した統計から
生成AIサービスの利用兆候を確認する法人向け評価用クライアントです。対象を限定したPoCで、
既存のDLP・SSE・SIEMへ追加できる通信判定の実現性を確認します。

- API: <https://shadowsignal-api.layersecurity.jp>
- API仕様: <https://shadowsignal-api.layersecurity.jp/docs>
- データ収集仕様: [docs/DATA_COLLECTION.md](docs/DATA_COLLECTION.md)
- PoCの実施範囲: [docs/POC_SCOPE.md](docs/POC_SCOPE.md)

## 構成

![ShadowSignalの判定フロー](docs/assets/architecture.png)

![APIへ送る情報と対象端末内に残す情報](docs/assets/data-boundary.png)

対象端末は、宛先情報とランダムな観測IDの対応を端末内に保持します。APIへは量子化した
フロー集約統計だけを送り、返された判定を端末内で宛先情報と結合します。

## データの取り扱い

APIへ送る情報：

- ランダムな観測ID
- TCP / QUIC区分
- パケット数、通信時間、到着間隔の統計
- 暗号化データサイズの分布、転送レート、送受信比率

対象端末内に残す情報：

- 宛先ホスト、IPアドレス、ポート、取得できる場合のTLS SNI
- プロセス名と絶対時刻
- 生パケットと取得用の一時ファイル
- 既知の生成AIサービスとの対応情報

APIは同じ観測IDと形状判定を返します。APIへのリクエスト本文には、宛先、IPアドレス、
プロセス、通信内容を含めません。

## デモの実行

対応環境はWindows 10/11またはmacOS 13以降、Python 3.11以降です。パケット取得には
OSの管理者権限が必要です。

### Windows

管理者権限のPowerShellで実行します。

```powershell
git clone https://github.com/layer-security-jp/shadowsignal.git
cd shadowsignal
py -3.11 -m venv .venv
.venv\Scripts\python -m pip install .

$env:SHADOWSIGNAL_API_KEY = "別経路で提供されたAPIキー"
.venv\Scripts\shadowsignal dashboard
```

### macOS

```bash
git clone https://github.com/layer-security-jp/shadowsignal.git
cd shadowsignal
python3.12 -m venv .venv
.venv/bin/python -m pip install .

export SHADOWSIGNAL_API_KEY="別経路で提供されたAPIキー"
sudo -E .venv/bin/shadowsignal dashboard
```

起動後、ブラウザで45秒の計測を開始し、その間に対象の生成AIサービスを利用します。
ダッシュボードには、APIへ送った情報と端末内だけで扱う情報が分けて表示されます。

## CLI

API接続を確認：

```bash
shadowsignal self-test
```

APIへ送信せず、送信予定のデータを確認：

```bash
shadowsignal capture \
  --target-host api.anthropic.com \
  --duration 45 \
  --dry-run
```

判定結果の例：

```json
{
  "final_verdict": "confirmed_ai_usage",
  "shape_verdict": "likely_llm",
  "confidence": "medium",
  "vendor": "Anthropic",
  "product": "claude-code"
}
```

## 利用条件

- 監視権限を持つ端末とネットワークでのみ使用してください。
- 取得用の一時ファイルは端末内で解析後に削除し、APIへ送信しません。
- 端末内で通信先または通信元プロセスを確認できない観測は、生成AIの利用確定に使用しません。
- 通常のHTTPS通信と同様に、API基盤は接続元IPと接続時刻を観測し得ます。
- 判定は`likely_llm`、`indeterminate`、`unlikely_llm`の3値で、通信内容の検査や遮断は行いません。
- 継続監視、全社配布、他製品との本番連携はPoC後の個別設計です。

## ライセンス

端末側クライアントはApache License 2.0です。ホストされた判定APIは対象外です。

セキュリティ上の問題は、公開Issueではなく`security@layersecurity.jp`へ連絡してください。
