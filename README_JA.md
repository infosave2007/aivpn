<p>
<sub><strong>実験的プロジェクトです。</strong> AIVPN は、ネットワークプロトコルと転送中のデータを保護する手法を探求するエンジニアリング研究プロジェクトです。ネットワーク制限の回避、匿名性、検出やブロックからの保護を保証するものではありません。本プロジェクトに政治的な目的はありません。</sub><br>
<sub>本プロジェクトは違法な用途を意図したものではありません。ユーザーは所在地で適用される法律を遵守し、自己責任でソフトウェアを使用する必要があります。作者は本プロジェクトの違法な使用を支持しません。</sub><br>
<sub>本プロジェクトの効果の保証や政治的目的に関する第三者の主張は、作者の立場を表すものではありません。</sub>
</p>

🌐 [English](README.md) | [Русский](README_RU.md) | [中文](README_CN.md)

# AIVPN

[![CI](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml)
[![Crates.io Server](https://img.shields.io/crates/v/aivpn-server.svg?label=aivpn-server)](https://crates.io/crates/aivpn-server)
[![Crates.io Client](https://img.shields.io/crates/v/aivpn-client.svg?label=aivpn-client)](https://crates.io/crates/aivpn-client)
![Rust](https://img.shields.io/badge/rust-1.97%2B-blue.svg)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20%7C%20iOS%20%7C%20MikroTik-informational)

---

## 概要

AIVPN は UDP トンネルの暗号化とトラフィックのマスキングを組み合わせています。マスクは外側のプロトコル、パケットサイズ、送信間隔を定義します。STUN や QUIC として認識されること自体は、特定のアプリケーションと統計的に区別できないことを証明するものではありません。

主な技術的特性:

- **InitialV2 と PFS** - 初期交換で新しいサーバー鍵を確認し、データと管理コマンドは PFS の後にのみ送信されます。バインド済みデバイスや特権デバイスは、永続鍵の所有も証明する必要があり、mTLS が必須の場合は有効な証明書を提示する必要があります。
- **O(1) のセッション検索** — セッション ID は平文で送信されません。すべてのパケットは、タイムスタンプとセッションごとのシークレットから導出される 8 バイトの *レゾナンスタグ* を持ちます。サーバーは `DashMap` を介して定数時間でセッションを解決します。
- **Perfect Forward Secrecy** — X25519 ラチェットによる通信中のセッション鍵ローテーション。サーバー鍵が漏洩しても過去のトラフィックは露出しません。
- **Neural Resonance モジュール** — マスクごとの micro-MLP (~66 KB) がライブのトラフィック統計を監視し、再構成誤差が大きい場合はクライアントを切断せずに自動でマスクをローテーションします。
- **生成的なマスク分布** - プロファイルは、キャプチャしたトラフィックから BIC で選択したガウス混合モデルで当てはめた、多峰性のパケットサイズおよびパケット到着間隔モデルをサポートします。クライアントは保存されたモデルからサンプリングしますが、モデルが存在することは、特定の名前のアプリケーションとの類似性を立証するものではありません。
- **Rust で記述** — メモリ安全で、GC による停止がありません。クライアントのバイナリは約 2.5 MB です。$5 の VPS で動作します。

---

## アーキテクチャ

### ワークスペース構成

```
crates/aivpn-common/     — shared crypto, protocol, mask profiles (no I/O)
crates/aivpn-server/     — Linux-only VPN gateway and management CLI
crates/aivpn-client/     — cross-platform VPN client (Linux / macOS / Windows)
crates/aivpn-android-core/ — JNI bridge for Android (Rust → Kotlin via C FFI)
crates/aivpn-ios-core/   — iOS Rust staticlib (C FFI), linked by PacketTunnelProvider
crates/aivpn-windows/    — Windows GUI (egui/eframe 0.31, manages aivpn-client.exe subprocess)
crates/aivpn-linux/      - Linux GUI (Iced 0.14, wraps aivpn-client subprocess)
platforms/android/       — Android Kotlin app (MVVM: MainViewModel + RecyclerView)
platforms/ios/           — iOS SwiftUI app + NetworkExtension PacketTunnelProvider
platforms/macos/         — macOS SwiftUI menu bar app + privileged helper daemon
platforms/aivpn-web/     — Web management panel (Hono 4 + SvelteKit 2, SQLite/PostgreSQL)
platforms/linux/         — Linux desktop packaging (AppImage, .desktop)
platforms/linux-kernel/  — optional in-kernel data-path module (out-of-tree)
platforms/openwrt/       — OpenWrt package
platforms/mikrotik/      — MikroTik RouterOS container
assets/masks/            — bundled traffic mimicry JSON profiles
assets/brand/            — icons and brand material
deploy/                  — server installer, systemd unit, Dockerfiles
deploy/ci/               — CI gates run by the Makefile (see `make help`)
```

### 主要モジュール

| モジュール | 場所 | 用途 |
|--------|----------|---------|
| `crypto.rs` | `aivpn-common` | X25519 鍵交換、ChaCha20-Poly1305 AEAD、BLAKE3/HMAC、レゾナンスタグの生成 |
| `protocol.rs` | `aivpn-common` | ワイヤーフォーマット: `[8-byte tag][pad_len][inner_header][encrypted payload][poly1305 tag]` |
| `mask.rs` | `aivpn-common` | `MaskProfile` — トラフィックシェーピング: ヘッダーテンプレート、FSM の状態、IAT 分布 |
| `gateway.rs` | `aivpn-server` | 中央のイベントループ: UDP 受信、セッションのディスパッチ、NAT 転送、ニューラルチェック |
| `session.rs` | `aivpn-server` | `SessionManager` — `DashMap` ベースの O(1) タグ検索、256 エントリのリプレイウィンドウ、セッション上限 500 |
| `neural.rs` | `aivpn-server` | Neural Resonance: マスクごとの MLP 64→16→64 / フォールバック 64→128→64、MSE しきい値 0.35、自動マスクローテーション |
| `client.rs` | `aivpn-client` | ステートマシン: Unprovisioned → Connecting → Connected、鍵交換、再接続 |
| `tunnel.rs` | `aivpn-client` | クロスプラットフォームの TUN: `/dev/net/tun` (Linux)、`utun` (macOS)、Wintun (Windows) |
| `mimicry.rs` | `aivpn-client` | `MimicryEngine` — 送信パケットに `MaskProfile` を適用 |

### 初期交換とアクセラレーターの互換性

1.2.0 以降、初期交換には InitialV2 を使用します。これは 1.1.0 および 1.2.0 の初期開発ビルドとは互換性がありません。サーバー、プール/サイト/チェーンノード、すべてのクライアント (組み込みのモバイルコアを含む) をまとめて更新してください。接続キーの形式とサーバー間の管理プロトコルは変更されていません。初期の AEAD は、ランダムな 24 バイトのノンスと AAD 内の接続コンテキストを用いる XChaCha20-Poly1305 を使用します。確立済みのチャネルは既存の ChaCha20-Poly1305 形式とカーネル ABI 7 を維持します。

Linux モジュールには、互換性のある Rust-for-Linux API、`CONFIG_RUST=y` でビルドされたカーネルヘッダー、および対応する Rust ツールチェーンが必要です。カーネルのバージョン番号だけではサポートは保証されません。`/dev/aivpn` を登録する前に、モジュールは実際の miscdevice vtable 内の `file_operations.owner` を確認し、API がモジュールコードを開いているディスクリプターに固定しない場合は `ENODEV` で失敗します。このチェックは回避できません。アクセラレーターがない場合は、ユーザー空間の TUN が使用されます。

### マスクの状態と外側トラフィックの検証

QUIC マスクは双方向の QUIC v1/TLS 1.3 を実行します。CID とパケット番号を保持し、ACK、損失、タイマー、接続のクローズを処理します。エンジンは、既存の UDP/DatagramTransport の上にある共有マスク層の内部で動作します。コールドな Initial は空の Token を持ちます。最初の AIVPN パケットは、TLS、HTTP/3 SETTINGS、CONNECT-UDP の後に、暗号化された HTTP DATAGRAM の中で送信されます。それまではペイロードデータは上限付きのキューで待機します。ローカルバッファがいっぱいになると、クライアントは ACK と制御メッセージの処理を続けながら空き容量を待ちます。論理的な UDP ピアはマスクの内部で終端し、プロキシソケットは開かれません。単純な GET や無関係な CONNECT-UDP には HTTP 403 が返されます。CONNECT-UDP は Avito や VK Video への通常の HTTP/3 リクエストと同等ではなく、それ自体がそれらとの類似性を証明するものではありません。内側の認証が完了する前、サーバーは VPN へのアクセスを一切許可せず、アクティブなセッションを置き換えることもできない、上限付きの別個の TLS 状態を保持します。このような状態はグローバルで最大 128 個、UDP ピアごとに最大 2 個まで許可され、セットアップの完了までは最大 10 秒です。処理は共有の CPU バジェットに計上されます。アドレスが検証されるまで、応答は受信トラフィックの 3 倍に制限されます。TLS はハンドシェイクの署名と証明書の鍵の所有を検証しますが、公開 PKI は検証しません。サーバーへの信頼は、内側の署名付き AIVPN 交換によって得られます。0-RTT と接続マイグレーションは無効です。

認証前の受信パケット制限は、サーバーの `--per-ip-pps-limit` / `AIVPN_PER_IP_PPS_LIMIT` で設定し、デフォルトは IP ごとに毎秒 5000 パケットです。PFS セッションが受け入れられた現行世代の QUIC には、別の有限な制限 `--per-ip-authenticated-pps-limit` / `AIVPN_PER_IP_AUTHENTICATED_PPS_LIMIT` があり、デフォルトは 100000 です。2 つのクラスのキューとカウンターはそれぞれ独立して上限が設けられています。保留中の TLS、プレーン、RTC のトラフィックには最初の制限が適用されます。CID はルートとクォータを選択しますが、パケットを認証するものではありません。既知の CID であっても、Quinn の AEAD と内側の AIVPN チェックは必須です。

7 つのプロファイルは、アラインされたオプションの STUN Binding Indication 属性で交換を開始します。PFS の後、保護された `MaskState` メッセージが外側のプロトコルパラメーターをプロファイルと接続世代に結び付けます。Zoom と `webrtc_yandex_telemost_v1` は ICE/DTLS/SRTP を使用します。SberJazz と Telegram 通話はさらに TURN の Allocate、Permission、ChannelBind、ChannelData を追加します。WhatsApp は DTLS なしの ICE/SRTP を使用し、保護された交換から得られる方向ごとの別々の鍵を用います。鍵、ICE 認証情報、証明書は世代ごとに新たに作成されます。すべての状態は既存の UDP ソケットの上にある共有マスク層で動作し、キューとセットアップ時間には上限があります。VK Teams と Salute は引き続き限定的な STUN キャリアを使用します。マスク名や正しい外側プロトコルは、特定のアプリケーションと区別できないことを保証するものではありません。20 バイトのヘッダーを持つ古い外部署名済みプロファイルは再発行する必要があります。クライアントは署名済みデータを自動的に変更しません。

`telegram_calls_v1` プロファイルは MTProto ではなく、Telegram の UDP 通話を対象としています。誤って QUIC を使用していた以前の `telegram_mtproto_v1` はカタログから削除されました。明示的なマスク選択ではその ID を置き換える必要があります。古い ID は新しい ID のエイリアスではありません。TURN/ICE/DTLS/SRTP は観測されたメディアチャネルの各段階を再現しますが、Telegram のシグナリングプロトコルは再現しません。

`yandex_alice_v1` プロファイルは、バンドルされたカタログとインストールバンドルから一時的に除外されています。検証済みの Alice モバイルアプリの音声 RPC は、現在の STUN/UDP キャリアではなく TLS/TCP を使用しています。スマートスピーカーのプロトコルは個別には検証されていません。

クライアントはサイズと IAT を 1 つのペアとして選択し、制御メッセージをブロックせずにデータをスケジュールします。サーバーはセッションごとに上限付きの別個のキューを使用し、逆方向のプロファイルパラメーターが定義されている場合はそれを使用します。両方向とも IP フローはインターリーブされ、各フローはパケットの順序を保ちます。大きなバックグラウンド転送が DNS や新しい接続より先にキュー全体を埋めることはありません。

`adaptive` がデフォルトです。QUIC では、プロトコル自身の輻輳制御とペーサーがレートを決定し、IP パケットごとの 2 つ目の IAT タイマーは追加されません。その他のマスクでは、負荷が軽い場合はプロファイルの間隔を維持します。キューイング遅延が続くとレートが徐々に上がり、バックログが解消されると元に戻ります。コントローラーは最も古いパケットの経過時間と、100 ms のウィンドウにおけるその経過時間の最小値を追跡します。遅延が 5 ms を超えるとウィンドウごとにレートを 1.5 倍に上げ、1 ms 未満になると係数 0.8 でレートを元の値に向けて戻します。加速の上限は 4096 倍です。加速された短い間隔は、元の IP パケット 64 個までに制限された 1 ms の量子にまとめられます。遅延の後、古い量子はクレジットになりません。フラグメンテーションにより外側のフレームが増えることがあります。期限切れのデッドラインは即座に処理され、将来のデッドラインは待機を続けます。プロファイルを変更するとコントローラーはリセットされます。これはローカルのキュー制御であり、物理的なリンク容量の測定ではありません。

`full` モードは、どのような負荷でも元の間隔を維持します。クライアントの `off` は、パディングとマスクの形式を維持したまま待機を無効にします。サーバーの `off` は従来どおりパディングも無効にします。サーバーの `light` は遅延の上限を 2 ミリ秒とし、少量のパディングバジェットを維持します。`adaptive` ではパディングは変わりませんが、負荷時の間隔は元のプロファイルと異なります。形式と暗号化を維持すること自体は、DPI への耐性を証明するものではありません。パディングは短いパケットを大きくしますが、長いパケットを小さくはしません。実際のワークロードのサイズとレートによって、プロファイルにどれだけ近づけられるかが制限されます。

このポリシーはローカルで設定され、接続キーからはインポートされません:

- クライアント: 共有の `config.json` で `"upload_shaping": "adaptive"`、`"full"`、または `"off"` を指定します。CLI は明示的に選択された `--config` からもこのフィールドを読み取ります。明示的な `--config` を指定した場合、デフォルトのファイルとはマージされません。Linux でのデフォルトのパスは `$XDG_CONFIG_HOME/aivpn/config.json` または `$HOME/.config/aivpn/config.json` で、どちらのディレクトリも存在しない場合は `/etc/aivpn/config.json` にフォールバックします。sudo やサービス経由で起動したクライアントは、そのプロセスの環境を使用します。Windows は `%APPDATA%/aivpn/config.json` を使用し、`C:\ProgramData\aivpn\config.json` にフォールバックします。macOS と iOS は `$HOME/Library/Application Support/aivpn/config.json` を使用します。Android はアプリの `filesDir/config.json` を使用し、直接 UDP の場合も同様です。
- サーバー: `server.json` で `"downlink_shaping": "adaptive"` を指定するか、`--shaping-level adaptive` を使用します。`full`、`light`、`off` および従来のブール値も引き続きサポートされます。`true` は `full`、`false` は `off` を意味します。明示的な設定はアップグレードによって変更されません。

新しい設定を適用するには、クライアントのプロセスまたはサーバーのサービスを再起動してください。無効な値は設定エラーとなり、黙ってデフォルトモードにフォールバックすることはありません。

Linux では、IPv6 アドレスが割り当てられていないフルトンネルは、IPv4 の MTU が 1280 未満の場合も含め、所有する 2 つのブラックホールルートで IPv6 をブロックします。IPv6 アドレスが割り当てられている場合、インターフェイスの MTU が 1280 を下回ることはありません。明示的に切断すると所有するルートは削除されます。クラッシュ後は、`aivpn-client kill-switch clear` がファイアウォールルールと残っている所有 IPv6 ガードを削除します。残った IPv6 ルートは通常の起動時に自動でクリーンアップされることはなく、オペレーターが明示的にコマンドを実行した場合のみ削除されます。CLI と `aivpn-ip-helper` は同じビルドから更新してください。

バンドルされた 10 個のプロファイルはすべて `--preferred-mask` と `--polymorphic-base` で利用でき、不明な ID は拒否されます。この優先指定は、検証済みのブートストラップから、要求されたベースの初期候補を選択します。該当する候補がない場合、クライアントは信頼済みの開始手順を維持し、PFS の後にそのベースを要求します。`--polymorphic-base` が優先され、その後のサーバーによる自動ローテーションは引き続き適用されます。初期交換の再試行では 1 回の試行内のエフェメラル鍵を維持しますが、新しいノンスを使用します。試行全体は 10 秒に制限されます。STUN と QUIC のマスクファミリー間の切り替えに新しいセッションは不要です。外側の QUIC および SRTP パケットは 1380 バイトに制限されます。QUIC は 1200 UDP バイトで開始し、パス MTU を最大 1380 までプローブします。内側のパケットは QUIC で 1140 バイト、ICE/DTLS/SRTP で 1324 バイト、ICE/SRTP で 1358 バイトに制限されます。パディングは、選択されたキャリアのヘッダー、AEAD、アラインメントを考慮します。制御メッセージは暗号化の前にフラグメント化されます。QUIC と RTC は両方向ともユーザー空間で動作し、プレーンな STUN の TX もユーザー空間にとどまります。ABI 7 は変更されていません。ネイティブインストールと systemd は従来どおりです。

デフォルトの TUN MTU は 1280 バイトです。明示的に指定した 1500 までの TUN MTU は維持されます。キャリアのバジェットを超える内側の DATA と FEC 修復は、個別に認証およびフラグメント化され、受信側で再構成されます。FEC は元の各 IP パケットを 1 回だけカウントします。ピアは 1.2.0 のフラグメント形式をサポートしている必要があります。すべての FEC メンバーは、小さなパケットも含め、認証されたグループ番号と位置を持ちます。グループは順序の入れ替わりや FEC の一時停止をまたいでも区別されたままです。完了したグループは、フラグメントの割り当て前に遅れて届いた元のパケットを拒否します。FEC フレームは、カーネルセッションのインストール後に FEC が有効化された場合でも、ユーザー空間の受信パスを使用します。

新しい QUIC マスク形式とバンドルされた STUN プロファイルのバージョンでは、プール/サイト/チェーンノードやモバイルコアを含め、クライアントとサーバーをまとめて更新する必要があります。接続キーの形式、PSK、サーバー間の管理メッセージは変更されていません。`make mask-gate` は、損失、遅延、重複のある UDP 上で実際のクライアントとゲートウェイを実行し、PFS と逆方向の交換を検証したうえで、双方向の PCAP を TShark と nDPI で解析し、最初のパケットを個別にチェックします。これは構造と分類を検証するものであり、任意の DPI やアクティブプロービングへの耐性を証明するものではありません。

### プール同期

サーバー間のクライアントデータベース同期は、通常の VPN UDP パケット内で運ばれる `ControlPayload::PoolSync` を使用し、クライアントのトラフィックと区別できません。別の TCP ポートやファイアウォールルールは不要です。

---

## プラットフォームサポート

| プラットフォーム | サーバー | クライアント | GUI | TUN ドライバー |
|----------|:------:|:------:|:---:|------------|
| Linux CLI | ✅ | ✅ | — | `/dev/net/tun` |
| Linux GUI | — | ✅ | ✅ iced AppImage + トレイ | `/dev/net/tun` |
| macOS | — | ✅ | ✅ メニューバー | `utun` |
| Windows | — | ✅ | ✅ egui GUI | [Wintun](https://www.wintun.net/) |
| Android | — | ✅ | ✅ ネイティブ Kotlin | `VpnService` API |
| iOS | — | ✅ | ✅ SwiftUI | `NetworkExtension` |
| MikroTik RouterOS 7.6+ | — | ✅ | — | コンテナ veth + TUN |
| Entware ルーター (ARMv7 / MIPSel) | — | ✅ | — | musl 静的バイナリ |

### 機能対応表

| 機能 | Linux CLI | Linux GUI | Win | Mac | Android | iOS |
|---------|:---------:|:---------:|:---:|:---:|:-------:|:---:|
| トラフィック模倣 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| アダプティブモード (4 レベル) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ライブ品質スコア | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| スプリットトンネル | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DNS プロキシ | ✅ | ✅ | ✅ | ✅ | N/A* | ❌ |
| キルスイッチ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| mTLS 証明書 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| FEC (前方誤り訂正) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| トラフィック記録 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| デバイスキー / JIT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SOCKS5 プロキシ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| フルトンネル | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 診断 / ベンチマーク | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ブートストラップディスクリプターの検出 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ポリモーフィックマスク | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| クラウドソーシングによるマスクフィードバック (オプトイン) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| アプリ内管理 (ロール、クライアント管理、失効、監査)‡ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| プールトポロジー表示 + クライアントごとの出口ノード | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SSH サーバーインストールウィザード§ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ライブメトリクスグラフ† | — | — | — | — | — | — |

macOS では、キルスイッチは VPN 外への新しい接続をブロックし、有効化した時点ですでに開いていた接続は維持します。

\* Android の `VpnService` API は、設計上、デバイスのすべてのトラフィック (DNS を含む) を暗号化されたトンネル経由でルーティングします。そのため別個のローカル DNS プロキシのリスナーは不要であり、存在しません。このプラットフォームでは DNS リークは起こりえません。

† ライブメトリクスグラフはサーバー + [Web 管理パネル](#web-管理パネル) の機能であり、クライアントの機能ではありません。サーバーを `--features metrics` でビルドする必要があり、上記のいずれのクライアントからでもなく、Web ダッシュボードから閲覧します。

‡ [アプリ内のクライアント管理とロール](#アプリ内のクライアント管理とロール) を参照してください。デスクトップでは、CLI が `aivpn-client mgmt`/`aivpn-client role` (ローカルの管理ソケット経由でブリッジ) で同じ機能を提供します。Linux CLI のチェックマークは、グラフィカルな管理画面ではなく、この CLI ブリッジを指しています。

§ [SSH サーバーインストーラー](#ssh-サーバーインストーラー) を参照してください。クライアントを `ssh-install` Cargo フィーチャー付きでビルドする必要があります (リリース版の GUI/モバイルビルドにはデフォルトで同梱)。Linux CLI では、グラフィカルなウィザードではなく `aivpn-client ssh-install {script,probe,run}` サブコマンドになります。

---

## Web 管理パネル

`platforms/aivpn-web/` は、aivpn サーバーを管理するためのフルスタックの Web UI を提供します。

**スタック:** Hono 4 + Bun (バックエンド) · SvelteKit 2 + Svelte 5 + TailwindCSS 4 (フロントエンド) · Layerchart によるチャート · SQLite (デフォルト) または PostgreSQL

**機能:**
- JWT 認証 (15 分のアクセストークン + 7 日間のリフレッシュ用 httpOnly Cookie)、argon2id によるパスワード
- TOTP 2FA (AES-256-GCM で暗号化されたシークレット) と WebAuthn パスキー
- ロール: `admin` (フルアクセス) と `viewer` (読み取り専用) — これらは **Web パネル独自の** ログイン用ロールであり、VPN クライアントの [`ClientRole`](#アプリ内のクライアント管理とロール) とは独立しています。`viewer` は、GET のみのプロキシ対象エンドポイント (クライアント、プールのノード/リンク/ヘルス、マスク、ステータス、カーネル、イベント) のフェイルクローズな許可リストによって強制されます。設定、バックアップ、ブートストラップのエクスポート、マスクのアップロード/削除は管理者のみ利用できます。
- ページ: ダッシュボード (ライブチャート)、クライアント (追加/編集/QR/失効、ロールの割り当て)、プール (トポロジーグラフ、クライアントごとの出口ノード、監査ハッシュチェーンの検証バッジ)、設定、マスク、バックアップ、ログ、設定 (Settings)
- すべての `/api/v1/*` は aivpn の Unix ソケット (`/run/aivpn/api.sock`) にプロキシされます
- `/web/events` でのリアルタイム SSE イベントストリーム
- **ライブメトリクスグラフ** — ダッシュボードは、ライブの時系列チャート (アクティブセッション数、送受信帯域幅、パケットレート、p50/p95 のパケット処理レイテンシ) に加え、マスク/鍵のローテーションと DPI 攻撃の検出を示す点滅バッジを表示します。これらはすべて、インメモリの約 10 分間のリングバッファ (新たな永続ストレージは不要) から、同じ `/web/events` SSE ストリームで配信されます。サーバーを `--features metrics` でビルドする必要があります ([オプション機能 (Cargo)](#オプション機能-cargo) を参照)。サーバーにこのフィーチャーがない場合、ダッシュボードはチャートの代わりにヒントを表示します。

**クイックスタート:**

```bash
# 1. Generate secrets
JWT_SECRET=$(openssl rand -base64 48)
TOTP_KEY=$(openssl rand -base64 32)

# 2. Run with Docker (simplest)
docker run -d --name aivpn-web \
  -v /run/aivpn:/run/aivpn \
  -e JWT_SECRET="$JWT_SECRET" \
  -e TOTP_ENCRYPTION_KEY="$TOTP_KEY" \
  -e ORIGIN=https://vpn.example.com \
  -p 8080:8080 \
  ghcr.io/infosave2007/aivpn-web:latest

# 3. Get the one-time admin password from the startup log
docker logs aivpn-web 2>&1 | grep -A4 "FIRST-TIME SETUP"

# 4. Open https://vpn.example.com and log in with username "admin"
```

または `docker compose up -d aivpn-web` でも起動できます (シークレットは `platforms/aivpn-web/.env` に記述します)。

**実行 (Bun、ソースから):**
```bash
cd platforms/aivpn-web
cp .env.example .env          # fill JWT_SECRET, TOTP_ENCRYPTION_KEY, ORIGIN
bun install && bun run build
bun run start                 # listens on PORT (default 8080)
```

**主な環境変数:**

| 変数 | デフォルト | 説明 |
|----------|---------|-------------|
| `DATABASE_URL` | `file:./data/aivpn-web.db` | SQLite のパスまたは `postgres://...` |
| `JWT_SECRET` | — | トークン署名用の長いランダム文字列 |
| `TOTP_ENCRYPTION_KEY` | — | 32 バイトの base64 鍵 (`openssl rand -base64 32`) |
| `ORIGIN` | — | 公開 HTTPS URL (WebAuthn / CSRF に必須) |
| `UNIX_SOCK` | `/run/aivpn/api.sock` | aivpn 管理ソケットのパス |
| `PORT` | `8080` | HTTP の待ち受けポート |

**Makefile ターゲット:**
```bash
make web           # install deps + build frontend
make web-docker    # build Docker image aivpn-web:latest
make web-dev       # start dev servers (hot reload)
```

nginx のリバースプロキシの例は `deploy/nginx/aivpn-web.conf` にあります。

**デフォルトの認証情報 (初回実行時):**

データベースが空の状態で初めて起動すると、ランダムな管理者パスワードが生成され、サーバーのコンソールに一度だけ表示されます:

```
╔══════════════════════════════════════════════════╗
║         FIRST-TIME SETUP — SAVE THESE NOW        ║
╠══════════════════════════════════════════════════╣
║  Username : admin                                 ║
║  Password : <random 22-char base64url string>     ║
╚══════════════════════════════════════════════════╝
```

このパスワードはすぐに保存してください。表示されるのは **一度だけ** です。ログイン後、**Settings → Security** で変更するか、パスキーを登録してください。

**OIDC / SSO (オプション):**

| 変数 | 説明 |
|----------|-------------|
| `OIDC_ISSUER` | IdP のベース URL (例: `https://accounts.google.com`) |
| `OIDC_CLIENT_ID` | OAuth2 クライアント ID |
| `OIDC_CLIENT_SECRET` | クライアントシークレット (公開 PKCE クライアントでは省略) |
| `OIDC_MODE` | `disabled` (デフォルト) · `enabled` (SSO ボタンを追加) · `exclusive` (SSO のみ) |
| `OIDC_ROLE_CLAIM` | ユーザーのロールを含む ID トークンのクレーム (例: `role`) |
| `OIDC_ADMIN_VALUE` | `admin` ロールを付与するクレームの値 (デフォルト: `admin`) |

OIDC からのロールは **初回** の SSO ログイン時にのみ適用されます。その後、管理者は Web パネルで上書きできます。

---

## クイックスタート

### サーバー (Linux)

#### Docker (推奨)

```bash
mkdir -p config
docker compose up -d aivpn-server
```

コンテナは初回起動時に `server.key` と `server.json` を自動生成します。`network_mode: host` で実行され、`./config` → `/etc/aivpn` をマウントします。

ファイアウォールで UDP ポート 443 を開放してください:

```bash
# UFW
sudo ufw allow 443/udp
# firewalld
sudo firewall-cmd --add-port=443/udp --permanent && sudo firewall-cmd --reload
```

#### ベアメタル

```bash
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
sudo ./aivpn-server --listen 0.0.0.0:443 --key-file /etc/aivpn/server.key
```

サーバーは IPv4 フォワーディングを自動的に有効化し、NAT マスカレードのルールをインストールします (nftables を優先し、iptables にフォールバック)。トンネル自体のために手動でファイアウォールを設定する必要はありません。

#### クライアントの追加

```bash
# Docker
docker compose exec aivpn-server aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443

# Bare metal
aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443
```

出力には接続キー (`aivpn://…`) が含まれます。これをクライアントに配布してください。

`--role viewer|admin` を追加すると、そのクライアントに [アプリ内の管理アクセス](#アプリ内のクライアント管理とロール) を付与できます (クライアントがすでにデバイスバインド済みである必要があります。`--device-pubkey <BASE64>` と組み合わせると、別途の登録手順なしに、デバイスバインド済みの管理者を一度に作成できます):

```bash
aivpn-server --add-client "Admin Phone" --role admin --device-pubkey <BASE64_DEVICE_PUBKEY> \
    --key-file /etc/aivpn/server.key --clients-db /etc/aivpn/clients.json --server-ip YOUR_PUBLIC_IP:443
```

その他の管理コマンド: `--list-clients`、`--show-client`、`--remove-client`、`--enable-client`/`--disable-client`、`--reset-device`。

---

### クライアント — Linux

```bash
sudo ./aivpn-client -k "aivpn://..."
# Full tunnel (route all traffic through VPN)
sudo ./aivpn-client -k "aivpn://..." --full-tunnel
```

Linux GUI には Material と KDE / Breeze の 2 つのレイアウトがあります。選択は Settings セクションで行い、起動をまたいで保持されます。カラーテーマはライト、ダーク、システムから別途選択します。外観を変更しても VPN セッションとフォームの入力内容は保持されます。プロファイル、ルート、マスク、サービスツールはどちらのレイアウトでも同じロジックを共有します。プロファイルやネットワーク設定を変更する前に VPN を切断してください。

### クライアント — macOS

[Releases](https://github.com/infosave2007/aivpn/releases) から `aivpn-macos.dmg` をダウンロードし、**Aivpn.app** をアプリケーションフォルダにドラッグして起動すると、メニューバーに表示されます。接続キーを貼り付けて **Connect** をクリックします。

CLI:
```bash
sudo ./aivpn-client -k "aivpn://..."
```

> `utun` インターフェースを作成するため、アプリは `sudo` 経由でパスワードを求めます。

### クライアント — Windows

Windows GUI には Fluent Desktop とコンパクトな Fluent レイアウトがあります。デフォルトは Desktop で、切り替えは Settings セクションにあります。レイアウトとカラーテーマは接続設定とは別に保存されます。外観を変更しても VPN セッション、カウンター、タイマー、フォームの入力内容は保持されます。プロファイルやネットワーク設定を手動で変更する前に VPN を切断してください。include/exclude と SOCKS5 は選択中のプロファイルに属し、DNS プロキシはクライアント全体の設定のままです。

**インストーラー (推奨):** `aivpn-windows-installer.exe` をダウンロードして管理者として実行し、スタートメニューから **AIVPN** を起動します。

**ポータブル版:** `aivpn-windows-package.zip` (`aivpn.exe`、`aivpn-client.exe`、`wintun.dll` を含む) を展開し、`aivpn.exe` を管理者として実行します。

CLI (PowerShell、管理者権限):
```powershell
.\aivpn-client.exe -k "aivpn://..."
```

> Wintun ネットワークアダプターを作成するには管理者権限が必要です。

### クライアント — Android

1. `aivpn-client.apk` をインストールします
2. 接続キー (`aivpn://…`) を貼り付けます
3. **Connect** をタップします

### クライアント — iOS

macOS 上でビルドします (Xcode 15 以上が必要):

```bash
make ios TEAM_ID=YOUR_TEAM_ID
```

`releases/aivpn-ios.ipa` をインストールします:
```bash
xcrun devicectl device install app --device <UDID> releases/aivpn-ios.ipa
```

> 無料の Apple Developer アカウントで十分です。サイドロードしたビルドは 7 日後に期限切れになります。

### クライアント — Entware ルーター (ARMv7 / MIPSel)

```bash
# Copy the static musl binary to the router
scp aivpn-client-linux-armv7-musleabihf root@router:/opt/bin/aivpn-client
ssh root@router 'chmod +x /opt/bin/aivpn-client && /opt/bin/aivpn-client -k "aivpn://..."'
```

### クライアント — MikroTik RouterOS 7.6+

```routeros
/system/device-mode/update container=yes   # then reboot
/interface/veth/add name=veth-aivpn address=172.31.0.2/30 gateway=172.31.0.1
/ip/address/add address=172.31.0.1/30 interface=veth-aivpn
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
/container/envs/add list=aivpn-env name=AIVPN_KEY value="aivpn://..."
/container/add remote-image=infosave2007/aivpn-mikrotik:latest \
    interface=veth-aivpn start-on-boot=yes envlist=aivpn-env mounts=aivpn-tun
/container/start [find remote-image~"aivpn-mikrotik"]
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2
```

ポリシールーティングとトラブルシューティングについては [platforms/mikrotik/README.md](platforms/mikrotik/README.md) を参照してください。

### SOCKS5 プロキシモード (root 不要)

```bash
aivpn-client -k "aivpn://..." --proxy-listen 127.0.0.1:1080
```

Firefox / Chrome / curl で `SOCKS5 127.0.0.1:1080` を使うように設定します。TUN デバイスも管理者権限も必要ありません。

複数のクライアントを使う場合は、SOCKS ポートと管理ポートをそれぞれ別にし、クライアントごとに別の接続キーを使ってください。管理エンドポイントは、ポートが 0 以外の `127.0.0.1` のみを受け付けます:

```bash
AIVPN_CONNECTION_KEY="$KEY_ONE" aivpn-client --proxy-listen 127.0.0.1:1080 --admin-listen 127.0.0.1:44301
AIVPN_CONNECTION_KEY="$KEY_TWO" aivpn-client --proxy-listen 127.0.0.1:1081 --admin-listen 127.0.0.1:44302

aivpn-client --admin-listen 127.0.0.1:44302 record status
aivpn-client --admin-listen 127.0.0.1:44302 role
aivpn-client --admin-listen 127.0.0.1:44302 mgmt --method GET --path /api/v1/clients
```

フラグの代わりに `AIVPN_ADMIN_LISTEN` を使うこともできます。トークン、記録ステータス、トラフィックカウンターは管理ポート単位で管理されます。GUI は `127.0.0.1:44301` を使うため、追加の CLI クライアントは別のポートを選ぶ必要があります。アドレスが使用中の場合はトンネルのセットアップ前に失敗し、実行中のクライアントのトークンが置き換えられることはありません。

---

## 接続キーの形式

接続キーは、サーバーとクライアントのすべてのパラメーターを 1 つのポータブルな文字列にエンコードします:

```
aivpn://<base64url(JSON)>
```

JSON フィールド:

| フィールド | 型 | 説明 |
|-------|------|-------------|
| `s` | `string` | サーバーのアドレス。例: `"1.2.3.4:443"` |
| `k` | `string` | サーバーの X25519 公開鍵 (base64) |
| `p` | `string` | クライアントの事前共有鍵 / PSK (base64) |
| `i` | `string` | クライアントの固定 VPN IP。例: `"10.0.0.2"` |
| `n` | `object` | *(省略可)* ブートストラップ用の `network_config` (下記参照) |

`network_config` オブジェクト (`n`):

| フィールド | 説明 |
|-------|-------------|
| `client_ip` | クライアントの TUN IP |
| `server_vpn_ip` | サーバーの TUN IP |
| `prefix_len` | サブネットのプレフィックス長 |
| `mtu` | 内側の MTU |

接続時の優先順位:

1. `ServerHello` で確定した設定 (最優先)
2. キーに含まれるブートストラップ用の `network_config`
3. レガシーのフォールバック `10.0.0.0/24`

`network_config` を含まないキーも引き続き完全にサポートされます。

キーを生成する:
```bash
aivpn-server --add-client "Name" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

既存のキーを再表示する:
```bash
aivpn-server --show-client "Name" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

---

## サーバー設定リファレンス

永続設定の優先順位: 明示的な CLI フラグ > 環境変数 > JSON ファイル > 組み込みのデフォルト値。明示的な `false`、`0`、および組み込みのデフォルト値と等しい値も、下位のレイヤーを上書きします。

JSON のすべてのフィールドは環境変数でも指定できます。名前は大文字にして `AIVPN_` プレフィックスを付け、ネストしたフィールドはダブルアンダースコアで区切ります。たとえば `pool.peers` は `AIVPN_POOL__PEERS` に、`network_config.server_vpn_ip` は `AIVPN_NETWORK_CONFIG__SERVER_VPN_IP` に対応します。オブジェクトと配列は JSON で渡します。ネストしたオブジェクトは下位のレイヤーを拡張し、配列は下位のレイヤーを完全に置き換えます。型エラーや未知のネストした環境変数フィールドがあると起動が停止し、その値を出力せずに設定名を示します。

```bash
AIVPN_CONFIG=/etc/aivpn/server.json \
AIVPN_SERVER_IP=vpn.example.com:443 \
AIVPN_KEY_FILE=/etc/aivpn/server.key \
AIVPN_CLIENTS_DB=/var/lib/aivpn/clients.json \
AIVPN_POOL__PEERS='["edge.example.com:443"]' \
AIVPN_NEURAL_ENABLED=false \
aivpn-server
```

パス `key_file`、`clients_db`、`audit_log`、公開アドレス `server_ip`、制限値 `per_ip_pps_limit`、`pool_config`、`log_level`、`event_webhook`、`event_stdout`、`kernel_downlink`、`enable_nat` は、ネットワーク設定と同じ JSON で設定します。`public_endpoint` は `server_ip` のエイリアスです。公開アドレスには DNS 名、IPv4、IPv6 を指定でき、ポートを省略した場合は `listen_addr` のポートが使われます。

既存の名前 `AIVPN_LISTEN`、`AIVPN_SHAPING_LEVEL`、`RUST_LOG` も引き続きサポートされます。正式な名前は `AIVPN_LISTEN_ADDR`、`AIVPN_DOWNLINK_SHAPING`、`AIVPN_LOG_LEVEL` です。設定ファイルのパスは `--config`、`AIVPN_CONFIG` で指定するか、`/etc/aivpn/server.json` と `deploy/config/server.json` から自動的に選ばれます。

Kubernetes では、同じ名前を `env`/`envFrom` に指定します。JSON ファイルと鍵ファイルはコンテナーにマウントできます。`--add-client` や `--remove-client` のような単発の操作は引き続き CLI コマンドです。

すべてのクライアントからの管理リクエストは 1 つのキューを共有します。送信間隔 210 ms により、サーバーの 200 ms 制限が守られます。明示的な `429` の後の GET は、元のタイムアウト内で最大 2 回まで再試行されます。変更を伴うリクエストとタイムアウトは自動では再試行されません。`/diagnostics/v1/*` の計測は別の制限を使い、管理用の待機と再試行の対象外です。管理エラーには `code`、`message`、および省略可能な `retry_after_ms` が含まれます。HTTP API は既存の Web パネル向けに `error` フィールドも維持します。


```json
{
  "listen_addr": "0.0.0.0:443",
  "tun_name": "aivpn0",
  "tun_mtu": "auto",
  "mask_dir": "/var/lib/aivpn/masks",
  "bootstrap_mask_files": [],
  "session_timeout_secs": 0,
  "idle_timeout_secs": 300,
  "allow_peer_routing": false,
  "network_config": {
    "server_vpn_ip": "10.0.0.1",
    "prefix_len": 24,
    "mtu": 1280,
    "keepalive_secs": 8,
    "ipv6_enabled": false,
    "ipv6_prefix": "fd10:cafe::/48"
  },
  "pool": {
    "peers": [],
    "sync_key": ""
  }
}
```

| フィールド | デフォルト | 説明 |
|-------|---------|-------------|
| `listen_addr` | `0.0.0.0:443` | UDP のバインドアドレス。ポートは接続キーに自動的に埋め込まれます |
| `tun_name` | ランダム | TUN インターフェース名 |
| `tun_mtu` | _(未設定)_ | `"auto"` = 物理 MTU から 64 バイトのオーバーヘッドを引いた値で、上限は 1280 (フォールバックは 1280)。または 1500 までの固定の整数 |
| `mask_dir` | `/var/lib/aivpn/masks` | `.json` マスクプロファイルを走査するディレクトリ |
| `bootstrap_mask_files` | `[]` | 初回接続のレイテンシーを減らすため、起動時に事前読み込みするマスクファイル |
| `session_timeout_secs` | `0` | セッションの絶対的な上限時間。`0` = 無制限 |
| `idle_timeout_secs` | `300` | この秒数だけ無通信のセッションを切断します |
| `allow_peer_routing` | `false` | サブネット内の VPN クライアント間でパケットをルーティングします |
| `network_config.server_vpn_ip` | `10.0.0.1` | サーバーの TUN IP |
| `network_config.prefix_len` | `24` | VPN サブネットのプレフィックス |
| `network_config.mtu` | `1280` | `ServerHello` でクライアントに送られる内側の MTU |
| `network_config.keepalive_secs` | `8` | クライアントとネゴシエートされるキープアライブ間隔 |
| `network_config.ipv6_enabled` | `false` | IPv6 NAT66 を有効にします |
| `network_config.ipv6_prefix` | `fd10:cafe::/48` | クライアントの IPv6 アドレス用の ULA /48 プレフィックス |
| `pool.peers` | `[]` | データベース同期のためのピアサーバーのアドレス |
| `pool.sync_key` | `""` | 共有の 32 バイト BLAKE3 鍵 (base64)。生成: `openssl rand -base64 32` |
| `pool.node_id` | _(未設定)_ | プール内でのこのノード自身の識別子 (推奨: そのノードの `host:port`)。未設定の間はプール同期が無効になります |
| `pool.node_ip_partition` | ハッシュから導出 | このノードの固定 VPN-IP パーティション番号を `hash(node_id)` から導出する代わりに明示的に指定します。ハッシュの衝突を排除したり、大規模なプールを手動で均衡させたりできます。[プールトポロジーとクライアントごとの出口ルーティング](#プールトポロジーとクライアントごとの出口ルーティング) を参照してください |
| `pool.transport` | `"legacy"` | `"masked"` にすると、マスクに依存しないプッシュ専用のレガシートランスポートの代わりに、完全にマスクされたプールクライアントとしてピアに接続し、双方向のアンチエントロピーでプール同期を行います |
| `pool.exit_node` / `pool.exit_node_enabled` | 未設定 / `false` | グローバルデフォルトのマルチホップ出口 ([マルチホップチェーン転送](#マルチホップチェーン転送) を参照)。クライアントごとに上書き可能 |

### オプション機能 (Cargo)

| フィーチャー | 有効になるもの |
|---------|----------------|
| `neural` | Neural Resonance モジュール (MSE ベースのマスクローテーション) |
| `management-api` | `/run/aivpn/api.sock` の Unix ソケット HTTP API |
| `metrics` | Prometheus エクスポーターと、[Web パネルのライブグラフ](#web-管理パネル) 向けの `/web/events` SSE 経由のライブランタイムメトリクス (アクティブセッション、帯域幅、マスク/鍵のローテーション、検出された DPI 攻撃、パケット処理レイテンシー) |
| `passive-distribution` | ブートストラップディスクリプターの配布チャネル |
| `bootstrap-publish` | ローテーションしたブートストラップディスクリプターを S3/GitHub/Telegram へ自動公開 ([ブートストラップディスクリプターの配布](#ブートストラップディスクリプターの配布) を参照) |

---

### リファレンスモデルの学習

マスク ID とシグネチャハッシュが一致する場合、サーバーは `assets/neural/models.json` の学習済みリファレンス重みを使います。`neural.trained_models_file` で別の検証済みライブラリを選択できます。未知のシグネチャでは、キャリブレーション済みの射影によるフォールバックが維持されます。現在のリファレンスは WebRTC と QUIC のファミリーを記述したもので、個々のサービスや DPI 耐性を保証するものではありません。

classic RAW-IP 形式の PCAP から特徴量を準備して学習し、その後、固定したモデルを評価します:

```bash
cargo run --release -p aivpn-server --example neural_dataset -- mask.json reference.pcap 40 > dataset.json
cargo run --release -p aivpn-server --example neural_train -- dataset.json model.json evaluation.json
cargo run --release -p aivpn-server --example neural_evaluate -- dataset.json model.json
```

`40` は、内側の IP キャプチャからサーバー側の観測へのサイズ調整を明示的に指定する値で、リファレンスの準備と一致させています。パケットサイズとタイムスタンプはキャプチャから取得し、暗号化ペイロードのエントロピーは同じ長さの一様ランダムなバイト列でモデル化します。エクスポーターはパケットのペイロードやアドレスを公開しません。学習、検証、テストは時間で分割され、パーティションごとに統計をリセットし、各境界に 256 パケットの間隔を空けます。各パーティションには、ゲートウェイのストライド 16 と、ウィンドウあたり最低 32 サンプルを満たすのに十分なサンプルが必要です。モデルライブラリは `schema_version: 1`、`feature_version: 1`、`models: [{"mask_id": "...", "model": <model.json>, "evaluation": <evaluation.json>}]` を持ちます。モデルとレポートは、シグネチャハッシュと隠れ層の次元が一致していなければなりません。レポートには正確なモデルダイジェスト、3 つのデータパーティションすべてのダイジェスト、Adam のパラメーターが含まれ、ライブラリの読み込み時に重みとの対応が検証されます。不正なライブラリは、要求されたモデルを黙って置き換えるのではなく、読み込みに失敗します。

ランタイムは設定されたウォームアップしきい値を維持し、マスクごとに 500 回の MSE チェックを行った後で、ライブの適応しきい値を導出します。新しいエンコーダーを学習しても、それらのしきい値が黙って下げられることはありません。`assets/neural/heldout.json` の集約済みホールドアウトウィンドウにより、テストは非公開のキャプチャなしで同梱の重みを検証できます。

## ソースからのビルド

必要なもの: Rust 1.97 以上、`cargo`、`make`。

```bash
git clone https://github.com/infosave2007/aivpn
cd aivpn
make help          # show all available targets
```

### サーバーのビルド (Linux)

```bash
make server        # x86_64 → releases/aivpn-server-linux-x86_64
make server-arm64  # ARM64  → releases/aivpn-server-linux-arm64
make server-docker # via Docker (minimal host dependencies)
```

### クライアントのビルド

```bash
make client        # Linux x86_64
```

### musl 静的クロスビルド (ルーター向け)

```bash
make server-musl-armv7        # ARMv7
make server-musl-mipsel       # MIPSel
make server-musl-aarch64      # AArch64 (default features)
make server-musl-aarch64-full # AArch64, full feature set (management-api,metrics,neural) — what CI publishes as aivpn-server-linux-aarch64
```

### プラットフォーム別のビルド

```bash
make windows              # Windows GUI + zip (cross-compile from Linux)
make windows-docker       # Windows GUI via Docker (no mingw-w64 required)
make ios [TEAM_ID=XX]     # iOS IPA (macOS + Xcode 15+ only)
make macos                # macOS .app + .pkg + .dmg (macOS only)
make linux                 # Linux GUI binary (no extra tools)
make linux-appimage        # Linux GUI as AppImage (requires appimagetool)
```

### デプロイ

```bash
make deploy               # VPS: download binary + start docker compose
make server-deploy HOST=vps.example.com  # SSH upload local binary to VPS
```

### テストと開発

```bash
make test           # cargo test --workspace
make clippy         # cargo clippy
make check          # cargo check (fast)
make test-docker    # integration test: server + client in Docker
```

### Android

```bash
export ANDROID_SDK_ROOT=/opt/android-sdk
export ANDROID_NDK_ROOT=/opt/android-ndk
echo "sdk.dir=$ANDROID_SDK_ROOT" > platforms/android/local.properties

make android
```

署名付きビルド: スクリプトを実行する前に `platforms/android/keystore.properties` を作成してください。

### オプションの Cargo 機能 (サーバー)

```bash
cargo build --release --bin aivpn-server --features "management-api,metrics,neural"
```

### crates.io からインストール

```bash
cargo install aivpn-client
cargo install aivpn-server
```

---

### Android リリース署名

`make android` は **リリース** APK をビルドし、署名用の素材を必要とします。署名用の素材がない場合、
デバッグビルドにフォールバックせずに失敗します。デバッグ APK は `android:debuggable` であるため、
adb にアクセスできる人なら誰でも VPN プロセスにアタッチしてメモリからセッション鍵と
PSK を読み取れます。また、デバッグ APK には公開されている Android デバッグ署名が付いており、
これは誰がビルドしたかを何も証明せず、後から正しく署名された
ビルドにアップグレードすることもできません。

キーストアは `platforms/android/keystore.properties` で指定します:

```properties
storeFile=/absolute/path/to/release.jks
storePassword=...
keyAlias=...
keyPassword=...
```

または `AIVPN_UPLOAD_STORE_FILE`、`AIVPN_UPLOAD_STORE_PASSWORD`、
`AIVPN_UPLOAD_KEY_ALIAS`、`AIVPN_UPLOAD_KEY_PASSWORD` で指定します。CI ではこれらは
リポジトリシークレットの `ANDROID_KEYSTORE_BASE64`、`ANDROID_KEYSTORE_PASSWORD`、
`ANDROID_KEY_ALIAS`、`ANDROID_KEY_PASSWORD` から取得されます。

使い捨てのローカルビルドの場合は、`AIVPN_ALLOW_DEBUG_APK=1 make android` で以前の
デバッグ署名によるフォールバックを復元できます。それで生成されたものは決して公開しないでください。

## 高度な機能

### デバイスバインディング (JIT 登録)

接続キーは*ワンタイム*として指定できます。最初に接続したデバイスがその X25519 静的鍵をバインドし、以降の別デバイスからの接続は拒否されます。

```bash
# Create enrollment slot
aivpn-server --add-client-one-time "Alice-Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip IP:PORT

# Reset binding (re-enable enrollment)
aivpn-server --reset-device "Alice-Phone" \
    --clients-db /etc/aivpn/clients.json
```

プラットフォームごとのデバイス鍵の保存場所:

| プラットフォーム | 場所 |
|----------|----------|
| Linux / macOS | `~/.config/aivpn/device.key` (モード 600、自動生成) |
| Windows | `%APPDATA%\aivpn\device.key` |
| Android | `EncryptedSharedPreferences` 経由の Android Keystore |
| iOS | Keychain、`kSecAttrAccessibleAfterFirstUnlock` |

### アプリ内のクライアント管理とロール

どのクライアントにも、実行できる操作を制限する管理**ロール**を付与できます。このロールは Unix ソケットの REST API に対しても、通常の VPN トラフィック内で運ばれるトンネル内管理チャネル経由でも適用されるため、サーバーへの他の経路が到達不能な場合でも管理操作が可能です:

| ロール (`ClientRole`) | ランク | 付与される権限 (厳選されたトンネル/API サーフェス: クライアント、プールトポロジー、監査ログ、ステータス、重い設定の適用/確定) |
|---|---|---|
| `user` (デフォルト) | 0 | 接続のみ — 管理アクセスなし |
| `viewer` | 1 | 読み取り専用: 厳選されたすべてのルートへの GET (クライアントの一覧/詳細表示、接続キー、プールのノード/ヘルス/リンク、ステータス、監査ログ) |
| `admin` | 2 | 厳選された許可リスト全体 (読み取りと変更): クライアントの追加/編集/削除/失効、ロール割り当て、クライアントごとの `exit_node`、reset-device、重い設定 (アクティブなマスク、グローバル出口ノード) の適用/確定 |

クライアントを `user` より上に昇格させるには、そのクライアントがすでに**デバイスバインド**されている必要があります ([デバイスバインディング](#デバイスバインディング-jit-登録) を参照)。ロールは権限の付与であるため、常に証明済みのデバイス鍵に紐付けられ、単なる PSK に紐付けられることはありません:

```bash
# Fresh client, device-bound and elevated to admin in one step
aivpn-server --add-client "Admin Phone" --role admin --device-pubkey <BASE64_DEVICE_PUBKEY> \
    --key-file /etc/aivpn/server.key --clients-db /etc/aivpn/clients.json --server-ip IP:PORT

# Elevate an already device-bound client afterwards (role-only re-add)
aivpn-server --add-client "Alice" --role viewer --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

`--role` と `--device-pubkey` は `--add-client-one-time` にも適用されるため、新しいワンタイム登録スロットに事前にロールを付与しておき、デバイスが実際にバインドした時点でそのロールを有効にすることができます。

**トンネル内からのサーバー管理** — admin/viewer ロールのクライアントは、REST サーフェスの厳選されたサブセット (`/api/v1/status`、`/api/v1/clients*`、`/api/v1/audit-log`、`/api/v1/config/apply`+`/confirm`、`/api/v1/pool/*`) に対して `MgmtRequest`/`MgmtResponse` 制御メッセージを発行でき、セッションごとにレート制限されます。設定全体の `PUT`、`/api/v1/backup/import`、マスク署名鍵の管理は、`admin` であっても意図的に**決して**この経路からは到達できません。これらは Unix ソケット専用 (ローカル CLI、または Web パネル自身の別途制御された `admin` ログイン) のままです。デスクトップクライアントは、CLI を介して厳選されたサーフェスをローカルの管理ソケットに橋渡しします:

```bash
aivpn-client mgmt --method GET --path /api/v1/clients
aivpn-client role   # prints the role (0=user/1=viewer/2=admin) the server granted this client
```

Android と iOS は同等の呼び出しを JNI/FFI (`mgmtRequest`/`getRole`/`qrPng`) を通じて公開しており、5 つのプラットフォームすべての GUI (Linux、Windows、macOS、Android、iOS) と Web パネルの Clients ページには管理画面が搭載されています。クライアントの一覧表示、QR コード付きでの新規追加、編集、失効が可能で、ロールによる制御があるため `viewer` ロールのセッションには読み取り側のみが表示されます。

**失効 (Revoke)** — `POST /api/v1/clients/:id/revoke` (またはトンネル内の同等の操作) は、クライアントのライブセッションを即座に強制切断して再接続を無効化し、優先プールビーコンを送出します。これにより、他のプールノードは次の同期間隔を待たずに失効を把握できます。

**改ざん検知可能な監査ログ** — REST API 経由でもトンネル内経路経由でも、すべての管理者操作はハッシュチェーンログ (`--audit-log`、デフォルトは `/var/log/aivpn/audit.log`、JSONL) に追記されます。`GET /api/v1/audit-log?verify=1` はチェーンを検証し、通常のエントリ配列の代わりに `{ entries, verified, broken_at }` を返します。Web パネルではこれを検証バッジとして表示します。

**重い設定のロールバック付き適用** — 誤って適用するとオペレーターが締め出される可能性のある変更 (サーバーのアクティブなマスク、グローバルデフォルトの出口ノード) は、即座に適用されるのではなく、コミット確認フローを経由します。`POST /api/v1/config/apply` が変更をステージしてロールバックタイマーを開始し、`POST /api/v1/config/confirm` がタイマー満了前に変更をコミットします。確定されなかった変更は自動的に元に戻ります。

**Web パネルのロール制御** — Web パネルには、サーバー API の前段にあるプロキシを制御するための独自の `admin`/`viewer` ログインロールがあります。許可リストについては [Web 管理パネル](#web-管理パネル) を参照してください。これらは上記の `ClientRole` の表とは独立しています。

### 接続品質スコアとアダプティブモード

AIVPN は、RTT (40 点)、ジッター (20 点)、パケットロス (30 点)、Neural MSE (10 点) から **0–100 の品質スコア**を継続的に算出します。アダプティブレベルによってキープアライブが選択されます。FEC 列は、初期設定と、新しい受信側レポートが利用できない場合に使われるレガシーモードを示しています:

| スコア | アダプティブレベル | キープアライブ | 初期 / レガシー FEC |
|-------|---------------|-----------|-----------|
| 80–100 | Off | 8 秒 | 無効 |
| 50–79 | Light | 6 秒 | 1/16 |
| 20–49 | Aggressive | 4 秒 | 1/8 |
| 0–19 | Satellite | 15 秒 | 1/4 |

アダプティブモードの有効化:
```bash
aivpn-client -k "aivpn://..." --adaptive
```

### 前方誤り訂正 (FEC)

クライアントの元の IP パケット N 個ごとに XOR パケットが 1 つ追加され、グループ内の 1 つの損失を回復できます。サーバー側の受信側は、別個の 4096 カウンターのウィンドウでカウンターの欠落を推定し、PFS が確立されるとレポートを送信します。統計は少なくとも 32 カウンターの範囲が揃った後に現れます。このレポートがクライアントのアップリンク FEC を決定し、キープアライブは引き続きクライアント自身の RTT とジッターによって選択されます。

| 新しい受信側レポートでの損失 | FEC |
|----------------------------------|-----|
| 0 | オフ |
| 0 より大きく 1% 未満 | 1/16 |
| 1% 以上 5% 未満 | 1/8 |
| 5% 以上 | 1/4 |

これはカウンターに基づく推定であり、あらゆる損失パターンに対する回復を保証するものではありません。レポートの有効期間は 30 秒で、古いレポートカウンターが新しいものを置き換えることはありません。再接続または完全な PFS によって推定はリセットされます。古いサーバー、不完全なカーネル RX 観測、または期限切れのレポートの場合は、以前のアダプティブレベルの設定が引き続き有効になります。サーバーはレポートの処理と送信を、セッションごとに 1 秒あたり 1 回の操作に制限しています。サーバー間セッションでは、レポートに対して別のレポートで応答することはありません。フラグメント形式は 900 バイトのサイズを維持します。FEC が有効な場合、900 バイトを超える IP パケットには複数の保護フレームが必要になります。サーバーの送信経路でのリバース FEC は実装されていません。

### マルチサーバープール同期

プール内のノードは、標準の VPN ポートを介してクライアントデータベースをリアルタイムで共有します:

```json
{
  "pool": {
    "peers": ["node2.example.com:443"],
    "sync_key": "<base64-32-byte-key>"
  }
}
```

### プールトポロジーとクライアントごとの出口ルーティング

**読み取り専用のトポロジーエンドポイント** — `GET /api/v1/pool/nodes`、`/api/v1/pool/health`、`/api/v1/pool/links` は、プールの現在のノード一覧、ノードごとのヘルス、ノード間リンクの状態を公開しており、`viewer` ロールのセッションからもアクセスできます。Web パネルの **Pool** ページでは、これをライブのトポロジーグラフとして描画します。

**ノードごとの厳格な VPN IP パーティショニング** — 各プールノードは VPN サブネットの互いに重ならない区画を確保します (デフォルトでは `hash(node_id) % partitions`、または `pool.node_ip_partition` で明示的に固定)。これにより、2 つの異なるノードで同時に独立して行われたクライアント追加が、同じ VPN IP で衝突することはありません。ノードは確保した区画を交換し (`ControlPayload::PartitionAnnounce`)、オペレーターに起因する重複 (ハッシュ衝突や `node_ip_partition` の設定ミスなど) があれば、プールを黙って破損させるのではなくフラグを立てます。既存の決定論的な再割り当てロジックは、それでも競合が残る IP に対する予備策として引き続き機能します。

**クライアントごとの出口ルーティング** — 後述のプール全体のデフォルトとは独立して、個々のクライアントを特定のプール出口ノード経由でルーティングでき、サーバーを再起動せずにライブで変更できます: `PATCH /api/v1/clients/:id` に `{"exit_node": "host:port"}` (またはグローバルデフォルトに戻す場合は `null`) を指定します。これはトンネル内の管理経路からも利用できます。`role` とは異なり、クライアント自身の `exit_node` の設定は権限の付与ではないため、デバイスバインディングは不要です。対象の出口ピアがまだアクティブなプール接続になっていない場合、サーバーはオンデマンドで接続します。5 つのクライアント GUI すべてと Web パネルの Pool/Clients ページには、クライアントごとの出口ノード選択機能があります。

### マルチホップチェーン転送

クライアントのトラフィックを 2 つの AIVPN ノード経由でルーティングします。クライアントはエントリーノードにのみ接続し、インターネットからは出口ノードの IP が見えます。これは、クライアントごとの `exit_node` の上書きを持たないすべてのクライアントに対する**グローバルデフォルト**の出口ノードを設定します (上記の [プールトポロジーとクライアントごとの出口ルーティング](#プールトポロジーとクライアントごとの出口ルーティング) を参照)。誤ったグローバル出口はプールのトラフィック全体をブラックホール化する可能性があるため、ライブでの変更は [ロールバック付き適用](#アプリ内のクライアント管理とロール) フローを経由します。

**エントリーノード:**
```json
{ "pool": { "sync_key": "<key>", "exit_node": "exit.example.com:443" } }
```
**出口ノード:**
```json
{ "pool": { "sync_key": "<same-key>", "exit_node_enabled": true } }
```

### SSH サーバーインストーラー

`deploy/install-server.sh` は、新規の Linux VPS 向けの冪等で systemd 優先のインストーラーです。ディストリビューション/アーキテクチャを検出し、対象ポートが空いていることを確認し、`aivpn-server` のリリースバイナリを取得 (またはローカルで提供されたものを受け入れ) してその SHA256 を検証し、`server.key`/`server.json` を生成し、マスクプロファイルを初期投入し、systemd ユニットをインストールして起動し (または `--mode docker` で `docker compose` を使ってデプロイし)、ファイアウォールを開放し、オプションで同じ実行内でデバイスバインドされた管理者クライアントをプロビジョニングし、最後に `aivpn-server` が実際に待ち受けポートを保持しているかヘルスチェックします。再実行はアップグレードとして動作します。`server.key`/`clients.json` は決して上書きされず、バイナリ/ユニットは常に置き換えられ、最後にサービスが再起動されます。各ステップは stdout に機械可読な行を 1 行出力します:

```
##AIVPN {"step":"...","status":"ok|error|info","code":"...","msg":"..."}
```

そのため、呼び出し側 (スクリプトや、後述のアプリ内インストーラー UI) はテキストをスクレイピングせずに進捗を追跡できます。

```bash
sudo bash deploy/install-server.sh --device-pubkey <BASE64_DEVICE_PUBKEY> --server-ip vpn.example.com:443
deploy/install-server.sh --help          # full flag / env-var reference
deploy/install-server.sh --show-script   # print the script's own source before running it as root
deploy/install-server.sh --print-sha256  # print the script's own sha256sum
```

主なフラグ: `--mode systemd|docker`、`--port`/`--listen`、`--binary-url`/`--binary-file`、`--masks-url`/`--masks-dir`、`--device-pubkey`/`--server-ip`/`--admin-name`、`--config`/`--key-file`/`--clients-db`/`--mask-dir`/`--management-socket`/`--audit-log`、`--skip-firewall`、`--skip-deps`。`deploy/config/server.json.example` と `deploy/systemd/aivpn-server.service` を隣に見つけられるよう、このリポジトリの `deploy/` ディレクトリ (または完全なチェックアウト) から実行する必要があります。デフォルトでネットワーク経由で取得されるのはサーバーの*バイナリ*のみです。

**アプリ内インストールウィザード** — すべてのネイティブクライアント (Linux、Windows、macOS、Android、iOS) は、`russh` ベースの SSH クライアント (`aivpn_common::ssh_install`、`ssh-install` Cargo フィーチャーで有効化) を、インストーラースクリプト、systemd ユニット、同梱マスク、設定テンプレートとともに埋め込みアセットとして内蔵しており、セットアップウィザードを完全にアプリ内から実行します。対象ホストを入力し、TOFU の SSH ホスト鍵フィンガープリントを確認し、オプションで実行前にインストールスクリプトとその SHA256 を確認し、`##AIVPN` マーカーから解析されたライブの進捗を見守り、最後に生成された `aivpn://` 接続キーをインポートします。ウィザードの入口はメイン画面にあり、既存の接続や管理者セッションの背後に隠されてはいません。まったく新しいサーバーをゼロからブートストラップするには、そのどちらも必要ないためです。CLI では同じフローが `aivpn-client ssh-install {script,probe,run}` です:

```bash
aivpn-client ssh-install probe --host vpn.example.com --user root
aivpn-client ssh-install run --host vpn.example.com --fingerprint "SHA256:..." \
    --key-file ~/.ssh/id_ed25519 --device-pubkey <BASE64_DEVICE_PUBKEY> --server-ip vpn.example.com:443
```

`ssh-install run` は `--password-env`/`--password-stdin`/`--key-file` のうちちょうど 1 つで認証し (生の `--password` 引数は決して使いません — argv は `/proc/<pid>/cmdline` から見えてしまうため)、どの `aivpn-server` ビルドをインストールするかを制御する `--binary-file`/`--binary-url`、さらに `--mode systemd|docker` と、`install-server.sh` に転送されるパススルーの `--extra-arg` トークンを受け付けます。

Web パネルでは、Backup ページでバックアップをエクスポートしたり、ファイルを変更せずにアップロードされたアーカイブを検証したり (`POST /api/v1/backup/import?dry_run=true`) できます。リストアは CLI を通じてオフラインでのみ実行されます。サーバーと同じデータベースを使用するすべてのプロセスを停止してから、`aivpn-server --import /path/backup.bin --config /path/server.json --clients-db /path/clients.json --mask-dir /path/masks` を実行してください。実際のファイルパスとマスクディレクトリを使用してください。インポートが成功したらサービスを起動します。データベースを開いている実行中のプロセスがあるとリストアはブロックされ、`dry_run=true` なしの HTTP リクエストは 409 を返します。ネイティブクライアントに含まれるのはインストールウィザードのみで、サーバー移行ウィザードは含まれません。

CI は、フル機能 (`management-api,metrics,neural`) の `aivpn-server` リリースバイナリを `x86_64` と `aarch64` の両方向けに、それぞれ `SHA256SUMS` ファイル付きで公開しています。これは `install-server.sh` のデフォルトの `--binary-url` (GitHub Releases) が取得・検証する対象と一致しています。

### ブートストラップディスクリプターの配布

署名済み (ed25519) のブートストラップディスクリプターにより、まったく新しいクライアント (まだ有効な `aivpn://` キーを持っていないもの) でも、クライアントの `bootstrap_loader.rs` がすでに取得方法を知っている冗長なフォールバックチャネル (CDN/GitHub/Telegram) を通じて、使用可能なマスク設定を見つけられます。サーバーはこれらを 24 時間ごとに自動的に構築・署名・ローテーションし、すでに接続済みのクライアントにはライブセッション経由で最新のコピーをプッシュします。

**CLI エクスポート** — 現在の前/現/次エポックの署名済みディスクリプターを JSON として出力または保存し、任意のホスティングに手動でアップロードできます:
```bash
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key --bootstrap-output /path/to/bootstrap.json
```
実際の `--key-file` が必要です。一時的/ランダムなサーバー鍵は拒否されます。使い捨ての鍵で署名されたディスクリプターを信頼するクライアントは存在しないためです。

**管理 API エクスポート** — 同じ JSON 配列が `GET /api/v1/bootstrap/export` で利用できます (フィーチャー `management-api`、API の他の部分と同じ Unix ソケット認証モデル)。Web パネルのプロキシ層では、`/config` や `/backup/*` と同様に管理者専用として扱ってください。

**ローテーション時の自動公開** — `--features bootstrap-publish` でビルドし、`server.json` に `bootstrap_publish` セクションを追加すると、24 時間エポックが実際に進んだときに、ローテーションされたばかりのディスクリプターを自動的にプッシュします:
```json
{
  "bootstrap_publish": {
    "enabled": true,
    "channels": [
      { "type": "s3", "endpoint": "https://s3.us-east-1.amazonaws.com", "region": "us-east-1", "bucket": "my-aivpn-bootstrap", "key": "bootstrap.json", "access_key": "...", "secret_key": "..." },
      { "type": "github", "repo": "owner/repo", "asset_name": "bootstrap-descriptors.json", "tag_name": "bootstrap", "token": "..." },
      { "type": "telegram", "bot_token": "...", "chat_id": "..." }
    ]
  }
}
```

- **S3** — 任意の S3 互換プロバイダー (AWS S3、Cloudflare R2、MinIO)、パススタイルのアドレス指定 (`{endpoint}/{bucket}/{key}`)、AWS SigV4 で署名。
- **GitHub** — 固定の `tag_name` の下にリリースアセットとして公開されます (クライアントは常に `/releases/latest` を取得するため、ローテーションをまたいで最新に保たれます)。その 1 つのリポジトリだけにスコープを絞った fine-grained personal access token を使用してください。
- **Telegram** — ボット (`sendDocument`) を介してドキュメントとして送信されます。ボットのスコープは単一のチャット/チャンネルに限定してください。

各チャネルは独立しており (1 つが失敗しても他はブロックされません)、失敗をログに記録する前にバックオフ (5 秒 / 30 秒 / 120 秒) 付きで 3 回リトライします。`bootstrap-publish` フィーチャーなしでは、`enabled: true` は警告をログに出すだけで何もしません。設定セクション自体は常に有効な JSON であるため、設定ファイルはビルド間で移植性を保ちます。

**セキュリティに関する注意:** サーバーの秘密鍵が漏洩した場合、攻撃者はすでに有効なブートストラップディスクリプターを偽造できます (署名鍵は秘密鍵から決定論的に導出されるため)。自動公開の認証情報がその偽造能力を追加するわけではありませんが、侵害されたサーバーがオペレーターの正規の信頼された配布チャネルを通じて偽造ディスクリプターをプッシュし、すでに接続済みのユーザーだけでなくまったく新しいユーザーにまで届けることを可能にしてしまいます。`server.json` 内のこれらの認証情報は、他のあらゆるシークレットと同様に慎重に扱ってください (ファイルモード `0600`、`aivpn-server` を実行するユーザーのみ読み取り可能)。

### ローカル DNS プロキシ

すべての DNS クエリを VPN トンネル経由で転送します (Linux):

```bash
aivpn-client -k "aivpn://..." --dns-proxy 127.0.0.1:5300 --dns-upstream 1.1.1.1:53
```

### トラフィック記録 — カスタムマスクの作成

実際のアプリケーショントラフィックを記録して、新しい擬態プロファイルを生成します:

```bash
# Connect with an admin key, then:
aivpn-client record start --service myapp
# ... use the application for 60+ seconds ...
aivpn-client record stop
```

サーバーはパケットサイズのヒストグラムとパケット到着間隔を分析して `MaskProfile` を生成し、セルフテストで検証してから、アクティブなセッションに配布します。

### ポリモーフィックマスク

各セッションは、ベースマスクからセッションごとに一意に摂動させたバリアントを使用できます。そのため、多数の接続のトラフィックを比較する観測者が、単一の静的なマスクプロファイルをユーザーやセッションをまたいでフィンガープリントすることはできません。サーバーはセッション自身の鍵素材から決定論的にバリアントを導出し、既存の `MaskUpdate` チャネルを通じてクライアントにプッシュします。クライアントはそれを適用するだけで、クライアント側に新たな暗号処理は必要ありません。摂動はマスクごとに上限が設けられており (IAT ジッタースケール、パディングシフト、ヘッダーギャップのバイト数、FSM 滞留時間スケール)、トラフィックは引き続き擬態対象のプロトコルにもっともらしく一致します。FSM の状態グラフ、偽装プロトコル、エフェメラル鍵の長さが変更されることはありません。最初のハンドシェイクでは常に (名前付きプリセットではなく) ブートストラップのフォールバックマスクを使用するため、セッションのバリアントがプッシュされる前の段階でフィンガープリントされることはありません。

```bash
aivpn-client -k "aivpn://..." --polymorphic-base webrtc_yandex_telemost_v1
```

Linux、Windows、macOS、iOS、Android の GUI では、マスク選択欄の隣に対応する「Polymorphic」チェックボックスがあります。

マスクプロファイルでは、オプションの `perturbation_bounds` を宣言して、ポリモーフィックなバリアントがベースプロファイルからどこまで逸脱してよいかを制御できます:

```json
{
  "mask_id": "webrtc_yandex_telemost_v1",
  "perturbation_bounds": {
    "iat_jitter_scale": 0.15,
    "padding_shift_bytes": 8,
    "header_gap_bytes": 4,
    "fsm_dwell_scale": 0.2
  }
}
```

### クラウドソーシングによるマスクフィードバック (オプトイン)

クライアントは (デフォルトではオフの) オプトインにより、どのマスクが機能したかを共有したり、自分の地域でうまく機能しているマスクについてのサーバーからのヒントを受け取ったりできます。レポートは、ユーザーが設定する粗い 2 文字の ISO-3166 国コードごとに集計され、それより細かい位置情報がクライアントから送信されることは決してありません。サーバーは、あるマスク/地域について少なくとも K=20 人の異なる報告者が寄与した時点で初めてレポートを集計します (報告者の識別情報を一切保存しない HyperLogLog スケッチで追跡)。また、報告の少ない国は、同じ大陸の近隣国が k-匿名性のゲートを満たした時点でその大陸単位にまとめられます。集計用メモリは、エビクション付きのハードキャップと定期的なスイープによって上限が設けられています。報告者ごとの投票上限によって、単一の報告者が地域のランキングをどれだけ歪められるかも制限されます。

デスクトップクライアントはマスクの*成功と失敗の両方*を記録します。ハンドシェイク前の接続失敗はまとめられ、その時点で使用されていたマスクに帰属され、再起動後も `~/.config/aivpn/mask_feedback.json` に保持され、次回接続に成功したときに集計して報告されます。`--receive-mask-hints` が有効な場合、クライアントは初期マスクの選択を、その地域で報告された最もスコアの高いプリセットへとゆるやかに寄せます。明示的な `--preferred-mask`/`--polymorphic-base` を上書きすることはなく、最初のマスクが署名済みブートストラップディスクリプターのままでなければならない場合 (例: `--no-fallback`/本番向けセキュアビルド) には適用されないため、ブートストラップのセキュリティが弱まることはありません。`--share-mask-feedback` と `--receive-mask-hints` は完全に独立したトグルであり、クライアントは自身のフィードバックを一切共有せずに地域ヒントを受け取ることもできます。

サーバーは、オプトインしたクライアントに `FeedbackConfig` 制御メッセージで報告の頻度をプッシュします。これは `server.json` のオプションの `"feedback"` ブロックで調整できます:

```json
{
  "feedback": {
    "report_failure_threshold": 3,
    "report_interval_secs": 3600
  }
}
```

`report_failure_threshold` は、マスクが失敗とマークされるまでの連続失敗回数の最小値です。`report_interval_secs` は、クライアントがフィードバックを送信する間隔の最小値です。どちらもオプションで、ブロック (またはキー) が省略された場合のデフォルトはそれぞれ `3` と `3600` です。

```bash
aivpn-client -k "aivpn://..." --share-mask-feedback --receive-mask-hints --country-code DE
```

両方のトグルと国コードの欄は、Linux、Windows、macOS、iOS、Android の GUI の設定画面でも利用できます。

### ベンチマーク

```bash
aivpn-client bench -k "aivpn://..."
# P50: 12ms  P95: 28ms  Up: 47 Mbps  Down: 52 Mbps  Score: 94/100
aivpn-client bench -k "aivpn://..." --json
```

---

### マスクの署名と検証 (来歴)

マスクはトラフィックの整形方法を定義し、さらに重要なことに*パケットの解析方法*
(`tag_offset`、ヘッダーレイアウト、`spoof_protocol`) も定義します。したがって、悪意のあるマスクや破損したマスクが
サーバーやクライアントに届くことは、現実の攻撃対象領域となります。aivpn のマスクは
プロファイル**全体**に対する ed25519 署名を持ちます。サーバーは配布するマスクに
オペレーター鍵で署名でき、サーバーとクライアントの両方が読み込み時にその
署名を検証できます。

検証には 3 つのモードがあります (`mask_verify_mode`、または `--mask-verify-mode`、環境変数
`AIVPN_MASK_VERIFY_MODE`):

| モード | 動作 |
|------|-----------|
| `off` | 署名チェックを行いません。 |
| `warn` | **デフォルト。** 検証し、失敗時には警告をログに出しますが、マスクは読み込みます。コーパスがまだ署名されていなくても何も壊れません。 |
| `enforce` | オペレーターの公開鍵に対して署名が検証できないマスクをすべて拒否します。事前にマスクコーパス全体が署名されている必要があります。 |

`enforce` を有効にするためのオペレーターの作業手順:

```bash
# 1. Generate an operator signing key (prints the public key to distribute).
aivpn-server --gen-mask-signing-key /etc/aivpn/mask-signing.key

# 2. Sign your whole mask corpus in place (run once; also re-run after adding masks).
aivpn-server --sign-mask-dir /var/lib/aivpn/masks --mask-signing-key /etc/aivpn/mask-signing.key

# 3. Server: point at the signing key (auto-signs newly generated masks) and enforce.
#    server.json:  "mask_signing_key": "/etc/aivpn/mask-signing.key", "mask_verify_mode": "enforce"

# 4. Clients: ship them the operator PUBLIC key and enforce.
#    client:  --mask-operator-pubkey <BASE64_PUBKEY> --mask-verify-mode enforce
```

ダウンリンクの `reverse_profile` に対しても、公開鍵は独立して検証されます。
`enforce` は署名されていないマスクを拒否するため、段階的に展開してください。すべてのサーバーの
マスクディレクトリが署名され、クライアントが公開鍵を持つまでは `warn` のままにしておきます。
署名鍵はシークレットです。`0600` で保存し、オペレーターのみが読み取れるようにしてください。


### ML-DPI 検証

GBDT は、クライアントの受け入れと認証の後に、選択された外側の QUIC、RTC、STUN フレームを受け取ります。カプセル化を解除した内側のパケットは、外側のトラフィックとしては使用されません。QUIC 1-RTT の特徴量は、スピンビットと先頭バイトの保護されたビットを無視します。ワイヤー上のバイトは変更されません。学習時の重みはクラス、マスク、元のセッションのバランスを取るため、ある 1 つのファミリーの長いキャプチャーが他を押しのけることはありません。学習と検証はセッション単位で分割され、nDPI がやり取り全体にラベルを付けます。そのラベルが表すのは対象プロトコルへの適合性であり、ISP が VPN を検出する確率ではありません。ツールは [tools/dpi](tools/dpi/README.md) にあり、指標と制限事項は [モデルレポート](assets/dpi/report.md) にあります。共通のトラフィック生成方式での検証は、任意の DPI に対する耐性を証明するものではありません。


## セキュリティモデル

| 特性 | メカニズム |
|----------|-----------|
| 暗号化 | ChaCha20-Poly1305 AEAD |
| 鍵交換 | X25519 ECDH |
| セッション認証 | クライアントごとの PSK (オプションでデバイスバインディング) |
| 前方秘匿性 | 通信中の X25519 鍵ラチェット |
| リプレイ保護 | セッションごとの 256 エントリのスライディングウィンドウ |
| セッションの匿名性 | BLAKE3 から導出した 8 バイトのレゾナンスタグ。平文のセッション ID なし |
| トラフィック擬態 | `MaskProfile` FSM: ヘッダー注入、IAT 整形 |
| マスクの完全性 | Neural Resonance の MSE しきい値 (0.35)、自動ローテーション |
| NAT 越え | サーバー側は nftables/iptables、クライアント側は `SO_REUSEPORT` |

詳細な攻撃者モデルと脅威分析: [THREAT_MODEL.md](THREAT_MODEL.md)。

---

## プロジェクト構成

```
aivpn/
├── crates/aivpn-common/src/
│   ├── crypto.rs          # X25519, ChaCha20-Poly1305, BLAKE3
│   ├── mask.rs            # Mimicry profiles (WebRTC, QUIC, DNS)
│   ├── protocol.rs        # Packet format and control plane
│   └── fec.rs             # XOR Forward Error Correction
├── crates/aivpn-client/src/
│   ├── client.rs          # Core state machine
│   ├── tunnel.rs          # Cross-platform TUN interface
│   ├── kill_switch.rs     # Kill-switch (nftables / pfctl / WFP)
│   └── mimicry.rs         # Traffic shaping engine
├── crates/aivpn-server/src/
│   ├── gateway.rs         # UDP gateway, session dispatch
│   ├── neural.rs          # Neural Resonance module
│   ├── nat.rs             # NAT forwarder (IPv4 + IPv6 NAT66)
│   ├── client_db.rs       # Client database (roles, device binding, exit_node)
│   ├── mgmt_service.rs    # Shared REST + in-tunnel management dispatch
│   ├── audit_log.rs       # Tamper-evident hash-chain admin audit log
│   ├── pending_config.rs  # Apply-with-rollback (commit-confirm) for heavy config
│   ├── pool_sync.rs       # In-protocol pool synchronization
│   ├── pool_dialer.rs     # Masked pool-client transport (dial peers, exit routing)
│   └── pool_partition.rs  # Hard per-node VPN-IP partitioning
├── crates/aivpn-common/src/ssh_install.rs  # russh SSH-install client + embedded installer bundle
├── deploy/install-server.sh   # systemd-first server installer (##AIVPN progress markers)
├── platforms/android/         # Android Kotlin app
├── platforms/ios/             # iOS SwiftUI app + NEPacketTunnelProvider
├── crates/aivpn-windows/      # Windows egui GUI
├── platforms/macos/           # macOS SwiftUI menu bar app
├── assets/masks/          # Bundled traffic mimicry profiles (JSON)
├── deploy/ci/             # CI gates invoked from the Makefile
├── deploy/docker/             # Dockerfiles and entrypoint
├── Dockerfile
├── docker-compose.yml
└── THREAT_MODEL.md
```

---

## ライセンス

MIT — [LICENSE](LICENSE) を参照してください。
