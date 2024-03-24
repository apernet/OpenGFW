# ![OpenGFW](docs/logo.png)

[![Quality check status](https://github.com/apernet/OpenGFW/actions/workflows/check.yaml/badge.svg)](https://github.com/apernet/OpenGFW/actions/workflows/check.yaml)
[![License][1]][2]

[1]: https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg
[2]: LICENSE

OpenGFW は、あなた専用の DIY 中国のグレートファイアウォール (https://en.wikipedia.org/wiki/Great_Firewall) です。Linux 上で利用可能な柔軟で使いやすいオープンソースプログラムとして提供されています。なぜ権力者だけが楽しむのでしょうか？権力を人々に与え、検閲を民主化する時が来ました。自宅のルーターにサイバー主権のスリルをもたらし、プロのようにフィルタリングを始めましょう - あなたもビッグブラザーになることができます。

Telegram グループ: https://t.me/OpGFW

> [!CAUTION]
> このプロジェクトはまだ開発の初期段階です。使用は自己責任でお願いします。

> [!NOTE]
> 私たちはこのプロジェクト、特により多くのプロトコル用のアナライザーの実装を手伝ってくれるコントリビューターを探しています！！！

## 特徴

- フル IP/TCP 再アセンブル、各種プロトコルアナライザー
  - HTTP、TLS、QUIC、DNS、SSH、SOCKS4/5、WireGuard、その他多数
  - Shadowsocks の「完全に暗号化されたトラフィック」の検出など (https://gfw.report/publications/usenixsecurity23/en/)
  - Trojan プロキシプロトコルの検出
  - [WIP] 機械学習に基づくトラフィック分類
- IPv4 と IPv6 をフルサポート
- フローベースのマルチコア負荷分散
- 接続オフロード
- [expr](https://github.com/expr-lang/expr) に基づく強力なルールエンジン
- ルールのホットリロード (`SIGHUP` を送信してリロード)
- 柔軟なアナライザ＆モディファイアフレームワーク
- 拡張可能な IO 実装 (今のところ NFQueue のみ)
- [WIP] ウェブ UI

## ユースケース

- 広告ブロック
- ペアレンタルコントロール
- マルウェア対策
- VPN/プロキシサービスの不正利用防止
- トラフィック分析（ログのみモード）
- 独裁的な野心を実現するのを助ける

## 使用方法

### ビルド

```shell
go build
```

### 実行

```shell
export OPENGFW_LOG_LEVEL=debug
./OpenGFW -c config.yaml rules.yaml
```

#### OpenWrt

OpenGFW は OpenWrt 23.05 で動作することがテストされています（他のバージョンも動作するはずですが、検証されていません）。

依存関係をインストールしてください：

```shell
opkg install nftables kmod-nft-queue kmod-nf-conntrack-netlink
```

### 設定例

```yaml
io:
  queueSize: 1024
  rcvBuf: 4194304
  sndBuf: 4194304
  local: true # FORWARD チェーンで OpenGFW を実行したい場合は false に設定する
  rst: false # ブロックされたTCP接続に対してRSTを送信する場合はtrueに設定してください。local=falseのみです

workers:
  count: 4
  queueSize: 16
  tcpMaxBufferedPagesTotal: 4096
  tcpMaxBufferedPagesPerConn: 64
  udpMaxStreams: 4096

# 特定のローカルGeoIP / GeoSiteデータベースファイルを読み込むためのパス。
# 設定されていない場合は、https://github.com/LoyalSoldier/v2ray-rules-dat から自動的にダウンロードされます。
# geo:
#   geoip: geoip.dat
#   geosite: geosite.dat
```

### ルール例

[アナライザーのプロパティ](docs/Analyzers.md)

式言語の構文については、[Expr 言語定義](https://expr-lang.org/docs/language-definition)を参照してください。

```yaml
# ルールは、"action" または "log" の少なくとも一方が設定されていなければなりません。
- name: log horny people
  log: true
  expr: let sni = string(tls?.req?.sni); sni contains "porn" || sni contains "hentai"

- name: block v2ex http
  action: block
  expr: string(http?.req?.headers?.host) endsWith "v2ex.com"

- name: block v2ex https
  action: block
  expr: string(tls?.req?.sni) endsWith "v2ex.com"

- name: block v2ex quic
  action: block
  expr: string(quic?.req?.sni) endsWith "v2ex.com"

- name: block and log shadowsocks
  action: block
  log: true
  expr: fet != nil && fet.yes

- name: block trojan
  action: block
  expr: trojan != nil && trojan.yes

- name: v2ex dns poisoning
  action: modify
  modifier:
    name: dns
    args:
      a: "0.0.0.0"
      aaaa: "::"
  expr: dns != nil && dns.qr && any(dns.questions, {.name endsWith "v2ex.com"})

- name: block google socks
  action: block
  expr: string(socks?.req?.addr) endsWith "google.com" && socks?.req?.port == 80

- name: block wireguard by handshake response
  action: drop
  expr: wireguard?.handshake_response?.receiver_index_matched == true

- name: block bilibili geosite
  action: block
  expr: geosite(string(tls?.req?.sni), "bilibili")

- name: block CN geoip
  action: block
  expr: geoip(string(ip.dst), "cn")

- name: block cidr
  action: block
  expr: cidr(string(ip.dst), "192.168.0.0/16")
```

#### サポートされるアクション

- `allow`: 接続を許可し、それ以上の処理は行わない。
- `block`: 接続をブロックし、それ以上の処理は行わない。
- `drop`: UDP の場合、ルールのトリガーとなったパケットをドロップし、同じフローに含まれる以降のパケットの処理を継続する。TCP の場合は、`block` と同じ。
- `modify`: UDP の場合、与えられた修飾子を使って、ルールをトリガしたパケットを修正し、同じフロー内の今後のパケットを処理し続ける。TCP の場合は、`allow` と同じ。
