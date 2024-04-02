# ![OpenGFW](docs/logo.png)

[![Quality check status](https://github.com/apernet/OpenGFW/actions/workflows/check.yaml/badge.svg)](https://github.com/apernet/OpenGFW/actions/workflows/check.yaml)
[![License][1]][2]

[1]: https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg
[2]: LICENSE

OpenGFW は、あなた専用の DIY 中国のグレートファイアウォール (https://en.wikipedia.org/wiki/Great_Firewall) です。Linux 上で利用可能な柔軟で使いやすいオープンソースプログラムとして提供されています。なぜ権力者だけが楽しむのでしょうか？権力を人々に与え、検閲を民主化する時が来ました。自宅のルーターにサイバー主権のスリルをもたらし、プロのようにフィルタリングを始めましょう - あなたもビッグブラザーになることができます。

**ドキュメントウェブサイト: https://gfw.dev/**

Telegram グループ: https://t.me/OpGFW

> [!CAUTION]
> 本プロジェクトはまだ初期開発段階にあります。テスト時のリスクは自己責任でお願いします。私たちは、このプロジェクトを一緒に改善するために貢献者を探しています。

## 特徴

- フル IP/TCP 再アセンブル、各種プロトコルアナライザー
  - HTTP、TLS、QUIC、DNS、SSH、SOCKS4/5、WireGuard、OpenVPN、その他多数
  - Shadowsocks、VMess の「完全に暗号化されたトラフィック」の検出など (https://gfw.report/publications/usenixsecurity23/en/)
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
