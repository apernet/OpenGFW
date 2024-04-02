# ![OpenGFW](docs/logo.png)

[![Quality check status](https://github.com/apernet/OpenGFW/actions/workflows/check.yaml/badge.svg)](https://github.com/apernet/OpenGFW/actions/workflows/check.yaml)
[![License][1]][2]

[1]: https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg
[2]: LICENSE

OpenGFW 是一个 Linux 上灵活、易用、开源的 DIY [GFW](https://zh.wikipedia.org/wiki/%E9%98%B2%E7%81%AB%E9%95%BF%E5%9F%8E) 实现，并且在许多方面比真正的 GFW 更强大。为何让那些掌权者独享乐趣？是时候把权力归还给人民，人人有墙建了。立即安装可以部署在家用路由器上的网络主权 - 你也能是老大哥。

**文档网站： https://gfw.dev/**

Telegram 群组： https://t.me/OpGFW

> [!CAUTION]
> 本项目仍处于早期开发阶段。测试时自行承担风险。我们正在寻求贡献者一起完善本项目。

## 功能

- 完整的 IP/TCP 重组，各种协议解析器
  - HTTP, TLS, QUIC, DNS, SSH, SOCKS4/5, WireGuard, OpenVPN, 更多协议正在开发中
  - Shadowsocks, VMess 等 "全加密流量" 检测 (https://gfw.report/publications/usenixsecurity23/zh/)
  - Trojan 协议检测
  - [开发中] 基于机器学习的流量分类
- 同等支持 IPv4 和 IPv6
- 基于流的多核负载均衡
- 连接 offloading
- 基于 [expr](https://github.com/expr-lang/expr) 的强大规则引擎
- 规则可以热重载 (发送 `SIGHUP` 信号)
- 灵活的协议解析和修改框架
- 可扩展的 IO 实现 (目前只有 NFQueue)
- [开发中] Web UI

## 使用场景

- 广告拦截
- 家长控制
- 恶意软件防护
- VPN/代理服务滥用防护
- 流量分析 (纯日志模式)
- 助你实现你的独裁野心
