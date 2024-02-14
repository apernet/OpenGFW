# ![OpenGFW](docs/logo.png)

[![License][1]][2]

[1]: https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg
[2]: LICENSE

OpenGFW 是一个 Linux 上灵活、易用、开源的 [GFW](https://zh.wikipedia.org/wiki/%E9%98%B2%E7%81%AB%E9%95%BF%E5%9F%8E)
实现，并且在许多方面比真正的 GFW 更强大。可以部署在家用路由器上的网络主权。

> [!CAUTION]
> 本项目仍处于早期开发阶段。测试时自行承担风险。

> [!NOTE]
> 我们正在寻求贡献者一起完善本项目，尤其是实现更多协议的解析器！

## 功能

- 完整的 IP/TCP 重组，各种协议解析器
  - HTTP, TLS, DNS, SSH, SOCKS4/5, WireGuard, 更多协议正在开发中
  - Shadowsocks 等 "全加密流量" 检测 (https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf)
  - 基于 Trojan-killer 的 Trojan 检测 (https://github.com/XTLS/Trojan-killer)
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

## 使用

### 构建

```shell
go build
```

### 运行

```shell
export OPENGFW_LOG_LEVEL=debug
./OpenGFW -c config.yaml rules.yaml
```

#### OpenWrt

OpenGFW 在 OpenWrt 23.05 上测试可用（其他版本应该也可以，暂时未经验证）。

安装依赖：

```shell
opkg install kmod-nft-queue kmod-nf-conntrack-netlink
```

### 样例配置

```yaml
io:
  queueSize: 1024
  local: true # 如果需要在 FORWARD 链上运行 OpenGFW，请设置为 false

workers:
  count: 4
  queueSize: 16
  tcpMaxBufferedPagesTotal: 4096
  tcpMaxBufferedPagesPerConn: 64
  udpMaxStreams: 4096

# 指定的geoip/geosite档案路径
geo:
  geoip: geoip.dat
  geosite: geosite.dat
```

### 样例规则

[解析器属性](docs/Analyzers.md)

规则的语法请参考 [Expr Language Definition](https://expr-lang.org/docs/language-definition)。

```yaml
- name: block v2ex http
  action: block
  expr: string(http?.req?.headers?.host) endsWith "v2ex.com"

- name: block v2ex https
  action: block
  expr: string(tls?.req?.sni) endsWith "v2ex.com"

- name: block shadowsocks
  action: block
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
```

#### 支持的 action

- `allow`: 放行连接，不再处理后续的包。
- `block`: 阻断连接，不再处理后续的包。
- `drop`: 对于 UDP，丢弃触发规则的包，但继续处理同一流中的后续包。对于 TCP，效果同 `block`。
- `modify`: 对于 UDP，用指定的修改器修改触发规则的包，然后继续处理同一流中的后续包。对于 TCP，效果同 `allow`。
