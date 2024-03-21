# Analyzers

Analyzers are one of the main components of OpenGFW. Their job is to analyze a connection, see if it's a protocol they
support, and if so, extract information from that connection and provide properties for the rule engine to match against
user-provided rules. OpenGFW will automatically analyze which analyzers are referenced in the given rules and enable
only those that are needed.

This document lists the properties provided by each analyzer that can be used by rules.

## DNS (TCP & UDP)

For queries:

```json
{
  "dns": {
    "aa": false,
    "id": 41953,
    "opcode": 0,
    "qr": false,
    "questions": [
      {
        "class": 1,
        "name": "www.google.com",
        "type": 1
      }
    ],
    "ra": false,
    "rcode": 0,
    "rd": true,
    "tc": false,
    "z": 0
  }
}
```

For responses:

```json
{
  "dns": {
    "aa": false,
    "answers": [
      {
        "a": "142.251.32.36",
        "class": 1,
        "name": "www.google.com",
        "ttl": 255,
        "type": 1
      }
    ],
    "id": 41953,
    "opcode": 0,
    "qr": true,
    "questions": [
      {
        "class": 1,
        "name": "www.google.com",
        "type": 1
      }
    ],
    "ra": true,
    "rcode": 0,
    "rd": true,
    "tc": false,
    "z": 0
  }
}
```

Example for blocking DNS queries for `www.google.com`:

```yaml
- name: Block Google DNS
  action: drop
  expr: dns != nil && !dns.qr && any(dns.questions, {.name == "www.google.com"})
```

## FET (Fully Encrypted Traffic)

Check https://www.usenix.org/system/files/usenixsecurity23-wu-mingshi.pdf for more information.

```json
{
  "fet": {
    "ex1": 3.7560976,
    "ex2": true,
    "ex3": 0.9512195,
    "ex4": 39,
    "ex5": false,
    "yes": false
  }
}
```

Example for blocking fully encrypted traffic:

```yaml
- name: Block suspicious proxy traffic
  action: block
  expr: fet != nil && fet.yes
```

## HTTP

```json
{
  "http": {
    "req": {
      "headers": {
        "accept": "*/*",
        "host": "ipinfo.io",
        "user-agent": "curl/7.81.0"
      },
      "method": "GET",
      "path": "/",
      "version": "HTTP/1.1"
    },
    "resp": {
      "headers": {
        "access-control-allow-origin": "*",
        "content-length": "333",
        "content-type": "application/json; charset=utf-8",
        "date": "Wed, 24 Jan 2024 05:41:44 GMT",
        "referrer-policy": "strict-origin-when-cross-origin",
        "server": "nginx/1.24.0",
        "strict-transport-security": "max-age=2592000; includeSubDomains",
        "via": "1.1 google",
        "x-content-type-options": "nosniff",
        "x-envoy-upstream-service-time": "2",
        "x-frame-options": "SAMEORIGIN",
        "x-xss-protection": "1; mode=block"
      },
      "status": 200,
      "version": "HTTP/1.1"
    }
  }
}
```

Example for blocking HTTP requests to `ipinfo.io`:

```yaml
- name: Block ipinfo.io HTTP
  action: block
  expr: http != nil && http.req != nil && http.req.headers != nil && http.req.headers.host == "ipinfo.io"
```

## SSH

```json
{
  "ssh": {
    "server": {
      "comments": "Ubuntu-3ubuntu0.6",
      "protocol": "2.0",
      "software": "OpenSSH_8.9p1"
    },
    "client": {
      "comments": "IMHACKER",
      "protocol": "2.0",
      "software": "OpenSSH_8.9p1"
    }
  }
}
```

Example for blocking all SSH connections:

```yaml
- name: Block SSH
  action: block
  expr: ssh != nil
```

## TLS

```json
{
  "tls": {
    "req": {
      "alpn": ["h2", "http/1.1"],
      "ciphers": [
        4866, 4867, 4865, 49196, 49200, 159, 52393, 52392, 52394, 49195, 49199,
        158, 49188, 49192, 107, 49187, 49191, 103, 49162, 49172, 57, 49161,
        49171, 51, 157, 156, 61, 60, 53, 47, 255
      ],
      "compression": "AA==",
      "random": "UqfPi+EmtMgusILrKcELvVWwpOdPSM/My09nPXl84dg=",
      "session": "jCTrpAzHpwrfuYdYx4FEjZwbcQxCuZ52HGIoOcbw1vA=",
      "sni": "ipinfo.io",
      "supported_versions": [772, 771],
      "version": 771,
      "ech": true
    },
    "resp": {
      "cipher": 4866,
      "compression": 0,
      "random": "R/Cy1m9pktuBMZQIHahD8Y83UWPRf8j8luwNQep9yJI=",
      "session": "jCTrpAzHpwrfuYdYx4FEjZwbcQxCuZ52HGIoOcbw1vA=",
      "supported_versions": 772,
      "version": 771
    }
  }
}
```

Example for blocking TLS connections to `ipinfo.io`:

```yaml
- name: Block ipinfo.io TLS
  action: block
  expr: tls != nil && tls.req != nil && tls.req.sni == "ipinfo.io"
```

## QUIC

QUIC analyzer produces the same result format as TLS analyzer, but currently only supports "req" direction (client
hello), not "resp" (server hello).

```json
{
  "quic": {
    "req": {
      "alpn": ["h3"],
      "ciphers": [4865, 4866, 4867],
      "compression": "AA==",
      "ech": true,
      "random": "FUYLceFReLJl9dRQ0HAus7fi2ZGuKIAApF4keeUqg00=",
      "session": "",
      "sni": "quic.rocks",
      "supported_versions": [772],
      "version": 771
    }
  }
}
```

Example for blocking QUIC connections to `quic.rocks`:

```yaml
- name: Block quic.rocks QUIC
  action: block
  expr: quic != nil && quic.req != nil && quic.req.sni == "quic.rocks"
```

## Trojan (proxy protocol)

```json
{
  "trojan": {
    "seq": [680, 4514, 293],
    "yes": true
  }
}
```

Example for blocking Trojan connections:

```yaml
- name: Block Trojan
  action: block
  expr: trojan != nil && trojan.yes
```

## SOCKS

SOCKS4:

```json
{
  "socks": {
    "version": 4,
    "req": {
      "cmd": 1,
      "addr_type": 1, // same as socks5
      "addr": "1.1.1.1",
      // for socks4a
      // "addr_type": 3,
      // "addr": "google.com",
      "port": 443,
      "auth": {
        "user_id": "user"
      }
    },
    "resp": {
      "rep": 90, // 0x5A(90) granted
      "addr_type": 1,
      "addr": "1.1.1.1",
      "port": 443
    }
  }
}
```

SOCKS5 without auth:

```json
{
  "socks": {
    "version": 5,
    "req": {
      "cmd": 1, // 0x01: connect, 0x02: bind, 0x03: udp
      "addr_type": 3, // 0x01: ipv4, 0x03: domain, 0x04: ipv6
      "addr": "google.com",
      "port": 80,
      "auth": {
        "method": 0 // 0x00: no auth, 0x02: username/password
      }
    },
    "resp": {
      "rep": 0, // 0x00: success
      "addr_type": 1, // 0x01: ipv4, 0x03: domain, 0x04: ipv6
      "addr": "198.18.1.31",
      "port": 80,
      "auth": {
        "method": 0 // 0x00: no auth, 0x02: username/password
      }
    }
  }
}
```

SOCKS5 with auth:

```json
{
  "socks": {
    "version": 5,
    "req": {
      "cmd": 1, // 0x01: connect, 0x02: bind, 0x03: udp
      "addr_type": 3, // 0x01: ipv4, 0x03: domain, 0x04: ipv6
      "addr": "google.com",
      "port": 80,
      "auth": {
        "method": 2, // 0x00: no auth, 0x02: username/password
        "username": "user",
        "password": "pass"
      }
    },
    "resp": {
      "rep": 0, // 0x00: success
      "addr_type": 1, // 0x01: ipv4, 0x03: domain, 0x04: ipv6
      "addr": "198.18.1.31",
      "port": 80,
      "auth": {
        "method": 2, // 0x00: no auth, 0x02: username/password
        "status": 0 // 0x00: success, 0x01: failure
      }
    }
  }
}
```

Example for blocking connections to `google.com:80` and user `foobar`:

```yaml
- name: Block SOCKS google.com:80
  action: block
  expr: string(socks?.req?.addr) endsWith "google.com" && socks?.req?.port == 80

- name: Block SOCKS user foobar
  action: block
  expr: socks?.req?.auth?.method == 2 && socks?.req?.auth?.username == "foobar"
```

## WireGuard

```json
{
  "wireguard": {
    "message_type": 1, // 0x1: handshake_initiation, 0x2: handshake_response, 0x3: packet_cookie_reply, 0x4: packet_data
    "handshake_initiation": {
      "sender_index": 0x12345678
    },
    "handshake_response": {
      "sender_index": 0x12345678,
      "receiver_index": 0x87654321,
      "receiver_index_matched": true
    },
    "packet_data": {
      "receiver_index": 0x12345678,
      "receiver_index_matched": true
    },
    "packet_cookie_reply": {
      "receiver_index": 0x12345678,
      "receiver_index_matched": true
    }
  }
}
```

Example for blocking WireGuard traffic:

```yaml
# false positive: high
- name: Block all WireGuard-like traffic
  action: block
  expr: wireguard != nil

# false positive: medium
- name: Block WireGuard by handshake_initiation
  action: drop
  expr: wireguard?.handshake_initiation != nil

# false positive: low
- name: Block WireGuard by handshake_response
  action: drop
  expr: wireguard?.handshake_response?.receiver_index_matched == true

# false positive: pretty low
- name: Block WireGuard by packet_data
  action: block
  expr: wireguard?.packet_data?.receiver_index_matched == true
```
