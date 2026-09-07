# STEALTH-Tunnel server

Standalone JVM endpoint for KoKo VPN's `STEALTH-Tunnel:` protocol. It listens for the client's
forced-SNI TLS + HTTP-injection handshake, verifies a shared token, and bridges verified traffic to
an internal **SOCKS5** or **WebSocket** proxy. Unverified peers (scanners, TLS crawlers, active
probes) are handed to a **fallback** that either returns a plain `200 OK` or transparently
reverse-proxies a real decoy site — so the port looks like an ordinary web server.

This module is completely independent of the Android app: no shared build, no shared classes. Only
plain Java SE (Java 8+), no third-party dependencies.

## One-click VPS install

On a fresh Ubuntu/Debian/CentOS VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/sugitan-byte/SNI-Stealth/main/install.sh | sudo bash
```

It installs a JDK, builds the server, generates a self-signed certificate, writes the config
(auto-generating a random auth token), installs a `systemd` service (`sni-stealth`), opens the
firewall, and prints the exact values to enter in the KoKo VPN admin. It is interactive by default
(port, SNI, fallback…) and fully non-interactive when the answers are given as env vars:

```bash
curl -fsSL https://raw.githubusercontent.com/sugitan-byte/SNI-Stealth/main/install.sh \
  | sudo PORT=443 SNI=m.google.com FALLBACK=forward FORWARD_HOST=www.bing.com BRIDGE=socks5 bash
```

Manage it afterwards:

```bash
systemctl status sni-stealth        # state
journalctl -u sni-stealth -f        # live logs
systemctl restart sni-stealth       # restart after editing server.properties
```

Re-running the installer is safe: it keeps the existing keystore and only rebuilds/reconfigures.

## Build (manual)

```bash
./build.sh                 # compiles src/ into out/
```

## Run

```bash
# Make a server certificate (self-signed is fine — the client does not validate it):
keytool -genkeypair -alias stealth -keyalg RSA -keysize 2048 -validity 3650 \
        -storetype PKCS12 -keystore server.p12 -storepass changeit \
        -dname "CN=front.example.com"

cp server.properties.example server.properties   # then edit token/keystore/fallback
java -cp out com.kokovpn.stealth.server.StealthServer --config server.properties
```

All settings can also be passed as flags (flags override the file):

```bash
java -cp out com.kokovpn.stealth.server.StealthServer \
     --port 443 --keystore server.p12 --keystore-pass changeit \
     --token 's3cr3t' --fallback forward --forward-host www.bing.com --forward-port 80
```

Terminating TLS upstream (nginx/CDN) instead? Add `--no-tls` and let the front end handle TLS.

## How a connection is routed

```
accept ─▶ read handshake head ─▶ X-Stealth-Auth == token ?
                                     ├─ yes + "Upgrade: websocket" ─▶ WebSocket bridge ─▶ SOCKS5 core
                                     ├─ yes (plain injection)      ─▶ SOCKS5 bridge
                                     └─ no  (probe)                ─▶ fallback (200 OK | forward)
```

The client forwards its device's tun2socks SOCKS5 stream through the tunnel, and the server runs
the SOCKS5 negotiation and makes the outbound connection.

## Test (no keystore needed)

```bash
./smoke-test.sh
```

Stands up an echo server and an in-process server (TLS off) and checks all three routes end to end:
correct-token SOCKS bridge, correct-token WebSocket bridge, and no-token probe → `200`.

## Probe resistance (manual)

```bash
curl -k https://<server>:8443/        # no token -> benign 200 or the decoy site
openssl s_client -connect <server>:8443 -servername front.example.com
```

A peer without the token never reaches a bridge.

## Client mapping (KoKo VPN app)

Set `HRL_SERVER_TYPE` to `STEALTH-Tunnel:` and populate, in the app's config store:

| Client setting | Source key | Meaning |
|---|---|---|
| server host / port | `_SERVER_KEY` / `_SERVER_PORT_KEY` | this server's real IP and port |
| forced SNI / front | `_SNI_HOST_KEY` | domain put in the TLS ClientHello and `Host:` |
| payload template | `_CUSTOM_PAYLOAD_KEY` | optional; supports `[crlf] [host] [port] [split] [delay] …` |
| auth token | `_STEALTH_TOKEN` | must equal this server's `token` |
| bridge | `_STEALTH_BRIDGE` | `socks5` (default) or `websocket` |
| use TLS | `_STEALTH_USE_TLS` | `true` (default) or `false` |
| extra headers | `_STEALTH_HEADERS` | optional extra request-header lines |
| ws path | `_STEALTH_WS_PATH` | WebSocket request path (default `/`) |
