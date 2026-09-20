# ProxyWiFi

Per-Wi-Fi transparent proxy for Linux: connect to a Wi-Fi network, and the
proxy configured for *that* connection is applied below the application layer —
no `HTTP_PROXY`, no browser settings, no per-application configuration.

```text
My Hotspot  →  NetworkManager  →  ProxyWiFi daemon  →  nftables / TUN  →  SOCKS5  →  Internet
```

The design principle: **proxy configuration belongs to the network connection,
while applications stay unaware of it.**

- Product and architecture spec: [`plan.md`](plan.md)
- Build / test / hack on it: [`docs/DEVELOPING.md`](docs/DEVELOPING.md)
- Install as a system service: [`packaging/README.md`](packaging/README.md)

## Workspace

| Crate | Binary | Role |
| --- | --- | --- |
| `proxywifi-core` | — | Models, NetworkManager client, profile store, secrets, config paths |
| `proxywifi-daemon` | `proxywifi-daemon` | Privileged daemon: polls NetworkManager, drives the proxy state machine, serves `org.proxywifi.Daemon` |
| `proxywifi-cli` | `proxywifi` | Shows Wi-Fi/proxy state and manages per-connection profiles |

## Quick start

```bash
cargo build --workspace
cargo test --workspace

cargo run -p proxywifi-cli -- status
cargo run -p proxywifi-cli -- profiles add <connection-uuid> \
    --host 10.0.0.1 --port 1080 --type socks5 --auto-connect
```

## Status

Phase 0–2 of the plan are implemented: NetworkManager detection (devices,
active Wi-Fi, saved connections, scans), the per-connection profile store, the
CLI, and the daemon's polling state machine plus D-Bus surface.

Phase 3 (TCP) is implemented: the daemon runs `tun2socks` on a `pwtun0` TUN
device, steers traffic with `0.0.0.0/1` + `128.0.0.0/1` routes, binds the engine
to the Wi-Fi interface for loop prevention, and installs an `inet proxywifi`
nftables table for the kill switch, local-network mode and IPv6 leak guard. It
needs `nft`, `ip` and `tun2socks` on `PATH`; without them the daemon refuses to
start unless `PROXYWIFI_ALLOW_PROTOTYPE=1` (observe-only stubs).

Phase 4 (DNS): with `dns = proxied` (the default) applications' UDP/53 is
redirected by nftables to a built-in forwarder on the tunnel address, which
re-sends each query as DNS-over-TCP to 1.1.1.1 / 9.9.9.9 *through the proxy* —
so it works with SOCKS5 servers that cannot relay UDP. Queries to a local stub
resolver (127.0.0.53) are left alone; the stub's own upstream queries are
caught. Plain IPv6 DNS is dropped while proxying, so it cannot leak. The proxy
test reports `dns_ok`. With `dns = direct` nothing is intercepted.

Phase 5 (UDP and IPv6), each covered by an end-to-end namespace test:

| Setting | Behaviour |
| --- | --- |
| `--udp proxy` (default) | UDP goes through the tunnel to the proxy's SOCKS5 UDP relay. `TestProxy` reports `udp_ok`; a proxy that refuses `UDP ASSOCIATE` (many do) leaves UDP failing — never leaking — so QUIC apps fall back to TCP after a timeout. |
| `--udp block` | UDP is rejected with ICMP so QUIC & co. fall back to TCP immediately. |
| `--udp direct` | IPv4 UDP (except proxied DNS and local networks) is fwmarked and routed around the tunnel via the Wi-Fi gateway; IPv6 UDP is rejected. Explicit opt-out of the proxy. |
| `--ipv6` | IPv6 TCP is routed through the proxy (IPv6 CONNECT). Without it IPv6 is dropped while proxying. |

QUIC/HTTP3 itself is untested: it needs a real proxy with a UDP relay.

Not done yet: GUI (Phase 7).
