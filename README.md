# ProxyWiFi

**Per-Wi-Fi transparent proxy for Linux.** Attach a proxy to a Wi-Fi connection
once; whenever you join that network, every app and terminal goes through it —
no `HTTP_PROXY`, no browser settings, no per-app configuration.

```text
Any Wi-Fi network -> NetworkManager -> ProxyWiFi daemon -> nftables + TUN -> SOCKS5 / HTTP proxy -> Internet
```

Design principle: **proxy configuration belongs to the network connection, not
to the application.**

## Features

- Per-connection proxy profiles (SOCKS5 or HTTP CONNECT), keyed by NetworkManager connection UUID
- Auto-start on connect, auto-stop on disconnect; manual Stop sticks until the connection changes
- Transparent: `tun2socks` on a `pwtun0` TUN device, split default routes (`0.0.0.0/1`, `128.0.0.0/1`)
- Kill switch (nftables) — no leak if the engine dies
- Proxied DNS (DNS-over-TCP through the proxy), IPv6 leak guard, UDP `proxy` / `block` / `direct` modes
- Local-network bypass
- GTK4 / libadwaita GUI (Wi-Fi list sorted by signal, connect, edit proxy, start/stop)
- Panel tray icon (StatusNotifier / AppIndicator) with start/stop toggle
- CLI and a D-Bus API (`org.proxywifi.Daemon`, system bus)
- Proxy passwords stored via the system secret service, not in the profile file

## Requirements

Linux with NetworkManager, systemd, `nftables`, `iproute2`, and
[`tun2socks`](https://github.com/xjasonlyu/tun2socks) in `PATH` (`install.sh` downloads it if missing). Rust (stable)
to build; `libgtk-4-dev` and `libadwaita-1-dev` for the GUI; Python 3 with
`gir1.2-ayatanaappindicator3-0.1` for the tray.

## Install

```bash
cargo build --release --workspace
sudo bash packaging/install.sh
```

The script installs the binaries, desktop/autostart entries, D-Bus policy and
systemd unit, creates the `proxywifi` group (adds you to it) and starts the
daemon. Log out and in once for the group to apply. Details:
[`packaging/README.md`](packaging/README.md).

## Usage

```bash
proxywifi status
proxywifi profiles add <connection-uuid> --host 10.0.0.1 --port 1080 --type socks5 --auto-connect
proxywifi-gui          # or click the tray icon
```

With `--type http` use an HTTP proxy that supports `CONNECT`; set `--udp block`
(HTTP proxies cannot relay UDP).

## Known limitations

- Another TUN tool (Clash Verge / Mihomo) also claims `198.18.0.0/15`. Set `PROXYWIFI_TUN_ADDR=<free IPv4>` for the daemon (e.g. `Environment=PROXYWIFI_TUN_ADDR=10.77.0.1` in the systemd unit) to move ProxyWiFi's tunnel address. Untested on a live system next to Clash; the two still both capture default traffic, so run only one at a time.
- UDP relay is covered by a namespace test against a local SOCKS5 relay; QUIC against a real proxy is untested.
- The hardened systemd unit has had limited real-world testing.

## Docs

- Build / test / hack: [`docs/DEVELOPING.md`](docs/DEVELOPING.md)
- Packaging: [`packaging/README.md`](packaging/README.md)

## Workspace

| Crate | Binary | Role |
| --- | --- | --- |
| `proxywifi-core` | — | Models, NetworkManager client, profile store, secrets, config paths |
| `proxywifi-daemon` | `proxywifi-daemon` | Privileged daemon: polls NetworkManager, drives the proxy state machine, serves `org.proxywifi.Daemon` |
| `proxywifi-cli` | `proxywifi` | Shows Wi-Fi/proxy state and manages per-connection profiles |
| `proxywifi-gui` | `proxywifi-gui` | GTK4/libadwaita front end |

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

Phase 7 (GUI and tray) is implemented.
