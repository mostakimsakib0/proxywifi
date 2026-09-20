# Developing ProxyWiFi

ProxyWiFi is a Rust workspace. This file is the practical "how do I build, run
and test it" guide.

## Workspace layout

```text
proxywifi-core/     shared library: models, NetworkManager client, profile
                    store, secret handling, config paths
proxywifi-daemon/   privileged system daemon (`proxywifi-daemon` binary)
proxywifi-cli/      user-facing CLI (`proxywifi` binary)
packaging/          systemd unit + D-Bus system-bus policy + install notes
```

| Crate | Depends on | Purpose |
| --- | --- | --- |
| `proxywifi-core` | `zbus` 4 (tokio) | Talks to NetworkManager, owns the on-disk profile model |
| `proxywifi-daemon` | `proxywifi-core` | Polls NetworkManager, drives the proxy state machine, exports `org.proxywifi.Daemon` |
| `proxywifi-cli` | `proxywifi-core` | Reads Wi-Fi state and edits profiles; never starts the proxy itself |

## Prerequisites

- Rust 1.96 or newer (workspace was developed and linted against 1.96).
- NetworkManager running, with a D-Bus **system** bus reachable.
  `cargo build`/`cargo test` compile fine without it — only the live
  integration tests care.
- `dbus-run-session` (package `dbus`) for the daemon's D-Bus surface tests,
  and `gdbus`/`busctl` if you want to poke the interface by hand while hacking.

## Build

```bash
cargo build --workspace            # debug
cargo build --workspace --release  # optimized (thin LTO, stripped)
```

## Test

```bash
cargo test --workspace
```

Two integration suites exist, and **both skip instead of failing** when the
environment they need is missing, so `cargo test` stays green in containers:

- `proxywifi-core/tests/networkmanager_live.rs` — talks to the real system bus
  and asserts our derived Wi-Fi state agrees with NetworkManager's own
  `PrimaryConnectionType`/device properties.
- `proxywifi-daemon/tests/dbus_surface.rs` — serves the real interface object on
  the **session** bus via `DaemonDbusServer::export_on` and checks method
  names, signatures, JSON payload shapes and error mapping.

To force the D-Bus suite onto a private bus (recommended when you are unsure
whether a session bus exists):

```bash
dbus-run-session -- cargo test -p proxywifi-daemon
```

## Lint and format

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

Both are expected to be clean: the tree is `rustfmt`-formatted and
warning-free under the default clippy lints.

## Running the daemon unprivileged

The daemon connects to the system bus and tries to own
`org.proxywifi.Daemon`. If the name cannot be taken (no policy file, no root)
it logs a warning and keeps running, so you can exercise the polling loop and
the routing logic as a normal user:

```bash
# keep state out of your real config, and point logs at a scratch dir
export XDG_CONFIG_HOME=/tmp/proxywifi-dev
export PROXYWIFI_RUN_DIR=/tmp/proxywifi-dev/run
export RUST_LOG=debug

cargo run -p proxywifi-daemon
```

The daemon exports the interface on the system bus only. To talk to it over a
private/session bus, use the test harness in
`proxywifi-daemon/tests/dbus_surface.rs` as a template
(`DaemonDbusServer::export_on`).

## Environment variables

| Variable | Read by | Meaning |
| --- | --- | --- |
| `XDG_CONFIG_HOME` | all binaries | Base config dir; profiles live in `$XDG_CONFIG_HOME/proxywifi/profiles.json` |
| `PROXYWIFI_RUN_DIR` | daemon | Absolute runtime dir (pids, sockets, logs). Defaults to the config dir |
| `RUST_LOG` | all binaries | `tracing` filter (`info` default in the daemon, `warn` in the CLI) |
| `PROXYWIFI_LOG_DESTINATION` | daemon | `journal` (default, stderr → journald) or `file` for daily-rotated files under `$PROXYWIFI_RUN_DIR/logs` |

## Using the CLI

```bash
cargo run -p proxywifi-cli -- status
cargo run -p proxywifi-cli -- profiles list
cargo run -p proxywifi-cli -- profiles add <connection-uuid> \
    --host 10.0.0.1 --port 1080 --type socks5 --auto-connect
cargo run -p proxywifi-cli -- profiles enable <connection-uuid>
```

`status` prints the active SSID, its NetworkManager connection UUID, the
matched profile and the effective proxy settings. When nothing is connected it
additionally lists saved Wi-Fi connections so you can copy a UUID.

## D-Bus surface (`org.proxywifi.Daemon`)

Object path: `/org/proxywifi/Daemon`. Aggregate results are JSON strings (see
the module docs in `proxywifi-daemon/src/dbus_server.rs` for why).

| Member | Signature | Returns |
| --- | --- | --- |
| `Version` (property) | `s` | package version |
| `ApiVersion` (property) | `u` | bumped when the surface changes (currently `1`) |
| `GetStatus()` | → `s` | JSON `ProxyStatus` |
| `GetWifiConnections()` | → `s` | JSON array of `WifiConnection` |
| `GetAvailableNetworks()` | → `s` | JSON array of `{ssid, strength}` |
| `GetProxyProfiles()` | → `s` | JSON array of `ProxyProfile` |
| `StartProxy(uuid)` | `s` → `b` | empty `uuid` means "use the active Wi-Fi" |
| `StopProxy()` | → `b` | removes all firewall/proxy state |
| `TestProxy()` | → `s` | JSON `ProxyTestResult` |

Example while the daemon runs as root:

```bash
busctl --system call org.proxywifi.Daemon /org/proxywifi/Daemon \
    org.proxywifi.Daemon GetStatus
```

## Installing the system service

See `packaging/README.md`. Short version: copy
`packaging/dbus/org.proxywifi.Daemon.conf` into
`/usr/share/dbus-1/system.d/`, copy `packaging/systemd/proxywifi.service`
into `/etc/systemd/system/`, then `systemctl daemon-reload &&
systemctl enable --now proxywifi`.
