# Installing ProxyWiFi as a system service

```text
packaging/
├── dbus/org.proxywifi.Daemon.conf   D-Bus system-bus policy
├── systemd/proxywifi.service        systemd unit for proxywifi-daemon
└── README.md                        this file
```

## 1. Build and install the binaries

```bash
cargo build --release --workspace
sudo install -Dm755 target/release/proxywifi-daemon /usr/bin/proxywifi-daemon
sudo install -Dm755 target/release/proxywifi        /usr/bin/proxywifi
```

## 2. Create the client group

Controlling the proxy means controlling the machine's traffic, so the daemon is
reachable only by root and by members of `proxywifi`.

```bash
sudo groupadd --system proxywifi
sudo usermod -aG proxywifi "$USER"   # log out/in for the new group to apply
```

## 3. Install the D-Bus policy

```bash
sudo install -Dm644 packaging/dbus/org.proxywifi.Daemon.conf \
    /usr/share/dbus-1/system.d/org.proxywifi.Daemon.conf
sudo systemctl reload dbus
```

## 4. Install and start the service

```bash
sudo install -Dm644 packaging/systemd/proxywifi.service \
    /etc/systemd/system/proxywifi.service
sudo systemctl daemon-reload
sudo systemctl enable --now proxywifi
```

The unit creates `/run/proxywifi` (`RuntimeDirectory=`) and `/var/lib/proxywifi`
(`StateDirectory=`) and sets `PROXYWIFI_RUN_DIR=/run/proxywifi` so daemon state
never lands in the working directory.

## 5. Verify

```bash
systemctl status proxywifi
journalctl -u proxywifi -n 50 --no-pager

# the daemon should own the name now
busctl --system status org.proxywifi.Daemon

# read the JSON status payload
busctl --system call org.proxywifi.Daemon /org/proxywifi/Daemon \
    org.proxywifi.Daemon GetStatus

# CLI (same machine, user in the proxywifi group)
proxywifi status
```

If `journalctl` shows

```text
could not request org.proxywifi.Daemon: ...
```

then step 3 was skipped or `dbus` was not reloaded.

If the CLI reports `AccessDenied` for the bus name, the user is not in the
`proxywifi` group yet (check with `id -nG`).

## Uninstall

```bash
sudo systemctl disable --now proxywifi
sudo rm /etc/systemd/system/proxywifi.service
sudo rm /usr/share/dbus-1/system.d/org.proxywifi.Daemon.conf
sudo rm /usr/bin/proxywifi-daemon /usr/bin/proxywifi
sudo systemctl daemon-reload
sudo systemctl reload dbus
```

## Known limitations of the current prototype (Phase 0–2)

- The daemon needs `nft`, `ip` and `tun2socks` (https://github.com/xjasonlyu/tun2socks)
  on `PATH`; it exits at start-up otherwise. Set `PROXYWIFI_ALLOW_PROTOTYPE=1`
  to run the observe-only stubs instead. A stale `inet proxywifi` table left by
  a crash is cleared at start-up, and `nft delete table inet proxywifi` removes
  it by hand.
- Proxy credentials are stored by the daemon in `secrets.json` next to its
  profile store (root-owned, `0600`); profiles only carry an opaque
  `secret_id`. `proxywifi profiles add --username/--password` needs a running
  daemon for this (`StoreSecret` / `DeleteSecret` over D-Bus). A root daemon
  cannot reach a user's session keyring, hence the file. The `Keyring` auth
  method name is historical.
- `ProtectKernelTunables=yes` is deliberately not set in the unit because
  Phase 3 needs sysctl access; see the comment in `systemd/proxywifi.service`.
