#!/usr/bin/env bash
# Install ProxyWiFi system-wide (daemon service, D-Bus policy, GUI, panel icon).
# Run from the repo root after `cargo build --release --workspace`:  sudo bash packaging/install.sh
set -euo pipefail
[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }
U=${SUDO_USER:?run via sudo}
if ! command -v tun2socks >/dev/null; then
  case $(uname -m) in x86_64) A=amd64;; aarch64) A=arm64;; *) echo "install tun2socks manually"; exit 1;; esac
  echo "tun2socks not found, downloading the official release ($A)"
  T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
  curl -fsSL -o "$T/t.zip" "https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-$A.zip"
  (cd "$T" && python3 -m zipfile -e t.zip .)
  install -Dm755 "$T/tun2socks-linux-$A" /usr/local/bin/tun2socks
fi

install -Dm755 target/release/proxywifi-daemon /usr/bin/proxywifi-daemon
install -Dm755 target/release/proxywifi        /usr/bin/proxywifi
install -Dm755 target/release/proxywifi-gui    /usr/bin/proxywifi-gui
install -Dm755 packaging/proxywifi-tray.py     /usr/bin/proxywifi-tray
install -Dm644 packaging/desktop/proxywifi.desktop      /usr/share/applications/proxywifi.desktop
install -Dm644 packaging/desktop/proxywifi-tray.desktop /etc/xdg/autostart/proxywifi-tray.desktop
getent group proxywifi >/dev/null || groupadd --system proxywifi
usermod -aG proxywifi "$U"
install -Dm644 packaging/dbus/org.proxywifi.Daemon.conf /usr/share/dbus-1/system.d/org.proxywifi.Daemon.conf
systemctl reload dbus

# Stop any hand-started daemon, carry its profiles over to the service's state dir.
pkill -x proxywifi-daem 2>/dev/null || pkill -f /proxywifi-daemon 2>/dev/null || true
sleep 1
if [ -f /root/.config/proxywifi/profiles.json ] && [ ! -f /var/lib/proxywifi/profiles.json ]; then
  install -Dm600 /root/.config/proxywifi/profiles.json /var/lib/proxywifi/profiles.json
fi
for f in /root/.config/proxywifi/*; do
  [ -e "$f" ] && [ ! -e "/var/lib/proxywifi/$(basename "$f")" ] && cp -a "$f" /var/lib/proxywifi/ || true
done

install -Dm644 packaging/systemd/proxywifi.service /etc/systemd/system/proxywifi.service
systemctl daemon-reload
systemctl enable --now proxywifi
sleep 2
systemctl --no-pager status proxywifi | head -12
echo "Done. Log out/in once so group 'proxywifi' applies to your desktop session; the panel icon starts at login."
