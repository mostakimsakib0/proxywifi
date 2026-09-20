#!/usr/bin/env python3
"""Panel icon for ProxyWiFi: shows the proxy state, toggles it, opens the GUI."""
import json, os, shutil, subprocess
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import Gtk, GLib, Gio, AyatanaAppIndicator3 as AI

NAME, PATH, IFACE = "org.proxywifi.Daemon", "/org/proxywifi/Daemon", "org.proxywifi.Daemon"
bus = Gio.bus_get_sync(Gio.BusType.SYSTEM)


def call(method, args=None):
    v = bus.call_sync(NAME, PATH, IFACE, method, args, None, Gio.DBusCallFlags.NONE, 15000)
    return v.unpack()[0] if v.n_children() else None


def status():
    try:
        return json.loads(call("GetStatus"))
    except Exception:
        return None  # daemon not running


ind = AI.Indicator.new("proxywifi", "network-vpn-disabled-symbolic", AI.IndicatorCategory.SYSTEM_SERVICES)
ind.set_status(AI.IndicatorStatus.ACTIVE)
menu = Gtk.Menu()
label = Gtk.MenuItem(label="ProxyWiFi")
label.set_sensitive(False)
toggle = Gtk.MenuItem(label="Start proxy")
gui = Gtk.MenuItem(label="Open ProxyWiFi…")
quit_ = Gtk.MenuItem(label="Quit tray")
for i in (label, toggle, Gtk.SeparatorMenuItem(), gui, quit_):
    menu.append(i)
menu.show_all()
ind.set_menu(menu)
cur = {"active": False, "uuid": None}


def refresh():
    s = status()
    if s is None:
        label.set_label("ProxyWiFi: daemon not running")
        toggle.set_sensitive(False)
        ind.set_icon_full("network-vpn-disabled-symbolic", "daemon off")
        return True
    st = s.get("proxy_state", "disconnected")
    wifi = (s.get("wifi") or {}).get("ssid")
    cur["active"] = st == "active"
    cur["uuid"] = s.get("matched_profile_uuid")
    label.set_label(f"{wifi or 'No Wi-Fi'}: proxy {st}")
    toggle.set_label("Stop proxy" if st != "disconnected" else "Start proxy")
    toggle.set_sensitive(st != "disconnected" or bool(cur["uuid"]))
    ind.set_icon_full("network-vpn-symbolic" if cur["active"] else "network-vpn-disabled-symbolic", st)
    return True


def on_toggle(_):
    try:
        if cur["active"] or toggle.get_label() == "Stop proxy":
            call("StopProxy")
        else:
            call("StartProxy", GLib.Variant("(s)", (cur["uuid"],)))
    except Exception as e:
        label.set_label(f"error: {e}")
    refresh()


toggle.connect("activate", on_toggle)
def open_gui(_):
    # installed binary first, then the source tree's release build
    dev = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "release", "proxywifi-gui")
    exe = shutil.which("proxywifi-gui") or (dev if os.path.exists(dev) else None)
    if exe:
        subprocess.Popen([exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


gui.connect("activate", open_gui)
quit_.connect("activate", lambda _: Gtk.main_quit())
refresh()
GLib.timeout_add_seconds(3, refresh)
Gtk.main()
