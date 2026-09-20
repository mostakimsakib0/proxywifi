//! GTK4/libadwaita front-end. Runs unprivileged and does everything through
//! the daemon's `org.proxywifi.Daemon` D-Bus interface.

use adw::prelude::*;
use gtk4::{self as gtk, glib};
use libadwaita as adw;
use proxywifi_core::models::*;
use proxywifi_core::networkmanager::NmClient;
use serde::de::DeserializeOwned;
use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// D-Bus plumbing: zbus runs on a tokio runtime, results hop back to GTK.
// ---------------------------------------------------------------------------

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// Run `fut` on the tokio runtime, then `then` on the GTK main loop.
fn spawn<T: Send + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
    then: impl FnOnce(T) + 'static,
) {
    glib::spawn_future_local(async move {
        if let Ok(v) = rt().spawn(fut).await {
            then(v)
        }
    });
}

async fn daemon() -> Result<zbus::Proxy<'static>, String> {
    static P: tokio::sync::OnceCell<zbus::Proxy<'static>> = tokio::sync::OnceCell::const_new();
    P.get_or_try_init(|| async {
        // PROXYWIFI_BUS=session selects the session bus for development.
        let conn = if std::env::var("PROXYWIFI_BUS").as_deref() == Ok("session") {
            zbus::Connection::session().await
        } else {
            zbus::Connection::system().await
        }?;
        zbus::Proxy::new(
            &conn,
            "org.proxywifi.Daemon",
            "/org/proxywifi/Daemon",
            "org.proxywifi.Daemon",
        )
        .await
    })
    .await
    .cloned()
    .map_err(|e: zbus::Error| e.to_string())
}

/// Wi-Fi listing and connecting go straight to NetworkManager (polkit
/// authorizes the user), so they work without the daemon.
async fn nm() -> Result<&'static NmClient, String> {
    static NM: tokio::sync::OnceCell<NmClient> = tokio::sync::OnceCell::const_new();
    NM.get_or_try_init(|| async { NmClient::new().await })
        .await
        .map_err(|e| e.to_string())
}

async fn call_s<B>(method: &str, body: &B) -> Result<String, String>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    let p = daemon().await?;
    p.call::<_, _, String>(method, body)
        .await
        .map_err(|e| e.to_string())
}

async fn call_b<B>(method: &str, body: &B) -> Result<(), String>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    let p = daemon().await?;
    p.call::<_, _, bool>(method, body)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn get<T: DeserializeOwned>(method: &str) -> Result<T, String> {
    serde_json::from_str(&call_s(method, &()).await?).map_err(|e| e.to_string())
}

type Lists = (
    Result<Vec<WifiConnection>, String>,
    Result<Vec<serde_json::Value>, String>,
);

async fn wifi_lists() -> Lists {
    let Ok(nm) = nm().await else {
        return (Err("NetworkManager unavailable".into()), Ok(Vec::new()));
    };
    let saved = nm.saved_wifi_connections().await.map_err(|e| e.to_string());
    nm.request_wifi_scan().await;
    let near = nm
        .available_wifi_networks()
        .await
        .map(|v| {
            v.into_iter()
                .map(|(ssid, strength)| serde_json::json!({ "ssid": ssid, "strength": strength }))
                .collect()
        })
        .map_err(|e| e.to_string());
    (saved, near)
}

async fn active_ssid() -> Option<String> {
    Some(nm().await.ok()?.active_wifi().await.ok()??.ssid)
}

/// What the proxy form holds; plain data so it can cross to the runtime.
struct Form {
    uuid: String,
    enabled: bool,
    kind: ProxyType,
    host: String,
    port: u16,
    user: String,
    pass: String,
    udp: UdpMode,
    local: LocalNetMode,
    dns: bool,
    ipv6: bool,
    kill: bool,
    auto: bool,
}

async fn save(f: Form) -> Result<(), String> {
    if f.host.trim().is_empty() {
        return Err("Enter a proxy host".into());
    }
    let mut profiles: Vec<ProxyProfile> = get("GetProxyProfiles").await?;
    let mut secret_id = profiles
        .iter()
        .find(|p| p.connection_uuid == f.uuid)
        .and_then(|p| p.proxy.secret_id.clone());
    // Blank credentials keep whatever is already stored.
    if !f.user.is_empty() || !f.pass.is_empty() {
        let label = format!("ProxyWiFi proxy credentials for {}", f.uuid);
        let id = call_s("StoreSecret", &(label, f.user.clone(), f.pass.clone())).await?;
        if let Some(prev) = secret_id.replace(id) {
            let _ = call_b("DeleteSecret", &(prev,)).await;
        }
    }
    profiles.retain(|p| p.connection_uuid != f.uuid);
    profiles.push(ProxyProfile {
        connection_uuid: f.uuid,
        label: None,
        enabled: f.enabled,
        proxy: ProxyConfig {
            proxy_type: f.kind,
            host: f.host.trim().to_string(),
            port: f.port,
            authentication: if secret_id.is_some() {
                AuthMethod::Keyring
            } else {
                AuthMethod::None
            },
            secret_id,
        },
        dns: if f.dns {
            DnsMode::Proxied
        } else {
            DnsMode::Direct
        },
        routing: IpVersionConfig {
            ipv4: true,
            ipv6: f.ipv6,
        },
        udp: f.udp,
        local_network: f.local,
        kill_switch: KillSwitchConfig { enabled: f.kill },
        auto_connect: f.auto,
    });
    let json = serde_json::to_string(&profiles).map_err(|e| e.to_string())?;
    call_b("SetProxyProfiles", &(json,)).await
}

// ---------------------------------------------------------------------------
// Widgets
// ---------------------------------------------------------------------------

const KINDS: [(&str, ProxyType); 2] = [
    ("SOCKS5", ProxyType::Socks5),
    ("HTTP (CONNECT)", ProxyType::Http),
];
const UDP: [(&str, UdpMode); 3] = [
    ("Proxy", UdpMode::Proxy),
    ("Block", UdpMode::Block),
    ("Direct", UdpMode::Direct),
];
const LOCAL: [(&str, LocalNetMode); 3] = [
    ("Direct", LocalNetMode::Direct),
    ("Proxy", LocalNetMode::Proxy),
    ("Block", LocalNetMode::Block),
];

fn row(title: &str, subtitle: &str) -> adw::ActionRow {
    let r = adw::ActionRow::builder()
        .title(title)
        .subtitle(subtitle)
        .build();
    r.set_use_markup(false);
    r
}

fn switch(title: &str, on: bool) -> adw::SwitchRow {
    adw::SwitchRow::builder().title(title).active(on).build()
}

fn combo<T>(title: &str, items: &[(&str, T)]) -> adw::ComboRow {
    let names: Vec<&str> = items.iter().map(|(n, _)| *n).collect();
    adw::ComboRow::builder()
        .title(title)
        .model(&gtk::StringList::new(&names))
        .build()
}

fn button(label: &str, suggested: bool) -> gtk::Button {
    let b = gtk::Button::with_label(label);
    if suggested {
        b.add_css_class("suggested-action");
    }
    b
}

fn page(children: &[&gtk::Widget]) -> gtk::ScrolledWindow {
    let v = gtk::Box::new(gtk::Orientation::Vertical, 18);
    for c in children {
        v.append(*c);
    }
    let clamp = adw::Clamp::builder()
        .maximum_size(640)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(16)
        .margin_end(16)
        .child(&v)
        .build();
    gtk::ScrolledWindow::builder().child(&clamp).build()
}

fn group(title: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder().title(title).build()
}

struct Ui {
    win: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    stack: adw::ViewStack,
    // Wi-Fi page
    net: adw::ActionRow,
    prox: adw::ActionRow,
    saved: adw::PreferencesGroup,
    nearby: adw::PreferencesGroup,
    listed: RefCell<Vec<(adw::PreferencesGroup, adw::ActionRow)>>,
    // Proxy page
    target: adw::PreferencesGroup,
    uuid: RefCell<Option<String>>,
    enabled: adw::SwitchRow,
    kind: adw::ComboRow,
    host: adw::EntryRow,
    port: adw::SpinRow,
    user: adw::EntryRow,
    pass: adw::PasswordEntryRow,
    udp: adw::ComboRow,
    local: adw::ComboRow,
    dns: adw::SwitchRow,
    ipv6: adw::SwitchRow,
    kill: adw::SwitchRow,
    auto: adw::SwitchRow,
    // Diagnostics page
    d: [adw::ActionRow; 7],
}

impl Ui {
    fn new(app: &adw::Application) -> Rc<Self> {
        let net = row("Network", "…");
        let prox = row("Proxy", "…");
        let saved = group("Saved networks");
        let nearby = group("Nearby networks");
        let st = group("Status");
        st.add(&net);
        st.add(&prox);

        let target = group("Proxy settings");
        target.set_description(Some(
            "Connect to a saved network, or press Proxy on one in the Wi-Fi tab.",
        ));
        let enabled = switch("Enabled", true);
        let kind = combo("Type", &KINDS);
        let host = adw::EntryRow::builder().title("Host").build();
        let port = adw::SpinRow::with_range(1.0, 65535.0, 1.0);
        port.set_title("Port");
        port.set_value(1080.0);
        let user = adw::EntryRow::builder()
            .title("Username (blank keeps saved)")
            .build();
        let pass = adw::PasswordEntryRow::builder()
            .title("Password (blank keeps saved)")
            .build();
        let udp = combo("UDP", &UDP);
        let local = combo("Local networks", &LOCAL);
        let dns = switch("Proxy DNS", true);
        let ipv6 = switch("Route IPv6 through the proxy", false);
        let kill = switch("Kill switch", true);
        let auto = switch("Auto-connect", true);
        for w in [
            &enabled as &dyn AsRef<gtk::Widget>,
            &kind,
            &host,
            &port,
            &user,
            &pass,
        ] {
            target.add(w.as_ref());
        }
        let opts = group("Behaviour");
        for w in [
            &udp as &dyn AsRef<gtk::Widget>,
            &local,
            &dns,
            &ipv6,
            &kill,
            &auto,
        ] {
            opts.add(w.as_ref());
        }
        let save_b = button("Save", true);
        let test_b = button("Test proxy", false);
        let start_b = button("Start", false);
        let stop_b = button("Stop", false);
        let bar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        bar.set_halign(gtk::Align::End);
        for b in [&stop_b, &start_b, &test_b, &save_b] {
            bar.append(b);
        }

        let d = [
            row("Wi-Fi", "…"),
            row("Interface", "…"),
            row("Proxy", "…"),
            row("Tunnel", "…"),
            row("DNS", "…"),
            row("Kill switch", "…"),
            row("Last test", "not run"),
        ];
        let diag = group("Diagnostics");
        for r in &d {
            diag.add(r);
        }
        let run_b = button("Run full test", true);
        run_b.set_halign(gtk::Align::End);

        let stack = adw::ViewStack::new();
        stack.add_titled_with_icon(
            &page(&[st.upcast_ref(), saved.upcast_ref(), nearby.upcast_ref()]),
            Some("wifi"),
            "Wi-Fi",
            "network-wireless-symbolic",
        );
        stack.add_titled_with_icon(
            &page(&[target.upcast_ref(), opts.upcast_ref(), bar.upcast_ref()]),
            Some("proxy"),
            "Proxy",
            "network-server-symbolic",
        );
        stack.add_titled_with_icon(
            &page(&[diag.upcast_ref(), run_b.upcast_ref()]),
            Some("diag"),
            "Diagnostics",
            "security-high-symbolic",
        );

        let refresh_b = gtk::Button::from_icon_name("view-refresh-symbolic");
        refresh_b.set_tooltip_text(Some("Refresh"));
        let header = adw::HeaderBar::new();
        header.pack_start(&refresh_b);
        header.set_title_widget(Some(
            &adw::ViewSwitcher::builder()
                .stack(&stack)
                .policy(adw::ViewSwitcherPolicy::Wide)
                .build(),
        ));
        let view = adw::ToolbarView::new();
        view.add_top_bar(&header);
        view.set_content(Some(&stack));
        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&view));
        let win = adw::ApplicationWindow::builder()
            .application(app)
            .title("ProxyWiFi")
            .default_width(720)
            .default_height(760)
            .content(&toasts)
            .build();

        let ui = Rc::new(Self {
            win,
            toasts,
            stack,
            net,
            prox,
            saved,
            nearby,
            listed: RefCell::new(Vec::new()),
            target,
            uuid: RefCell::new(None),
            enabled,
            kind,
            host,
            port,
            user,
            pass,
            udp,
            local,
            dns,
            ipv6,
            kill,
            auto,
            d,
        });

        // HTTP proxies cannot relay UDP: default it to Block.
        let u = ui.clone();
        ui.kind.connect_selected_notify(move |k| {
            if KINDS[k.selected() as usize].1 == ProxyType::Http {
                u.udp.set_selected(1);
            }
        });
        let u = ui.clone();
        refresh_b.connect_clicked(move |_| u.refresh());
        let u = ui.clone();
        save_b.connect_clicked(move |_| u.save());
        let u = ui.clone();
        test_b.connect_clicked(move |_| u.test());
        let u = ui.clone();
        run_b.connect_clicked(move |_| u.test());
        let u = ui.clone();
        start_b.connect_clicked(move |_| {
            let uuid = u.uuid.borrow().clone().unwrap_or_default();
            u.act("Proxy started", async move {
                call_b("StartProxy", &(uuid,)).await
            });
        });
        let u = ui.clone();
        stop_b.connect_clicked(move |_| {
            u.act("Proxy stopped", async { call_b("StopProxy", &()).await })
        });
        ui
    }

    fn toast(&self, msg: &str) {
        self.toasts.add_toast(adw::Toast::new(msg));
    }

    /// Run a daemon call, toast the outcome, refresh.
    fn act(
        self: &Rc<Self>,
        ok: &'static str,
        fut: impl Future<Output = Result<(), String>> + Send + 'static,
    ) {
        let u = self.clone();
        spawn(fut, move |r| {
            u.toast(&match r {
                Ok(()) => ok.to_string(),
                Err(e) => e,
            });
            u.refresh();
        });
    }

    fn refresh(self: &Rc<Self>) {
        let u = self.clone();
        spawn(
            async { tokio::join!(get::<ProxyStatus>("GetStatus"), wifi_lists(), active_ssid(),) },
            move |(st, (saved, near), ssid)| {
                u.show_status(st, ssid);
                u.show_lists(saved, near);
            },
        );
    }

    fn poll(self: &Rc<Self>) {
        let u = self.clone();
        spawn(
            async { tokio::join!(get::<ProxyStatus>("GetStatus"), active_ssid()) },
            move |(st, ssid)| u.show_status(st, ssid),
        );
    }

    fn show_status(&self, st: Result<ProxyStatus, String>, ssid: Option<String>) {
        let st = match st {
            Ok(s) => s,
            Err(e) => {
                self.net
                    .set_subtitle(ssid.as_deref().unwrap_or("Not connected"));
                self.prox.set_subtitle(&format!("Daemon not running ({e})"));
                return;
            }
        };
        let (net, iface) = match &st.wifi {
            Some(w) => (w.ssid.clone(), w.interface.clone()),
            None => ("Not connected".into(), "—".into()),
        };
        let yn = |b: bool| if b { "Active" } else { "Off" };
        let proxy = match &st.message {
            Some(m) => format!("{} — {m}", st.proxy_state),
            None => st.proxy_state.to_string(),
        };
        self.net.set_subtitle(&net);
        self.prox.set_subtitle(&proxy);
        self.d[0].set_subtitle(&net);
        self.d[1].set_subtitle(&iface);
        self.d[2].set_subtitle(&proxy);
        self.d[3].set_subtitle(st.tun_name.as_deref().unwrap_or("—"));
        self.d[4].set_subtitle(&st.dns_mode.map_or("—".into(), |m| m.to_string()));
        self.d[5].set_subtitle(yn(st.kill_switch_active));
    }

    fn show_lists(
        self: &Rc<Self>,
        saved: Result<Vec<WifiConnection>, String>,
        near: Result<Vec<serde_json::Value>, String>,
    ) {
        for (g, r) in self.listed.borrow_mut().drain(..) {
            g.remove(&r);
        }
        let mut listed = self.listed.borrow_mut();
        let near = near.unwrap_or_default();
        let signal = |ssid: &str| {
            near.iter()
                .find(|n| n["ssid"] == ssid)
                .and_then(|n| n["strength"].as_u64())
        };
        // Connected first, then strongest signal; out-of-range networks last.
        let mut saved = saved.unwrap_or_default();
        // Nothing picked yet: edit the connected network's proxy by default.
        if self.uuid.borrow().is_none() {
            if let Some(c) = saved.iter().find(|c| c.state == "activated") {
                self.edit(c.uuid.clone(), c.name.clone(), false);
            }
        }
        saved.sort_by_key(|c| {
            let ssid = c.ssid.as_deref().unwrap_or(&c.name);
            (c.state != "activated", std::cmp::Reverse(signal(ssid)))
        });
        for c in saved {
            let active = c.state == "activated";
            let ssid = c.ssid.clone().unwrap_or_else(|| c.name.clone());
            let state = if active { "Connected" } else { "Saved" };
            let subtitle = match signal(&ssid) {
                Some(s) => format!("{state} · Signal {s}%"),
                None => format!("{state} · Out of range"),
            };
            let r = row(&c.name, &subtitle);
            let proxy_b = button("Proxy", false);
            let conn_b = button("Connect", !active);
            conn_b.set_sensitive(!active);
            for b in [&proxy_b, &conn_b] {
                b.set_valign(gtk::Align::Center);
                r.add_suffix(b);
            }
            let (u, uuid, name) = (self.clone(), c.uuid.clone(), c.name.clone());
            proxy_b.connect_clicked(move |_| u.edit(uuid.clone(), name.clone(), true));
            let u = self.clone();
            conn_b.connect_clicked(move |_| u.connect(ssid.clone(), String::new()));
            self.saved.add(&r);
            listed.push((self.saved.clone(), r));
        }
        for n in near.iter() {
            let ssid = n["ssid"].as_str().unwrap_or_default().to_string();
            let r = row(&ssid, &format!("Signal {}%", n["strength"]));
            let b = button("Connect…", false);
            b.set_valign(gtk::Align::Center);
            r.add_suffix(&b);
            let u = self.clone();
            b.connect_clicked(move |_| u.ask_password(ssid.clone()));
            self.nearby.add(&r);
            listed.push((self.nearby.clone(), r));
        }
    }

    fn ask_password(self: &Rc<Self>, ssid: String) {
        let entry = gtk::PasswordEntry::builder().show_peek_icon(true).build();
        let d = adw::MessageDialog::new(
            Some(&self.win),
            Some(&format!("Connect to {ssid}")),
            Some("Leave the password empty for an open or already-saved network."),
        );
        d.add_responses(&[("cancel", "Cancel"), ("connect", "Connect")]);
        d.set_response_appearance("connect", adw::ResponseAppearance::Suggested);
        d.set_default_response(Some("connect"));
        d.set_extra_child(Some(&entry));
        let u = self.clone();
        d.connect_response(None, move |_, r| {
            if r == "connect" {
                u.connect(ssid.clone(), entry.text().to_string());
            }
        });
        d.present();
    }

    fn connect(self: &Rc<Self>, ssid: String, password: String) {
        let u = self.clone();
        spawn(
            async move {
                nm().await?
                    .connect_wifi(&ssid, Some(password.as_str()).filter(|p| !p.is_empty()))
                    .await
                    .map_err(|e| e.to_string())
            },
            move |r| {
                u.toast(&match r {
                    Ok(()) => "Connecting…".into(),
                    Err(e) => e,
                });
                let u2 = u.clone();
                glib::timeout_add_seconds_local_once(4, move || u2.refresh());
            },
        );
    }

    /// Load `uuid`'s profile (or defaults) into the form and show it.
    fn edit(self: &Rc<Self>, uuid: String, name: String, show: bool) {
        *self.uuid.borrow_mut() = Some(uuid.clone());
        self.target.set_title(&format!("Proxy for {name}"));
        self.target.set_description(None);
        let u = self.clone();
        spawn(get::<Vec<ProxyProfile>>("GetProxyProfiles"), move |r| {
            let p = r
                .unwrap_or_default()
                .into_iter()
                .find(|p| p.connection_uuid == uuid);
            u.enabled.set_active(p.as_ref().is_none_or(|p| p.enabled));
            u.kind.set_selected(
                p.as_ref()
                    .is_some_and(|p| p.proxy.proxy_type == ProxyType::Http) as u32,
            );
            u.host.set_text(p.as_ref().map_or("", |p| &p.proxy.host));
            u.port
                .set_value(p.as_ref().map_or(1080.0, |p| p.proxy.port as f64));
            u.user.set_text("");
            u.pass.set_text("");
            u.udp.set_selected(
                UDP.iter()
                    .position(|(_, m)| p.as_ref().is_some_and(|p| p.udp == *m))
                    .unwrap_or(0) as u32,
            );
            u.local.set_selected(
                LOCAL
                    .iter()
                    .position(|(_, m)| p.as_ref().is_some_and(|p| p.local_network == *m))
                    .unwrap_or(0) as u32,
            );
            u.dns
                .set_active(p.as_ref().is_none_or(|p| p.dns == DnsMode::Proxied));
            u.ipv6
                .set_active(p.as_ref().is_some_and(|p| p.routing.ipv6));
            u.kill
                .set_active(p.as_ref().is_none_or(|p| p.kill_switch.enabled));
            u.auto.set_active(p.as_ref().is_none_or(|p| p.auto_connect));
            if show {
                u.stack.set_visible_child_name("proxy");
            }
        });
    }

    fn save(self: &Rc<Self>) {
        let Some(uuid) = self.uuid.borrow().clone() else {
            return self.toast("Pick a saved network first (Wi-Fi tab → Proxy)");
        };
        let form = Form {
            uuid,
            enabled: self.enabled.is_active(),
            kind: KINDS[self.kind.selected() as usize].1.clone(),
            host: self.host.text().to_string(),
            port: self.port.value() as u16,
            user: self.user.text().to_string(),
            pass: self.pass.text().to_string(),
            udp: UDP[self.udp.selected() as usize].1.clone(),
            local: LOCAL[self.local.selected() as usize].1.clone(),
            dns: self.dns.is_active(),
            ipv6: self.ipv6.is_active(),
            kill: self.kill.is_active(),
            auto: self.auto.is_active(),
        };
        self.act("Saved", save(form));
    }

    fn test(self: &Rc<Self>) {
        self.d[6].set_subtitle("running…");
        let u = self.clone();
        spawn(get::<ProxyTestResult>("TestProxy"), move |r| {
            let ok = |b: bool| if b { "✓" } else { "✗" };
            let text = match r {
                Ok(t) => format!(
                    "reachable {} · login {} · TCP {} · DNS {} · UDP {}{}",
                    ok(t.reachable),
                    ok(t.authentication_ok),
                    ok(t.tcp_ok),
                    ok(t.dns_ok),
                    ok(t.udp_ok),
                    t.error.map(|e| format!(" — {e}")).unwrap_or_default()
                ),
                Err(e) => e,
            };
            u.d[6].set_subtitle(&text);
            u.toast(&text);
        });
    }
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder()
        .application_id("org.proxywifi.Gui")
        .build();
    app.connect_activate(|app| {
        let ui = Ui::new(app);
        ui.win.present();
        ui.refresh();
        glib::timeout_add_seconds_local(3, move || {
            ui.poll();
            glib::ControlFlow::Continue
        });
    });
    app.run()
}
