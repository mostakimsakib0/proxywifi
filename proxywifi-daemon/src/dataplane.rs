//! Real data plane: a TUN device fed by `tun2socks`, plus an `inet proxywifi`
//! nftables table for the kill switch and IPv6 leak guard.
//!
//! ```text
//! app -> route 0.0.0.0/1 + 128.0.0.0/1 via pwtun0 -> tun2socks -> SOCKS5 -> Internet
//!                                                      (bound to the Wi-Fi interface)
//! ```
//!
//! * **Loop prevention:** `tun2socks -interface <wifi>` binds the engine's own
//!   sockets to the physical interface, so their route lookup never sees the
//!   tunnel routes.
//! * **Local networks:** the connected subnet route (`/24` etc.) is more
//!   specific than the `/1` tunnel routes, so LAN traffic stays direct.
//! * **Kill switch:** the tunnel device vanishes when `tun2socks` dies, traffic
//!   falls back to the Wi-Fi default route, and the nftables table drops
//!   everything leaving that interface except the proxy itself.

use crate::service::{FirewallOps, ProxyEngine, RouteContext};
use proxywifi_core::models::{
    DnsMode, LocalNetMode, ProxyProfile, ProxyTestResult, ProxyType, UdpMode,
};
use proxywifi_core::secrets::SecretServiceOps;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Name of the tunnel device.
pub const TUN_NAME: &str = "pwtun0";
/// Table that holds every rule ProxyWiFi owns.
const TABLE: &str = "inet proxywifi";

/// Address of the tunnel; the DNS forwarder listens here. Override with
/// `PROXYWIFI_TUN_ADDR` (IPv4) when another tool, e.g. Clash TUN, owns 198.18/15.
const DEFAULT_TUN_ADDR: &str = "198.18.0.1";

fn tun_addr() -> String {
    match std::env::var("PROXYWIFI_TUN_ADDR") {
        Ok(a) if a.parse::<std::net::Ipv4Addr>().is_ok() => a,
        _ => DEFAULT_TUN_ADDR.to_string(),
    }
}
/// Port of the DNS forwarder. Not 53: something on the host may already hold
/// `*:53`, and the nftables redirect works with any port.
const DNS_PORT: u16 = 5335;

/// Packet mark that sends UDP around the tunnel in `udp = direct` mode.
const DIRECT_MARK: u32 = 0x5057;
/// Routing table (and rule priority) used for marked UDP: 0x5057 = 20567.
const DIRECT_TABLE: &str = "20567";

const LOCAL_V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";
const LOCAL_V6: &str = "fc00::/7, fe80::/10";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run `program args`, feeding `stdin`; error carries stderr.
fn run(program: &str, args: &[&str], stdin: Option<&str>) -> anyhow::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run {program}: {e}"))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

/// Everything the ruleset depends on.
#[derive(Clone)]
pub struct RulesetParams {
    pub iface: String,
    pub proxy_ip: IpAddr,
    pub proxy_port: u16,
    pub local: LocalNetMode,
    pub ipv6: bool,
    pub kill_switch: bool,
    /// Redirect applications' UDP/53 to the DNS forwarder.
    pub dns_proxied: bool,
    pub udp: UdpMode,
}

/// Interface names go into rule text, so only allow what the kernel allows
/// in practice.
fn valid_iface(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Render an idempotent script: drop any previous table, then define ours.
pub fn render_ruleset(p: &RulesetParams) -> anyhow::Result<String> {
    if !valid_iface(&p.iface) {
        anyhow::bail!("refusing unusual interface name {:?}", p.iface);
    }
    let iface = &p.iface;
    let mut r = vec![
        r#"oifname "lo" accept"#.to_string(),
        // Lease renewal must keep working (DHCPv4 / DHCPv6 clients).
        format!(r#"oifname "{iface}" udp dport {{ 67, 547 }} accept"#),
    ];
    let tun_addr = tun_addr();
    if p.dns_proxied {
        // Redirected DNS must reach the forwarder even when other UDP is
        // rejected below.
        r.push(format!(
            r#"ip daddr {tun_addr} udp dport {DNS_PORT} accept"#
        ));
    }
    match p.udp {
        // `reject` answers with ICMP so QUIC & co. fall back to TCP at once.
        UdpMode::Block => r.push("meta l4proto udp reject".into()),
        UdpMode::Direct => {
            // UDP is marked below and routed around the tunnel: allow it out,
            // but only IPv4 -- IPv6 UDP has no direct route and must not leak.
            r.push(r#"meta nfproto ipv6 meta l4proto udp reject"#.into());
            r.push(format!(
                r#"oifname "{iface}" meta l4proto udp meta mark {DIRECT_MARK:#x} accept"#
            ));
        }
        UdpMode::Proxy => {}
    }
    r.push(format!(r#"oifname "{TUN_NAME}" accept"#));
    // The proxy itself, before any local-network rule: it may live on the LAN.
    let family = if p.proxy_ip.is_ipv4() { "ip" } else { "ip6" };
    r.push(format!(
        r#"oifname "{iface}" {family} daddr {} tcp dport {} accept"#,
        p.proxy_ip, p.proxy_port
    ));
    if p.udp == UdpMode::Proxy {
        // The SOCKS5 UDP relay listens on a port the proxy picks per session.
        r.push(format!(
            r#"oifname "{iface}" {family} daddr {} meta l4proto udp accept"#,
            p.proxy_ip
        ));
    }
    match p.local {
        LocalNetMode::Block => {
            r.push(format!(
                r#"oifname "{iface}" ip daddr {{ {LOCAL_V4} }} drop"#
            ));
            r.push(format!(
                r#"oifname "{iface}" ip6 daddr {{ {LOCAL_V6} }} drop"#
            ));
        }
        LocalNetMode::Direct => {
            r.push(format!(
                r#"oifname "{iface}" ip daddr {{ {LOCAL_V4} }} accept"#
            ));
            r.push(format!(
                r#"oifname "{iface}" ip6 daddr {{ {LOCAL_V6} }} accept"#
            ));
        }
        // Proxy: LAN traffic is not exempted, but the connected-subnet route
        // beats the tunnel's /1 routes, so it still leaves via the Wi-Fi
        // interface and the kill switch drops it. ponytail: behaves like
        // `block` with the kill switch on; add LAN tunnel routes if needed.
        LocalNetMode::Proxy => {}
    }
    if !p.ipv6 {
        // The tunnel carries IPv4 only: keep IPv6 from leaking past it.
        // Link-local ND and multicast are still needed for the link to work.
        r.push(format!(
            r#"oifname "{iface}" ip6 daddr != {{ fe80::/10, ff00::/8 }} drop"#
        ));
    }
    if p.kill_switch {
        r.push(format!(r#"oifname "{iface}" drop"#));
    }
    if p.dns_proxied {
        // Plain IPv6 DNS cannot be redirected: fail closed so it cannot leak.
        r.insert(
            0,
            r#"oifname != "lo" meta nfproto ipv6 udp dport 53 drop"#.into(),
        );
    }

    let body: String = r.iter().map(|l| format!("        {l}\n")).collect();
    // Redirect before routing decisions are final; `oifname != "lo"` leaves
    // apps that talk to a local stub resolver (127.0.0.53) alone, while the
    // stub's own upstream queries are caught.
    let mark = if p.udp == UdpMode::Direct {
        let dns = if p.dns_proxied {
            "udp dport != 53 "
        } else {
            ""
        };
        format!(
            "    chain udp_direct {{\n        type route hook output priority -150; policy accept;\n        \
             meta nfproto ipv4 ip daddr != {{ {LOCAL_V4} }} {dns}meta l4proto udp meta mark set {DIRECT_MARK:#x}\n    }}\n"
        )
    } else {
        String::new()
    };
    let nat = if p.dns_proxied {
        format!(
            "    chain dns {{\n        type nat hook output priority -100; policy accept;\n        \
             oifname != \"lo\" meta nfproto ipv4 udp dport 53 dnat ip to {tun_addr}:{DNS_PORT}\n    }}\n"
        )
    } else {
        String::new()
    };
    Ok(format!(
        "add table {TABLE}\ndelete table {TABLE}\n\
         table {TABLE} {{\n{mark}{nat}    chain output {{\n        type filter hook output priority 0; policy accept;\n{body}    }}\n}}\n"
    ))
}

/// nftables-backed [`FirewallOps`].
pub struct NftFirewall {
    nft: String,
    applied: Mutex<Option<RulesetParams>>,
}

impl NftFirewall {
    pub fn new(nft: String) -> Self {
        Self {
            nft,
            applied: Mutex::new(None),
        }
    }

    fn load(&self, p: &RulesetParams) -> anyhow::Result<()> {
        run(&self.nft, &["-f", "-"], Some(&render_ruleset(p)?))
    }
}

impl FirewallOps for NftFirewall {
    fn apply(&self, profile: &ProxyProfile, route: &RouteContext) -> anyhow::Result<()> {
        let params = RulesetParams {
            iface: route.iface.clone(),
            proxy_ip: route.proxy_ip,
            proxy_port: profile.proxy.port,
            local: profile.local_network.clone(),
            ipv6: profile.routing.ipv6,
            kill_switch: profile.kill_switch.enabled,
            dns_proxied: profile.dns == DnsMode::Proxied,
            udp: profile.udp.clone(),
        };
        self.load(&params)?;
        *lock(&self.applied) = Some(params);
        Ok(())
    }

    fn remove(&self) -> anyhow::Result<()> {
        *lock(&self.applied) = None;
        // Add-then-delete succeeds whether or not the table exists.
        run(
            &self.nft,
            &["-f", "-"],
            Some(&format!("add table {TABLE}\ndelete table {TABLE}\n")),
        )
    }

    fn set_kill_switch(&self, armed: bool) -> anyhow::Result<()> {
        let mut applied = lock(&self.applied);
        match applied.as_mut() {
            Some(params) => {
                let mut next = params.clone();
                next.kill_switch = armed;
                self.load(&next)?;
                *params = next;
                Ok(())
            }
            // Nothing installed: disarming is trivially done.
            None if !armed => Ok(()),
            None => anyhow::bail!("cannot arm the kill switch: no ruleset has been applied"),
        }
    }
}

// ---------------------------------------------------------------------------
// TUN engine
// ---------------------------------------------------------------------------

/// `tun2socks`-backed [`ProxyEngine`].
pub struct TunEngine {
    tun2socks: String,
    ip: String,
    run_dir: PathBuf,
    secrets: Arc<dyn SecretServiceOps>,
    child: Mutex<Option<Child>>,
    dns: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TunEngine {
    pub fn new(
        tun2socks: String,
        ip: String,
        run_dir: PathBuf,
        secrets: Arc<dyn SecretServiceOps>,
    ) -> Self {
        Self {
            tun2socks,
            ip,
            run_dir,
            secrets,
            child: Mutex::new(None),
            dns: Mutex::new(None),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.run_dir.join("tun2socks.yaml")
    }

    /// Credentials, if the profile has any.
    fn credentials(&self, profile: &ProxyProfile) -> anyhow::Result<Option<(String, String)>> {
        let Some(id) = &profile.proxy.secret_id else {
            return Ok(None);
        };
        let s = self.secrets.get_secret(id)?;
        Ok(Some((s.username.unwrap_or_default(), s.password)))
    }

    /// Gateway of `iface`'s default route, if it has one.
    fn default_gateway(&self, iface: &str) -> Option<String> {
        let out = Command::new(&self.ip)
            .args(["route", "show", "default", "dev", iface])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let mut words = text.split_whitespace();
        words.find(|w| *w == "via")?;
        words.next().map(str::to_string)
    }

    fn ip(&self, args: &[&str]) -> anyhow::Result<()> {
        run(&self.ip, args, None)
    }

    fn bring_up(&self, profile: &ProxyProfile, route: &RouteContext) -> anyhow::Result<()> {
        if !valid_iface(&route.iface) {
            anyhow::bail!("refusing unusual interface name {:?}", route.iface);
        }
        // The config file, not argv, carries the proxy password: argv is
        // world-readable through /proc.
        let creds = self.credentials(profile)?;
        let auth = creds
            .map(|(u, p)| format!("{}:{}@", pct(&u), pct(&p)))
            .unwrap_or_default();
        let host = match route.proxy_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let yaml = format!(
            "device: tun://{TUN_NAME}\nproxy: {}://{auth}{host}:{}\ninterface: {}\nloglevel: info\n",
            profile.proxy.proxy_type, profile.proxy.port, route.iface
        );
        let cfg = self.config_path();
        proxywifi_core::profiles::write_private(&cfg, yaml.as_bytes(), 0o600)?;

        let child = Command::new(&self.tun2socks)
            .args(["-config"])
            .arg(&cfg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow::anyhow!("could not run {}: {e}", self.tun2socks))?;
        *lock(&self.child) = Some(child);

        // Wait for tun2socks to create the device.
        // ponytail: blocks a runtime thread for up to 3s; make async if it hurts.
        let mut created = false;
        for _ in 0..30 {
            if self.ip(&["link", "show", "dev", TUN_NAME]).is_ok() {
                created = true;
                break;
            }
            if !self.is_running() {
                anyhow::bail!("tun2socks exited during start-up (see the journal)");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !created {
            anyhow::bail!("tun2socks did not create {TUN_NAME}");
        }

        let tun_addr = tun_addr();
        self.ip(&["addr", "add", &format!("{tun_addr}/30"), "dev", TUN_NAME])?;
        self.ip(&["link", "set", TUN_NAME, "up"])?;
        self.ip(&["route", "add", "0.0.0.0/1", "dev", TUN_NAME])?;
        self.ip(&["route", "add", "128.0.0.0/1", "dev", TUN_NAME])?;
        if profile.routing.ipv6 {
            self.ip(&["-6", "addr", "add", "fd00:5057::1/64", "dev", TUN_NAME])?;
            self.ip(&["-6", "route", "add", "::/1", "dev", TUN_NAME])?;
            self.ip(&["-6", "route", "add", "8000::/1", "dev", TUN_NAME])?;
        }

        if profile.udp == UdpMode::Direct {
            let gw = self.default_gateway(&route.iface);
            let mut route_cmd = vec!["route", "replace", "default"];
            if let Some(gw) = gw.as_deref() {
                route_cmd.extend(["via", gw]);
            }
            route_cmd.extend(["dev", &route.iface, "table", DIRECT_TABLE]);
            self.ip(&route_cmd)?;
            self.ip(&[
                "rule",
                "add",
                "fwmark",
                &format!("{DIRECT_MARK:#x}"),
                "lookup",
                DIRECT_TABLE,
                "priority",
                DIRECT_TABLE,
            ])?;
        }

        if profile.dns == DnsMode::Proxied {
            // Bind now (the address exists), serve on the runtime.
            let sock = std::net::UdpSocket::bind((tun_addr.as_str(), DNS_PORT)).map_err(|e| {
                anyhow::anyhow!("cannot bind the DNS forwarder on {tun_addr}:{DNS_PORT}: {e}")
            })?;
            let upstreams = crate::dns::UPSTREAMS
                .iter()
                .filter_map(|u| u.parse().ok())
                .collect();
            let rt = tokio::runtime::Handle::try_current()
                .map_err(|_| anyhow::anyhow!("DNS forwarder needs a tokio runtime"))?;
            *lock(&self.dns) = Some(rt.spawn(crate::dns::serve(sock, upstreams)));
        }
        Ok(())
    }
}

/// Percent-encode everything outside the URL-unreserved set.
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl ProxyEngine for TunEngine {
    fn start(&self, profile: &ProxyProfile, route: &RouteContext) -> anyhow::Result<String> {
        self.stop()?;
        match self.bring_up(profile, route) {
            Ok(()) => Ok(TUN_NAME.to_string()),
            Err(e) => {
                let _ = self.stop();
                Err(e)
            }
        }
    }

    fn stop(&self) -> anyhow::Result<()> {
        if let Some(task) = lock(&self.dns).take() {
            task.abort();
        }
        if let Some(mut child) = lock(&self.child).take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // The device and its routes disappear with the process; this only
        // matters if tun2socks left a persistent device behind.
        let _ = self.ip(&["link", "del", TUN_NAME]);
        let _ = self.ip(&["rule", "del", "priority", DIRECT_TABLE]);
        let _ = self.ip(&["route", "flush", "table", DIRECT_TABLE]);
        let _ = std::fs::remove_file(self.config_path());
        Ok(())
    }

    fn test(
        &self,
        profile: &ProxyProfile,
        route: &RouteContext,
    ) -> anyhow::Result<ProxyTestResult> {
        let creds = self.credentials(profile)?;
        let addr = SocketAddr::new(route.proxy_ip, profile.proxy.port);
        let mut result = match profile.proxy.proxy_type {
            ProxyType::Socks5 => socks5_probe(addr, creds),
            ProxyType::Http => http_probe(addr, creds),
        };
        if profile.dns == DnsMode::Proxied && self.is_running() {
            // Resolve through the forwarder, i.e. through the proxy.
            let via_forwarder = SocketAddr::new(tun_addr().parse()?, DNS_PORT);
            result.dns_ok = crate::dns::probe(via_forwarder, "example.com");
            if !result.dns_ok && result.error.is_none() {
                result.error = Some("DNS through the tunnel failed".into());
            }
        }
        Ok(result)
    }

    fn is_running(&self) -> bool {
        matches!(
            lock(&self.child).as_mut().map(|c| c.try_wait()),
            Some(Ok(None))
        )
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 probe
// ---------------------------------------------------------------------------

/// Open a SOCKS5 session: greeting plus optional RFC 1929 login.
fn socks5_session(
    addr: SocketAddr,
    creds: &Option<(String, String)>,
) -> std::io::Result<TcpStream> {
    let t = Duration::from_secs(5);
    let mut s = TcpStream::connect_timeout(&addr, t)?;
    s.set_read_timeout(Some(t))?;
    s.set_write_timeout(Some(t))?;
    s.write_all(&[5, 1, if creds.is_some() { 2 } else { 0 }])?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply)?;
    if reply[0] != 5 || reply[1] == 0xff {
        return Err(std::io::Error::other(
            "proxy rejected the authentication method",
        ));
    }
    if reply[1] == 2 {
        let (u, p) = creds.clone().unwrap_or_default();
        if u.len() > 255 || p.len() > 255 {
            return Err(std::io::Error::other("credentials too long for SOCKS5"));
        }
        let mut msg = vec![1, u.len() as u8];
        msg.extend(u.as_bytes());
        msg.push(p.len() as u8);
        msg.extend(p.as_bytes());
        s.write_all(&msg)?;
        s.read_exact(&mut reply)?;
        if reply[1] != 0 {
            return Err(std::io::Error::other("proxy rejected the credentials"));
        }
    }
    Ok(s)
}

/// Send a SOCKS5 request on a fresh session; `Ok` when the reply code is 0.
fn socks5_request(
    addr: SocketAddr,
    creds: &Option<(String, String)>,
    request: &[u8],
    what: &str,
) -> std::io::Result<()> {
    let mut s = socks5_session(addr, creds)?;
    s.write_all(request)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!(
            "proxy refused {what} (reply code {})",
            head[1]
        )));
    }
    Ok(())
}

/// Talk SOCKS5 to the proxy: login, a CONNECT to 1.1.1.1:443 (TCP) and a
/// UDP ASSOCIATE (UDP). Never fails; the result says how far it got.
pub fn socks5_probe(addr: SocketAddr, creds: Option<(String, String)>) -> ProxyTestResult {
    let mut result = ProxyTestResult {
        reachable: false,
        authentication_ok: false,
        tcp_ok: false,
        dns_ok: false,
        ipv4_ok: false,
        ipv6_ok: false,
        udp_ok: false,
        external_ip: None,
        error: None,
    };
    if let Err(e) = socks5_session(addr, &creds).map(|_| {
        result.reachable = true;
        result.authentication_ok = true;
    }) {
        // Distinguish "cannot connect" from "login refused".
        result.reachable = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok();
        result.error = Some(e.to_string());
        return result;
    }
    match socks5_request(
        addr,
        &creds,
        &[5, 1, 0, 1, 1, 1, 1, 1, 0x01, 0xbb],
        "CONNECT to 1.1.1.1:443",
    ) {
        Ok(()) => {
            result.tcp_ok = true;
            result.ipv4_ok = true;
        }
        Err(e) => result.error = Some(e.to_string()),
    }
    // UDP relay is optional in SOCKS5; many servers refuse it.
    match socks5_request(
        addr,
        &creds,
        &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0],
        "UDP ASSOCIATE",
    ) {
        Ok(()) => result.udp_ok = true,
        Err(e) if result.error.is_none() => result.error = Some(e.to_string()),
        Err(_) => {}
    }
    result
}

/// Probe an HTTP proxy: `CONNECT 1.1.1.1:443`. A 407 means bad credentials.
pub fn http_probe(addr: SocketAddr, creds: Option<(String, String)>) -> ProxyTestResult {
    let mut result = ProxyTestResult {
        reachable: false,
        authentication_ok: false,
        tcp_ok: false,
        dns_ok: false,
        ipv4_ok: false,
        ipv6_ok: false,
        udp_ok: false,
        external_ip: None,
        error: None,
    };
    let t = Duration::from_secs(5);
    let mut s = match TcpStream::connect_timeout(&addr, t) {
        Ok(s) => s,
        Err(e) => {
            result.error = Some(e.to_string());
            return result;
        }
    };
    result.reachable = true;
    let _ = s.set_read_timeout(Some(t));
    let auth = creds
        .map(|(u, p)| {
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                base64(format!("{u}:{p}").as_bytes())
            )
        })
        .unwrap_or_default();
    let req = format!("CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n{auth}\r\n");
    let mut line = [0u8; 64];
    let n = s
        .write_all(req.as_bytes())
        .and_then(|_| s.read(&mut line))
        .unwrap_or(0);
    let status = String::from_utf8_lossy(&line[..n]);
    let code = status.split_whitespace().nth(1).unwrap_or("");
    result.authentication_ok = code != "407";
    if code == "200" {
        result.tcp_ok = true;
        result.ipv4_ok = true;
    } else {
        result.error = Some(format!(
            "proxy answered {:?} to CONNECT",
            status.lines().next().unwrap_or("nothing")
        ));
    }
    result
}

fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    data.chunks(3)
        .flat_map(|c| {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
            (0..4).map(move |i| {
                if i <= c.len() {
                    A[(n >> (18 - 6 * i) & 63) as usize] as char
                } else {
                    '='
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(super::base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(super::base64(b"ab"), "YWI=");
        assert_eq!(super::base64(b"a"), "YQ==");
    }

    use super::*;

    fn params(local: LocalNetMode, ipv6: bool, kill_switch: bool) -> RulesetParams {
        RulesetParams {
            iface: "wlan0".into(),
            proxy_ip: "10.0.0.1".parse().unwrap(),
            proxy_port: 1080,
            local,
            ipv6,
            kill_switch,
            dns_proxied: true,
            udp: UdpMode::Proxy,
        }
    }

    #[test]
    fn kill_switch_drops_last_and_proxy_is_exempt_first() {
        let r = render_ruleset(&params(LocalNetMode::Direct, false, true)).unwrap();
        let proxy = r.find("ip daddr 10.0.0.1 tcp dport 1080 accept").unwrap();
        let drop = r.rfind(r#"oifname "wlan0" drop"#).unwrap();
        assert!(proxy < drop);
        assert!(!render_ruleset(&params(LocalNetMode::Direct, true, false))
            .unwrap()
            .contains(r#"oifname "wlan0" drop"#));
    }

    #[test]
    fn udp_relay_of_the_proxy_is_exempt_from_the_kill_switch() {
        let r = render_ruleset(&params(LocalNetMode::Direct, false, true)).unwrap();
        let relay = r.find("ip daddr 10.0.0.1 meta l4proto udp accept").unwrap();
        assert!(relay < r.rfind(r#"oifname "wlan0" drop"#).unwrap());
    }

    #[test]
    fn redirected_dns_is_accepted_before_the_udp_reject() {
        let mut p = params(LocalNetMode::Direct, false, true);
        p.udp = UdpMode::Block;
        let r = render_ruleset(&p).unwrap();
        let dns = r.find("ip daddr 198.18.0.1 udp dport 5335 accept").unwrap();
        assert!(dns < r.find("meta l4proto udp reject").unwrap());
    }

    #[test]
    fn hostile_interface_names_are_refused() {
        let mut p = params(LocalNetMode::Direct, false, true);
        p.iface = "wlan0\" accept #".into();
        assert!(render_ruleset(&p).is_err());
    }

    #[test]
    fn percent_encoding_protects_url_delimiters() {
        assert_eq!(pct("a:b@c/d"), "a%3Ab%40c%2Fd");
    }

    /// Ask the real `nft` to validate every variant, inside a throwaway
    /// user+network namespace so no privileges are needed. Skips when the
    /// tools or namespaces are unavailable.
    #[test]
    fn rendered_rulesets_are_accepted_by_nft() {
        for local in [
            LocalNetMode::Proxy,
            LocalNetMode::Direct,
            LocalNetMode::Block,
        ] {
            for (ipv6, ks) in [(false, true), (true, false), (false, false), (true, true)] {
                let script = render_ruleset(&params(local.clone(), ipv6, ks)).unwrap();
                let mut child = match Command::new("unshare")
                    .args(["-Urn", "nft", "-c", "-f", "-"])
                    .stdin(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(_) => return eprintln!("skipping: unshare/nft unavailable"),
                };
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(script.as_bytes())
                    .unwrap();
                let out = child.wait_with_output().unwrap();
                let err = String::from_utf8_lossy(&out.stderr);
                if err.contains("Operation not permitted") || err.contains("unshare failed") {
                    return eprintln!("skipping: user namespaces unavailable");
                }
                assert!(out.status.success(), "nft rejected:\n{script}\n{err}");
            }
        }
    }

    // ---- end-to-end harness -------------------------------------------------
    //
    // These need CAP_NET_ADMIN and `tun2socks`, so they only run on request,
    // inside a throwaway namespace, one at a time:
    //
    //   unshare -Urn cargo test -p proxywifi-daemon --lib e2e -- --ignored --test-threads=1

    use proxywifi_core::models::UdpMode;
    use proxywifi_core::secrets::NoOpSecrets;
    use std::net::TcpListener;
    use std::sync::mpsc::Receiver;

    /// What the stub proxy saw: destination address bytes and port.
    type Seen = (Vec<u8>, u16);

    struct Lab {
        engine: TunEngine,
        firewall: NftFirewall,
        profile: ProxyProfile,
        route: RouteContext,
        seen: Receiver<Seen>,
    }

    fn sh(cmd: &str) {
        let mut a = cmd.split(' ');
        let _ = run(a.next().unwrap(), &a.collect::<Vec<_>>(), None);
    }

    /// Fake Wi-Fi (`wlan0`, dummy device), a stub SOCKS5 proxy on it, and the
    /// engine + firewall under test. `port` must differ between tests.
    fn lab(port: u16, udp: UdpMode, ipv6: bool, relay: bool) -> Lab {
        sh("ip link set lo up");
        sh("ip link del wlan0");
        for cmd in [
            "ip link add wlan0 type dummy",
            "ip addr add 10.9.0.2/24 dev wlan0",
            "ip link set wlan0 up",
            "ip route add default via 10.9.0.254 dev wlan0",
            "ip -6 addr add fd00:9::2/64 dev wlan0 nodad",
            "ip -6 route add default via fd00:9::fe dev wlan0",
        ] {
            sh(cmd);
        }

        // Stub proxy: accept, no-auth, record the CONNECT target, answer.
        let listener = TcpListener::bind(("10.9.0.2", port)).unwrap();
        let (tx, seen) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for mut c in listener.incoming().flatten() {
                let mut buf = [0u8; 256];
                let _ = c.read(&mut buf);
                let _ = c.write_all(&[5, 0]);
                let n = c.read(&mut buf).unwrap_or(0);
                if buf[1] == 3 {
                    if !relay {
                        // UDP ASSOCIATE: many real proxies refuse it too.
                        let _ = c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
                        continue;
                    }
                    // Minimal UDP relay: answer every datagram with "pong".
                    let udp = std::net::UdpSocket::bind("10.9.0.2:0").unwrap();
                    let port = udp.local_addr().unwrap().port().to_be_bytes();
                    let _ = c.write_all(&[5, 0, 0, 1, 10, 9, 0, 2, port[0], port[1]]);
                    let tx = tx.clone();
                    std::thread::spawn(move || {
                        let _keep_control_connection_open = c;
                        let mut d = [0u8; 1500];
                        while let Ok((n, peer)) = udp.recv_from(&mut d) {
                            // Header: RSV RSV FRAG ATYP addr(4) port(2).
                            if n > 10 && d[3] == 1 {
                                let _ =
                                    tx.send((d[4..8].to_vec(), u16::from_be_bytes([d[8], d[9]])));
                                let mut reply = d[..10].to_vec();
                                reply.extend(b"pong");
                                let _ = udp.send_to(&reply, peer);
                            }
                        }
                    });
                    continue;
                }
                let (addr, at) = match buf.get(3) {
                    Some(4) => (buf[4..20].to_vec(), 20),
                    _ => (buf[4..8].to_vec(), 8),
                };
                let dst_port = u16::from_be_bytes([buf[at], buf[at + 1]]);
                if n >= 10 {
                    let _ = tx.send((addr, dst_port));
                }
                let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                if dst_port == 53 {
                    // DNS-over-TCP: answer the query with one record.
                    let mut len = [0u8; 2];
                    let _ = c.read_exact(&mut len);
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    let _ = c.read_exact(&mut q);
                    q[2] |= 0x80;
                    q[7] = 1;
                    let _ = c.write_all(&(q.len() as u16).to_be_bytes());
                    let _ = c.write_all(&q);
                    continue;
                }
                let _ = c.write_all(b"HTTP/1.0 200 OK\r\n\r\nvia-proxy");
            }
        });

        let dir = std::env::temp_dir().join(format!("pw-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut profile = crate::service::tests::profile(true, true);
        profile.proxy.host = "10.9.0.2".into();
        profile.proxy.port = port;
        profile.udp = udp;
        profile.routing.ipv6 = ipv6;
        let route = RouteContext::resolve(&profile, "wlan0").unwrap();
        Lab {
            engine: TunEngine::new("tun2socks".into(), "ip".into(), dir, Arc::new(NoOpSecrets)),
            firewall: NftFirewall::new("nft".into()),
            profile,
            route,
            seen,
        }
    }

    impl Lab {
        fn up(&self) {
            self.firewall.apply(&self.profile, &self.route).unwrap();
            assert_eq!(
                self.engine.start(&self.profile, &self.route).unwrap(),
                TUN_NAME
            );
            assert!(self.engine.is_running());
        }
        fn down(&self) {
            self.engine.stop().unwrap();
            assert!(!self.engine.is_running());
            self.firewall.remove().unwrap();
        }
        fn next_seen(&self) -> Seen {
            self.seen
                .recv_timeout(Duration::from_secs(3))
                .expect("proxy saw no request")
        }
    }

    fn curl(args: &[&str]) -> String {
        let out = Command::new("curl")
            .args(["-s", "-m", "5"])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// TX packet count of `wlan0` (the fake uplink).
    fn wlan0_tx_packets() -> u64 {
        let out = Command::new("ip")
            .args(["-s", "link", "show", "dev", "wlan0"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut lines = text
            .lines()
            .skip_while(|l| !l.trim_start().starts_with("TX:"));
        lines.next();
        lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
            .unwrap_or(0)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn e2e_tcp_and_dns_go_through_the_proxy() {
        let lab = lab(1080, UdpMode::Proxy, false, false);

        // Probe first: the SOCKS5 handshake itself.
        let probe = lab.engine.test(&lab.profile, &lab.route).unwrap();
        assert!(
            probe.reachable && probe.authentication_ok && probe.tcp_ok,
            "{probe:?}"
        );
        assert!(!probe.udp_ok, "the stub proxy has no UDP relay");
        let _ = lab.next_seen();

        lab.up();
        assert_eq!(curl(&["http://93.184.216.34/"]), "via-proxy");
        assert_eq!(lab.next_seen(), (vec![93, 184, 216, 34], 80));

        // Plain UDP/53 to a public resolver is redirected into the forwarder
        // and leaves through the proxy.
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        sock.send_to(&crate::dns::build_query(7, "example.com"), "8.8.8.8:53")
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).expect("DNS reply");
        assert!(crate::dns::reply_ok(7, &buf[..n]));
        assert_eq!(
            lab.next_seen(),
            (vec![1, 1, 1, 1], 53),
            "DNS must leave via the proxy"
        );
        assert!(lab.engine.test(&lab.profile, &lab.route).unwrap().dns_ok);
        lab.down();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn e2e_udp_proxy_uses_the_socks5_relay() {
        let lab = lab(1084, UdpMode::Proxy, false, true);
        assert!(lab.engine.test(&lab.profile, &lab.route).unwrap().udp_ok);
        while lab.seen.try_recv().is_ok() {}
        lab.up();

        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        sock.connect("93.184.216.34:443").unwrap();
        sock.send(b"ping").unwrap();
        let mut buf = [0u8; 64];
        let n = sock.recv(&mut buf).expect("UDP reply through the relay");
        assert_eq!(&buf[..n], b"pong");
        assert_eq!(lab.next_seen(), (vec![93, 184, 216, 34], 443));
        lab.down();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn e2e_udp_block_is_rejected_immediately() {
        let lab = lab(1081, UdpMode::Block, false, false);
        lab.up();
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.connect("93.184.216.34:443").unwrap();
        let _ = sock.send(b"x");
        let err = sock.recv(&mut [0u8; 8]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused, "{err}");
        lab.down();
    }

    /// `udp = block` must not break proxied DNS: the redirected queries are
    /// UDP too and have to reach the forwarder.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn e2e_dns_works_when_udp_is_blocked() {
        let lab = lab(1086, UdpMode::Block, false, false);
        lab.up();
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        sock.send_to(&crate::dns::build_query(9, "example.com"), "8.8.8.8:53")
            .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).expect("DNS reply");
        assert!(crate::dns::reply_ok(9, &buf[..n]));
        lab.down();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn e2e_udp_direct_bypasses_the_tunnel() {
        let lab = lab(1082, UdpMode::Direct, false, false);
        lab.up();
        let before = wlan0_tx_packets();
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.send_to(b"x", "93.184.216.34:9999").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            wlan0_tx_packets() > before,
            "direct UDP must leave via wlan0"
        );
        // ...and it never reached the stub proxy as a CONNECT.
        assert!(lab.seen.try_recv().is_err());
        lab.down();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn e2e_ipv6_tcp_goes_through_the_proxy() {
        let lab = lab(1083, UdpMode::Proxy, true, false);
        lab.up();
        assert_eq!(curl(&["-6", "http://[2001:db8::1]/"]), "via-proxy");
        let (addr, port) = lab.next_seen();
        assert_eq!((addr.len(), port), (16, 80), "expected an IPv6 CONNECT");
        assert_eq!(&addr[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        lab.down();
    }
}
