//! Domain types: proxy profiles, Wi-Fi connection info, and runtime status.
//!
//! This is the data model the GUI, CLI, and daemon all share.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Proxy configuration
// ---------------------------------------------------------------------------

/// Supported proxy protocol types for the MVP and beyond.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    /// SOCKS5 — the initial MVP target. Supports TCP and, depending on
    /// the proxy engine, UDP.
    Socks5,
    /// HTTP proxy used through `CONNECT` (TCP only; no UDP relay).
    Http,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Socks5 => write!(f, "socks5"),
            ProxyType::Http => write!(f, "http"),
        }
    }
}

/// How the proxy engine obtains credentials for the upstream proxy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    /// No authentication required.
    None,
    /// Credentials are fetched from the desktop Secret Service / keyring
    /// at connection time. The `secret_id` field in `ProxyConfig`
    /// references the stored secret.
    Keyring,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::None => write!(f, "none"),
            AuthMethod::Keyring => write!(f, "keyring"),
        }
    }
}

/// Per-connection proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub authentication: AuthMethod,
    /// Optional opaque identifier used to look up credentials in the
    /// Secret Service. Only meaningful when `authentication == Keyring`.
    #[serde(default)]
    pub secret_id: Option<String>,
}

// ---------------------------------------------------------------------------
// DNS behaviour
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    #[default]
    Proxied,
    Direct,
}

impl std::fmt::Display for DnsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsMode::Proxied => write!(f, "proxied"),
            DnsMode::Direct => write!(f, "direct"),
        }
    }
}

// ---------------------------------------------------------------------------
// Routing / protocol coverage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpVersionConfig {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Default for IpVersionConfig {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UdpMode {
    #[default]
    Proxy,
    Block,
    Direct,
}

impl std::fmt::Display for UdpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpMode::Proxy => write!(f, "proxy"),
            UdpMode::Block => write!(f, "block"),
            UdpMode::Direct => write!(f, "direct"),
        }
    }
}

// ---------------------------------------------------------------------------
// Local network behaviour
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LocalNetMode {
    /// No LAN exemption. Note the connected-subnet route still bypasses the
    /// tunnel, so with the kill switch on this behaves like `Block`.
    Proxy,
    /// Default: local networks are reached directly, never through the proxy.
    #[default]
    Direct,
    Block,
}

impl std::fmt::Display for LocalNetMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalNetMode::Proxy => write!(f, "proxy"),
            LocalNetMode::Direct => write!(f, "direct"),
            LocalNetMode::Block => write!(f, "block"),
        }
    }
}

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchConfig {
    pub enabled: bool,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// ---------------------------------------------------------------------------
// The top-level profile
// ---------------------------------------------------------------------------

/// A proxy profile associated with one NetworkManager connection UUID.
///
/// Stored in `profiles.json`. Credentials are NOT stored here; they
/// live in the desktop Secret Service and are referenced by `secret_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyProfile {
    pub connection_uuid: String,
    #[serde(default)]
    pub label: Option<String>,
    pub enabled: bool,
    pub proxy: ProxyConfig,
    pub dns: DnsMode,
    pub routing: IpVersionConfig,
    #[serde(default)]
    pub udp: UdpMode,
    #[serde(default)]
    pub local_network: LocalNetMode,
    #[serde(default)]
    pub kill_switch: KillSwitchConfig,
    #[serde(default)]
    pub auto_connect: bool,
}

impl ProxyProfile {
    pub fn should_auto_activate(&self) -> bool {
        self.enabled && self.auto_connect
    }
}

// ---------------------------------------------------------------------------
// Wi-Fi connection information (from NetworkManager)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConnection {
    pub uuid: String,
    pub name: String,
    #[serde(default)]
    pub ssid: Option<String>,
    #[serde(default)]
    pub state: String,
    pub wifi_enabled: bool,
    #[serde(default)]
    pub active_connection_path: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveWifi {
    pub uuid: String,
    pub ssid: String,
    pub interface: String,
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv6: Option<String>,
    pub has_default_route: bool,
}

// ---------------------------------------------------------------------------
// Runtime status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub wifi: Option<ActiveWifi>,
    pub wifi_enabled: bool,
    pub matched_profile_uuid: Option<String>,
    pub profile_enabled: bool,
    pub proxy_state: ProxyState,
    pub proxy_active: bool,
    #[serde(default)]
    pub tun_name: Option<String>,
    pub dns_mode: Option<DnsMode>,
    pub kill_switch_active: bool,
    #[serde(default)]
    pub last_health_check: Option<u64>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    #[default]
    Disconnected,
    ProfileLookup,
    Starting,
    HealthCheck,
    Active,
    Stopping,
    Failed,
}

impl std::fmt::Display for ProxyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyState::Disconnected => write!(f, "disconnected"),
            ProxyState::ProfileLookup => write!(f, "profile_lookup"),
            ProxyState::Starting => write!(f, "starting"),
            ProxyState::HealthCheck => write!(f, "health_check"),
            ProxyState::Active => write!(f, "active"),
            ProxyState::Stopping => write!(f, "stopping"),
            ProxyState::Failed => write!(f, "failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy test result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTestResult {
    pub reachable: bool,
    pub authentication_ok: bool,
    pub tcp_ok: bool,
    pub dns_ok: bool,
    pub ipv4_ok: bool,
    pub ipv6_ok: bool,
    pub udp_ok: bool,
    #[serde(default)]
    pub external_ip: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl ProxyTestResult {
    pub fn all_passed(&self) -> bool {
        self.reachable
            && self.authentication_ok
            && self.tcp_ok
            && self.dns_ok
            && self.ipv4_ok
            && self.ipv6_ok
            && self.udp_ok
    }
}
