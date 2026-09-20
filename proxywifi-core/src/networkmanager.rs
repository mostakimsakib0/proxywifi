//! NetworkManager D-Bus integration (zbus 4.x, async).
//!
//! Talks to `org.freedesktop.NetworkManager` on the **system bus** to:
//!   - discover Wi-Fi devices
//!   - read the active Wi-Fi connection (SSID, interface, UUID, IP info)
//!   - list *saved* Wi-Fi connections and their UUIDs (the things a
//!     proxy profile can be assigned to)
//!   - enumerate visible access points
//!
//! Everything is best-effort: individual property reads that fail are
//! tolerated so that one broken access point or device cannot take down
//! the whole status query.

use crate::models::{ActiveWifi, WifiConnection};
use std::collections::HashMap;
use zbus::proxy;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

/// Well-known bus name of NetworkManager.
pub const NM_SERVICE: &str = "org.freedesktop.NetworkManager";
/// Main NetworkManager object path.
pub const NM_PATH: &str = "/org/freedesktop/NetworkManager";
/// Object path of the `org.freedesktop.NetworkManager.Settings` singleton.
pub const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";

/// `NM_DEVICE_TYPE_WIFI` from the `NMDeviceType` enum.
const NM_DEVICE_TYPE_WIFI: u32 = 2;

/// `NM_ACTIVE_CONNECTION_STATE_ACTIVATED` from `NMActiveConnectionState`.
const NM_ACTIVE_CONNECTION_STATE_ACTIVATED: u32 = 2;

/// NetworkManager setting name for Wi-Fi connections.
const NM_SETTING_WIRELESS: &str = "802-11-wireless";

/// The connection `type` value identifying a Wi-Fi profile.
const NM_TYPE_WIRELESS: &str = "802-11-wireless";

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum NmError {
    /// Transport- or method-level D-Bus failure.
    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    /// NetworkManager is not reachable on the system bus.
    #[error("NetworkManager is not reachable: {0}")]
    Unavailable(String),
}

pub type NmResult<T> = std::result::Result<T, NmError>;

// ---------------------------------------------------------------------------
// Typed proxies
// ---------------------------------------------------------------------------

/// `org.freedesktop.NetworkManager` — the top-level manager object.
#[proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager",
    gen_blocking = false
)]
trait NetworkManager {
    fn get_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    #[zbus(property)]
    fn active_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    #[zbus(property)]
    fn wireless_enabled(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn networking_enabled(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn primary_connection(&self) -> zbus::Result<OwnedObjectPath>;

    /// Connection type of the primary connection, e.g. `802-11-wireless`.
    /// Usable as ground truth for "is Wi-Fi currently carrying traffic?".
    #[zbus(property)]
    fn primary_connection_type(&self) -> zbus::Result<String>;

    fn activate_connection(
        &self,
        connection: &ObjectPath<'_>,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
    ) -> zbus::Result<OwnedObjectPath>;

    fn add_and_activate_connection(
        &self,
        connection: HashMap<&str, HashMap<&str, Value<'_>>>,
        device: &ObjectPath<'_>,
        specific_object: &ObjectPath<'_>,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;
}

/// `org.freedesktop.NetworkManager.Settings` — the connection-store singleton
/// living at `/org/freedesktop/NetworkManager/Settings`.
///
/// Note: saved connections are **not** reachable from the main manager
/// object; `ListConnections()` (or the `Connections` property) on this
/// interface is the only way to enumerate them.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager/Settings",
    gen_blocking = false
)]
trait Settings {
    fn list_connections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

/// `org.freedesktop.NetworkManager.Device` — a single network device.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Device",
    default_service = "org.freedesktop.NetworkManager",
    gen_blocking = false
)]
trait Device {
    #[zbus(property)]
    fn device_type(&self) -> zbus::Result<u32>;

    #[zbus(property)]
    fn interface(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn ip4_config(&self) -> zbus::Result<OwnedObjectPath>;

    #[zbus(property)]
    fn ip6_config(&self) -> zbus::Result<OwnedObjectPath>;
}

/// `org.freedesktop.NetworkManager.Device.Wireless`.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Device.Wireless",
    default_service = "org.freedesktop.NetworkManager",
    gen_blocking = false
)]
trait Wireless {
    fn get_access_points(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    #[zbus(property)]
    fn active_access_point(&self) -> zbus::Result<OwnedObjectPath>;
}

/// `org.freedesktop.NetworkManager.AccessPoint`.
#[proxy(
    interface = "org.freedesktop.NetworkManager.AccessPoint",
    default_service = "org.freedesktop.NetworkManager",
    gen_blocking = false
)]
trait AccessPoint {
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<Vec<u8>>;

    #[zbus(property)]
    fn strength(&self) -> zbus::Result<u8>;
}

/// `org.freedesktop.NetworkManager.Connection.Active`.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Connection.Active",
    default_service = "org.freedesktop.NetworkManager",
    gen_blocking = false
)]
trait ActiveConnection {
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn uuid(&self) -> zbus::Result<String>;

    /// The `Settings.Connection` object this active connection was built from.
    #[zbus(property)]
    fn connection(&self) -> zbus::Result<OwnedObjectPath>;

    #[zbus(property)]
    fn devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    #[zbus(property, name = "Type")]
    fn connection_type(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn state(&self) -> zbus::Result<u32>;
}

/// `org.freedesktop.NetworkManager.Settings.Connection`.
#[proxy(
    interface = "org.freedesktop.NetworkManager.Settings.Connection",
    default_service = "org.freedesktop.NetworkManager",
    gen_blocking = false
)]
trait SettingsConnection {
    fn get_settings(&self) -> zbus::Result<HashMap<String, HashMap<String, OwnedValue>>>;
}

/// `org.freedesktop.NetworkManager.IP4Config`.
#[proxy(
    interface = "org.freedesktop.NetworkManager.IP4Config",
    default_service = "org.freedesktop.NetworkManager",
    gen_blocking = false
)]
trait Ip4Config {
    #[zbus(property)]
    fn address_data(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;
}

/// `org.freedesktop.NetworkManager.IP6Config`.
#[proxy(
    interface = "org.freedesktop.NetworkManager.IP6Config",
    default_service = "org.freedesktop.NetworkManager",
    gen_blocking = false
)]
trait Ip6Config {
    #[zbus(property)]
    fn address_data(&self) -> zbus::Result<Vec<HashMap<String, OwnedValue>>>;
}

/// Interface name constants (used for explicit builder calls).
const IFACE_DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const IFACE_WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const IFACE_AP: &str = "org.freedesktop.NetworkManager.AccessPoint";
const IFACE_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const IFACE_SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
const IFACE_SETTINGS_CONN: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const IFACE_IP4: &str = "org.freedesktop.NetworkManager.IP4Config";
const IFACE_IP6: &str = "org.freedesktop.NetworkManager.IP6Config";

// ---------------------------------------------------------------------------
// Helper conversions
// ---------------------------------------------------------------------------

/// NetworkManager reports SSIDs as raw bytes. They are UTF-8 in practice,
/// but we decode lossily so a malformed SSID never aborts a query.
fn ssid_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
}

/// Pull a typed value out of an `a{sv}`-style map.
///
/// `OwnedValue` only implements `TryFrom<OwnedValue>` (not `TryFrom<&OwnedValue>`)
/// for owned types like `String`, so the value is cloned first.
fn map_value<T>(map: &HashMap<String, OwnedValue>, key: &str) -> Option<T>
where
    T: TryFrom<OwnedValue>,
{
    let value = map.get(key)?;
    let owned = value.try_clone().ok()?;
    T::try_from(owned).ok()
}

/// Look up a typed value inside a `a{sa{sv}}` NetworkManager settings map.
fn setting_value<T>(
    settings: &HashMap<String, HashMap<String, OwnedValue>>,
    group: &str,
    key: &str,
) -> Option<T>
where
    T: TryFrom<OwnedValue>,
{
    map_value(settings.get(group)?, key)
}

/// Look up a string value inside a `a{sa{sv}}` NetworkManager settings map.
fn setting_str(
    settings: &HashMap<String, HashMap<String, OwnedValue>>,
    group: &str,
    key: &str,
) -> Option<String> {
    setting_value::<String>(settings, group, key)
}

/// Look up a byte-array value inside a `a{sa{sv}}` settings map.
fn setting_bytes(
    settings: &HashMap<String, HashMap<String, OwnedValue>>,
    group: &str,
    key: &str,
) -> Option<Vec<u8>> {
    setting_value::<Vec<u8>>(settings, group, key)
}

/// Extract the `address` field of the first entry of an `aa{sv}` array.
fn first_address(entries: &[HashMap<String, OwnedValue>]) -> Option<String> {
    map_value(entries.first()?, "address")
}

/// In D-Bus, an object path of `/` means "no such object".
fn is_null_path(path: &OwnedObjectPath) -> bool {
    path.as_str() == "/"
}

// ---------------------------------------------------------------------------
// NmClient
// ---------------------------------------------------------------------------

/// Async handle to NetworkManager on the system bus.
///
/// Cheap to clone the `Arc` around it; the underlying D-Bus connection is
/// shared. All methods are best-effort and never panic on missing objects.
pub struct NmClient {
    conn: zbus::Connection,
}

impl NmClient {
    /// Connect to the system bus and verify NetworkManager is present.
    pub async fn new() -> NmResult<Self> {
        let conn = zbus::Connection::system()
            .await
            .map_err(|e| NmError::Unavailable(e.to_string()))?;
        let client = Self { conn };
        client.probe().await?;
        Ok(client)
    }

    /// Same as [`NmClient::new`] but returns `None` instead of an error when
    /// NetworkManager is not reachable. Useful for the CLI, which should be
    /// able to report profile state on machines without NetworkManager.
    pub async fn try_new() -> Option<Self> {
        Self::new().await.ok()
    }

    /// Underlying bus connection (shared with any other zbus proxy).
    pub fn connection(&self) -> &zbus::Connection {
        &self.conn
    }

    /// Confirm the well-known NetworkManager name answers.
    async fn probe(&self) -> NmResult<()> {
        let nm = NetworkManagerProxy::new(&self.conn).await?;
        nm.networking_enabled()
            .await
            .map(|_| ())
            .map_err(|e| NmError::Unavailable(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Object builders
    // -----------------------------------------------------------------------

    // NOTE: the path argument is tied to the same lifetime as `&self`
    // because `Proxy` borrows the connection, so the returned proxy cannot
    // outlive either borrow.
    async fn device<'a>(&'a self, path: &'a OwnedObjectPath) -> NmResult<DeviceProxy<'a>> {
        Ok(DeviceProxy::builder(&self.conn)
            .destination(NM_SERVICE)?
            .path(path.as_str())?
            .interface(IFACE_DEVICE)?
            .build()
            .await?)
    }

    async fn wireless<'a>(&'a self, path: &'a OwnedObjectPath) -> NmResult<WirelessProxy<'a>> {
        Ok(WirelessProxy::builder(&self.conn)
            .destination(NM_SERVICE)?
            .path(path.as_str())?
            .interface(IFACE_WIRELESS)?
            .build()
            .await?)
    }

    async fn access_point<'a>(
        &'a self,
        path: &'a OwnedObjectPath,
    ) -> NmResult<AccessPointProxy<'a>> {
        Ok(AccessPointProxy::builder(&self.conn)
            .destination(NM_SERVICE)?
            .path(path.as_str())?
            .interface(IFACE_AP)?
            .build()
            .await?)
    }

    async fn active_connection<'a>(
        &'a self,
        path: &'a OwnedObjectPath,
    ) -> NmResult<ActiveConnectionProxy<'a>> {
        Ok(ActiveConnectionProxy::builder(&self.conn)
            .destination(NM_SERVICE)?
            .path(path.as_str())?
            .interface(IFACE_ACTIVE)?
            .build()
            .await?)
    }

    async fn settings_connection<'a>(
        &'a self,
        path: &'a OwnedObjectPath,
    ) -> NmResult<SettingsConnectionProxy<'a>> {
        Ok(SettingsConnectionProxy::builder(&self.conn)
            .destination(NM_SERVICE)?
            .path(path.as_str())?
            .interface(IFACE_SETTINGS_CONN)?
            .build()
            .await?)
    }

    /// The connection-store singleton, used to enumerate saved connections.
    async fn settings<'a>(&'a self) -> NmResult<SettingsProxy<'a>> {
        Ok(SettingsProxy::builder(&self.conn)
            .destination(NM_SERVICE)?
            .path(NM_SETTINGS_PATH)?
            .interface(IFACE_SETTINGS)?
            .build()
            .await?)
    }

    /// Object paths of every currently activated connection
    /// (`ActiveConnections` property of the main manager object).
    async fn activated_connection_paths(&self) -> NmResult<Vec<OwnedObjectPath>> {
        let nm = NetworkManagerProxy::new(&self.conn).await?;
        Ok(nm.active_connections().await?)
    }
}

// ---------------------------------------------------------------------------
// Public queries
// ---------------------------------------------------------------------------

impl NmClient {
    /// Is Wi-Fi globally enabled *and* is the network stack enabled at all?
    pub async fn wifi_enabled(&self) -> NmResult<bool> {
        let nm = NetworkManagerProxy::new(&self.conn).await?;
        let networking = nm.networking_enabled().await.unwrap_or(false);
        let wireless = nm.wireless_enabled().await.unwrap_or(false);
        Ok(networking && wireless)
    }

    /// `PrimaryConnectionType` — the connection type of the connection that
    /// currently owns the default route (`802-11-wireless` for Wi-Fi, the
    /// empty string when there is no primary connection).
    ///
    /// This is NetworkManager's own answer to "which network is carrying my
    /// traffic?", so it is the ground truth to compare our derived Wi-Fi
    /// state against.
    pub async fn primary_connection_type(&self) -> NmResult<String> {
        let nm = NetworkManagerProxy::new(&self.conn).await?;
        Ok(nm.primary_connection_type().await.unwrap_or_default())
    }

    /// All Wi-Fi devices as `(object_path, interface_name)` pairs.
    pub async fn wifi_devices(&self) -> NmResult<Vec<(OwnedObjectPath, String)>> {
        let nm = NetworkManagerProxy::new(&self.conn).await?;
        let mut out = Vec::new();

        for path in nm.get_devices().await.unwrap_or_default() {
            let Ok(device) = self.device(&path).await else {
                continue;
            };
            if device.device_type().await.unwrap_or(0) != NM_DEVICE_TYPE_WIFI {
                continue;
            }
            let iface = device.interface().await.unwrap_or_default();
            out.push((path, iface));
        }

        Ok(out)
    }

    /// The currently activated Wi-Fi connection, if any.
    ///
    /// Returns `None` when the machine is not associated with a Wi-Fi
    /// network, when the active connection is not Wi-Fi (e.g. ethernet),
    /// or when NetworkManager reports an incomplete profile.
    pub async fn active_wifi(&self) -> NmResult<Option<ActiveWifi>> {
        let nm = NetworkManagerProxy::new(&self.conn).await?;
        let primary = nm.primary_connection().await.ok();
        // NOTE: `ActiveConnections` is a property; there is no
        // `GetActiveConnections` method on the manager interface. The error is
        // propagated (rather than swallowed) so a broken query can never be
        // mistaken for "not connected to Wi-Fi".
        let mut active_paths = nm.active_connections().await?;
        // Prefer the connection carrying the default route, so a secondary
        // Wi-Fi never shadows it.
        if let Some(primary) = &primary {
            active_paths.sort_by_key(|p| p != primary);
        }

        for ac_path in active_paths {
            let Ok(ac) = self.active_connection(&ac_path).await else {
                continue;
            };

            // Only Wi-Fi connections are of interest.
            let conn_type = ac.connection_type().await.unwrap_or_default();
            if conn_type != NM_TYPE_WIRELESS {
                continue;
            }

            // Only fully activated connections count.
            let state = ac.state().await.unwrap_or(0);
            if state != NM_ACTIVE_CONNECTION_STATE_ACTIVATED {
                continue;
            }

            let uuid = ac.uuid().await.unwrap_or_default();
            let devices = ac.devices().await.unwrap_or_default();
            let Some(device_path) = devices.into_iter().next() else {
                continue;
            };

            let iface = match self.device(&device_path).await {
                Ok(d) => d.interface().await.unwrap_or_default(),
                Err(_) => String::new(),
            };

            let ssid = self.device_ssid(&device_path).await.unwrap_or_default();
            let ipv4 = self.device_ip(&device_path, true).await;
            let ipv6 = self.device_ip(&device_path, false).await;

            let has_default_route = primary
                .as_ref()
                .map(|p| p.as_str() == ac_path.as_str())
                .unwrap_or(false);

            return Ok(Some(ActiveWifi {
                uuid,
                ssid,
                interface: iface,
                ipv4,
                ipv6,
                has_default_route,
            }));
        }

        Ok(None)
    }

    /// SSID currently associated with a Wi-Fi device, via its active AP.
    async fn device_ssid(&self, device_path: &OwnedObjectPath) -> Option<String> {
        let wifi = self.wireless(device_path).await.ok()?;
        let ap_path = wifi.active_access_point().await.ok()?;
        if is_null_path(&ap_path) {
            return None;
        }
        let ap = self.access_point(&ap_path).await.ok()?;
        let bytes = ap.ssid().await.ok()?;
        if bytes.is_empty() {
            return None;
        }
        Some(ssid_to_string(&bytes))
    }

    /// First IPv4 (`ipv4 == true`) or IPv6 address of a device.
    async fn device_ip(&self, device_path: &OwnedObjectPath, ipv4: bool) -> Option<String> {
        let device = self.device(device_path).await.ok()?;
        let cfg_path = if ipv4 {
            device.ip4_config().await.ok()?
        } else {
            device.ip6_config().await.ok()?
        };
        if is_null_path(&cfg_path) {
            return None;
        }

        let entries = if ipv4 {
            let cfg = Ip4ConfigProxy::builder(&self.conn)
                .destination(NM_SERVICE)
                .ok()?
                .path(cfg_path.as_str())
                .ok()?
                .interface(IFACE_IP4)
                .ok()?
                .build()
                .await
                .ok()?;
            cfg.address_data().await.ok()?
        } else {
            let cfg = Ip6ConfigProxy::builder(&self.conn)
                .destination(NM_SERVICE)
                .ok()?
                .path(cfg_path.as_str())
                .ok()?
                .interface(IFACE_IP6)
                .ok()?
                .build()
                .await
                .ok()?;
            cfg.address_data().await.ok()?
        };

        first_address(&entries)
    }
}

// ---------------------------------------------------------------------------
// Saved connections + visible access points
// ---------------------------------------------------------------------------

impl NmClient {
    /// Map of `Settings.Connection` path -> `(active connection path, uuid)`
    /// for every currently activated connection, used to flag saved Wi-Fi
    /// profiles as active.
    async fn active_connection_index(&self) -> HashMap<String, (String, String)> {
        let mut index = HashMap::new();

        for ac_path in self.activated_connection_paths().await.unwrap_or_default() {
            let Ok(ac) = self.active_connection(&ac_path).await else {
                continue;
            };
            let Ok(settings_path) = ac.connection().await else {
                continue;
            };
            let uuid = ac.uuid().await.unwrap_or_default();
            index.insert(
                settings_path.as_str().to_string(),
                (ac_path.as_str().to_string(), uuid),
            );
        }

        index
    }

    /// Saved Wi-Fi connections from NetworkManager — the connection UUIDs a
    /// proxy profile can be assigned to.
    pub async fn saved_wifi_connections(&self) -> NmResult<Vec<WifiConnection>> {
        // Saved connections live in the `Settings` singleton, not on the main
        // manager object. A failure here is propagated: reporting "no saved
        // Wi-Fi connections" when the query itself failed would silently hide
        // every assignable profile from the user.
        let conn_paths = self.settings().await?.list_connections().await?;
        let active_index = self.active_connection_index().await;
        let wifi_enabled = self.wifi_enabled().await.unwrap_or(false);
        let mut out = Vec::new();

        for conn_path in conn_paths {
            let Ok(proxy) = self.settings_connection(&conn_path).await else {
                continue;
            };
            let Ok(settings) = proxy.get_settings().await else {
                continue;
            };

            // Only Wi-Fi profiles.
            if setting_str(&settings, "connection", "type").as_deref() != Some(NM_TYPE_WIRELESS) {
                continue;
            }

            let uuid = setting_str(&settings, "connection", "uuid").unwrap_or_default();
            let name = setting_str(&settings, "connection", "id").unwrap_or_default();
            let ssid = setting_bytes(&settings, NM_SETTING_WIRELESS, "ssid")
                .map(|bytes| ssid_to_string(&bytes))
                .filter(|s| !s.is_empty());

            let active = active_index.get(conn_path.as_str());

            out.push(WifiConnection {
                uuid,
                name: if name.is_empty() {
                    ssid.clone().unwrap_or_default()
                } else {
                    name
                },
                ssid,
                state: if active.is_some() {
                    String::from("activated")
                } else {
                    String::from("disconnected")
                },
                wifi_enabled,
                active_connection_path: active.map(|(p, _)| p.clone()),
                interface: None,
            });
        }

        // Stable ordering makes CLI output and tests deterministic.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Visible access points as `(ssid, signal_strength_percent)`, strongest
    /// first. Used by the "assign a profile to this network" workflows.
    pub async fn available_wifi_networks(&self) -> NmResult<Vec<(String, u8)>> {
        let mut seen: Vec<(String, u8)> = Vec::new();

        for (device_path, _iface) in self.wifi_devices().await? {
            let Ok(wifi) = self.wireless(&device_path).await else {
                continue;
            };
            for ap_path in wifi.get_access_points().await.unwrap_or_default() {
                let Ok(ap) = self.access_point(&ap_path).await else {
                    continue;
                };
                let Ok(bytes) = ap.ssid().await else { continue };
                if bytes.is_empty() {
                    continue;
                }
                let ssid = ssid_to_string(&bytes);
                if ssid.is_empty() {
                    continue;
                }
                let strength = ap.strength().await.unwrap_or(0);

                // Keep the strongest reading per SSID.
                match seen.iter_mut().find(|(s, _)| *s == ssid) {
                    Some(entry) => {
                        if strength > entry.1 {
                            entry.1 = strength;
                        }
                    }
                    None => seen.push((ssid, strength)),
                }
            }
        }

        seen.sort_by_key(|entry| std::cmp::Reverse(entry.1));
        Ok(seen)
    }
}

// ---------------------------------------------------------------------------
// Connecting
// ---------------------------------------------------------------------------

impl NmClient {
    /// Connect the first Wi-Fi device to `ssid`.
    ///
    /// A saved connection for the SSID is reused (its stored secrets apply,
    /// `password` is ignored). Otherwise a new WPA-PSK connection is created
    /// (open network when `password` is `None`) and saved by NetworkManager.
    /// Returns once NetworkManager has *started* activating; the daemon picks
    /// the connection up on its next poll.
    /// ponytail: no hidden SSIDs, WPA3-only or 802.1X; use nmcli for those.
    pub async fn connect_wifi(&self, ssid: &str, password: Option<&str>) -> NmResult<()> {
        let (device, _iface) = self
            .wifi_devices()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| NmError::Unavailable("no Wi-Fi device found".into()))?;
        let nm = NetworkManagerProxy::new(&self.conn).await?;
        let none = ObjectPath::try_from("/").expect("valid path");

        for conn_path in self.settings().await?.list_connections().await? {
            let Ok(proxy) = self.settings_connection(&conn_path).await else {
                continue;
            };
            let Ok(settings) = proxy.get_settings().await else {
                continue;
            };
            let saved = setting_bytes(&settings, NM_SETTING_WIRELESS, "ssid");
            if setting_str(&settings, "connection", "type").as_deref() == Some(NM_TYPE_WIRELESS)
                && saved.as_deref() == Some(ssid.as_bytes())
            {
                nm.activate_connection(&conn_path, &device, &none).await?;
                return Ok(());
            }
        }

        let mut settings: HashMap<&str, HashMap<&str, Value<'_>>> = HashMap::new();
        settings.insert(
            "connection",
            HashMap::from([
                ("type", Value::from(NM_TYPE_WIRELESS)),
                ("id", Value::from(ssid)),
            ]),
        );
        settings.insert(
            NM_SETTING_WIRELESS,
            HashMap::from([("ssid", Value::from(ssid.as_bytes().to_vec()))]),
        );
        if let Some(psk) = password.filter(|p| !p.is_empty()) {
            settings.insert(
                "802-11-wireless-security",
                HashMap::from([
                    ("key-mgmt", Value::from("wpa-psk")),
                    ("psk", Value::from(psk)),
                ]),
            );
        }
        nm.add_and_activate_connection(settings, &device, &none)
            .await?;
        Ok(())
    }
}
