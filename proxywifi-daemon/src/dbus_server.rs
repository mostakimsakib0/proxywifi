//! D-Bus server for the ProxyWiFi daemon.
//!
//! Exposes `org.proxywifi.Daemon` at `/org/proxywifi/Daemon` on the
//! **system bus** so the GTK GUI (and CLI tooling) can query status,
//! list connections/profiles, and manually start/stop/test the proxy.
//!
//! Implemented with zbus 4's `#[zbus::interface]` attribute macro, which
//! is applied to an `impl` block (zbus 3's `#[dbus_interface]`-on-a-trait
//! form no longer exists).
//!
//! ## Payload encoding
//!
//! Aggregate results (`ProxyStatus`, connection lists, profiles, test
//! results) are returned as **JSON strings**. This keeps the D-Bus surface
//! stable while the wire model in `proxywifi-core::models` is still
//! evolving and avoids duplicating it as `zvariant` structs. Simple
//! control results are returned as native `b` (boolean).

use crate::service::DaemonService;
use std::sync::Arc;

/// Well-known bus name the daemon owns.
pub const DAEMON_BUS_NAME: &str = "org.proxywifi.Daemon";

/// Object path the daemon exports at.
pub const DAEMON_OBJECT_PATH: &str = "/org/proxywifi/Daemon";

/// Encode a value as JSON, mapping encoding failures onto a D-Bus error.
fn encode_json<T: serde::Serialize>(value: &T, what: &str) -> zbus::fdo::Result<String> {
    serde_json::to_string(value)
        .map_err(|e| zbus::fdo::Error::Failed(format!("could not encode {what}: {e}")))
}

/// Map an internal error onto a generic D-Bus failure.
fn dbus_failed(context: &str, error: impl std::fmt::Display) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(format!("{context}: {error}"))
}

// ---------------------------------------------------------------------------
// Server object
// ---------------------------------------------------------------------------

/// The object exported on the system bus.
///
/// Holds only an `Arc` to the service, so registering an instance with the
/// object server is cheap and the D-Bus layer cannot observe partial state.
pub struct DaemonDbusServer {
    service: Arc<DaemonService>,
    /// Check the caller's UID on control methods (defence in depth on top of
    /// the bus policy). Off for session-bus tests, on for the system bus.
    enforce_caller: bool,
}

/// Group whose members may control the daemon; mirrors the bus policy.
const CONTROL_GROUP: &str = "proxywifi";

/// Whether `uid` is root or a listed member of [`CONTROL_GROUP`].
fn uid_may_control(uid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let field = |line: &str, n: usize| line.split(':').nth(n).map(str::to_owned);
    let user = std::fs::read_to_string("/etc/passwd").ok().and_then(|p| {
        p.lines()
            .find(|l| field(l, 2).as_deref() == Some(&uid.to_string()))
            .and_then(|l| field(l, 0))
    });
    let Some(user) = user else { return false };
    std::fs::read_to_string("/etc/group")
        .map(|g| {
            g.lines()
                .filter(|l| field(l, 0).as_deref() == Some(CONTROL_GROUP))
                .filter_map(|l| field(l, 3))
                .any(|members| members.split(',').any(|m| m == user))
        })
        .unwrap_or(false)
}

impl DaemonDbusServer {
    /// Wrap a service instance for export.
    pub fn new(service: Arc<DaemonService>) -> Self {
        Self {
            service,
            enforce_caller: false,
        }
    }

    /// Connect to the system bus, export [`DAEMON_OBJECT_PATH`], and request
    /// [`DAEMON_BUS_NAME`].
    ///
    /// The returned connection must be kept alive for as long as the daemon
    /// runs; dropping it removes the object and releases the name.
    pub async fn export(service: Arc<DaemonService>) -> anyhow::Result<zbus::Connection> {
        let conn = zbus::Connection::system()
            .await
            .map_err(|e| anyhow::anyhow!("could not connect to the system bus: {e}"))?;

        Self::export_object(
            conn,
            DaemonDbusServer {
                enforce_caller: true,
                ..Self::new(service)
            },
        )
        .await
    }

    /// Export [`DAEMON_OBJECT_PATH`] on an existing connection.
    ///
    /// Split out from [`DaemonDbusServer::export`] so the interface can be
    /// served on a session bus (or any other connection) — which is how the
    /// D-Bus surface is tested without root privileges and without a
    /// system-bus policy file.
    pub async fn export_on(
        conn: zbus::Connection,
        service: Arc<DaemonService>,
    ) -> anyhow::Result<zbus::Connection> {
        Self::export_object(conn, Self::new(service)).await
    }

    async fn export_object(
        conn: zbus::Connection,
        server: DaemonDbusServer,
    ) -> anyhow::Result<zbus::Connection> {
        conn.object_server()
            .at(DAEMON_OBJECT_PATH, server)
            .await
            .map_err(|e| anyhow::anyhow!("could not export {DAEMON_OBJECT_PATH}: {e}"))?;

        // Requesting the well-known name needs a D-Bus policy that allows
        // this user to own it. Without one the object is still reachable via
        // the connection's unique name, so this is not fatal.
        match conn.request_name(DAEMON_BUS_NAME).await {
            Ok(()) => tracing::info!("owning D-Bus name {DAEMON_BUS_NAME}"),
            Err(e) => tracing::warn!(
                "could not request {DAEMON_BUS_NAME}: {e} \
                 (install packaging/dbus/org.proxywifi.Daemon.conf to allow it)"
            ),
        }

        Ok(conn)
    }
}

impl DaemonDbusServer {
    /// Reject callers that are neither root nor in [`CONTROL_GROUP`].
    async fn authorize(
        &self,
        hdr: &zbus::message::Header<'_>,
        conn: &zbus::Connection,
    ) -> zbus::fdo::Result<()> {
        if !self.enforce_caller {
            return Ok(());
        }
        let sender = hdr
            .sender()
            .ok_or_else(|| zbus::fdo::Error::AccessDenied("caller has no bus name".into()))?;
        let uid = zbus::fdo::DBusProxy::new(conn)
            .await?
            .get_connection_unix_user(sender.clone().into())
            .await?;
        if uid_may_control(uid) {
            Ok(())
        } else {
            Err(zbus::fdo::Error::AccessDenied(format!(
                "uid {uid} is not root or a member of group {CONTROL_GROUP}"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// D-Bus interface: org.proxywifi.Daemon
// ---------------------------------------------------------------------------

#[zbus::interface(name = "org.proxywifi.Daemon")]
impl DaemonDbusServer {
    /// Daemon package version.
    #[zbus(property)]
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Effective API level, bumped when the D-Bus surface changes.
    #[zbus(property)]
    fn api_version(&self) -> u32 {
        2
    }

    /// Current Wi-Fi + proxy status as a JSON-encoded `ProxyStatus`.
    async fn get_status(&self) -> zbus::fdo::Result<String> {
        let snapshot = self.service.snapshot().await;
        encode_json(&snapshot.status(), "status")
    }

    /// Saved Wi-Fi connections as a JSON array of `WifiConnection`.
    async fn get_wifi_connections(&self) -> zbus::fdo::Result<String> {
        let connections = self
            .service
            .wifi_connections()
            .await
            .map_err(|e| dbus_failed("could not list Wi-Fi connections", e))?;
        encode_json(&connections, "Wi-Fi connections")
    }

    /// Visible access points as a JSON array of `{\"ssid\", \"strength\"}`.
    async fn get_available_networks(&self) -> zbus::fdo::Result<String> {
        let networks = self
            .service
            .available_networks()
            .await
            .map_err(|e| dbus_failed("could not scan for networks", e))?;

        let payload: Vec<serde_json::Value> = networks
            .into_iter()
            .map(|(ssid, strength)| serde_json::json!({ "ssid": ssid, "strength": strength }))
            .collect();
        encode_json(&payload, "access points")
    }

    /// All stored proxy profiles as a JSON array of `ProxyProfile`.
    async fn get_proxy_profiles(&self) -> zbus::fdo::Result<String> {
        encode_json(&self.service.profiles(), "proxy profiles")
    }

    /// Replace all stored proxy profiles with the given JSON array of
    /// `ProxyProfile` and persist it. Clients edit a copy fetched with
    /// `GetProxyProfiles` and push it back.
    async fn set_proxy_profiles(
        &self,
        profiles_json: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<bool> {
        self.authorize(&hdr, conn).await?;
        let profiles = serde_json::from_str(&profiles_json)
            .map_err(|e| dbus_failed("invalid profile JSON", e))?;
        self.service
            .set_profiles(profiles)
            .map_err(|e| dbus_failed("could not save profiles", e))?;
        Ok(true)
    }

    /// Store proxy credentials (empty `username` = none); returns the opaque
    /// secret id to put in a profile.
    async fn store_secret(
        &self,
        label: String,
        username: String,
        password: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        self.authorize(&hdr, conn).await?;
        let username = (!username.is_empty()).then_some(username);
        self.service
            .secrets()
            .store_secret(&label, username, password)
            .map_err(|e| dbus_failed("could not store secret", e))
    }

    /// Delete a stored secret; unknown ids are not an error.
    async fn delete_secret(
        &self,
        secret_id: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<bool> {
        self.authorize(&hdr, conn).await?;
        self.service
            .secrets()
            .delete_secret(&secret_id)
            .map_err(|e| dbus_failed("could not delete secret", e))?;
        Ok(true)
    }

    /// Start the proxy for `uuid`, or for the active Wi-Fi when `uuid` is
    /// the empty string.
    async fn start_proxy(
        &self,
        uuid: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<bool> {
        self.authorize(&hdr, conn).await?;
        let uuid = if uuid.trim().is_empty() {
            None
        } else {
            Some(uuid)
        };

        self.service
            .manual_start(uuid)
            .await
            .map_err(|e| dbus_failed("could not start proxy", e))?;
        Ok(true)
    }

    /// Connect to a Wi-Fi network; an empty `password` means open network or
    /// an already-saved connection.
    async fn connect_wifi(
        &self,
        ssid: String,
        password: String,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<bool> {
        self.authorize(&hdr, conn).await?;
        self.service
            .connect_wifi(&ssid, Some(password.as_str()).filter(|p| !p.is_empty()))
            .await
            .map_err(|e| dbus_failed("could not connect", e))?;
        Ok(true)
    }

    /// Stop the proxy and remove all firewall state.
    async fn stop_proxy(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<bool> {
        self.authorize(&hdr, conn).await?;
        self.service
            .manual_stop()
            .await
            .map_err(|e| dbus_failed("could not stop proxy", e))?;
        Ok(true)
    }

    /// Run the proxy probe suite; returns a JSON-encoded `ProxyTestResult`.
    async fn test_proxy(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> zbus::fdo::Result<String> {
        self.authorize(&hdr, conn).await?;
        let result = self
            .service
            .manual_test()
            .await
            .map_err(|e| dbus_failed("proxy test failed", e))?;
        encode_json(&result, "proxy test result")
    }
}
