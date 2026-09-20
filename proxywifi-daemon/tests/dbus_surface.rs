//! D-Bus surface test for the daemon.
//!
//! The daemon normally owns `org.proxywifi.Daemon` on the **system** bus,
//! which needs a D-Bus policy file and root privileges. That makes the system
//! bus unusable for tests, so this test serves the exact same interface object
//! on the **session** bus (via `DaemonDbusServer::export_on`) and talks to it
//! with a real client proxy.
//!
//! What it proves: interface name, method names, argument and reply
//! signatures, JSON payload shapes, and the error mapping.
//!
//! It skips (never fails) when NetworkManager or a session bus is missing, so
//! `cargo test` still works inside containers. Run it against a private bus
//! with `dbus-run-session -- cargo test -p proxywifi-daemon`.

use proxywifi_core::models::{
    AuthMethod, DnsMode, IpVersionConfig, KillSwitchConfig, LocalNetMode, ProxyConfig,
    ProxyProfile, ProxyType, UdpMode,
};
use proxywifi_core::networkmanager::NmClient;
use proxywifi_core::profiles::ProfileStore;
use proxywifi_daemon::dbus_server::{DaemonDbusServer, DAEMON_OBJECT_PATH};
use proxywifi_daemon::service::{DaemonService, NoOpFirewall, NoOpProxyEngine};
use std::sync::Arc;

/// The interface under test.
const IFACE: &str = "org.proxywifi.Daemon";

/// UUID of the profile seeded into the test store. Deliberately *not* the
/// UUID of the machine's live Wi-Fi connection.
const SEEDED_UUID: &str = "00000000-0000-0000-0000-000000000000";

/// A profile pointing at a proxy that does not have to exist: the prototype's
/// `NoOpProxyEngine` never connects anywhere.
fn test_profile(connection_uuid: &str) -> ProxyProfile {
    ProxyProfile {
        connection_uuid: connection_uuid.to_string(),
        label: Some("dbus surface test".to_string()),
        enabled: true,
        proxy: ProxyConfig {
            proxy_type: ProxyType::Socks5,
            host: "127.0.0.1".to_string(),
            port: 11080,
            authentication: AuthMethod::None,
            secret_id: None,
        },
        dns: DnsMode::Proxied,
        routing: IpVersionConfig::default(),
        udp: UdpMode::default(),
        local_network: LocalNetMode::default(),
        kill_switch: KillSwitchConfig::default(),
        auto_connect: true,
    }
}

/// Scratch directory for the profile store, removed on drop.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "proxywifi-dbus-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("could not create scratch dir");
        Self(path)
    }

    fn profiles_path(&self) -> std::path::PathBuf {
        self.0.join("profiles.json")
    }
}

/// Exported object plus a client proxy bound to it.
struct Harness {
    /// Kept alive: dropping the connection removes the exported object.
    _conn: zbus::Connection,
    proxy: zbus::Proxy<'static>,
    service: Arc<DaemonService>,
}

/// Serve the daemon interface on the session bus with `profile` seeded into a
/// fresh profile store, and connect a client to it.
///
/// Returns `None` (skip, not fail) when NetworkManager or a session bus is
/// unavailable.
async fn connect_with(profile: ProxyProfile) -> Option<Harness> {
    let nm = match NmClient::try_new().await {
        Some(nm) => nm,
        None => {
            eprintln!("skipping: NetworkManager not reachable on the system bus");
            return None;
        }
    };

    let session = match zbus::Connection::session().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("skipping: no session bus available ({e})");
            return None;
        }
    };

    let scratch = ScratchDir::new();
    let mut store = ProfileStore::load_or_create(scratch.profiles_path()).expect("store");
    store
        .upsert(profile)
        .expect("could not seed the profile store");

    let service = Arc::new(DaemonService::new(
        Arc::new(nm),
        store,
        Arc::new(NoOpProxyEngine),
        Arc::new(NoOpFirewall),
        // Never reached: the tests step the machine through `refresh()`.
        3600,
    ));

    let conn = DaemonDbusServer::export_on(session, service.clone())
        .await
        .expect("could not export the daemon interface");

    // Use the unique name: it always works, whereas the well-known name may
    // already be taken on a shared bus or denied by a system-bus policy.
    let destination = conn
        .unique_name()
        .expect("session connection without a unique name")
        .to_string();

    let proxy = zbus::Proxy::new(&conn, destination, DAEMON_OBJECT_PATH, IFACE)
        .await
        .expect("could not build a client proxy for the exported object");

    // The store file must outlive the service, which holds its path; leaking
    // this tiny temp directory keeps that valid for the whole test process.
    let profiles_path = scratch.profiles_path();
    assert!(profiles_path.exists(), "scratch store was not created");
    std::mem::forget(scratch);

    Some(Harness {
        _conn: conn,
        proxy,
        service,
    })
}

/// The default harness: a single profile assigned to an unrelated UUID.
async fn connect() -> Option<Harness> {
    connect_with(test_profile(SEEDED_UUID)).await
}

/// UUID of the Wi-Fi connection currently carrying traffic, or `None` when
/// the machine is not on Wi-Fi. Auto-connect behaviour can only be observed
/// against a connection that is actually up.
async fn live_wifi_uuid() -> Option<String> {
    let nm = NmClient::try_new().await?;
    nm.active_wifi().await.ok().flatten().map(|wifi| wifi.uuid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn properties_report_version_and_api_level() {
    let Some(h) = connect().await else { return };

    let version: String = h
        .proxy
        .get_property("Version")
        .await
        .expect("Version property");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));

    let api: u32 = h
        .proxy
        .get_property("ApiVersion")
        .await
        .expect("ApiVersion property");
    assert!(api >= 1, "ApiVersion must be a positive level, got {api}");
}

#[tokio::test]
async fn get_status_returns_a_well_formed_proxy_status() {
    let Some(h) = connect().await else { return };

    let raw: String = h.proxy.call("GetStatus", &()).await.expect("GetStatus");
    let status: serde_json::Value = serde_json::from_str(&raw).expect("GetStatus must return JSON");

    // A freshly constructed service has not polled yet.
    assert!(status["wifi"].is_null(), "unexpected wifi state: {status}");
    assert_eq!(status["proxy_state"], "disconnected");
    assert_eq!(status["proxy_active"], false);
    assert_eq!(status["wifi_enabled"], false);
    assert_eq!(status["kill_switch_active"], false);
    assert!(status["matched_profile_uuid"].is_null());
    assert!(status["message"].is_null());
}

#[tokio::test]
async fn get_proxy_profiles_returns_the_stored_profiles() {
    let Some(h) = connect().await else { return };

    let raw: String = h
        .proxy
        .call("GetProxyProfiles", &())
        .await
        .expect("GetProxyProfiles");
    let profiles: serde_json::Value =
        serde_json::from_str(&raw).expect("GetProxyProfiles must return JSON");

    let list = profiles.as_array().expect("expected a JSON array");
    assert_eq!(list.len(), 1, "seeded exactly one profile: {profiles}");
    assert_eq!(list[0]["connection_uuid"], SEEDED_UUID);
    assert_eq!(list[0]["enabled"], true);
    assert_eq!(list[0]["proxy"]["host"], "127.0.0.1");
    assert_eq!(list[0]["proxy"]["port"], 11080);
}

#[tokio::test]
async fn wifi_connections_and_networks_are_json_arrays() {
    let Some(h) = connect().await else { return };

    let raw: String = h
        .proxy
        .call("GetWifiConnections", &())
        .await
        .expect("GetWifiConnections must not fail while NetworkManager is up");
    let connections: serde_json::Value =
        serde_json::from_str(&raw).expect("GetWifiConnections must return JSON");
    for c in connections.as_array().expect("expected a JSON array") {
        assert!(c["uuid"].is_string(), "connection without a uuid: {c}");
        assert!(c["name"].is_string(), "connection without a name: {c}");
        assert!(c["state"].is_string(), "connection without a state: {c}");
    }

    let raw: String = h
        .proxy
        .call("GetAvailableNetworks", &())
        .await
        .expect("GetAvailableNetworks must not fail while NetworkManager is up");
    let networks: serde_json::Value =
        serde_json::from_str(&raw).expect("GetAvailableNetworks must return JSON");
    for ap in networks.as_array().expect("expected a JSON array") {
        assert!(ap["ssid"].is_string(), "access point without an ssid: {ap}");
        assert!(
            ap["strength"].is_u64(),
            "access point without strength: {ap}"
        );
    }
}

#[tokio::test]
async fn start_proxy_reports_a_helpful_error_for_unknown_profiles() {
    let Some(h) = connect().await else { return };

    // Unknown connection UUID.
    let err = h
        .proxy
        .call::<_, _, bool>("StartProxy", &("does-not-exist"))
        .await
        .expect_err("starting an unknown profile must fail");
    assert_dbus_failure_contains(err, "Wi-Fi connection");

    // Empty UUID with nothing active: the client learns what to fix.
    let err = h
        .proxy
        .call::<_, _, bool>("StartProxy", &(""))
        .await
        .expect_err("starting with no active Wi-Fi must fail");
    assert_dbus_failure_contains(err, "no active Wi-Fi connection");

    // Same for a proxy test with nothing matched.
    let err = h
        .proxy
        .call::<_, _, String>("TestProxy", &())
        .await
        .expect_err("testing without a matched profile must fail");
    assert_dbus_failure_contains(err, "no proxy profile is currently matched");
}

#[tokio::test]
async fn stop_proxy_succeeds_when_nothing_is_running() {
    let Some(h) = connect().await else { return };

    // `stop_proxy` / `firewall.remove` are documented as idempotent, so this
    // must succeed even though nothing was ever started.
    let stopped: bool = h
        .proxy
        .call("StopProxy", &())
        .await
        .expect("StopProxy must be idempotent");
    assert!(stopped);

    let raw: String = h.proxy.call("GetStatus", &()).await.expect("GetStatus");
    let status: serde_json::Value = serde_json::from_str(&raw).expect("JSON");
    assert_eq!(status["proxy_state"], "disconnected");
    assert_eq!(status["proxy_active"], false);
}

/// A poll tick must be visible through the D-Bus status method.
#[tokio::test]
async fn refresh_publishes_networkmanager_state_over_dbus() {
    let Some(h) = connect().await else { return };

    assert!(
        h.service.snapshot().await.active_wifi.is_none(),
        "a fresh service must not have polled yet"
    );

    h.service
        .refresh()
        .await
        .expect("one poll tick must succeed");

    let raw: String = h.proxy.call("GetStatus", &()).await.expect("GetStatus");
    let status: serde_json::Value = serde_json::from_str(&raw).expect("JSON");

    match status["wifi"].as_object() {
        Some(wifi) => {
            // Wi-Fi is up: SSID and interface must have travelled intact.
            assert!(wifi["ssid"].is_string(), "wifi without an ssid: {status}");
            assert!(
                wifi["interface"].is_string(),
                "wifi without an interface: {status}"
            );
            assert_eq!(status["wifi_enabled"], true);
            // The seeded profile belongs to a different UUID, so nothing may
            // match and nothing may be started.
            assert!(
                status["matched_profile_uuid"].is_null(),
                "an unrelated profile must not match: {status}"
            );
            assert_eq!(status["proxy_state"], "disconnected");
            assert_eq!(status["proxy_active"], false);
        }
        None => {
            // No Wi-Fi: the snapshot must say so instead of lying.
            assert_eq!(status["proxy_state"], "disconnected");
            assert!(status["matched_profile_uuid"].is_null());
        }
    }
}

/// Read `proxy_state` / `proxy_active` / `message` off the D-Bus status call.
async fn proxy_state_of(h: &Harness) -> (String, bool, Option<String>) {
    let raw: String = h.proxy.call("GetStatus", &()).await.expect("GetStatus");
    let status: serde_json::Value = serde_json::from_str(&raw).expect("JSON");
    (
        status["proxy_state"]
            .as_str()
            .expect("proxy_state must be a string")
            .to_string(),
        status["proxy_active"].as_bool().expect("proxy_active"),
        status["message"].as_str().map(|s| s.to_string()),
    )
}

/// Regression: an *enabled* profile whose `auto_connect` is off must be left
/// alone by the polling loop.
///
/// This is the behaviour the CLI promises ("Profile is enabled but
/// auto-connect is off; it will only be used when started manually"), and it
/// is the safe default: enabling a profile for later use must never reroute
/// traffic on its own.
#[tokio::test]
async fn poll_loop_leaves_a_non_auto_connecting_profile_alone() {
    let Some(uuid) = live_wifi_uuid().await else {
        eprintln!("skipping: not connected to a Wi-Fi network");
        return;
    };

    let mut profile = test_profile(&uuid);
    profile.enabled = true;
    profile.auto_connect = false;

    let Some(h) = connect_with(profile).await else {
        return;
    };

    // The profile does match the live connection...
    h.service.refresh().await.expect("one poll tick");

    let raw: String = h.proxy.call("GetStatus", &()).await.expect("GetStatus");
    let status: serde_json::Value = serde_json::from_str(&raw).expect("JSON");
    assert_eq!(
        status["matched_profile_uuid"].as_str(),
        Some(uuid.as_str()),
        "the profile must still be reported as matched: {status}"
    );

    // ...but nothing may have been started for it.
    let (state, active, message) = proxy_state_of(&h).await;
    assert_eq!(
        state, "disconnected",
        "an enabled, non-auto-connecting profile must not be started (message: {message:?})"
    );
    assert!(!active, "no proxy may be active: {status}");
}

/// The counterpart: turning `auto_connect` on is what authorises the polling
/// loop to act, so the state must leave `disconnected`.
#[tokio::test]
async fn poll_loop_starts_an_auto_connecting_profile() {
    let Some(uuid) = live_wifi_uuid().await else {
        eprintln!("skipping: not connected to a Wi-Fi network");
        return;
    };

    let mut profile = test_profile(&uuid);
    profile.enabled = true;
    profile.auto_connect = true;

    let Some(h) = connect_with(profile).await else {
        return;
    };

    h.service.refresh().await.expect("one poll tick");

    // Which state it lands in is the NoOp engine's business (it cannot
    // actually carry traffic, so it ends up in `failed`); what matters here is
    // that the start attempt happened at all.
    let (state, _, message) = proxy_state_of(&h).await;
    assert_ne!(
        state, "disconnected",
        "an enabled, auto-connecting profile must be started by the poll loop"
    );
    assert!(
        message.is_some(),
        "a failed start must explain itself through `message`"
    );
}

/// Assert a D-Bus call failed with the daemon's generic failure + a message.
fn assert_dbus_failure_contains(err: zbus::Error, needle: &str) {
    match err {
        zbus::Error::MethodError(name, message, _) => {
            assert_eq!(
                name.as_str(),
                "org.freedesktop.DBus.Error.Failed",
                "unexpected D-Bus error name"
            );
            let message = message.unwrap_or_default();
            assert!(
                message.contains(needle),
                "expected the error to mention {needle:?}, got {message:?}"
            );
        }
        other => panic!("expected a D-Bus method error, got {other:?}"),
    }
}

#[tokio::test]
async fn set_proxy_profiles_replaces_and_persists_the_set() {
    let Some(h) = connect().await else { return };

    let raw: String = h.proxy.call("GetProxyProfiles", &()).await.expect("get");
    let mut profiles: Vec<serde_json::Value> = serde_json::from_str(&raw).expect("json");
    profiles[0]["enabled"] = false.into();

    let ok: bool = h
        .proxy
        .call(
            "SetProxyProfiles",
            &(serde_json::to_string(&profiles).unwrap(),),
        )
        .await
        .expect("SetProxyProfiles");
    assert!(ok);
    assert!(!h.service.profiles()[0].enabled);

    let bad = h
        .proxy
        .call::<_, _, bool>("SetProxyProfiles", &("not json",))
        .await;
    assert!(bad.is_err(), "invalid JSON must be rejected");
    assert_eq!(h.service.profiles().len(), 1, "bad input must not clobber");
}
