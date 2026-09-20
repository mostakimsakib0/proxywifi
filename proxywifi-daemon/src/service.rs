//! ProxyWiFi daemon service.
//!
//! This module owns the daemon's *logic*: the profile store, the
//! NetworkManager polling loop, and the proxy state machine. The D-Bus
//! interface that exposes this logic to the GUI lives in
//! [`crate::dbus_server`].
//!
//! State machine (see `models::ProxyState`):
//!
//! ```text
//! Disconnected --(Wi-Fi up + enabled profile with auto-connect)--> Starting
//! Starting     --(firewall + engine ok)---------> HealthCheck
//! HealthCheck  --(probe ok)---------------------> Active
//! HealthCheck  --(probe failed)-----------------> Failed / Disconnected
//! Active       --(Wi-Fi down / disabled)--------> Stopping -> Disconnected
//! ```

use proxywifi_core::models::{ActiveWifi, ProxyProfile, ProxyState, ProxyStatus, ProxyTestResult};
use proxywifi_core::networkmanager::NmClient;
use proxywifi_core::profiles::ProfileStore;
use proxywifi_core::secrets::{NoOpSecrets, SecretServiceOps};
use std::sync::Arc;
use tokio::sync::{watch, Mutex, RwLock};

// ---------------------------------------------------------------------------
// Proxy engine trait — Phase 3+ implementation point
// ---------------------------------------------------------------------------

/// Where the proxy runs: the physical interface carrying the connection and
/// the proxy's resolved address (resolved once, before any rule is installed).
#[derive(Debug, Clone)]
pub struct RouteContext {
    pub iface: String,
    pub proxy_ip: std::net::IpAddr,
}

impl RouteContext {
    /// Resolve `profile`'s proxy host, preferring IPv4.
    pub fn resolve(profile: &ProxyProfile, iface: &str) -> anyhow::Result<Self> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<_> = (profile.proxy.host.as_str(), profile.proxy.port)
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("cannot resolve proxy host {}: {e}", profile.proxy.host))?
            .collect();
        let addr = addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or(addrs.first())
            .ok_or_else(|| anyhow::anyhow!("proxy host {} has no address", profile.proxy.host))?;
        Ok(Self {
            iface: iface.to_string(),
            proxy_ip: addr.ip(),
        })
    }
}

/// Abstraction over the transparent-proxy data plane (TUN device +
/// SOCKS5 forwarder, or an external helper such as `tun2socks`).
///
/// The Phase 0–2 prototype ships [`NoOpProxyEngine`]; the real engine
/// (TUN read/write loop, SOCKS5 handshake, UDP relay) lands in Phase 3.
pub trait ProxyEngine: Send + Sync {
    /// Bring the engine up for `profile`; returns the TUN device name.
    fn start(&self, profile: &ProxyProfile, route: &RouteContext) -> anyhow::Result<String>;
    /// Tear the engine down; must be idempotent.
    fn stop(&self) -> anyhow::Result<()>;
    /// Run the connectivity / authentication probe suite.
    fn test(&self, profile: &ProxyProfile, route: &RouteContext)
        -> anyhow::Result<ProxyTestResult>;
    /// Whether the data plane is currently up.
    fn is_running(&self) -> bool;
}

/// No-op engine used until Phase 3 lands. Reports "not running" so the
/// state machine parks in `Failed` rather than claiming a working proxy.
pub struct NoOpProxyEngine;

impl ProxyEngine for NoOpProxyEngine {
    fn start(&self, _profile: &ProxyProfile, _route: &RouteContext) -> anyhow::Result<String> {
        Ok(String::new())
    }

    fn stop(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn test(
        &self,
        _profile: &ProxyProfile,
        _route: &RouteContext,
    ) -> anyhow::Result<ProxyTestResult> {
        Ok(ProxyTestResult {
            reachable: false,
            authentication_ok: false,
            tcp_ok: false,
            dns_ok: false,
            ipv4_ok: false,
            ipv6_ok: false,
            udp_ok: false,
            external_ip: None,
            error: Some("proxy engine not implemented in prototype".into()),
        })
    }

    fn is_running(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Firewall trait — Phase 3+ implementation point
// ---------------------------------------------------------------------------

/// Abstraction over the nftables ruleset (`inet proxywifi` table) that
/// steers traffic into the TUN device and implements the kill switch.
pub trait FirewallOps: Send + Sync {
    /// Install the redirect / marking rules for `profile`.
    fn apply(&self, profile: &ProxyProfile, route: &RouteContext) -> anyhow::Result<()>;
    /// Remove every rule ProxyWiFi owns; must be idempotent.
    fn remove(&self) -> anyhow::Result<()>;
    /// Arm or disarm the kill switch (drop non-proxied traffic).
    fn set_kill_switch(&self, armed: bool) -> anyhow::Result<()>;
}

/// No-op firewall used until Phase 3 lands.
pub struct NoOpFirewall;

impl FirewallOps for NoOpFirewall {
    fn apply(&self, _profile: &ProxyProfile, _route: &RouteContext) -> anyhow::Result<()> {
        Ok(())
    }

    fn remove(&self) -> anyhow::Result<()> {
        Ok(())
    }

    fn set_kill_switch(&self, _armed: bool) -> anyhow::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Daemon snapshot — cheap, consistent read model for D-Bus consumers
// ---------------------------------------------------------------------------

/// A point-in-time view of the daemon, replaced wholesale by the polling
/// loop each tick. The D-Bus server and the CLI read this instead of
/// reaching into the state machine, so they cannot observe a torn state.
#[derive(Clone)]
pub struct DaemonSnapshot {
    /// Wi-Fi radio state reported by NetworkManager.
    pub wifi_enabled: bool,
    /// The Wi-Fi connection currently carrying traffic, if any.
    pub active_wifi: Option<ActiveWifi>,
    /// The (enabled) proxy profile matched to `active_wifi`.
    pub matched_profile: Option<ProxyProfile>,
    /// Current state-machine state.
    pub proxy_state: ProxyState,
    /// Whether the data plane is up.
    pub proxy_active: bool,
    /// Human-readable description of the last failure, if any.
    pub last_error: Option<String>,
}

impl Default for DaemonSnapshot {
    fn default() -> Self {
        Self {
            wifi_enabled: false,
            active_wifi: None,
            matched_profile: None,
            proxy_state: ProxyState::Disconnected,
            proxy_active: false,
            last_error: None,
        }
    }
}

impl DaemonSnapshot {
    /// Project the snapshot onto the shared `ProxyStatus` wire model.
    pub fn status(&self) -> ProxyStatus {
        ProxyStatus {
            wifi: self.active_wifi.clone(),
            wifi_enabled: self.wifi_enabled,
            matched_profile_uuid: self
                .matched_profile
                .as_ref()
                .map(|p| p.connection_uuid.clone()),
            profile_enabled: self
                .matched_profile
                .as_ref()
                .map(|p| p.enabled)
                .unwrap_or(false),
            proxy_state: self.proxy_state,
            proxy_active: self.proxy_active,
            tun_name: None,
            dns_mode: self.matched_profile.as_ref().map(|p| p.dns.clone()),
            kill_switch_active: self
                .matched_profile
                .as_ref()
                .map(|p| p.kill_switch.enabled)
                .unwrap_or(false),
            last_health_check: None,
            message: self.last_error.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal mutable state
// ---------------------------------------------------------------------------

/// The mutable half of the daemon state, guarded by a single mutex.
struct DaemonStateInner {
    proxy_state: ProxyState,
    proxy_active: bool,
    last_error: Option<String>,
    /// UUID of the connection the proxy was started for, so we can detect
    /// a Wi-Fi *switch* (SSID change) and restart the tunnel.
    active_uuid: Option<String>,
    /// Consecutive poll ticks spent in `ProxyState::Failed`. Used as a
    /// cheap retry back-off so a broken upstream cannot cause a hot
    /// restart loop.
    failed_ticks: u32,
    /// Connection the user explicitly stopped. The poller will not
    /// auto-restart it until the user starts it again or Wi-Fi changes.
    user_stopped: Option<String>,
    /// The running proxy was started by the user (not by auto-connect), so
    /// the poller must not stop it just because auto-connect is off.
    manual: bool,
}

impl DaemonStateInner {
    fn new() -> Self {
        Self {
            proxy_state: ProxyState::Disconnected,
            proxy_active: false,
            last_error: None,
            active_uuid: None,
            failed_ticks: 0,
            user_stopped: None,
            manual: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DaemonService — polling loop + state machine
// ---------------------------------------------------------------------------

/// How many consecutive failed ticks to wait before retrying a failed proxy.
/// At the default 5 s poll interval this is a ~30 s back-off, which keeps a
/// broken upstream from causing a hot restart loop in the logs.
const FAILED_RETRY_TICKS: u32 = 6;

#[derive(Clone)]
pub struct DaemonService {
    state: Arc<Mutex<DaemonStateInner>>,
    snapshot: Arc<RwLock<DaemonSnapshot>>,
    /// Serialises start/stop transitions between the poller and D-Bus calls.
    transition: Arc<Mutex<()>>,
    /// `true` once shutdown was requested. A watch channel (unlike `Notify`)
    /// remembers the signal, so a SIGTERM before anyone waits is not lost.
    shutdown: Arc<watch::Sender<bool>>,
    nm: Arc<NmClient>,
    profile_store: Arc<std::sync::RwLock<ProfileStore>>,
    engine: Arc<dyn ProxyEngine>,
    firewall: Arc<dyn FirewallOps>,
    secrets: Arc<dyn SecretServiceOps>,
    poll_interval_secs: u64,
}

impl DaemonService {
    pub fn new(
        nm: Arc<NmClient>,
        profile_store: ProfileStore,
        engine: Arc<dyn ProxyEngine>,
        firewall: Arc<dyn FirewallOps>,
        poll_interval_secs: u64,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(DaemonStateInner::new())),
            snapshot: Arc::new(RwLock::new(DaemonSnapshot::default())),
            transition: Arc::new(Mutex::new(())),
            shutdown: Arc::new(watch::channel(false).0),
            nm,
            profile_store: Arc::new(std::sync::RwLock::new(profile_store)),
            engine,
            firewall,
            secrets: Arc::new(NoOpSecrets),
            poll_interval_secs,
        }
    }

    /// Use `secrets` for proxy credentials (default: none available).
    pub fn with_secrets(mut self, secrets: Arc<dyn SecretServiceOps>) -> Self {
        self.secrets = secrets;
        self
    }

    /// Credential store, for the D-Bus surface and the future engine.
    pub fn secrets(&self) -> &dyn SecretServiceOps {
        self.secrets.as_ref()
    }

    // ------------------------------------------------------------------
    // Read-only accessors
    // ------------------------------------------------------------------

    /// Consistent snapshot of daemon state for the D-Bus server.
    pub async fn snapshot(&self) -> DaemonSnapshot {
        self.snapshot.read().await.clone()
    }

    fn store(&self) -> std::sync::RwLockReadGuard<'_, ProfileStore> {
        self.profile_store.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Replace the whole profile set (the D-Bus write path) and persist it.
    ///
    /// The running proxy is left alone; the next poll re-matches profiles, so
    /// a removed or disabled profile stops the proxy within one tick.
    pub fn set_profiles(&self, profiles: Vec<ProxyProfile>) -> anyhow::Result<()> {
        self.profile_store
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .replace_all(profiles)?;
        Ok(())
    }

    /// All stored proxy profiles.
    pub fn profiles(&self) -> Vec<ProxyProfile> {
        self.store().all()
    }

    /// Saved Wi-Fi connections as reported by NetworkManager.
    pub async fn wifi_connections(
        &self,
    ) -> anyhow::Result<Vec<proxywifi_core::models::WifiConnection>> {
        Ok(self.nm.saved_wifi_connections().await?)
    }

    /// Visible access points as `(ssid, strength)`.
    /// Connect to `ssid` (see [`NmClient::connect_wifi`]).
    pub async fn connect_wifi(&self, ssid: &str, password: Option<&str>) -> anyhow::Result<()> {
        Ok(self.nm.connect_wifi(ssid, password).await?)
    }

    pub async fn available_networks(&self) -> anyhow::Result<Vec<(String, u8)>> {
        Ok(self.nm.available_wifi_networks().await?)
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Run until SIGTERM/SIGINT, then tear the data plane down.
    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!(
            "ProxyWiFi daemon running (poll interval {}s)",
            self.poll_interval_secs
        );

        // Signal handling task: wakes everything waiting on `shutdown`.
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");
            let mut int = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("failed to install SIGINT handler");
            tokio::select! {
                _ = term.recv() => tracing::info!("received SIGTERM"),
                _ = int.recv() => tracing::info!("received SIGINT"),
            }
            shutdown.send_replace(true);
        });

        // Polling / state-machine task.
        let poller = self.clone();
        let poll_task = tokio::spawn(async move { poller.poll_loop().await });

        let _ = self.shutdown.subscribe().wait_for(|down| *down).await;
        tracing::info!("shutdown signalled, running cleanup");
        // Let an in-flight transition finish instead of cancelling it midway.
        let _ = poll_task.await;
        self.cleanup().await;
        tracing::info!("ProxyWiFi daemon stopped");
        Ok(())
    }

    /// Run a single poll iteration immediately.
    ///
    /// [`DaemonService::run`] drives this from its own loop; exposing it lets
    /// callers force a refresh instead of waiting up to `poll_interval_secs`,
    /// and lets tests step the state machine deterministically.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        self.poll_once().await
    }

    /// Poll NetworkManager forever, advancing the state machine each tick.
    async fn poll_loop(&self) {
        let mut down = self.shutdown.subscribe();
        loop {
            if let Err(e) = self.poll_once().await {
                tracing::warn!("poll iteration failed: {e:?}");
            }

            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(
                    self.poll_interval_secs,
                )) => {}
                _ = down.wait_for(|d| *d) => {
                    tracing::debug!("poll loop observed shutdown");
                    return;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// One poll iteration
// ---------------------------------------------------------------------------

/// Whether the polling loop should bring the proxy up on its own for
/// `profile`.
///
/// [`ProfileStore::find_enabled_for`] only tells us the profile is *usable*;
/// `auto_connect` is the separate, explicit opt-in to letting the daemon
/// reroute traffic without being asked, so both must be set. This is
/// deliberately not consulted by [`DaemonService::manual_start`]: a manual
/// request *is* the user asking for the proxy.
fn should_auto_start(profile: Option<&ProxyProfile>) -> bool {
    profile
        .map(ProxyProfile::should_auto_activate)
        .unwrap_or(false)
}

impl DaemonService {
    /// Read NetworkManager state, match a profile, advance the state machine.
    async fn poll_once(&self) -> anyhow::Result<()> {
        let wifi_enabled = self.nm.wifi_enabled().await.unwrap_or(false);
        let active = self.nm.active_wifi().await?;

        let _transition = self.transition.lock().await;

        let Some(wifi) = active else {
            self.state.lock().await.user_stopped = None;
            // No Wi-Fi: if anything is up, take it down.
            let was_up = {
                let inner = self.state.lock().await;
                inner.proxy_active || inner.proxy_state != ProxyState::Disconnected
            };

            if was_up {
                tracing::info!("Wi-Fi disconnected - stopping proxy");
                self.state.lock().await.proxy_state = ProxyState::Stopping;
                self.stop_proxy().await;
            }

            self.publish(DaemonSnapshot {
                wifi_enabled,
                ..Default::default()
            })
            .await;
            return Ok(());
        };

        // Wi-Fi is up: find the profile assigned to this connection.
        let profile = self.store().find_enabled_for(&wifi.uuid);
        // An enabled profile is *not* sufficient on its own — the user must
        // also have opted into automatic activation (CLI `--auto-connect`),
        // otherwise the daemon would reroute traffic the CLI told them would
        // only ever be used manually.
        // Never reroute on a Wi-Fi that is not carrying the default route
        // (e.g. Ethernet is primary): the proxy would apply to the wrong link.
        let mut should_start = wifi.has_default_route && should_auto_start(profile.as_ref());
        let kill_switch = profile
            .as_ref()
            .map(|p| p.kill_switch.enabled)
            .unwrap_or(false);

        let (state, current_uuid, failed_ticks, manual) = {
            let mut inner = self.state.lock().await;
            // A manual stop sticks for that connection only.
            if inner.user_stopped.as_deref() != Some(wifi.uuid.as_str()) {
                inner.user_stopped = None;
            }
            if inner.user_stopped.is_some() {
                should_start = false;
            }
            let state = inner.proxy_state;
            let current_uuid = inner.active_uuid.clone();
            // Count how long we have been sitting in `Failed`.
            if state == ProxyState::Failed {
                inner.failed_ticks = inner.failed_ticks.saturating_add(1);
            } else {
                inner.failed_ticks = 0;
            }
            // A manual start stays up while its own enabled profile matches.
            let manual = inner.manual
                && profile.is_some()
                && inner.active_uuid.as_deref() == Some(wifi.uuid.as_str());
            (state, current_uuid, inner.failed_ticks, manual)
        };

        // Roaming to a different Wi-Fi network invalidates the tunnel.
        let switched = current_uuid
            .as_deref()
            .map(|uuid| uuid != wifi.uuid)
            .unwrap_or(false);

        // `start_proxy` records its own failure in the state, so an error here
        // is only logged: the snapshot below must still be published.
        if should_start && (state == ProxyState::Disconnected || switched) {
            if switched {
                // Drop the old network's tunnel before building the new one.
                self.stop_proxy().await;
            }
            if let Err(e) = self.start_proxy(&wifi.uuid, &wifi.interface).await {
                tracing::warn!("proxy start failed: {e}");
            }
        } else if should_start && state == ProxyState::Failed {
            if failed_ticks >= FAILED_RETRY_TICKS {
                tracing::info!("retrying proxy start after {failed_ticks} failed ticks");
                if let Err(e) = self.start_proxy(&wifi.uuid, &wifi.interface).await {
                    tracing::warn!("proxy retry failed: {e}");
                }
            }
        } else if !should_start && !manual && state != ProxyState::Disconnected {
            tracing::info!("no enabled profile for {} - stopping proxy", wifi.uuid);
            self.stop_proxy().await;
        } else if (should_start || manual) && state == ProxyState::Active {
            if let Err(e) = self.health_check().await {
                if kill_switch {
                    self.record_failure(format!("health check failed: {e}"))
                        .await;
                } else {
                    self.stop_proxy().await;
                }
            }
        }

        let snapshot = {
            let inner = self.state.lock().await;
            DaemonSnapshot {
                wifi_enabled,
                active_wifi: Some(wifi),
                matched_profile: profile,
                proxy_state: inner.proxy_state,
                proxy_active: inner.proxy_active,
                last_error: inner.last_error.clone(),
            }
        };
        self.publish(snapshot).await;
        Ok(())
    }

    /// Log and store the newest snapshot.
    async fn publish(&self, snapshot: DaemonSnapshot) {
        tracing::debug!(
            "poll: state={}, wifi={:?}, profile={:?}",
            snapshot.proxy_state,
            snapshot.active_wifi.as_ref().map(|w| w.ssid.clone()),
            snapshot
                .matched_profile
                .as_ref()
                .map(|p| p.connection_uuid.clone()),
        );
        *self.snapshot.write().await = snapshot;
    }
}

// ---------------------------------------------------------------------------
// Proxy lifecycle
// ---------------------------------------------------------------------------

impl DaemonService {
    /// Bring up firewall rules and the proxy engine for `uuid`.
    async fn start_proxy(&self, uuid: &str, iface: &str) -> anyhow::Result<()> {
        let profile = self
            .store()
            .find_enabled_for(uuid)
            .ok_or_else(|| anyhow::anyhow!("no enabled proxy profile for connection {uuid}"))?;

        {
            let mut inner = self.state.lock().await;
            inner.proxy_state = ProxyState::Starting;
            inner.last_error = None;
        }

        tracing::info!(
            "starting proxy for {} ({}:{} via {})",
            uuid,
            profile.proxy.host,
            profile.proxy.port,
            profile.proxy.proxy_type,
        );

        let route = match RouteContext::resolve(&profile, iface) {
            Ok(r) => r,
            Err(e) => {
                self.record_failure(e.to_string()).await;
                return Err(e);
            }
        };

        // 1. Firewall first, so traffic is already steered when the engine
        //    comes up and nothing leaks in the gap.
        if let Err(e) = self.firewall.apply(&profile, &route) {
            self.record_failure(format!("firewall setup failed: {e}"))
                .await;
            return Err(e);
        }

        // 2. Data plane.
        match self.engine.start(&profile, &route) {
            Ok(tun) => {
                tracing::info!("proxy engine started (tun={tun})");
                let mut inner = self.state.lock().await;
                inner.proxy_active = true;
                inner.proxy_state = ProxyState::HealthCheck;
                inner.active_uuid = Some(uuid.to_string());
                inner.failed_ticks = 0;
            }
            Err(e) => {
                let _ = self.firewall.remove();
                self.record_failure(format!("proxy engine failed to start: {e}"))
                    .await;
                return Err(e);
            }
        }

        // 3. Health check.
        match self.health_check().await {
            Ok(()) => {
                self.state.lock().await.proxy_state = ProxyState::Active;
                tracing::info!("proxy is active on {uuid}");
            }
            Err(e) => {
                self.record_failure(format!("health check failed: {e}"))
                    .await;
                if profile.kill_switch.enabled {
                    // Fail closed: keep the rules so traffic cannot escape
                    // unproxied just because the tunnel is unhealthy.
                    tracing::warn!("kill switch armed - rules kept, traffic is blocked");
                } else {
                    self.stop_proxy().await;
                }
            }
        }

        Ok(())
    }

    /// Tear down the engine and firewall rules. Idempotent.
    async fn stop_proxy(&self) {
        tracing::info!("stopping proxy");

        if let Err(e) = self.engine.stop() {
            tracing::warn!("proxy engine stop failed: {e}");
        }
        if let Err(e) = self.firewall.remove() {
            tracing::warn!("firewall cleanup failed: {e}");
        }
        // `remove` owns every rule, but disarm explicitly so a stop can never
        // leave a drop-all kill switch behind.
        if let Err(e) = self.firewall.set_kill_switch(false) {
            tracing::warn!("could not disarm kill switch: {e}");
        }

        let mut inner = self.state.lock().await;
        inner.proxy_active = false;
        inner.proxy_state = ProxyState::Disconnected;
        inner.active_uuid = None;
        inner.manual = false;
        inner.failed_ticks = 0;
        inner.last_error = None;
    }

    /// Verify the data plane is actually up.
    async fn health_check(&self) -> anyhow::Result<()> {
        if !self.engine.is_running() {
            anyhow::bail!("proxy engine is not running");
        }
        Ok(())
    }

    /// Record a failure and bump the retry back-off counter.
    async fn record_failure(&self, message: String) {
        tracing::error!("{message}");
        let mut inner = self.state.lock().await;
        inner.proxy_state = ProxyState::Failed;
        inner.proxy_active = false;
        inner.last_error = Some(message);
        // `failed_ticks` is counted by the poller, one per tick in `Failed`.
        inner.failed_ticks = 0;
    }

    /// Shutdown hook: make sure nothing is left running on the system.
    async fn cleanup(&self) {
        tracing::info!("running shutdown cleanup");
        let _transition = self.transition.lock().await;
        self.stop_proxy().await;
        tracing::info!("cleanup complete");
    }
}

// ---------------------------------------------------------------------------
// Manual control (used by the D-Bus interface / GUI)
// ---------------------------------------------------------------------------

impl DaemonService {
    /// Manually start the proxy for `uuid`, or for the active Wi-Fi when
    /// `uuid` is `None`.
    pub async fn manual_start(&self, uuid: Option<String>) -> anyhow::Result<()> {
        let (active, iface) = self
            .snapshot
            .read()
            .await
            .active_wifi
            .as_ref()
            .map(|w| (w.uuid.clone(), w.interface.clone()))
            .ok_or_else(|| anyhow::anyhow!("no active Wi-Fi connection"))?;
        let uuid = match uuid {
            Some(u) if !u.is_empty() => u,
            _ => active.clone(),
        };
        // Routing state for a network we are not on would be wrong and unsafe.
        if uuid != active {
            anyhow::bail!("connection {uuid} is not the active Wi-Fi connection ({active})");
        }

        let _transition = self.transition.lock().await;
        self.state.lock().await.user_stopped = None;
        let started = self.start_proxy(&uuid, &iface).await;
        if started.is_ok() {
            self.state.lock().await.manual = true;
        }

        let snapshot = {
            let inner = self.state.lock().await;
            let snap = self.snapshot.read().await;
            DaemonSnapshot {
                wifi_enabled: snap.wifi_enabled,
                active_wifi: snap.active_wifi.clone(),
                matched_profile: snap.matched_profile.clone(),
                proxy_state: inner.proxy_state,
                proxy_active: inner.proxy_active,
                last_error: inner.last_error.clone(),
            }
        };
        self.publish(snapshot).await;
        started?;
        // `start_proxy` records a failed health check without erroring; tell
        // the caller instead of reporting success for a broken proxy.
        let inner = self.state.lock().await;
        if inner.proxy_state == ProxyState::Failed {
            anyhow::bail!(
                "{}",
                inner
                    .last_error
                    .as_deref()
                    .unwrap_or("proxy failed health check")
            );
        }
        Ok(())
    }

    /// Manually stop the proxy.
    pub async fn manual_stop(&self) -> anyhow::Result<()> {
        let _transition = self.transition.lock().await;
        let stopped = self.state.lock().await.active_uuid.clone();
        self.stop_proxy().await;
        // Remember the stop so auto-connect does not undo it on the next tick.
        self.state.lock().await.user_stopped = match stopped {
            Some(uuid) => Some(uuid),
            None => self
                .snapshot
                .read()
                .await
                .active_wifi
                .as_ref()
                .map(|w| w.uuid.clone()),
        };
        let mut snap = self.snapshot.write().await;
        snap.proxy_active = false;
        snap.proxy_state = ProxyState::Disconnected;
        snap.last_error = None;
        Ok(())
    }

    /// Run the proxy probe suite against the currently matched profile.
    pub async fn manual_test(&self) -> anyhow::Result<ProxyTestResult> {
        let profile = self
            .snapshot
            .read()
            .await
            .matched_profile
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no proxy profile is currently matched"))?;

        let iface = self
            .snapshot
            .read()
            .await
            .active_wifi
            .as_ref()
            .map(|w| w.interface.clone())
            .ok_or_else(|| anyhow::anyhow!("no active Wi-Fi connection"))?;
        let route = RouteContext::resolve(&profile, &iface)?;
        // The probe blocks (sockets, up to seconds) and talks to tasks on this
        // runtime, so it must not run on an async worker.
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || engine.test(&profile, &route)).await?
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::should_auto_start;
    use proxywifi_core::models::{
        AuthMethod, DnsMode, IpVersionConfig, KillSwitchConfig, LocalNetMode, ProxyConfig,
        ProxyProfile, ProxyType, UdpMode,
    };

    pub(crate) fn profile(enabled: bool, auto_connect: bool) -> ProxyProfile {
        ProxyProfile {
            connection_uuid: "uuid-under-test".to_string(),
            label: None,
            enabled,
            proxy: ProxyConfig {
                proxy_type: ProxyType::Socks5,
                host: "127.0.0.1".to_string(),
                port: 1080,
                authentication: AuthMethod::None,
                secret_id: None,
            },
            dns: DnsMode::Proxied,
            routing: IpVersionConfig::default(),
            udp: UdpMode::default(),
            local_network: LocalNetMode::default(),
            kill_switch: KillSwitchConfig::default(),
            auto_connect,
        }
    }

    #[test]
    fn no_matched_profile_means_no_auto_start() {
        assert!(!should_auto_start(None));
    }

    #[test]
    fn enabled_profile_without_auto_connect_stays_idle() {
        // Regression: the poll loop used to treat a merely-enabled profile as
        // permission to reroute traffic, contradicting the CLI's promise that
        // such a profile "will only be used when started manually".
        assert!(!should_auto_start(Some(&profile(true, false))));
    }

    #[test]
    fn auto_connect_requires_an_enabled_profile() {
        assert!(!should_auto_start(Some(&profile(false, true))));
    }

    #[test]
    fn enabled_and_auto_connecting_profile_starts() {
        assert!(should_auto_start(Some(&profile(true, true))));
    }
}
