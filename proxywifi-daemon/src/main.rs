//! ProxyWiFi daemon --- systemd service entrypoint.
//!
//! Responsibilities:
//!   - initialise logging (journal by default, rotating file optionally)
//!   - connect to NetworkManager on the system D-Bus
//!   - load the on-disk profile store
//!   - export `org.proxywifi.Daemon` for the GUI / CLI
//!   - run the polling + state-machine loop until SIGTERM/SIGINT

use proxywifi_core::config::ConfigPaths;
use proxywifi_core::networkmanager::NmClient;
use proxywifi_core::profiles::ProfileStore;
use proxywifi_core::secrets::FileSecrets;
use proxywifi_daemon::dataplane::{NftFirewall, TunEngine};
use proxywifi_daemon::dbus_server::DaemonDbusServer;
use proxywifi_daemon::service::{
    DaemonService, FirewallOps, NoOpFirewall, NoOpProxyEngine, ProxyEngine,
};
use std::sync::Arc;

/// How often the daemon re-reads NetworkManager state.
const POLL_INTERVAL_SECS: u64 = 5;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging()?;

    tracing::info!(
        "ProxyWiFi daemon starting (version {})",
        env!("CARGO_PKG_VERSION")
    );

    // --- Configuration paths -------------------------------------------
    let paths = ConfigPaths::from_env()?;
    paths.ensure_dirs()?;
    tracing::debug!("config dir: {:?}", paths.config_dir);

    // --- NetworkManager -------------------------------------------------
    let nm = match NmClient::new().await {
        Ok(nm) => Arc::new(nm),
        Err(e) => {
            anyhow::bail!("NetworkManager is required but not reachable on the system bus: {e}");
        }
    };
    tracing::info!("connected to NetworkManager");

    // --- Profile store ---------------------------------------------------
    let profile_store = ProfileStore::load_or_create(paths.profiles_path.clone())?;
    tracing::info!(
        "loaded {} proxy profile(s) from {:?}",
        profile_store.len(),
        paths.profiles_path
    );

    // --- Data plane + firewall ------------------------------------------
    let secrets = Arc::new(FileSecrets::load_or_create(paths.secrets_path.clone())?);
    let (engine, firewall): (Arc<dyn ProxyEngine>, Arc<dyn FirewallOps>) = match (
        find_in_path("nft"),
        find_in_path("ip"),
        find_in_path("tun2socks"),
    ) {
        (Some(nft), Some(ip), Some(tun2socks)) => {
            let firewall = NftFirewall::new(nft);
            // A previous run may have died with its table installed.
            if let Err(e) = firewall.remove() {
                tracing::warn!("could not clear stale firewall state: {e}");
            }
            let engine = TunEngine::new(tun2socks, ip, paths.run_dir.clone(), secrets.clone());
            // Likewise stale routing rules/tunnel from a previous run.
            let _ = engine.stop();
            (Arc::new(engine), Arc::new(firewall))
        }
        // Refuse to run as if protection existed: with stubs nothing is
        // proxied and the kill switch does nothing.
        _ if std::env::var_os("PROXYWIFI_ALLOW_PROTOTYPE").is_none() => anyhow::bail!(
            "nft, ip and tun2socks must all be installed; \
                 set PROXYWIFI_ALLOW_PROTOTYPE=1 to run the observe-only prototype"
        ),
        _ => {
            tracing::warn!("PROTOTYPE: no traffic is proxied and the kill switch is inert");
            (Arc::new(NoOpProxyEngine), Arc::new(NoOpFirewall))
        }
    };

    // --- Service ---------------------------------------------------------
    let service = Arc::new(
        DaemonService::new(nm, profile_store, engine, firewall, POLL_INTERVAL_SECS)
            .with_secrets(secrets),
    );

    // --- D-Bus -----------------------------------------------------------
    // Not fatal: a developer machine without a system bus can still run the
    // daemon to exercise the routing logic (see docs/DEVELOPING.md).
    let _dbus_conn = match DaemonDbusServer::export(service.clone()).await {
        Ok(conn) => {
            tracing::info!(
                "D-Bus server running at {}",
                proxywifi_daemon::dbus_server::DAEMON_OBJECT_PATH
            );
            Some(conn)
        }
        Err(e) => {
            tracing::warn!("D-Bus interface unavailable: {e}");
            None
        }
    };

    // --- Run until shutdown ---------------------------------------------
    service.run().await
}

/// First executable called `name` on `PATH`.
fn find_in_path(name: &str) -> Option<String> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

/// Configure `tracing`.
///
/// Default is stderr, which systemd captures into the journal. Set
/// `PROXYWIFI_LOG_DESTINATION=file` to get daily rotating files under the
/// runtime directory instead.
fn init_logging() -> anyhow::Result<()> {
    let destination =
        std::env::var("PROXYWIFI_LOG_DESTINATION").unwrap_or_else(|_| "journal".to_string());

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if destination == "file" {
        let paths = ConfigPaths::from_env()?;
        let log_dir = paths.run_dir.join("logs");
        std::fs::create_dir_all(&log_dir)?;

        let appender = tracing_appender::rolling::daily(&log_dir, "proxywifi.log");
        let (writer, guard) = tracing_appender::non_blocking(appender);
        // The worker thread must outlive `main`, so the guard is leaked.
        std::mem::forget(guard);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .with_target(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    }

    Ok(())
}
