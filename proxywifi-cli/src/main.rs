//! ProxyWiFi CLI
//!
//! Phase 1 deliverable: display Wi-Fi state and manage the proxy profiles
//! stored in `$XDG_CONFIG_HOME/proxywifi/profiles.json`.
//!
//! ```text
//! proxywifi status                     show current Wi-Fi and proxy state
//! proxywifi profiles list              list saved proxy profiles
//! proxywifi profiles add <UUID> ...    create or update a profile
//! proxywifi profiles remove <UUID>     remove a profile
//! proxywifi profiles enable <UUID>     enable a profile
//! proxywifi profiles disable <UUID>    disable a profile
//! proxywifi profiles assign <C> <P>    copy profile <P> onto connection <C>
//! ```
//!
//! The CLI talks directly to NetworkManager over D-Bus to read Wi-Fi state,
//! and edits the profile store directly. It never starts or stops the proxy
//! --- transparent routing is the daemon's job, and the daemon applies the
//! matching profile automatically when a known Wi-Fi connects.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL, Table};
use proxywifi_core::models::{
    AuthMethod, DnsMode, IpVersionConfig, KillSwitchConfig, LocalNetMode, ProxyConfig,
    ProxyProfile, ProxyType, UdpMode,
};
use proxywifi_core::networkmanager::NmClient;
use proxywifi_core::profiles::ProfileStore;
use proxywifi_core::ConfigPaths;

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "proxywifi",
    version,
    about = "Per-Wi-Fi transparent SOCKS5 proxy for Linux",
    after_help = "\
Examples:
  proxywifi status
  proxywifi connect \"My Hotspot\" --password-stdin
  proxywifi profiles list
  proxywifi profiles add 8f3c-uuid --host 10.0.0.1 --port 1080 --type socks5 --auto-connect
  proxywifi profiles enable 8f3c-uuid
  proxywifi profiles assign <connection-uuid> <profile-uuid>"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current Wi-Fi and proxy state.
    Status,

    /// Manage proxy profiles.
    #[command(subcommand)]
    Profiles(ProfileCommands),

    /// Connect to a Wi-Fi network (saved, open, or WPA-PSK).
    Connect {
        /// Network name.
        ssid: String,

        /// Read the WPA-PSK passphrase from the first line of stdin
        /// (keeps it out of argv and shell history).
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// List saved proxy profiles.
    List,

    /// Add or update a proxy profile for a NetworkManager connection UUID.
    Add {
        /// NetworkManager connection UUID (see `proxywifi status` or nmcli).
        uuid: String,

        /// Upstream proxy host.
        #[arg(short = 'H', long)]
        host: String,

        /// Upstream proxy port.
        #[arg(short, long)]
        port: u16,

        /// Proxy type: socks5 (default) or http (CONNECT; use with --udp block).
        #[arg(short = 't', long = "type", default_value = "socks5")]
        proxy_type: String,

        /// Human-readable label for this profile.
        #[arg(short, long)]
        label: Option<String>,

        /// Create the profile in a disabled state.
        #[arg(long)]
        disable: bool,

        /// Activate the proxy automatically when this Wi-Fi connects.
        #[arg(long)]
        auto_connect: bool,

        /// Resolve DNS through the proxy (default). Pass to resolve directly.
        #[arg(long)]
        direct_dns: bool,

        /// Do not install the kill switch.
        #[arg(long)]
        no_kill_switch: bool,

        /// UDP handling: proxy (needs a SOCKS5 UDP relay), block, or direct.
        #[arg(long, default_value = "proxy")]
        udp: String,

        /// Local networks: direct (default), proxy, or block.
        #[arg(long, default_value = "direct")]
        local_network: String,

        /// Route IPv6 through the proxy too (default: IPv6 is blocked while proxying).
        #[arg(long)]
        ipv6: bool,

        /// Upstream proxy username (stored in the keyring, not in the profile).
        #[arg(short, long)]
        username: Option<String>,

        /// Upstream proxy password (stored in the keyring, not in the profile).
        #[arg(short = 'P', long)]
        password: Option<String>,
    },

    /// Remove a proxy profile by connection UUID.
    Remove {
        /// NetworkManager connection UUID.
        uuid: String,
    },

    /// Enable a proxy profile.
    Enable {
        /// NetworkManager connection UUID.
        uuid: String,
    },

    /// Disable a proxy profile.
    Disable {
        /// NetworkManager connection UUID.
        uuid: String,
    },

    /// Copy an existing profile onto another Wi-Fi connection.
    Assign {
        /// Target NetworkManager connection UUID.
        connection_uuid: String,

        /// Source profile UUID to copy from.
        profile_uuid: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let paths = ConfigPaths::from_env()?;
    paths.ensure_dirs()?;

    match cli.cmd {
        Commands::Status => cmd_status(&paths).await,
        Commands::Profiles(cmd) => cmd_profiles(&paths, cmd).await,
        Commands::Connect {
            ssid,
            password_stdin,
        } => {
            let password = if password_stdin {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                Some(line.trim_end_matches(['\r', '\n']).to_string())
            } else {
                None
            };
            proxywifi_core::networkmanager::NmClient::new()
                .await?
                .connect_wifi(&ssid, password.as_deref())
                .await?;
            println!("Connecting to {ssid}...");
            Ok(())
        }
    }
}

/// Build a table pre-configured with the ProxyWiFi look.
///
/// comfy-table 7 dropped the old `TableStyle` enum in favour of string
/// presets applied with `load_preset`.
fn new_table(header: Vec<&str>) -> Table {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(header);
    table
}

// ---------------------------------------------------------------------------
// `proxywifi status`
// ---------------------------------------------------------------------------

/// Connect to the running daemon, if there is one.
///
/// The daemon owns the profile store (it runs as root with its own config
/// dir), so when it is reachable the CLI edits *its* profiles over D-Bus.
/// `PROXYWIFI_BUS=session` selects the session bus for development.
async fn connect_daemon() -> Option<zbus::Proxy<'static>> {
    let conn = if std::env::var("PROXYWIFI_BUS").as_deref() == Ok("session") {
        zbus::Connection::session().await
    } else {
        zbus::Connection::system().await
    }
    .ok()?;
    let proxy = zbus::Proxy::new(
        &conn,
        "org.proxywifi.Daemon",
        "/org/proxywifi/Daemon",
        "org.proxywifi.Daemon",
    )
    .await
    .ok()?;
    // Probe: fails when nothing owns the name.
    proxy
        .call::<_, _, String>("GetProxyProfiles", &())
        .await
        .ok()?;
    Some(proxy)
}

/// Profiles from the daemon when it is up, otherwise the local file.
async fn load_store(paths: &ConfigPaths) -> Result<(ProfileStore, Option<zbus::Proxy<'static>>)> {
    if let Some(daemon) = connect_daemon().await {
        let json: String = daemon.call("GetProxyProfiles", &()).await?;
        let profiles = serde_json::from_str(&json).context("daemon returned invalid profiles")?;
        return Ok((ProfileStore::in_memory(profiles), Some(daemon)));
    }
    Ok((
        ProfileStore::load_or_create(paths.profiles_path.clone())?,
        None,
    ))
}

async fn cmd_status(paths: &ConfigPaths) -> Result<()> {
    let (store, _daemon) = load_store(paths).await?;

    let nm = match NmClient::try_new().await {
        Some(nm) => nm,
        None => {
            println!("NetworkManager: NOT REACHABLE (system D-Bus)");
            println!(
                "Stored proxy profiles: {} ({} profile file)",
                store.len(),
                paths.profiles_path.display()
            );
            anyhow::bail!("cannot read Wi-Fi state without NetworkManager");
        }
    };

    let wifi_enabled = nm.wifi_enabled().await.unwrap_or(false);
    let active = nm.active_wifi().await?;

    let mut table = new_table(vec!["Property", "Value"]);
    table.add_row(vec!["Wi-Fi enabled".to_string(), wifi_enabled.to_string()]);

    match &active {
        Some(wifi) => {
            table.add_row(vec!["Connected SSID".to_string(), wifi.ssid.clone()]);
            table.add_row(vec!["Connection UUID".to_string(), wifi.uuid.clone()]);
            table.add_row(vec!["Interface".to_string(), wifi.interface.clone()]);
            table.add_row(vec![
                "IPv4".to_string(),
                wifi.ipv4.clone().unwrap_or_else(|| "-".to_string()),
            ]);
            table.add_row(vec![
                "IPv6".to_string(),
                wifi.ipv6.clone().unwrap_or_else(|| "-".to_string()),
            ]);
            table.add_row(vec![
                "Default route".to_string(),
                wifi.has_default_route.to_string(),
            ]);

            match store.get(&wifi.uuid) {
                Some(profile) => {
                    table.add_row(vec![
                        "Matched profile".to_string(),
                        profile
                            .label
                            .clone()
                            .unwrap_or_else(|| "<no label>".to_string()),
                    ]);
                    table.add_row(vec![
                        "Profile enabled".to_string(),
                        profile.enabled.to_string(),
                    ]);
                    table.add_row(vec![
                        "Auto-activate".to_string(),
                        profile.should_auto_activate().to_string(),
                    ]);
                    table.add_row(vec![
                        "Proxy".to_string(),
                        format!(
                            "{}://{}:{}",
                            profile.proxy.proxy_type, profile.proxy.host, profile.proxy.port
                        ),
                    ]);
                    table.add_row(vec!["DNS mode".to_string(), profile.dns.to_string()]);
                    table.add_row(vec![
                        "Kill switch".to_string(),
                        profile.kill_switch.enabled.to_string(),
                    ]);
                }
                None => {
                    table.add_row(vec![
                        "Matched profile".to_string(),
                        "none assigned to this connection".to_string(),
                    ]);
                }
            }
        }
        None => {
            table.add_row(vec![
                "Connected SSID".to_string(),
                "(not connected)".to_string(),
            ]);
            table.add_row(vec!["Matched profile".to_string(), "n/a".to_string()]);
        }
    }

    println!("{table}");

    if active.is_none() {
        // Helpful for picking a UUID to assign a profile to.
        match nm.saved_wifi_connections().await {
            Ok(saved) if !saved.is_empty() => {
                println!("\nSaved Wi-Fi connections:");
                let mut saved_table = new_table(vec!["UUID", "Name", "SSID", "State"]);
                for c in saved {
                    saved_table.add_row(vec![
                        c.uuid,
                        c.name,
                        c.ssid.unwrap_or_else(|| "-".to_string()),
                        c.state,
                    ]);
                }
                println!("{saved_table}");
            }
            Ok(_) => {}
            // Do not fail the whole status command, but never hide a failed
            // query either: an empty list and an error look identical.
            Err(e) => eprintln!("warning: could not list saved Wi-Fi connections: {e}"),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `proxywifi profiles ...`
// ---------------------------------------------------------------------------

/// Arguments collected from `profiles add`.
struct AddArgs {
    uuid: String,
    host: String,
    port: u16,
    proxy_type: ProxyType,
    label: Option<String>,
    enabled: bool,
    auto_connect: bool,
    dns: DnsMode,
    kill_switch: bool,
    udp: UdpMode,
    local_network: LocalNetMode,
    ipv6: bool,
    /// Id of credentials already stored in the daemon, if any.
    secret_id: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn cmd_profiles(paths: &ConfigPaths, cmd: ProfileCommands) -> Result<()> {
    let (mut store, daemon) = load_store(paths).await?;
    let is_write = !matches!(cmd, ProfileCommands::List);
    let secret_ids = |s: &ProfileStore| -> std::collections::HashSet<String> {
        s.all()
            .into_iter()
            .filter_map(|p| p.proxy.secret_id)
            .collect()
    };
    let secrets_before = secret_ids(&store);

    let result = match cmd {
        ProfileCommands::List => list_profiles(&store),
        ProfileCommands::Add {
            uuid,
            host,
            port,
            proxy_type,
            label,
            disable,
            auto_connect,
            direct_dns,
            no_kill_switch,
            udp,
            local_network,
            ipv6,
            username,
            password,
        } => {
            // Credentials live in the daemon's root-only secret store, never
            // in profiles.json.
            let secret_id = match (&username, &password) {
                (None, None) => None,
                (u, p) => {
                    let daemon = daemon.as_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "storing proxy credentials needs the daemon (it owns the secret store)"
                        )
                    })?;
                    let label = format!("ProxyWiFi proxy credentials for {uuid}");
                    let id: String = daemon
                        .call(
                            "StoreSecret",
                            &(
                                label,
                                u.clone().unwrap_or_default(),
                                p.clone().unwrap_or_default(),
                            ),
                        )
                        .await
                        .context("daemon could not store the credentials")?;
                    Some(id)
                }
            };
            add_profile(
                &mut store,
                AddArgs {
                    uuid,
                    host,
                    port,
                    proxy_type: parse_proxy_type(&proxy_type)?,
                    label,
                    enabled: !disable,
                    // Auto-activation is opt-in: a fresh profile is stored but
                    // never silently reroutes traffic on its own.
                    auto_connect,
                    dns: if direct_dns {
                        DnsMode::Direct
                    } else {
                        DnsMode::Proxied
                    },
                    kill_switch: !no_kill_switch,
                    udp: parse_udp(&udp)?,
                    local_network: parse_local_network(&local_network)?,
                    ipv6,
                    secret_id,
                },
            )
        }
        ProfileCommands::Remove { uuid } => remove_profile(&mut store, &uuid),
        ProfileCommands::Enable { uuid } => set_profile_enabled(&mut store, &uuid, true),
        ProfileCommands::Disable { uuid } => set_profile_enabled(&mut store, &uuid, false),
        ProfileCommands::Assign {
            connection_uuid,
            profile_uuid,
        } => assign_profile(&mut store, &connection_uuid, &profile_uuid),
    };

    // Edits were made on a copy: push it back so the daemon persists it.
    // ponytail: last writer wins if two clients edit at once.
    if let (true, Some(daemon), Ok(())) = (is_write, daemon.as_ref(), &result) {
        let json = serde_json::to_string(&store.all())?;
        daemon
            .call::<_, _, bool>("SetProxyProfiles", &(json,))
            .await
            .context("daemon rejected the profile update")?;
    }
    // Drop credentials no profile references any more (removed, replaced, or
    // overwritten by `assign`); `assign` shares ids, so check what remains.
    if let (true, Some(daemon)) = (result.is_ok(), daemon.as_ref()) {
        let still_used = secret_ids(&store);
        for id in secrets_before.difference(&still_used) {
            let _ = daemon.call::<_, _, bool>("DeleteSecret", &(id,)).await;
        }
    }
    result
}

fn parse_udp(raw: &str) -> Result<UdpMode> {
    match raw.to_ascii_lowercase().as_str() {
        "proxy" => Ok(UdpMode::Proxy),
        "block" => Ok(UdpMode::Block),
        "direct" => Ok(UdpMode::Direct),
        other => anyhow::bail!("unknown UDP mode '{other}' (proxy, block, direct)"),
    }
}

fn parse_local_network(raw: &str) -> Result<LocalNetMode> {
    match raw.to_ascii_lowercase().as_str() {
        "proxy" => Ok(LocalNetMode::Proxy),
        "direct" => Ok(LocalNetMode::Direct),
        "block" => Ok(LocalNetMode::Block),
        other => anyhow::bail!("unknown local-network mode '{other}' (proxy, direct, block)"),
    }
}

fn parse_proxy_type(raw: &str) -> Result<ProxyType> {
    match raw.to_ascii_lowercase().as_str() {
        "socks5" | "socks" => Ok(ProxyType::Socks5),
        "http" => Ok(ProxyType::Http),
        other => anyhow::bail!("unsupported proxy type '{other}' (supported: socks5, http)"),
    }
}

fn list_profiles(store: &ProfileStore) -> Result<()> {
    let mut profiles = store.all();

    if profiles.is_empty() {
        println!("No proxy profiles configured.");
        println!(
            "Add one with: proxywifi profiles add <connection-uuid> \
             --host <host> --port <port>"
        );
        return Ok(());
    }

    profiles.sort_by(|a, b| a.connection_uuid.cmp(&b.connection_uuid));

    let mut table = new_table(vec![
        "Connection UUID",
        "Label",
        "Status",
        "Auto",
        "Proxy",
        "DNS",
        "Kill switch",
        "Auth",
    ]);

    for p in &profiles {
        table.add_row(vec![
            p.connection_uuid.clone(),
            p.label.clone().unwrap_or_else(|| "-".to_string()),
            if p.enabled { "enabled" } else { "disabled" }.to_string(),
            if p.auto_connect { "yes" } else { "no" }.to_string(),
            format!("{}://{}:{}", p.proxy.proxy_type, p.proxy.host, p.proxy.port),
            p.dns.to_string(),
            if p.kill_switch.enabled { "on" } else { "off" }.to_string(),
            p.proxy.authentication.to_string(),
        ]);
    }

    println!("{table}");
    println!("{} profile(s).", profiles.len());
    Ok(())
}

fn add_profile(store: &mut ProfileStore, args: AddArgs) -> Result<()> {
    let host = args.host.trim().to_string();
    if host.is_empty() {
        anyhow::bail!("proxy host must not be empty");
    }
    if args.port == 0 {
        anyhow::bail!("proxy port must be between 1 and 65535");
    }

    let secret_id = args.secret_id;
    let authentication = if secret_id.is_some() {
        AuthMethod::Keyring
    } else {
        AuthMethod::None
    };

    let profile = ProxyProfile {
        connection_uuid: args.uuid.clone(),
        label: args.label,
        enabled: args.enabled,
        proxy: ProxyConfig {
            proxy_type: args.proxy_type,
            host,
            port: args.port,
            authentication,
            secret_id,
        },
        dns: args.dns,
        routing: IpVersionConfig {
            ipv4: true,
            ipv6: args.ipv6,
        },
        udp: args.udp,
        local_network: args.local_network,
        kill_switch: KillSwitchConfig {
            enabled: args.kill_switch,
        },
        auto_connect: args.auto_connect,
    };

    let auto = profile.should_auto_activate();
    store.upsert(profile).context("could not save profile")?;

    println!("Profile saved for connection {}.", args.uuid);
    if auto {
        println!("The daemon will activate this proxy whenever that Wi-Fi connects.");
    } else if args.enabled {
        println!(
            "Profile is enabled but auto-connect is off; it will only be used \
             when started manually."
        );
    } else {
        println!("Profile is disabled; enable it with `proxywifi profiles enable <uuid>`.");
    }
    Ok(())
}

fn remove_profile(store: &mut ProfileStore, uuid: &str) -> Result<()> {
    if store.get(uuid).is_none() {
        anyhow::bail!("no profile for connection {uuid}");
    }
    store.remove(uuid).context("could not save profile store")?;
    println!("Removed profile for connection {uuid}.");
    Ok(())
}

fn set_profile_enabled(store: &mut ProfileStore, uuid: &str, enabled: bool) -> Result<()> {
    store
        .set_enabled(uuid, enabled)
        .context("could not save profile store")?;
    println!(
        "Profile {uuid} {}.",
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

fn assign_profile(
    store: &mut ProfileStore,
    connection_uuid: &str,
    profile_uuid: &str,
) -> Result<()> {
    let mut source = store
        .get(profile_uuid)
        .ok_or_else(|| anyhow::anyhow!("no profile with uuid {profile_uuid}"))?;

    if store.get(connection_uuid).is_some() {
        println!("warning: overwriting the existing profile for {connection_uuid}");
    }

    source.connection_uuid = connection_uuid.to_string();
    store
        .upsert(source)
        .context("could not save profile store")?;

    println!("Assigned profile to connection {connection_uuid}.");
    Ok(())
}
