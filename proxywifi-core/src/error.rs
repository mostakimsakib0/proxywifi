//! Error types for ProxyWiFi core operations.

use crate::networkmanager::NmError;
use crate::profiles::ProfileStoreError;
use crate::secrets::SecretServiceError;
use thiserror::Error;

/// Top-level error type shared by the CLI, the daemon, and any future GUI.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(#[from] anyhow::Error),

    #[error("profile store error: {0}")]
    Profiles(#[from] ProfileStoreError),

    #[error("secret service error: {0}")]
    Secrets(#[from] SecretServiceError),

    #[error("NetworkManager error: {0}")]
    NetworkManager(#[from] NmError),

    #[error("proxy engine error: {0}")]
    ProxyEngine(String),

    #[error("firewall / nftables error: {0}")]
    Firewall(String),

    #[error("TUN device error: {0}")]
    Tun(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("D-Bus error: {0}")]
    Dbus(#[from] zbus::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("state machine error: {0}")]
    StateMachine(String),

    #[error("not connected to a Wi-Fi network")]
    NotConnected,

    #[error("no proxy profile assigned to connection {uuid}")]
    NoProfileAssigned { uuid: String },

    #[error("profile for connection {uuid} is disabled")]
    ProfileDisabled { uuid: String },

    #[error("internal error: {0}")]
    Internal(String),
}

/// Convenience alias used throughout the core crate.
pub type Result<T> = std::result::Result<T, Error>;
