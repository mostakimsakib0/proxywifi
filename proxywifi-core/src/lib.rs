//! ProxyWiFi — core library.
//!
//! Shared types, proxy profile model, configuration, secrets interface,
//! and NetworkManager D-Bus integration used by both the CLI and the daemon.

pub mod config;
pub mod error;
pub mod models;
pub mod networkmanager;
pub mod profiles;
pub mod secrets;

pub use config::ConfigPaths;
pub use error::{Error, Result};
pub use models::*;
pub use networkmanager::{NmClient, NmError};
pub use profiles::{ProfileStore, ProfileStoreError};
pub use secrets::{SecretServiceError, SecretServiceOps, SecretValue};
