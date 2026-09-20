//! Configuration paths and defaults.
//!
//! Profiles are stored per-user under `XDG_CONFIG_HOME/proxywifi/`.
//! Secrets are *not* stored in the profile JSON; they live in the
//! desktop Secret Service / keyring and are referenced by an opaque
//! secret-id stored in the profile.

use std::path::PathBuf;

/// Well-known filesystem paths used by ProxyWiFi.
pub struct ConfigPaths {
    /// Base config directory: `$XDG_CONFIG_HOME/proxywifi` (or `~/.config/proxywifi`).
    pub config_dir: PathBuf,
    /// Per-user profile store (`profiles.json`).
    pub profiles_path: PathBuf,
    /// Credentials for authenticated proxies (`secrets.json`, owner-only).
    pub secrets_path: PathBuf,
    /// Daemon runtime state directory (`/run/proxywifi` when privileged,
    /// fallback to config dir for unprivileged operation).
    pub run_dir: PathBuf,
}

impl ConfigPaths {
    /// Build paths using the XDG base dir spec.
    pub fn from_env() -> anyhow::Result<Self> {
        let config_base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| dirs::config_dir().unwrap_or_else(|| PathBuf::from(".config")));
        let config_dir = config_base.join("proxywifi");

        // Prefer a privileged runtime directory; fall back to config dir.
        let run_dir = std::env::var_os("PROXYWIFI_RUN_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| config_dir.clone());

        let profiles_path = config_dir.join("profiles.json");
        let secrets_path = config_dir.join("secrets.json");

        Ok(Self {
            config_dir,
            profiles_path,
            secrets_path,
            run_dir,
        })
    }

    /// Ensure the on-disk directories exist.
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.config_dir)?;
        std::fs::create_dir_all(&self.run_dir)?;
        Ok(())
    }
}
