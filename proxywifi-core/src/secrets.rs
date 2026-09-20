//! Secret Service / keyring integration.
//!
//! Proxy passwords are NEVER stored in `profiles.json`. Instead each
//! profile stores an opaque `secret_id`; the daemon queries the Secret
//! Service at proxy-start time to obtain the credentials.
//!
//! The privileged daemon runs as root and cannot reach a user's session
//! keyring, so [`FileSecrets`] keeps credentials in a root-owned `0600`
//! file next to the daemon's profile store. [`NoOpSecrets`] remains for
//! tests and keyring-less setups.

use crate::error::Result;

/// A secret value returned from the keyring.
#[derive(Debug, Clone)]
pub struct SecretValue {
    pub username: Option<String>,
    pub password: String,
}

/// Errors from the Secret Service.
#[derive(Debug, thiserror::Error)]
pub enum SecretServiceError {
    #[error("secret service unavailable: {0}")]
    Unavailable(String),

    #[error("secret not found for id: {0}")]
    NotFound(String),

    #[error("secret service error: {0}")]
    Other(String),
}

/// Operations that a Secret Service backend must support.
pub trait SecretServiceOps: Send + Sync {
    /// Look up a secret by the opaque `secret_id` stored in a profile.
    fn get_secret(&self, secret_id: &str) -> Result<SecretValue>;

    /// Store a new secret and return its `secret_id`.
    fn store_secret(
        &self,
        label: &str,
        username: Option<String>,
        password: String,
    ) -> Result<String>;

    /// Delete a secret by id.
    fn delete_secret(&self, secret_id: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Stub implementation: compiles everywhere, no-op at runtime.
// ---------------------------------------------------------------------------

/// A no-op secret backend useful for testing and for systems without
/// a running keyring. In production the daemon would swap this for a
/// real `SecretService` backed by the freedesktop Secret Service D-Bus API.
pub struct NoOpSecrets;

impl SecretServiceOps for NoOpSecrets {
    fn get_secret(&self, _secret_id: &str) -> Result<SecretValue> {
        Err(crate::error::Error::Secrets(
            SecretServiceError::Unavailable("no keyring backend configured (NoOpSecrets)".into()),
        ))
    }

    fn store_secret(
        &self,
        _label: &str,
        _username: Option<String>,
        _password: String,
    ) -> Result<String> {
        Err(crate::error::Error::Secrets(
            SecretServiceError::Unavailable("no keyring backend configured (NoOpSecrets)".into()),
        ))
    }

    fn delete_secret(&self, _secret_id: &str) -> Result<()> {
        Err(crate::error::Error::Secrets(
            SecretServiceError::Unavailable("no keyring backend configured (NoOpSecrets)".into()),
        ))
    }
}

// ---------------------------------------------------------------------------
// File-backed implementation
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredSecret {
    username: Option<String>,
    password: String,
}

/// Secrets in a single owner-only JSON file (`secret_id -> credentials`).
pub struct FileSecrets {
    path: std::path::PathBuf,
    // ponytail: whole file rewritten on each change; fine for a handful of proxies.
    entries: std::sync::Mutex<std::collections::HashMap<String, StoredSecret>>,
}

impl FileSecrets {
    /// Open the store at `path`; a missing file is an empty store.
    pub fn load_or_create(path: std::path::PathBuf) -> Result<Self> {
        // A pre-existing file may have been created with a loose mode.
        {
            use std::os::unix::fs::PermissionsExt;
            if path.exists() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| SecretServiceError::Other(format!("{}: {e}", path.display())))?;
            }
        }
        let entries = match std::fs::read_to_string(&path) {
            Ok(data) if !data.trim().is_empty() => serde_json::from_str(&data)
                .map_err(|e| SecretServiceError::Other(format!("{}: {e}", path.display())))?,
            Ok(_) => Default::default(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Default::default(),
            Err(e) => {
                return Err(SecretServiceError::Other(format!("{}: {e}", path.display())).into())
            }
        };
        Ok(Self {
            path,
            entries: std::sync::Mutex::new(entries),
        })
    }

    fn entries(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, StoredSecret>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, entries: &std::collections::HashMap<String, StoredSecret>) -> Result<()> {
        let io = |e: std::io::Error| SecretServiceError::Other(e.to_string());
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(format!(".tmp.{}", std::process::id()));
        let tmp = std::path::PathBuf::from(tmp);
        let data = serde_json::to_vec_pretty(entries)?;
        crate::profiles::write_private(&tmp, &data, 0o600).map_err(io)?;
        std::fs::rename(&tmp, &self.path).map_err(io)?;
        Ok(())
    }

    /// 128 random bits from the kernel, hex-encoded.
    fn new_id() -> Result<String> {
        use std::io::Read as _;
        let mut buf = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .map_err(|e| SecretServiceError::Other(format!("no randomness: {e}")))?;
        Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
    }
}

impl SecretServiceOps for FileSecrets {
    fn get_secret(&self, secret_id: &str) -> Result<SecretValue> {
        self.entries()
            .get(secret_id)
            .map(|s| SecretValue {
                username: s.username.clone(),
                password: s.password.clone(),
            })
            .ok_or_else(|| SecretServiceError::NotFound(secret_id.to_string()).into())
    }

    fn store_secret(
        &self,
        _label: &str,
        username: Option<String>,
        password: String,
    ) -> Result<String> {
        let id = Self::new_id()?;
        let mut entries = self.entries();
        entries.insert(id.clone(), StoredSecret { username, password });
        if let Err(e) = self.save(&entries) {
            entries.remove(&id);
            return Err(e);
        }
        Ok(id)
    }

    fn delete_secret(&self, secret_id: &str) -> Result<()> {
        let mut entries = self.entries();
        if entries.remove(secret_id).is_some() {
            self.save(&entries)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_secrets_round_trip_and_persist_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("pw-secrets-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let store = FileSecrets::load_or_create(path.clone()).unwrap();
        let id = store
            .store_secret("l", Some("u".into()), "p".into())
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let reopened = FileSecrets::load_or_create(path.clone()).unwrap();
        let v = reopened.get_secret(&id).unwrap();
        assert_eq!(
            (v.username.as_deref(), v.password.as_str()),
            (Some("u"), "p")
        );

        reopened.delete_secret(&id).unwrap();
        assert!(reopened.get_secret(&id).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn loading_tightens_a_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("pw-secrets-loose-{}.json", std::process::id()));
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        FileSecrets::load_or_create(path.clone()).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_file(&path);
    }
}
