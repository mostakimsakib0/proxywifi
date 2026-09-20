//! Proxy profile storage.
//!
//! Profiles are persisted as a single JSON array in `profiles.json`.
//! This module does NOT touch the Secret Service; it only stores the
//! opaque `secret_id` that the secrets module resolves at runtime.

use crate::error::{Error, Result};
use crate::models::ProxyProfile;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Simple in-memory + on-disk profile store; callers needing sharing wrap it in a lock.
/// For the MVP a single-file JSON store is sufficient; the daemon
/// can later swap this for a more concurrent backend if needed.
#[derive(Debug)]
pub struct ProfileStore {
    profiles: HashMap<String, ProxyProfile>, // uuid -> profile
    /// `None` for an in-memory store (never touches disk).
    path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileStoreError {
    #[error("profile store I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("profile store JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The store on disk could not be parsed. Its bytes are moved aside to
    /// `backup` rather than discarded, so the user can still recover them
    /// by hand; the next load then starts from an empty store instead of
    /// failing forever.
    #[error(
        "profile store {} is not valid JSON; the original bytes were kept at {}: {source}",
        path.display(),
        backup.display()
    )]
    Corrupt {
        path: PathBuf,
        backup: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("profile store internal error: {0}")]
    Internal(String),
}

impl ProfileStore {
    /// Load or create the store at `path`.
    ///
    /// A missing file is not an error — it just means "no profiles
    /// configured yet". A file that exists but cannot be parsed is an
    /// error: see [`parse_profiles`].
    pub fn load_or_create(path: PathBuf) -> Result<Self> {
        let profiles = match std::fs::read_to_string(&path) {
            Ok(data) => parse_profiles(&path, &data)?,
            // A missing file just means "no profiles configured yet";
            // anything else is a real error worth surfacing.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(Error::Profiles(ProfileStoreError::Io(e))),
        };

        Ok(Self {
            profiles,
            path: Some(path),
        })
    }

    /// A store that lives only in memory: `save` is a no-op. Used by clients
    /// that edit a copy fetched from the daemon and push it back.
    pub fn in_memory(profiles: Vec<ProxyProfile>) -> Self {
        Self {
            profiles: Self::index(profiles),
            path: None,
        }
    }

    /// Replace every profile and persist.
    pub fn replace_all(&mut self, profiles: Vec<ProxyProfile>) -> Result<()> {
        self.profiles = Self::index(profiles);
        self.save()
    }

    fn index(profiles: Vec<ProxyProfile>) -> HashMap<String, ProxyProfile> {
        profiles
            .into_iter()
            .map(|p| (p.connection_uuid.clone(), p))
            .collect()
    }

    /// Persist the current profiles to disk atomically (write-to-temp,
    /// flush, then rename) to avoid corruption on crash.
    ///
    /// The temporary file is written with the store's own permissions (see
    /// [`store_mode`]) so that saving never widens what the user may have
    /// tightened, and is flushed before the rename publishes it.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let tmp = with_suffix(path, &format!(".tmp.{}", std::process::id()));
        let data = serde_json::to_string_pretty(&self.profiles.values().collect::<Vec<_>>())?;
        write_private(&tmp, data.as_bytes(), store_mode(path))?;
        std::fs::rename(&tmp, path)?;
        // Persist the rename itself.
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }

    /// Return an immutable view of all profiles.
    pub fn all(&self) -> Vec<ProxyProfile> {
        self.profiles.values().cloned().collect()
    }

    /// Return the profile for `uuid`, if any.
    pub fn get(&self, uuid: &str) -> Option<ProxyProfile> {
        self.profiles.get(uuid).cloned()
    }

    /// Return the profile assigned to the active connection UUID,
    /// considering only enabled profiles.
    pub fn find_enabled_for(&self, uuid: &str) -> Option<ProxyProfile> {
        self.profiles.get(uuid).filter(|p| p.enabled).cloned()
    }

    /// Add or replace a profile.
    pub fn upsert(&mut self, profile: ProxyProfile) -> Result<()> {
        self.profiles
            .insert(profile.connection_uuid.clone(), profile);
        self.save()?;
        Ok(())
    }

    /// Remove a profile by UUID.
    pub fn remove(&mut self, uuid: &str) -> Result<()> {
        if self.profiles.remove(uuid).is_none() {
            return Err(Error::Profiles(ProfileStoreError::Internal(format!(
                "no profile for uuid {uuid}"
            ))));
        }
        self.save()?;
        Ok(())
    }

    /// Enable or disable a profile by UUID.
    pub fn set_enabled(&mut self, uuid: &str, enabled: bool) -> Result<()> {
        if let Some(p) = self.profiles.get_mut(uuid) {
            p.enabled = enabled;
            self.save()?;
            Ok(())
        } else {
            Err(Error::Profiles(ProfileStoreError::Internal(format!(
                "no profile for uuid {}",
                uuid
            ))))
        }
    }

    /// Count of profiles currently stored.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

// ---------------------------------------------------------------------------
// On-disk helpers
// ---------------------------------------------------------------------------

/// Parse store contents, quarantining a corrupt file instead of silently
/// discarding whatever the user had configured.
///
/// An unparseable store is renamed to `profiles.json.corrupt` (the bytes are
/// kept verbatim) and the error is propagated, so the first load after
/// corruption fails loudly rather than reporting "no profiles configured"
/// and then letting the next save overwrite the evidence.
fn parse_profiles(path: &Path, data: &str) -> Result<HashMap<String, ProxyProfile>> {
    // A zero-length or whitespace-only file holds no data to lose, so it is
    // treated as an empty store rather than as corruption.
    if data.trim().is_empty() {
        return Ok(HashMap::new());
    }

    match serde_json::from_str::<Vec<ProxyProfile>>(data) {
        Ok(stored) => Ok(stored.into_iter().fold(HashMap::new(), |mut m, p| {
            m.insert(p.connection_uuid.clone(), p);
            m
        })),
        Err(source) => {
            let backup = quarantine(path)?;
            Err(Error::Profiles(ProfileStoreError::Corrupt {
                path: path.to_path_buf(),
                backup,
                source,
            }))
        }
    }
}

/// Move a store we cannot parse to the first free `<path>.corrupt[N]` name.
fn quarantine(path: &Path) -> Result<PathBuf> {
    let backup = next_backup_path(path);
    std::fs::rename(path, &backup)?;
    tracing::error!(
        "profile store {} could not be parsed; kept the original bytes at {}",
        path.display(),
        backup.display()
    );
    Ok(backup)
}

/// `<path>.corrupt`, then `<path>.corrupt.1`, `.corrupt.2`, ... so a newer
/// quarantine never overwrites an older one.
fn next_backup_path(path: &Path) -> PathBuf {
    let fallback = with_suffix(path, ".corrupt");
    if !fallback.exists() {
        return fallback;
    }

    // Bounded so a directory full of backups cannot spin this forever.
    for n in 1..=MAX_BACKUP_ATTEMPTS {
        let candidate = with_suffix(path, &format!(".corrupt.{n}"));
        if !candidate.exists() {
            return candidate;
        }
    }

    // Every candidate is taken: reuse the plain `.corrupt` name rather than
    // leaving the store unloadable.
    fallback
}

/// Append `suffix` to a path's file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Permission bits the store should carry, given what it has now.
///
/// A user who tightened the file (`0600`, `0400`, ...) keeps that mode.
/// Anything wider — including a store widened by an older version of this
/// code, which let the process umask decide — is brought back to owner-only,
/// because the store can hold proxy hosts, ports and secret ids.
fn store_mode(path: &Path) -> u32 {
    /// Owner may read and write; nobody else gets anything.
    const OWNER_ONLY: u32 = 0o600;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & !OWNER_ONLY == 0 {
                    mode
                } else {
                    OWNER_ONLY
                }
            }
            Err(_) => OWNER_ONLY,
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        OWNER_ONLY
    }
}

/// Write `contents` to `path` with `mode`, then flush it to disk.
///
/// Any existing file is removed first so `mode` always applies at creation, and
/// `sync_all` makes sure the bytes are durable before the caller renames the
/// file into place.
pub fn write_private(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    // `mode` only takes effect when the file is created, so a stale file left
    // behind by an earlier run is removed first rather than written loosely.
    let _ = std::fs::remove_file(path);
    let mut file = options.open(path)?;
    file.write_all(contents)?;

    file.sync_all()?;
    Ok(())
}

/// Upper bound on `.corrupt.N` suffixes tried before reusing `.corrupt`.
const MAX_BACKUP_ATTEMPTS: u32 = 100;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AuthMethod, DnsMode, IpVersionConfig, KillSwitchConfig, LocalNetMode, ProxyConfig,
        ProxyType, UdpMode,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique-per-test scratch directory, removed on drop.
    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new(name: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "proxywifi-profiles-{}-{name}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self { dir }
        }

        /// Path of the store file, which does not exist until the first save.
        fn store(&self) -> PathBuf {
            self.dir.join("profiles.json")
        }

        fn quarantine(&self) -> PathBuf {
            self.dir.join("profiles.json.corrupt")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn profile(uuid: &str, enabled: bool, auto_connect: bool) -> ProxyProfile {
        ProxyProfile {
            connection_uuid: uuid.to_string(),
            label: Some(format!("label for {uuid}")),
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
    fn missing_store_loads_empty_and_is_not_created() {
        let scratch = Scratch::new("missing");
        let store = ProfileStore::load_or_create(scratch.store()).expect("load");

        assert!(store.is_empty());
        assert!(
            !scratch.store().exists(),
            "loading must not create the store file"
        );
    }

    #[test]
    fn profiles_round_trip_through_disk() {
        let scratch = Scratch::new("roundtrip");
        {
            let mut store = ProfileStore::load_or_create(scratch.store()).expect("load");
            store
                .upsert(profile("uuid-a", true, true))
                .expect("upsert a");
            store
                .upsert(profile("uuid-b", false, false))
                .expect("upsert b");
        }

        let reloaded = ProfileStore::load_or_create(scratch.store()).expect("reload");
        assert_eq!(reloaded.len(), 2);

        let a = reloaded.get("uuid-a").expect("uuid-a present");
        assert!(a.enabled);
        assert!(a.auto_connect);
        assert_eq!(a.proxy.port, 1080);

        let b = reloaded.get("uuid-b").expect("uuid-b present");
        assert!(!b.enabled);
        assert!(!b.auto_connect);
    }

    #[test]
    fn enable_disable_and_remove_persist() {
        let scratch = Scratch::new("mutate");
        let mut store = ProfileStore::load_or_create(scratch.store()).expect("load");
        store.upsert(profile("uuid-a", true, true)).expect("upsert");

        store.set_enabled("uuid-a", false).expect("disable");
        assert!(!store.get("uuid-a").expect("present").enabled);

        let mut store = ProfileStore::load_or_create(scratch.store()).expect("reload");
        assert!(!store.get("uuid-a").expect("present").enabled);

        store.remove("uuid-a").expect("remove");
        assert!(ProfileStore::load_or_create(scratch.store())
            .expect("reload")
            .is_empty());
    }

    #[test]
    fn disabling_an_unknown_profile_is_an_error() {
        let scratch = Scratch::new("unknown");
        let mut store = ProfileStore::load_or_create(scratch.store()).expect("load");

        let err = store
            .set_enabled("nope", false)
            .expect_err("must not silently succeed");
        assert!(
            matches!(err, Error::Profiles(ProfileStoreError::Internal(_))),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn corrupt_store_is_quarantined_not_discarded() {
        let scratch = Scratch::new("corrupt");
        let garbage = "this is not json at all";
        std::fs::write(scratch.store(), garbage).expect("write garbage");

        let err = ProfileStore::load_or_create(scratch.store()).expect_err("must fail loudly");
        assert!(
            matches!(err, Error::Profiles(ProfileStoreError::Corrupt { .. })),
            "unexpected error: {err:?}"
        );

        // The original bytes survive in the backup, and the bad file is gone
        // so a later save cannot overwrite the evidence.
        assert_eq!(
            std::fs::read_to_string(scratch.quarantine()).expect("backup readable"),
            garbage
        );
        assert!(
            !scratch.store().exists(),
            "the corrupt store must be moved aside"
        );

        // ...and the next load starts clean instead of failing forever.
        assert!(ProfileStore::load_or_create(scratch.store())
            .expect("second load")
            .is_empty());
    }

    #[test]
    fn each_quarantine_keeps_its_own_backup() {
        let scratch = Scratch::new("quarantine-twice");

        std::fs::write(scratch.store(), "first bad file").expect("write");
        ProfileStore::load_or_create(scratch.store()).expect_err("first load fails");

        std::fs::write(scratch.store(), "second bad file").expect("write");
        ProfileStore::load_or_create(scratch.store()).expect_err("second load fails");

        assert_eq!(
            std::fs::read_to_string(scratch.quarantine()).expect("first backup"),
            "first bad file"
        );
        assert_eq!(
            std::fs::read_to_string(scratch.dir.join("profiles.json.corrupt.1"))
                .expect("second backup"),
            "second bad file"
        );
    }

    #[test]
    fn blank_store_file_is_not_treated_as_corruption() {
        let scratch = Scratch::new("blank");
        std::fs::write(scratch.store(), "  \n\t\n").expect("write");

        let store = ProfileStore::load_or_create(scratch.store()).expect("blank file loads");
        assert!(store.is_empty());
        assert!(
            !scratch.quarantine().exists(),
            "a blank file is not corruption"
        );
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn save_is_owner_only_and_never_widens_the_store() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("mode");
        let mut store = ProfileStore::load_or_create(scratch.store()).expect("load");

        // A fresh store is owner-only regardless of the process umask.
        store.upsert(profile("uuid-a", true, true)).expect("upsert");
        assert_eq!(mode_of(&scratch.store()), 0o600);

        // A store the user tightened by hand keeps that mode across saves.
        std::fs::set_permissions(scratch.store(), std::fs::Permissions::from_mode(0o400))
            .expect("chmod 0400");
        store.upsert(profile("uuid-b", true, true)).expect("upsert");
        assert_eq!(mode_of(&scratch.store()), 0o400);

        // A store left group/world-readable is brought back to owner-only.
        std::fs::set_permissions(scratch.store(), std::fs::Permissions::from_mode(0o644))
            .expect("chmod 0644");
        store.upsert(profile("uuid-c", true, true)).expect("upsert");
        assert_eq!(mode_of(&scratch.store()), 0o600);

        // The save is still a complete, parseable store.
        let reloaded = ProfileStore::load_or_create(scratch.store()).expect("reload");
        assert_eq!(reloaded.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn save_leaves_no_temp_file_behind() {
        let scratch = Scratch::new("tmp");
        let mut store = ProfileStore::load_or_create(scratch.store()).expect("load");
        store.upsert(profile("uuid-a", true, true)).expect("upsert");

        assert!(
            !scratch.dir.join("profiles.json.tmp").exists(),
            "the temp file must be renamed into place, not left behind"
        );
    }
}
