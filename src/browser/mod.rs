//! Reading the Edge session cookie out of the browser's profile.
//!
//! Each platform supplies the same two things: where the cookie database is
//! ([`paths`]) and how to turn an encrypted value into text ([`linux`], [`macos`],
//! [`windows`]). The rest of the crate only sees [`Credentials`] and [`Browser`], so no
//! platform `cfg` leaks into it.
//!
//! The manual alternative — `--session-cookie-file` — lives in [`crate::cookie_file`]
//! and needs none of this, which is what keeps Windows usable when Edge uses app-bound
//! encryption.

pub mod cookie_db;
pub mod macos;
pub mod paths;
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

use crate::Result;
use std::path::PathBuf;

/// The PBKDF2 iteration count this platform's key derivation uses.
///
/// Linux derives with 1 iteration, macOS with 1003. Tests that build a synthetic
/// profile have to use the same count, or the server cannot decrypt what they wrote.
pub const ITERATIONS: u32 = if cfg!(target_os = "macos") {
    crate::decrypt::MACOS_ITERATIONS
} else {
    crate::decrypt::LINUX_ITERATIONS
};

/// How to decrypt this profile's cookie values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credentials {
    /// AES-128-CBC with one of these candidate keys (Linux, macOS).
    Cbc(Vec<[u8; 16]>),
    /// AES-256-GCM with the DPAPI-unwrapped key (Windows).
    Gcm([u8; 32]),
    /// No key could be obtained, so only plaintext cookie values can be used.
    ///
    /// This is a normal state, not a crash: a profile whose cookies are all stored in
    /// plaintext still works, and an encrypted value produces the reason as its error.
    Unavailable(String),
}

impl Credentials {
    /// Decrypt one cookie value.
    pub fn decrypt(&self, encrypted: &[u8], host_key: &str) -> std::result::Result<String, String> {
        match self {
            Self::Cbc(keys) => crate::decrypt::decrypt_cookie_value(encrypted, host_key, keys),
            Self::Gcm(key) => {
                if crate::decrypt::is_app_bound(encrypted) || encrypted.starts_with(b"v10") {
                    crate::decrypt::decrypt_gcm(encrypted, host_key, key)
                } else {
                    // Older Chromium on Windows stored the plaintext under DPAPI.
                    windows::decrypt_legacy(encrypted, host_key)
                }
            }
            Self::Unavailable(reason) => Err(reason.clone()),
        }
    }
}

/// A profile's cookie database, already copied aside, plus how to decrypt it.
pub struct Browser {
    /// The copied database, safe to read while Edge runs.
    pub cookies_db: PathBuf,
    /// Keeps the temporary copy alive for as long as this value lives.
    pub copy: tempfile::TempDir,
    pub credentials: Credentials,
    /// Where the key came from, for error messages.
    pub key_source: String,
}

/// Open the named Edge profile on this platform.
pub async fn open(profile: &str) -> Result<Browser> {
    let db = paths::cookie_db(profile)?;
    let (copy, cookies_db) = cookie_db::copy_cookie_db(&db)?;
    let (credentials, key_source) = platform_credentials().await?;
    Ok(Browser {
        cookies_db,
        copy,
        credentials,
        key_source,
    })
}

#[cfg(target_os = "linux")]
async fn platform_credentials() -> Result<(Credentials, String)> {
    Ok(linux::credentials().await)
}

#[cfg(target_os = "macos")]
async fn platform_credentials() -> Result<(Credentials, String)> {
    Ok(macos::credentials())
}

#[cfg(target_os = "windows")]
async fn platform_credentials() -> Result<(Credentials, String)> {
    // A missing or unusable `Local State` is not fatal: plaintext cookies still work,
    // and `--session-cookie-file` is available. The reason is carried along so that an
    // encrypted cookie fails with something actionable.
    let local_state = match paths::local_state() {
        Ok(path) => path,
        Err(error) => {
            return Ok((
                Credentials::Unavailable(error.to_string()),
                "no Local State file".to_string(),
            ));
        }
    };
    match windows::credentials(&local_state) {
        Ok(pair) => Ok(pair),
        Err(reason) => {
            let key_source = format!("Local State unusable: {reason}");
            Ok((Credentials::Unavailable(reason), key_source))
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn platform_credentials() -> Result<(Credentials, String)> {
    Err(crate::Error::UnsupportedPlatform)
}
