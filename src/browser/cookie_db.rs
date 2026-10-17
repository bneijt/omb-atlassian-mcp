//! Reading the Edge cookie database.
//!
//! Edge is Chromium-based, so its schema matches Chrome's: a SQLite database named
//! `Cookies` inside a profile directory. Edge keeps the live database locked while it
//! runs, so callers read a copy.

use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags, params_from_iter};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Chromium's epoch (1601-01-01) in Unix seconds; cookie expiry is stored as
/// microseconds since this moment.
pub const CHROMIUM_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

/// A row of Edge's `cookies` table, before decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCookie {
    pub host_key: String,
    pub name: String,
    /// Plaintext value; empty when the value is encrypted.
    pub value: String,
    /// Encrypted value; empty when the cookie is stored in plaintext.
    pub encrypted_value: Vec<u8>,
    pub path: String,
    pub is_secure: bool,
    pub is_httponly: bool,
    /// Microseconds since [`CHROMIUM_EPOCH_OFFSET_SECS`]; 0 means "session cookie".
    pub expires_utc: i64,
}

impl RawCookie {
    /// Whether the cookie has a value at all, plaintext or encrypted.
    pub fn has_value(&self) -> bool {
        !self.value.is_empty() || !self.encrypted_value.is_empty()
    }
}

/// Append a suffix to a path's final component (`Cookies` -> `Cookies-wal`).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Copy the cookie database (plus its WAL/SHM sidecars) somewhere private and readable.
///
/// The returned `TempDir` must be kept alive for as long as the copy is needed; the
/// files are deleted when it is dropped.
pub fn copy_cookie_db(db: &Path) -> Result<(tempfile::TempDir, PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix("omb-atlassian-mcp-")
        .tempdir()
        .map_err(|e| Error::CookieDb {
            path: db.display().to_string(),
            reason: format!("could not create a temporary directory: {e}"),
        })?;

    let dest = dir.path().join("Cookies");
    copy_file(db, &dest)?;
    for sidecar in ["-wal", "-shm"] {
        let from = with_suffix(db, sidecar);
        if from.is_file() {
            copy_file(&from, &with_suffix(&dest, sidecar))?;
        }
    }
    Ok((dir, dest))
}

fn copy_file(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to).map_err(|e| Error::CookieDb {
        path: from.display().to_string(),
        reason: format!("could not copy it aside (is Edge running?): {e}"),
    })?;
    Ok(())
}

/// Read the named cookies from the database, whatever their domain.
///
/// Domain filtering is deliberately left to [`host_matches`] so it can be tested and
/// audited as plain Rust rather than as a SQL `LIKE` pattern.
pub fn read_cookies(db: &Path, names: &[&str]) -> Result<Vec<RawCookie>> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| {
        Error::CookieDb {
            path: db.display().to_string(),
            reason: e.to_string(),
        }
    })?;

    let placeholders = std::iter::repeat_n("?", names.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT host_key, name, value, CAST(encrypted_value AS BLOB), path, \
         is_secure, is_httponly, expires_utc \
         FROM cookies WHERE name IN ({placeholders})"
    );

    let mut stmt = conn.prepare(&sql).map_err(|e| Error::CookieDb {
        path: db.display().to_string(),
        reason: e.to_string(),
    })?;

    let rows = stmt
        .query_map(params_from_iter(names.iter().copied()), |row| {
            Ok(RawCookie {
                host_key: row.get(0)?,
                name: row.get(1)?,
                value: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                encrypted_value: row.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                path: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                is_secure: row.get::<_, Option<i64>>(5)?.unwrap_or(0) != 0,
                is_httponly: row.get::<_, Option<i64>>(6)?.unwrap_or(0) != 0,
                expires_utc: row.get::<_, Option<i64>>(7)?.unwrap_or(0),
            })
        })
        .map_err(|e| Error::CookieDb {
            path: db.display().to_string(),
            reason: e.to_string(),
        })?;

    let mut cookies = Vec::new();
    for row in rows {
        cookies.push(row.map_err(|e| Error::CookieDb {
            path: db.display().to_string(),
            reason: e.to_string(),
        })?);
    }
    Ok(cookies)
}

/// RFC 6265 domain matching: a `host_key` of `.atlassian.net` covers
/// `acme.atlassian.net`, but never `notatlassian.net`.
pub fn host_matches(cookie_host: &str, site_host: &str) -> bool {
    if cookie_host == site_host {
        return true;
    }
    match cookie_host.strip_prefix('.') {
        Some(parent) => {
            site_host == parent
                || (site_host.len() > parent.len()
                    && site_host.ends_with(parent)
                    && site_host.as_bytes()[site_host.len() - parent.len() - 1] == b'.')
        }
        None => false,
    }
}

/// Convert Chromium's `expires_utc` into Unix seconds.
///
/// Returns `None` for session cookies, which carry no expiry.
pub fn expires_at_unix(expires_utc: i64) -> Option<i64> {
    if expires_utc <= 0 {
        None
    } else {
        Some(expires_utc / 1_000_000 - CHROMIUM_EPOCH_OFFSET_SECS)
    }
}

/// Whether a cookie with this `expires_utc` is already expired.
///
/// Session cookies (`expires_utc <= 0`) are never considered expired.
pub fn is_expired(expires_utc: i64, now_unix: i64) -> bool {
    match expires_at_unix(expires_utc) {
        Some(at) => at <= now_unix,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching_follows_rfc6265() {
        // exact host
        assert!(host_matches("acme.atlassian.net", "acme.atlassian.net"));
        // domain cookie covering a subdomain
        assert!(host_matches(".atlassian.net", "acme.atlassian.net"));
        assert!(host_matches(".atlassian.net", "atlassian.net"));
        // suffix traps: these must NOT match
        assert!(!host_matches(".atlassian.net", "notatlassian.net"));
        assert!(!host_matches(".atlassian.net", "evil-atlassian.net"));
        assert!(!host_matches(".atlassian.net", "atlassian.net.evil.com"));
        // a bare host does not cover other hosts
        assert!(!host_matches("acme.atlassian.net", "other.atlassian.net"));
        // sibling domains must not match
        assert!(!host_matches(".acme.atlassian.net", "other.atlassian.net"));
    }

    #[test]
    fn expiry_uses_the_chromium_epoch() {
        // 2024-01-01T00:00:00Z == 1704067200 unix
        let utc = (1_704_067_200 + CHROMIUM_EPOCH_OFFSET_SECS) * 1_000_000;
        assert_eq!(expires_at_unix(utc), Some(1_704_067_200));
        // Still valid one second before it expires, expired at the expiry instant.
        assert!(!is_expired(utc, 1_704_067_199));
        assert!(is_expired(utc, 1_704_067_200));
        assert!(is_expired(utc, 1_704_067_201));
        // session cookies never expire
        assert_eq!(expires_at_unix(0), None);
        assert!(!is_expired(0, i64::MAX));
    }

    #[test]
    fn suffix_helper_keeps_the_extension() {
        assert_eq!(
            with_suffix(Path::new("/a/b/Cookies"), "-wal"),
            PathBuf::from("/a/b/Cookies-wal")
        );
    }
}
