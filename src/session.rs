//! Turning an Edge profile into a usable Atlassian session.
//!
//! This is the only place that knows which cookies matter, and the only place a
//! decrypted secret exists. The result is a `Cookie:` header value that lives in
//! memory for the lifetime of the process.

use crate::atlassian::Site;
use crate::edge::{self, RawCookie};
use crate::keyring::{self, KeyringLookup};
use crate::{Error, Result};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// The cookies that authenticate a browser session against Atlassian Cloud.
///
/// `cloud.session.token` is the session itself; `tenant.session.token` covers the
/// tenant-scoped endpoints. Order matters: it is the order they are sent in.
pub const SESSION_COOKIE_NAMES: [&str; 2] = ["cloud.session.token", "tenant.session.token"];

/// A live Atlassian session, reduced to what the HTTP client needs.
#[derive(Debug, Clone)]
pub struct Session {
    /// Ready-to-send `Cookie` header value. Never log this.
    pub cookie_header: String,
    /// Names of the cookies that made it into the header (not the values).
    pub cookie_names: Vec<String>,
}

/// Acquire a session from the named Edge profile.
pub async fn acquire(site: &Site, profile: &str) -> Result<Session> {
    let db = edge::cookie_db_for(profile)?;
    let lookup = keyring::safe_storage_passwords().await;
    acquire_from_db(site, &db, profile, &lookup)
}

/// Acquire a session from a specific cookie database.
///
/// Split out from [`acquire`] so it can be tested without an Edge installation or a
/// keyring.
pub fn acquire_from_db(
    site: &Site,
    db: &Path,
    profile: &str,
    lookup: &KeyringLookup,
) -> Result<Session> {
    // Read a copy: Edge holds a lock on the live database while it runs.
    let (_temp, copy) = edge::copy_cookie_db(db)?;
    let rows = edge::read_cookies(&copy, &SESSION_COOKIE_NAMES)?;

    let host = site.host().to_string();
    let matching: Vec<&RawCookie> = rows
        .iter()
        .filter(|cookie| edge::host_matches(&cookie.host_key, &host))
        .collect();

    if matching.is_empty() {
        return Err(Error::NoSessionCookie {
            site: host,
            profile: profile.to_string(),
            wanted: SESSION_COOKIE_NAMES.iter().map(|n| n.to_string()).collect(),
            seen: rows
                .iter()
                .map(|cookie| format!("{} ({})", cookie.name, cookie.host_key))
                .collect(),
        });
    }

    // Drop anything the browser has already expired.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut live = Vec::new();
    let mut latest_expiry = None;
    for cookie in matching {
        if edge::is_expired(cookie.expires_utc, now) {
            crate::log!(
                "ignoring expired cookie {} for {}",
                cookie.name,
                cookie.host_key
            );
            latest_expiry = edge::expires_at_unix(cookie.expires_utc)
                .into_iter()
                .chain(latest_expiry)
                .max();
        } else {
            live.push(cookie);
        }
    }
    if live.is_empty() {
        return Err(Error::SessionExpired {
            host,
            expired_at: latest_expiry
                .map(|t| format!("unix time {t}"))
                .unwrap_or_else(|| "an unknown time".to_string()),
        });
    }

    let keys = keys_for(lookup);
    let mut values: Vec<(String, String)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for cookie in &live {
        if !cookie.has_value() {
            failures.push(format!("{}: no value stored", cookie.name));
            continue;
        }
        let value = if !cookie.value.is_empty() {
            cookie.value.clone()
        } else {
            match crate::decrypt::decrypt_cookie_value(
                &cookie.encrypted_value,
                &cookie.host_key,
                &keys,
            ) {
                Ok(value) => value,
                Err(reason) => {
                    failures.push(format!("{} ({}): {reason}", cookie.name, cookie.host_key));
                    continue;
                }
            }
        };
        if value.is_empty() {
            failures.push(format!("{}: decrypted to an empty value", cookie.name));
            continue;
        }
        values.push((cookie.name.clone(), value));
    }

    if values.is_empty() {
        return Err(Error::Undecryptable {
            host,
            count: live.len(),
            keys: keys.len(),
            keyring: lookup.describe(),
            details: failures.join("; "),
        });
    }
    if !failures.is_empty() {
        crate::log!(
            "warning: some Atlassian session cookies could not be used: {}",
            failures.join("; ")
        );
    }

    // Send the cookies in a stable, predictable order.
    let ordered: Vec<(String, String)> = SESSION_COOKIE_NAMES
        .iter()
        .filter_map(|name| {
            values
                .iter()
                .find(|(candidate, _)| candidate == name)
                .cloned()
        })
        .collect();

    let cookie_header = ordered
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");

    Ok(Session {
        cookie_header,
        cookie_names: ordered.into_iter().map(|(name, _)| name).collect(),
    })
}

/// Candidate AES keys, in the order they are tried.
///
/// Keyring-derived keys come first because when a keyring entry exists it is the one
/// Chromium used; the built-in fallbacks only apply to `--password-store=basic` setups.
pub fn keys_for(lookup: &KeyringLookup) -> Vec<[u8; 16]> {
    let mut keys: Vec<[u8; 16]> = lookup
        .passwords()
        .iter()
        .map(|password| crate::decrypt::derive_key(password, crate::decrypt::LINUX_ITERATIONS))
        .collect();
    for password in crate::decrypt::KEYRING_FALLBACK_PASSWORDS {
        let key = crate::decrypt::derive_key(password, crate::decrypt::LINUX_ITERATIONS);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_keys_are_always_available() {
        let keys = keys_for(&KeyringLookup::Unavailable("no dbus".into()));
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], crate::decrypt::derive_key("peanuts", 1));
        assert_eq!(keys[1], crate::decrypt::derive_key("", 1));
    }

    #[test]
    fn keyring_passwords_come_first_and_are_not_duplicated() {
        let keys = keys_for(&KeyringLookup::Passwords(vec![
            "keyring-secret".to_string(),
            "peanuts".to_string(),
        ]));
        // keyring-secret, then peanuts (from the keyring, deduplicated against the
        // fallback), then the empty password.
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], crate::decrypt::derive_key("keyring-secret", 1));
        assert_eq!(keys[1], crate::decrypt::derive_key("peanuts", 1));
        assert_eq!(keys[2], crate::decrypt::derive_key("", 1));
    }
}
