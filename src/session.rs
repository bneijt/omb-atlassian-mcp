//! Turning an Edge profile — or a cookie file — into a usable Atlassian session.
//!
//! This is the only place that knows which cookies matter, and the only place a
//! decrypted secret exists. The result is a `Cookie:` header value that lives in memory
//! for the lifetime of the process.

use crate::atlassian::Site;
use crate::browser::cookie_db::{self, RawCookie};
use crate::browser::{Browser, Credentials};
use crate::{Error, Result};
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

/// Acquire a session from the named Edge profile on this platform.
pub async fn acquire(site: &Site, profile: &str) -> Result<Session> {
    let browser = crate::browser::open(profile).await?;
    from_browser(site, &browser, profile)
}

/// Acquire a session from an already-opened browser profile.
pub fn from_browser(site: &Site, browser: &Browser, profile: &str) -> Result<Session> {
    let rows = cookie_db::read_cookies(&browser.cookies_db, &SESSION_COOKIE_NAMES)?;
    select(
        site,
        &rows,
        profile,
        &browser.credentials,
        &browser.key_source,
    )
}

/// Use a cookie supplied by hand instead of reading the browser profile.
pub fn from_cookie_file(file: &crate::cookie_file::CookieFile) -> Session {
    Session {
        cookie_header: file.header.clone(),
        cookie_names: file.names.clone(),
    }
}

/// Pick the session cookies out of the database rows and turn them into a header.
fn select(
    site: &Site,
    rows: &[RawCookie],
    profile: &str,
    credentials: &Credentials,
    key_source: &str,
) -> Result<Session> {
    let host = site.host().to_string();
    let matching: Vec<&RawCookie> = rows
        .iter()
        .filter(|cookie| cookie_db::host_matches(&cookie.host_key, &host))
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
        if cookie_db::is_expired(cookie.expires_utc, now) {
            crate::log!(
                "ignoring expired cookie {} for {}",
                cookie.name,
                cookie.host_key
            );
            latest_expiry = cookie_db::expires_at_unix(cookie.expires_utc)
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
            match credentials.decrypt(&cookie.encrypted_value, &cookie.host_key) {
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
            key_source: key_source.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::cookie_db::CHROMIUM_EPOCH_OFFSET_SECS;

    fn site() -> Site {
        Site::parse("https://acme.atlassian.net").unwrap()
    }

    /// A cookie with a plaintext value, so these tests need no crypto at all.
    fn plain(host_key: &str, name: &str, value: &str) -> RawCookie {
        RawCookie {
            host_key: host_key.to_string(),
            name: name.to_string(),
            value: value.to_string(),
            encrypted_value: Vec::new(),
            path: "/".to_string(),
            is_secure: true,
            is_httponly: true,
            expires_utc: 0,
        }
    }

    /// A cookie whose value has to be decrypted; with no keys it cannot be.
    fn encrypted_to(host_key: &str, name: &str) -> RawCookie {
        RawCookie {
            encrypted_value: b"v10\x00\x01\x02".to_vec(),
            ..plain(host_key, name, "")
        }
    }

    fn no_keys() -> Credentials {
        Credentials::Cbc(Vec::new())
    }

    #[test]
    fn only_matching_session_cookies_reach_the_header() {
        let rows = vec![
            plain(".atlassian.net", "cloud.session.token", "cloud"),
            plain("acme.atlassian.net", "tenant.session.token", "tenant"),
            plain(".other.atlassian.net", "cloud.session.token", "other"),
            plain("example.com", "cloud.session.token", "example"),
            plain(".atlassian.net", "atlassian.xsrf.token", "xsrf"),
        ];
        let session = select(&site(), &rows, "Default", &no_keys(), "test").unwrap();
        assert_eq!(
            session.cookie_header,
            "cloud.session.token=cloud; tenant.session.token=tenant"
        );
        assert_eq!(session.cookie_names, SESSION_COOKIE_NAMES);
    }

    #[test]
    fn no_matching_cookie_is_reported_with_what_was_found() {
        let rows = vec![plain("example.com", "cloud.session.token", "nope")];
        let error = select(&site(), &rows, "Default", &no_keys(), "test").unwrap_err();
        assert!(
            matches!(error, Error::NoSessionCookie { .. }),
            "got {error:?}"
        );
        assert!(error.to_string().contains("acme.atlassian.net"));
    }

    #[test]
    fn expired_cookies_are_rejected() {
        let mut expired = plain(".atlassian.net", "cloud.session.token", "cloud");
        // 2001-01-01
        expired.expires_utc = (978_307_200 + CHROMIUM_EPOCH_OFFSET_SECS) * 1_000_000;
        let error = select(&site(), &[expired], "Default", &no_keys(), "test").unwrap_err();
        assert!(
            matches!(error, Error::SessionExpired { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn undecryptable_cookies_name_the_key_source() {
        let rows = vec![encrypted_to(".atlassian.net", "cloud.session.token")];
        let error = select(
            &site(),
            &rows,
            "Default",
            &no_keys(),
            "OS keyring (no matching entry)",
        )
        .unwrap_err();
        match &error {
            Error::Undecryptable { key_source, .. } => {
                assert!(key_source.contains("OS keyring"), "got {key_source:?}");
            }
            other => panic!("expected Undecryptable, got {other:?}"),
        }
        assert!(error.to_string().contains("OS keyring"));
    }

    #[test]
    fn a_cookie_file_becomes_a_session_directly() {
        let file = crate::cookie_file::parse("cloud.session.token=abc").unwrap();
        let session = from_cookie_file(&file);
        assert_eq!(session.cookie_header, "cloud.session.token=abc");
        assert_eq!(session.cookie_names, ["cloud.session.token"]);
    }
}
