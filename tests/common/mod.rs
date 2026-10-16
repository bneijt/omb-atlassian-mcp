//! Shared test helpers: a synthetic, Chromium-shaped Edge cookie database.
//!
//! Edge is not required to run these tests. The database written here mirrors the
//! columns Chromium/Edge actually use, so the reader is exercised against the real
//! schema rather than a convenient invention.

#![allow(dead_code)]

use omb_atlassian_mcp::decrypt::{derive_key, encrypt_cookie_value};
use rusqlite::{Connection, params};
use std::path::Path;

/// The Chromium cookie schema, restricted to the columns this server reads plus the
/// `NOT NULL` columns a real insert has to satisfy.
const SCHEMA: &str = "
CREATE TABLE cookies(
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL DEFAULT '',
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL DEFAULT 0,
    is_secure INTEGER NOT NULL DEFAULT 0,
    is_httponly INTEGER NOT NULL DEFAULT 0,
    last_access_utc INTEGER NOT NULL DEFAULT 0,
    has_expires INTEGER NOT NULL DEFAULT 1,
    is_persistent INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 1,
    samesite INTEGER NOT NULL DEFAULT -1,
    source_scheme INTEGER NOT NULL DEFAULT 0,
    source_port INTEGER NOT NULL DEFAULT -1,
    last_update_utc INTEGER NOT NULL DEFAULT 0,
    source_type INTEGER NOT NULL DEFAULT 0,
    has_cross_site_ancestor INTEGER NOT NULL DEFAULT 0
)";

/// One cookie to place in a synthetic Edge profile.
#[derive(Debug, Clone)]
pub struct TestCookie {
    pub host_key: String,
    pub name: String,
    /// The cleartext value the cookie should have once decrypted.
    pub value: String,
    /// Password to encrypt with; `None` stores the value in plaintext, as Chromium
    /// does for non-sensitive cookies.
    pub encrypt_with: Option<String>,
    /// Whether to prepend `SHA256(host_key)`, as cookie database version 24+ does.
    pub domain_hash: bool,
    /// Microseconds since the Chromium epoch; 0 means "session cookie".
    pub expires_utc: i64,
}

impl TestCookie {
    /// A plaintext cookie for `host_key`.
    pub fn plain(host_key: &str, name: &str, value: &str) -> Self {
        Self {
            host_key: host_key.to_string(),
            name: name.to_string(),
            value: value.to_string(),
            encrypt_with: None,
            domain_hash: true,
            expires_utc: 0,
        }
    }

    /// A cookie encrypted the way Chromium would encrypt it with `password`.
    pub fn encrypted(host_key: &str, name: &str, value: &str, password: &str) -> Self {
        Self {
            encrypt_with: Some(password.to_string()),
            ..Self::plain(host_key, name, value)
        }
    }

    /// The same cookie, but with an expiry in the past.
    pub fn expired(mut self) -> Self {
        // 2001-01-01, comfortably before any test run.
        self.expires_utc =
            (978_307_200 + omb_atlassian_mcp::edge::CHROMIUM_EPOCH_OFFSET_SECS) * 1_000_000;
        self
    }
}

/// Write a synthetic Edge cookie database at `db`.
pub fn write_cookie_db(db: &Path, cookies: &[TestCookie]) {
    let connection = Connection::open(db).expect("create the cookie database");
    connection
        .execute_batch(SCHEMA)
        .expect("create the cookies table");

    for cookie in cookies {
        let (value, encrypted_value) = match &cookie.encrypt_with {
            Some(password) => {
                let key = derive_key(password, omb_atlassian_mcp::decrypt::LINUX_ITERATIONS);
                let encrypted =
                    encrypt_cookie_value(&cookie.value, &cookie.host_key, &key, cookie.domain_hash);
                (String::new(), encrypted)
            }
            None => (cookie.value.clone(), Vec::new()),
        };

        connection
            .execute(
                "INSERT INTO cookies (creation_utc, host_key, name, value, encrypted_value, \
                 path, expires_utc, is_secure, is_httponly) \
                 VALUES (0, ?1, ?2, ?3, ?4, '/', ?5, 1, 1)",
                params![
                    cookie.host_key,
                    cookie.name,
                    value,
                    encrypted_value,
                    cookie.expires_utc
                ],
            )
            .expect("insert the cookie");
    }
}

/// Build a synthetic Edge profile at `<config_home>/microsoft-edge/<profile>/Cookies`.
///
/// Returns the configuration directory to hand to the server as `XDG_CONFIG_HOME`.
pub fn write_edge_profile(config_home: &Path, profile: &str, cookies: &[TestCookie]) {
    let dir = config_home.join("microsoft-edge").join(profile);
    std::fs::create_dir_all(&dir).expect("create the Edge profile directory");
    write_cookie_db(&dir.join("Cookies"), cookies);
}

/// The site the tests pretend to talk to.
pub const SITE_URL: &str = "https://acme.atlassian.net";

/// The host key Atlassian actually sets its Cloud session cookies under.
pub const ATLASSIAN_DOMAIN: &str = ".atlassian.net";

/// A plausible Atlassian Cloud session cookie set.
pub fn session_cookies(password: &str) -> Vec<TestCookie> {
    vec![
        TestCookie::encrypted(
            ATLASSIAN_DOMAIN,
            "cloud.session.token",
            "cloud-token",
            password,
        ),
        TestCookie::encrypted(
            "acme.atlassian.net",
            "tenant.session.token",
            "tenant-token",
            password,
        ),
        // An unrelated Atlassian cookie that must not reach the header.
        TestCookie::encrypted(
            ATLASSIAN_DOMAIN,
            "atlassian.xsrf.token",
            "xsrf-value",
            password,
        ),
        // A same-named cookie for a different tenant, which must not match.
        TestCookie::encrypted(
            ".other-tenant.atlassian.net",
            "cloud.session.token",
            "other-tenant-token",
            password,
        ),
        // A same-named cookie for an unrelated domain, which must not match either.
        TestCookie::encrypted(
            "example.com",
            "cloud.session.token",
            "example-token",
            password,
        ),
    ]
}
