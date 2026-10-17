//! End-to-end tests of the browser-session path, against a synthetic Edge profile.

mod common;

use common::*;
use omb_atlassian_mcp::Error;
use omb_atlassian_mcp::atlassian::Site;
use omb_atlassian_mcp::browser::ITERATIONS;
use omb_atlassian_mcp::browser::cookie_db::{self, CHROMIUM_EPOCH_OFFSET_SECS};
use omb_atlassian_mcp::browser::{Browser, Credentials};
use omb_atlassian_mcp::decrypt::{KEYRING_FALLBACK_PASSWORDS, derive_key};
use omb_atlassian_mcp::session::{self, SESSION_COOKIE_NAMES};
use std::path::Path;

fn site() -> Site {
    Site::parse(SITE_URL).unwrap()
}

/// The keys a profile would offer: keyring passwords first, then the built-in fallbacks.
fn keys(passwords: &[&str]) -> Credentials {
    let mut keys: Vec<[u8; 16]> = passwords
        .iter()
        .map(|password| derive_key(password, ITERATIONS))
        .collect();
    for password in KEYRING_FALLBACK_PASSWORDS {
        let key = derive_key(password, ITERATIONS);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    Credentials::Cbc(keys)
}

fn browser(db: &Path, credentials: Credentials, key_source: &str) -> Browser {
    let (copy, cookies_db) = cookie_db::copy_cookie_db(db).expect("copy the database");
    Browser {
        cookies_db,
        copy,
        credentials,
        key_source: key_source.to_string(),
    }
}

fn session_from(
    db: &Path,
    credentials: Credentials,
) -> omb_atlassian_mcp::Result<session::Session> {
    session::from_browser(
        &site(),
        &browser(db, credentials, "test key source"),
        "Default",
    )
}

fn temp_db(cookies: &[TestCookie]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    write_cookie_db(&db, cookies);
    (dir, db)
}

#[test]
fn builds_a_cookie_header_from_a_profile() {
    let (_dir, db) = temp_db(&session_cookies("peanuts"));
    let session = session_from(&db, keys(&[])).expect("the session should be acquired");

    assert_eq!(session.cookie_names, SESSION_COOKIE_NAMES);
    assert_eq!(
        session.cookie_header,
        "cloud.session.token=cloud-token; tenant.session.token=tenant-token"
    );
    // Cookies for other tenants/domains, and cookies we do not send, must stay out.
    assert!(!session.cookie_header.contains("other-tenant-token"));
    assert!(!session.cookie_header.contains("example-token"));
    assert!(!session.cookie_header.contains("xsrf-value"));
}

#[test]
fn uses_a_password_recovered_from_the_keyring() {
    let (_dir, db) = temp_db(&session_cookies("real-keyring-password"));
    let session = session_from(&db, keys(&["real-keyring-password"])).unwrap();
    assert!(
        session
            .cookie_header
            .contains("cloud.session.token=cloud-token")
    );
}

#[test]
fn reads_plaintext_cookies_too() {
    let (_dir, db) = temp_db(&[TestCookie::plain(
        ATLASSIAN_DOMAIN,
        "cloud.session.token",
        "plain-token",
    )]);
    let session = session_from(&db, keys(&[])).unwrap();
    assert_eq!(session.cookie_header, "cloud.session.token=plain-token");
}

#[test]
fn reads_cookies_written_before_the_domain_hash_existed() {
    let mut cookie = TestCookie::encrypted(
        ATLASSIAN_DOMAIN,
        "cloud.session.token",
        "old-token",
        "peanuts",
    );
    cookie.domain_hash = false;
    let (_dir, db) = temp_db(&[cookie]);
    let session = session_from(&db, keys(&[])).unwrap();
    assert_eq!(session.cookie_header, "cloud.session.token=old-token");
}

#[test]
fn an_undecryptable_cookie_explains_why() {
    // Built explicitly: the shared helper uses plaintext values on Windows.
    let (_dir, db) = temp_db(&[TestCookie::encrypted(
        ATLASSIAN_DOMAIN,
        "cloud.session.token",
        "cloud-token",
        "a-password-we-do-not-have",
    )]);
    let error = session_from(&db, keys(&[])).expect_err("decryption must fail");

    match &error {
        Error::Undecryptable { key_source, .. } => {
            assert_eq!(key_source, "test key source");
        }
        other => panic!("expected Undecryptable, got {other:?}"),
    }
    // The message names the key source and the detail of each failed attempt.
    let message = error.to_string();
    assert!(message.contains("test key source"), "got: {message}");
    assert!(message.contains("padding check failed"), "got: {message}");
}

#[test]
fn a_profile_without_cookies_for_the_site_is_reported_clearly() {
    let (_dir, db) = temp_db(&[TestCookie::plain(
        ".example.com",
        "cloud.session.token",
        "nope",
    )]);
    let error = session_from(&db, keys(&[])).expect_err("no matching cookie");

    let message = error.to_string();
    assert!(message.contains("acme.atlassian.net"), "got: {message}");
    assert!(message.contains("cloud.session.token"), "got: {message}");
    assert!(error.is_auth_failure());
}

#[test]
fn an_empty_cookie_database_is_reported_clearly() {
    let (_dir, db) = temp_db(&[]);
    let error = session_from(&db, keys(&[])).expect_err("no cookies at all");
    assert!(matches!(error, Error::NoSessionCookie { .. }));
}

#[test]
fn expired_session_cookies_are_rejected() {
    let cookies: Vec<TestCookie> = session_cookies("peanuts")
        .into_iter()
        .map(TestCookie::expired)
        .collect();
    let (_dir, db) = temp_db(&cookies);
    let error = session_from(&db, keys(&[])).expect_err("the cookies are expired");
    assert!(
        matches!(error, Error::SessionExpired { .. }),
        "got {error:?}"
    );
    assert!(error.is_auth_failure());
}

#[test]
fn a_missing_database_is_a_cookie_database_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = cookie_db::copy_cookie_db(&dir.path().join("missing/Cookies"))
        .expect_err("there is no database");
    assert!(matches!(error, Error::CookieDb { .. }), "got {error:?}");
}

#[test]
fn the_expiry_helper_agrees_with_the_shared_constant() {
    // Guards against the test helper drifting from the code it is meant to exercise.
    assert_eq!(
        (978_307_200 + CHROMIUM_EPOCH_OFFSET_SECS) * 1_000_000,
        TestCookie::plain("h", "n", "v").expired().expires_utc
    );
}
