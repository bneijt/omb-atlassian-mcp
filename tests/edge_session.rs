//! End-to-end tests of the Edge session path, against a synthetic Edge profile.

mod common;

use common::*;
use omb_atlassian_mcp::atlassian::Site;
use omb_atlassian_mcp::keyring::KeyringLookup;
use omb_atlassian_mcp::session;
use omb_atlassian_mcp::{Error, session::SESSION_COOKIE_NAMES};

fn site() -> Site {
    Site::parse(SITE_URL).unwrap()
}

#[test]
fn builds_a_cookie_header_from_an_encrypted_edge_profile() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    write_cookie_db(&db, &session_cookies("peanuts"));

    let session = session::acquire_from_db(
        &site(),
        &db,
        "Default",
        &KeyringLookup::Unavailable("not used in this test".into()),
    )
    .expect("the session should be acquired");

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
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    // Encrypted with a keyring password, so the `peanuts` fallback cannot open it.
    write_cookie_db(&db, &session_cookies("real-keyring-password"));

    let lookup = KeyringLookup::Passwords(vec!["real-keyring-password".to_string()]);
    let session = session::acquire_from_db(&site(), &db, "Default", &lookup).unwrap();
    assert!(
        session
            .cookie_header
            .contains("cloud.session.token=cloud-token")
    );
}

#[test]
fn reads_plaintext_cookies_too() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    write_cookie_db(
        &db,
        &[TestCookie::plain(
            ATLASSIAN_DOMAIN,
            "cloud.session.token",
            "plain-token",
        )],
    );

    let session = session::acquire_from_db(
        &site(),
        &db,
        "Default",
        &KeyringLookup::Unavailable("x".into()),
    )
    .unwrap();
    assert_eq!(session.cookie_header, "cloud.session.token=plain-token");
}

#[test]
fn reads_cookies_written_before_the_domain_hash_existed() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    let mut cookie = TestCookie::encrypted(
        ATLASSIAN_DOMAIN,
        "cloud.session.token",
        "old-token",
        "peanuts",
    );
    cookie.domain_hash = false;
    write_cookie_db(&db, &[cookie]);

    let session = session::acquire_from_db(
        &site(),
        &db,
        "Default",
        &KeyringLookup::Unavailable("x".into()),
    )
    .unwrap();
    assert_eq!(session.cookie_header, "cloud.session.token=old-token");
}

#[test]
fn an_undecryptable_cookie_explains_why() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    write_cookie_db(&db, &session_cookies("a-password-we-do-not-have"));

    let error = session::acquire_from_db(
        &site(),
        &db,
        "Default",
        &KeyringLookup::Unavailable("no session bus".into()),
    )
    .expect_err("decryption must fail");

    let message = error.to_string();
    match error {
        Error::Undecryptable { keys, .. } => assert_eq!(keys, 2, "the two fallback keys"),
        other => panic!("expected Undecryptable, got {other:?}"),
    }
    // The message must point at both the key count and the keyring state.
    assert!(message.contains("no session bus"), "got: {message}");
    assert!(message.contains("2 key(s)"), "got: {message}");
}

#[test]
fn a_profile_without_cookies_for_the_site_is_reported_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    write_cookie_db(
        &db,
        &[TestCookie::plain(
            ".example.com",
            "cloud.session.token",
            "nope",
        )],
    );

    let error = session::acquire_from_db(
        &site(),
        &db,
        "Default",
        &KeyringLookup::Unavailable("x".into()),
    )
    .expect_err("no matching cookie");

    let message = error.to_string();
    assert!(message.contains("acme.atlassian.net"), "got: {message}");
    assert!(message.contains("cloud.session.token"), "got: {message}");
    assert!(error.is_auth_failure());
}

#[test]
fn an_empty_cookie_database_is_reported_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    write_cookie_db(&db, &[]);

    let error = session::acquire_from_db(
        &site(),
        &db,
        "Default",
        &KeyringLookup::Unavailable("x".into()),
    )
    .expect_err("no cookies at all");
    assert!(matches!(error, Error::NoSessionCookie { .. }));
}

#[test]
fn expired_session_cookies_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("Cookies");
    let cookies: Vec<TestCookie> = session_cookies("peanuts")
        .into_iter()
        .map(TestCookie::expired)
        .collect();
    write_cookie_db(&db, &cookies);

    let error = session::acquire_from_db(
        &site(),
        &db,
        "Default",
        &KeyringLookup::Unavailable("x".into()),
    )
    .expect_err("the cookies are expired");
    assert!(
        matches!(error, Error::SessionExpired { .. }),
        "got {error:?}"
    );
    assert!(error.is_auth_failure());
}

#[test]
fn a_missing_profile_points_at_the_paths_that_were_searched() {
    let dir = tempfile::tempdir().unwrap();
    let error = session::acquire_from_db(
        &site(),
        &dir.path().join("does-not-exist").join("Cookies"),
        "Default",
        &KeyringLookup::Unavailable("x".into()),
    )
    .expect_err("there is no database");
    assert!(matches!(error, Error::CookieDb { .. }), "got {error:?}");
}
