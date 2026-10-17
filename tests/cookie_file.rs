//! `--session-cookie-file` must work with no browser profile at all.
//!
//! This is the path Windows users take when Edge uses app-bound (`v20`) encryption, and
//! the simplest way to run the server without a browser.

mod common;

use common::*;
use serde_json::json;

#[test]
fn a_cookie_file_replaces_the_edge_profile() {
    // Deliberately no Edge profile anywhere on the machine.
    let env = TestEnv::empty("Default");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookies.txt");
    std::fs::write(&path, "cloud.session.token=abc; tenant.session.token=def\n").unwrap();

    let mut server = Harness::start(&env, &["--session-cookie-file", path.to_str().unwrap()]);
    let initialized = server.initialize();
    assert_eq!(initialized["serverInfo"]["name"], "omb-atlassian-mcp");

    // The session must be real: the call reaches Atlassian and comes back as a tool
    // result, failing only because the cookie is not a live session.
    let response = server.call(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "get_myself", "arguments": {} }
    }));
    assert_eq!(response["id"], 3);
    assert!(
        response.get("error").is_none(),
        "a failed tool call is still a result, not a protocol error: {response}"
    );
    assert_eq!(response["result"]["isError"], true);
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("HTTP"),
        "the supplied cookie should have been sent: {text}"
    );
}

#[test]
fn a_json_cookie_file_works_too() {
    let env = TestEnv::empty("Default");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookies.json");
    std::fs::write(&path, r#"{"cloud.session.token": "abc"}"#).unwrap();

    let mut server = Harness::start(&env, &["--session-cookie-file", path.to_str().unwrap()]);
    server.initialize();
    // Reaching `initialize` is enough: a bad cookie file would have exited first.
    assert_eq!(server.visible_tools().len(), 10);
}

#[test]
fn a_cookie_file_without_a_session_cookie_is_refused() {
    let env = TestEnv::empty("Default");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cookies.txt");
    std::fs::write(&path, "some.other.cookie=1").unwrap();

    let (code, stdout, stderr) = run_to_completion(
        &env,
        &[
            "--site",
            SITE_URL,
            "--session-cookie-file",
            path.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "got: {stdout:?}");
    assert!(stderr.contains("cloud.session.token"), "got: {stderr}");
}

#[test]
fn a_missing_cookie_file_is_reported_clearly() {
    let env = TestEnv::empty("Default");
    let (code, stdout, stderr) = run_to_completion(
        &env,
        &[
            "--site",
            SITE_URL,
            "--session-cookie-file",
            "/nonexistent/cookies.txt",
        ],
    );
    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "got: {stdout:?}");
    assert!(stderr.contains("cookie file"), "got: {stderr}");
}
