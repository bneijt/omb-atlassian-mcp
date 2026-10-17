//! Drives the real binary over stdio, the way an MCP client would.
//!
//! The Edge profile is synthetic (see `common`), so these tests exercise the whole
//! path — profile discovery, cookie decryption, allowlist, MCP framing — without an
//! Edge installation or an Atlassian account.

mod common;

use common::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

/// MCP framing over stdio is one JSON-RPC message per line.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(90);

const BIN: &str = env!("CARGO_BIN_EXE_omb-atlassian-mcp");

struct Harness {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Harness {
    /// Start the server with `XDG_CONFIG_HOME` pointed at a synthetic Edge profile.
    fn start(config_home: &Path, extra_args: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .arg("--site")
            .arg(SITE_URL)
            .args(extra_args)
            .env("XDG_CONFIG_HOME", config_home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the server");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");

        // Read stdout on a thread so a missing response surfaces as a timeout instead
        // of hanging the test run forever.
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            child,
            stdin,
            lines,
        }
    }

    fn send(&mut self, message: &Value) {
        writeln!(self.stdin, "{message}").expect("write to the server");
        self.stdin.flush().expect("flush");
    }

    fn receive(&self) -> Value {
        match self.lines.recv_timeout(RESPONSE_TIMEOUT) {
            Ok(line) => serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout must carry only JSON-RPC, got {line:?}: {e}")),
            Err(RecvTimeoutError::Timeout) => {
                panic!("no response within {RESPONSE_TIMEOUT:?}")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!(
                    "the server closed stdout without answering; it most likely exited with an error"
                )
            }
        }
    }

    fn call(&mut self, message: &Value) -> Value {
        self.send(message);
        self.receive()
    }

    /// Complete the MCP handshake and return the `initialize` result.
    fn initialize(&mut self) -> Value {
        let response = self.call(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "omb-atlassian-mcp-tests", "version": "0" }
            }
        }));
        assert_eq!(response["id"], 1);
        assert!(
            response.get("error").is_none(),
            "initialize failed: {response}"
        );
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        response["result"].clone()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        // Closing stdin ends the transport, which should end the server.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn profile_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    write_edge_profile(dir.path(), "Default", &session_cookies("peanuts"));
    dir
}

/// Run the binary to completion and return (exit code, stdout, stderr).
fn run_to_completion(config_home: &Path, args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BIN)
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .stdin(Stdio::null())
        .output()
        .expect("run the server");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn serves_the_handshake_and_exposes_only_read_only_tools() {
    let profile = profile_dir();
    let mut server = Harness::start(profile.path(), &[]);

    let initialized = server.initialize();
    assert_eq!(initialized["serverInfo"]["name"], "omb-atlassian-mcp");
    assert_eq!(
        initialized["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert!(
        initialized["protocolVersion"]
            .as_str()
            .unwrap_or_default()
            .contains('-'),
        "protocol version was not negotiated: {initialized}"
    );
    assert!(
        initialized["capabilities"]["tools"].is_object(),
        "the server must advertise the tools capability: {initialized}"
    );

    let listed = server.call(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    assert_eq!(listed["id"], 2);
    let tools = listed["result"]["tools"]
        .as_array()
        .expect("a tools array")
        .clone();

    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names.len(), 10, "unexpected tool set: {names:?}");
    for expected in [
        "get_myself",
        "search_issues",
        "get_issue",
        "list_projects",
        "get_issue_comments",
        "search_pages",
        "get_page",
        "list_spaces",
        "get_page_children",
        "list_page_comments",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} is missing from {names:?}"
        );
    }

    for tool in &tools {
        let name = tool["name"].as_str().unwrap_or_default();
        assert_eq!(
            tool["annotations"]["readOnlyHint"], true,
            "tool {name} is not advertised as read-only: {tool}"
        );
        assert!(
            tool["description"].as_str().is_some_and(|d| !d.is_empty()),
            "tool {name} has no description"
        );
        assert!(
            tool["inputSchema"].is_object(),
            "tool {name} has no input schema"
        );
    }
}

#[test]
fn a_tool_call_comes_back_as_a_structured_tool_result() {
    let profile = profile_dir();
    let mut server = Harness::start(profile.path(), &[]);
    server.initialize();

    // `get_myself` reaches the real Atlassian endpoint with the synthetic cookie, so
    // the HTTP call must fail — but it must fail as a *tool result*, not a crash or a
    // protocol error, and the message must reach the agent.
    let response = server.call(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "get_myself", "arguments": {} }
    }));

    assert_eq!(response["id"], 3);
    assert!(
        response.get("error").is_none(),
        "a failed tool execution must not be a protocol error: {response}"
    );
    let content = response["result"]["content"]
        .as_array()
        .expect("tool results carry content");
    assert!(!content.is_empty());
    assert_eq!(content[0]["type"], "text");
    assert!(
        response["result"]["isError"] == true,
        "the synthetic cookie cannot be valid, so this should be an error result: {response}"
    );
}

#[test]
fn an_unknown_tool_is_rejected_without_touching_the_network() {
    let profile = profile_dir();
    let mut server = Harness::start(profile.path(), &[]);
    server.initialize();

    let response = server.call(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": { "name": "delete_everything", "arguments": {} }
    }));

    assert_eq!(response["id"], 4);
    assert!(
        response.get("error").is_some(),
        "an unknown tool must be a protocol error: {response}"
    );
}

#[test]
fn exits_with_a_clear_message_when_no_edge_profile_exists() {
    let empty = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_to_completion(empty.path(), &["--site", SITE_URL]);

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stdout.is_empty(),
        "nothing may be written to stdout outside the protocol: {stdout:?}"
    );
    assert!(
        stderr.contains("no Microsoft Edge cookie database found"),
        "got: {stderr}"
    );
    // The message tells the user where it looked.
    assert!(stderr.contains("microsoft-edge"), "got: {stderr}");
}

#[test]
fn exits_with_a_clear_message_when_the_profile_has_no_session_cookie() {
    let config = tempfile::tempdir().unwrap();
    write_edge_profile(
        config.path(),
        "Default",
        &[TestCookie::plain(
            ".example.com",
            "cloud.session.token",
            "nope",
        )],
    );

    let (code, stdout, stderr) = run_to_completion(config.path(), &["--site", SITE_URL]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "got: {stdout:?}");
    assert!(stderr.contains("no Edge session cookie"), "got: {stderr}");
    assert!(stderr.contains("acme.atlassian.net"), "got: {stderr}");
}

fn listed_tool_names(server: &mut Harness) -> Vec<String> {
    let listed = server.call(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
    listed["result"]["tools"]
        .as_array()
        .expect("a tools array")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn each_access_level_exposes_a_different_tool_surface() {
    let profile = profile_dir();
    for (level, expected) in [("read", 10), ("update", 22), ("write", 33), ("full", 37)] {
        let mut server = Harness::start(profile.path(), &["--access-level", level]);
        server.initialize();
        let names = listed_tool_names(&mut server);

        assert_eq!(
            names.len(),
            expected,
            "level {level} saw {} tools: {names:?}",
            names.len()
        );

        // The boundary that matters at each level: the next tier up is invisible.
        let has = |name: &str| names.iter().any(|n| n == name);
        match level {
            "read" => {
                assert!(has("get_issue"));
                assert!(!has("update_issue"));
            }
            "update" => {
                assert!(has("update_issue"));
                assert!(has("update_sprint"));
                assert!(!has("create_issue"));
                assert!(!has("create_sprint"));
            }
            "write" => {
                assert!(has("create_issue"));
                assert!(has("create_sprint"));
                assert!(has("upload_attachment"));
                assert!(!has("create_project"));
            }
            "full" => {
                assert!(has("create_project"));
                assert!(has("remove_group_member"));
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn a_tool_above_the_level_cannot_be_called_even_by_name() {
    // Default level is `read`, so create_issue is not registered at all.
    let profile = profile_dir();
    let mut server = Harness::start(profile.path(), &[]);
    server.initialize();

    let response = server.call(&json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "create_issue",
            "arguments": { "project_key": "ABC", "issue_type": "Task", "summary": "nope" }
        }
    }));

    assert!(
        response.get("error").is_some(),
        "a tool above the session's level must be rejected: {response}"
    );
}

#[test]
fn refuses_to_send_the_session_cookie_to_a_non_atlassian_host() {
    let profile = profile_dir();
    let (code, stdout, stderr) =
        run_to_completion(profile.path(), &["--site", "https://evil.example.com"]);

    assert_eq!(code, 1);
    assert!(stdout.is_empty(), "got: {stdout:?}");
    assert!(
        stderr.contains("not an Atlassian Cloud host"),
        "got: {stderr}"
    );
}

#[test]
fn reports_that_the_session_is_valid_via_check() {
    // `--check` calls the real endpoint with a synthetic cookie, so it must fail with
    // an Atlassian HTTP error rather than succeeding — proving it really called out.
    let profile = profile_dir();
    let (code, _stdout, stderr) =
        run_to_completion(profile.path(), &["--site", SITE_URL, "--check"]);

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("HTTP") || stderr.contains("error"),
        "expected an HTTP failure against the real endpoint, got: {stderr}"
    );
}
