//! Shared test helpers: a synthetic, Chromium-shaped Edge profile.
//!
//! Edge is not required to run these tests. The database written here mirrors the real
//! cookie schema, and it is placed in the platform's own layout so the same tests work
//! on Linux, macOS and Windows CI runners.

#![allow(dead_code)]

use omb_atlassian_mcp::browser::cookie_db::CHROMIUM_EPOCH_OFFSET_SECS;
use omb_atlassian_mcp::decrypt::{derive_key, encrypt_cookie_value};
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};

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
    /// Password to encrypt with; `None` stores the value in plaintext, as Chromium does
    /// for non-sensitive cookies.
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
        self.expires_utc = (978_307_200 + CHROMIUM_EPOCH_OFFSET_SECS) * 1_000_000;
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
                // Must match the count the server uses on this platform.
                let key = derive_key(password, omb_atlassian_mcp::browser::ITERATIONS);
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

/// A temporary directory plus the environment variables that point the server at it.
///
/// The server reads the platform's own location (`XDG_CONFIG_HOME` on Linux, `HOME` on
/// macOS, `LOCALAPPDATA` on Windows), so the same synthetic profile works everywhere.
pub struct TestEnv {
    temp: tempfile::TempDir,
    vars: Vec<(&'static str, String)>,
}

impl TestEnv {
    /// The directory the server should treat as its configuration root.
    pub fn root(&self) -> &Path {
        Path::new(&self.vars[0].1)
    }

    /// Environment variables to set on a child process.
    pub fn vars(&self) -> &[(&'static str, String)] {
        &self.vars
    }

    /// A temp dir that holds no Edge profile at all.
    pub fn empty(profile: &str) -> Self {
        Self::with_cookies(profile, &[])
    }

    /// A temp dir holding an Edge profile with these cookies.
    pub fn with_cookies(profile: &str, cookies: &[TestCookie]) -> Self {
        // The platform's configuration root, and where the profile lives inside it.
        let (variable, relative_root): (&'static str, &str) = if cfg!(target_os = "macos") {
            ("HOME", "home")
        } else if cfg!(target_os = "windows") {
            ("LOCALAPPDATA", "localappdata")
        } else {
            ("XDG_CONFIG_HOME", "xdg")
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().join(relative_root);
        std::fs::create_dir_all(&root).expect("create the config root");

        if !cookies.is_empty() {
            let db = cookie_db_path(&root, profile);
            std::fs::create_dir_all(db.parent().expect("profile dir")).expect("create profile");
            write_cookie_db(&db, cookies);
        }

        Self {
            temp,
            vars: vec![(variable, root.to_string_lossy().into_owned())],
        }
    }

    /// Keep the temporary directory alive.
    pub fn temp(&self) -> &tempfile::TempDir {
        &self.temp
    }
}

/// Where Edge keeps `Cookies` for `profile`, relative to the configuration root.
fn cookie_db_path(root: &Path, profile: &str) -> PathBuf {
    if cfg!(target_os = "macos") {
        root.join("Library/Application Support")
            .join("Microsoft Edge")
            .join(profile)
            .join("Cookies")
    } else if cfg!(target_os = "windows") {
        root.join("Microsoft")
            .join("Edge")
            .join("User Data")
            .join(profile)
            .join("Network")
            .join("Cookies")
    } else {
        root.join("microsoft-edge").join(profile).join("Cookies")
    }
}

/// The site the tests pretend to talk to.
pub const SITE_URL: &str = "https://acme.atlassian.net";

/// The host key Atlassian actually sets its Cloud session cookies under.
pub const ATLASSIAN_DOMAIN: &str = ".atlassian.net";

/// A plausible Atlassian Cloud session cookie set.
///
/// On Windows these are stored in plaintext: the real key comes from DPAPI, which a
/// synthetic profile cannot reproduce. The Windows cipher itself is covered by unit
/// tests that build AES-GCM values directly.
pub fn session_cookies(password: &str) -> Vec<TestCookie> {
    let cookie = |host: &str, name: &str, value: &str| {
        if cfg!(target_os = "windows") {
            TestCookie::plain(host, name, value)
        } else {
            TestCookie::encrypted(host, name, value, password)
        }
    };
    vec![
        cookie(ATLASSIAN_DOMAIN, "cloud.session.token", "cloud-token"),
        cookie("acme.atlassian.net", "tenant.session.token", "tenant-token"),
        // An unrelated Atlassian cookie that must not reach the header.
        cookie(ATLASSIAN_DOMAIN, "atlassian.xsrf.token", "xsrf-value"),
        // A same-named cookie for a different tenant.
        cookie(
            ".other-tenant.atlassian.net",
            "cloud.session.token",
            "other-tenant-token",
        ),
        // A same-named cookie for an unrelated domain.
        cookie("example.com", "cloud.session.token", "example-token"),
    ]
}

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

/// MCP framing over stdio is one JSON-RPC message per line.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(90);

pub const BIN: &str = env!("CARGO_BIN_EXE_omb-atlassian-mcp");

pub struct Harness {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    /// The server's stderr, captured so a crash can explain itself.
    stderr_path: PathBuf,
    _stderr_dir: tempfile::TempDir,
}

impl Harness {
    /// Start the server pointed at a synthetic Edge profile (or an empty one).
    pub fn start(env: &TestEnv, extra_args: &[&str]) -> Self {
        let mut command = Command::new(BIN);
        // Capture stderr to a file: if the server dies before answering, its own
        // diagnostics are the only way to know why.
        let stderr_dir = tempfile::tempdir().expect("temp dir for stderr");
        let stderr_path = stderr_dir.path().join("stderr.log");
        let stderr = std::fs::File::create(&stderr_path).expect("create the stderr log");

        command
            .arg("--site")
            .arg(SITE_URL)
            .args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr));
        // Point the server at the platform's own configuration root.
        for (key, value) in env.vars() {
            command.env(key, value);
        }
        let mut child = command.spawn().expect("spawn the server");

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
            stderr_path,
            _stderr_dir: stderr_dir,
        }
    }

    pub fn send(&mut self, message: &Value) {
        writeln!(self.stdin, "{message}").expect("write to the server");
        self.stdin.flush().expect("flush");
    }

    pub fn receive(&self) -> Value {
        match self.lines.recv_timeout(RESPONSE_TIMEOUT) {
            Ok(line) => serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout must carry only JSON-RPC, got {line:?}: {e}")),
            Err(RecvTimeoutError::Timeout) => {
                panic!("no response within {RESPONSE_TIMEOUT:?}")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!(
                    "the server closed stdout without answering. Its stderr was:\n{}",
                    self.stderr()
                )
            }
        }
    }

    /// The server's stderr so far. Reads twice, because the process may still be
    /// flushing when stdout closes.
    fn stderr(&self) -> String {
        let read = || std::fs::read_to_string(&self.stderr_path).unwrap_or_default();
        let first = read();
        if !first.is_empty() {
            return first;
        }
        std::thread::sleep(Duration::from_millis(100));
        read()
    }

    pub fn call(&mut self, message: &Value) -> Value {
        self.send(message);
        self.receive()
    }

    /// Names of the tools the server currently exposes.
    pub fn visible_tools(&mut self) -> Vec<String> {
        let listed = self.call(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }));
        listed["result"]["tools"]
            .as_array()
            .expect("a tools array")
            .iter()
            .map(|tool| tool["name"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// Complete the MCP handshake and return the `initialize` result.
    pub fn initialize(&mut self) -> Value {
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

/// Run the binary to completion and return (exit code, stdout, stderr).
pub fn run_to_completion(env: &TestEnv, args: &[&str]) -> (i32, String, String) {
    let mut command = Command::new(BIN);
    command.args(args).stdin(Stdio::null());
    for (key, value) in env.vars() {
        command.env(key, value);
    }
    let output = command.output().expect("run the server");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}
