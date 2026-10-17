//! `omb-atlassian-mcp` — an *on my behalf* MCP server for Atlassian Cloud.
//!
//! The server authenticates to Confluence and Jira by reusing the Atlassian session
//! cookie that already lives in the local Microsoft Edge profile (Linux, macOS and
//! Windows), instead of asking the user for an API token. What the agent may do is
//! bounded by `--access-level`.
//!
//! Module map:
//!
//! - [`decrypt`] — Chromium's cookie ciphers (AES-128-CBC, AES-256-GCM).
//! - [`browser`] — per-platform profile discovery and key retrieval.
//! - [`cookie_file`] — the manual `--session-cookie-file` alternative.
//! - [`session`] — turning a profile or cookie file into an Atlassian session cookie.
//! - [`policy`] — which access level may call which endpoint.
//! - [`atlassian`] — the HTTP client, which enforces [`policy`].
//! - [`tools`] — the MCP tool surface exposed to the agent.
//!
//! All diagnostics go to stderr; stdout is reserved for the MCP protocol stream.

pub mod atlassian;
pub mod browser;
pub mod cli;
pub mod cookie_file;
pub mod decrypt;
pub mod error;
pub mod policy;
pub mod session;
pub mod tools;

pub use error::{Error, Result};

/// Emit a diagnostic line on stderr.
///
/// stdout carries the MCP protocol stream, so every diagnostic — including any hint of
/// why a session could not be acquired — must go to stderr instead.
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        eprintln!("[{}] {}", $crate::SERVER_NAME, ::std::format_args!($($arg)*))
    };
}

/// Name reported to MCP clients during initialization.
pub const SERVER_NAME: &str = "omb-atlassian-mcp";

/// Version reported to MCP clients during initialization.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
