//! `omb-atlassian-mcp` — an *on my behalf* MCP server for Atlassian Cloud.
//!
//! The server authenticates to Confluence and Jira by reusing the Atlassian session
//! cookie that already lives in the local Microsoft Edge profile, instead of asking the
//! user for an API token. What the agent may do is bounded by `--access-level`.
//!
//! Module map:
//!
//! - [`decrypt`] — Chromium's Linux cookie encryption (PBKDF2 + AES-128-CBC).
//! - [`keyring`] — best-effort lookup of the "Safe Storage" password in the OS keyring.
//! - [`edge`] — locating and reading the Edge cookie database.
//! - [`session`] — turning the Edge profile into a usable Atlassian session cookie.
//! - [`policy`] — which access level may call which endpoint.
//! - [`atlassian`] — the HTTP client, which enforces [`policy`].
//! - [`tools`] — the MCP tool surface exposed to the agent.
//!
//! All diagnostics go to stderr; stdout is reserved for the MCP protocol stream.

pub mod atlassian;
pub mod cli;
pub mod decrypt;
pub mod edge;
pub mod error;
pub mod keyring;
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
