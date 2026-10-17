//! Error type shared by the whole crate.

use crate::cli::AccessLevel;

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong on the way to serving a request.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "no Microsoft Edge cookie database found (looked in: {})",
        .searched.join(", ")
    )]
    ProfileNotFound { searched: Vec<String> },

    #[error("could not read the Edge cookie database at {path}: {reason}")]
    CookieDb { path: String, reason: String },

    #[error(
        "no Edge session cookie for {site} in the {profile} profile \
         (wanted one of {wanted:?}; Atlassian cookies found: {seen:?}). \
         Open Edge, sign in to {site}, and retry."
    )]
    NoSessionCookie {
        site: String,
        profile: String,
        wanted: Vec<String>,
        seen: Vec<String>,
    },

    #[error(
        "found {count} session cookie(s) for {host} but none could be decrypted \
         (key source: {key_source}). Details: {details}"
    )]
    Undecryptable {
        host: String,
        count: usize,
        key_source: String,
        details: String,
    },

    #[error("could not find {what} (looked in: {})", .searched.join(", "))]
    NotFound { what: String, searched: Vec<String> },

    #[error(
        "could not use the cookie file {path}: {reason}. The file must contain a `Cookie:` \
         header value or a JSON object with cloud.session.token / tenant.session.token"
    )]
    CookieFile { path: String, reason: String },

    #[error("this platform is not supported; build for Linux, macOS or Windows")]
    UnsupportedPlatform,

    #[error(
        "the Edge session cookie for {host} expired at {expired_at}; \
         sign in to {host} in Edge again"
    )]
    SessionExpired { host: String, expired_at: String },

    #[error("blocked: {method} {path} is not on the allowlist for access level '{level}'")]
    Blocked {
        level: AccessLevel,
        method: String,
        path: String,
    },

    #[error(
        "blocked: {method} {path} requires access level '{required}' or higher; \
         this session is '{session}'"
    )]
    RequiresLevel {
        session: AccessLevel,
        required: AccessLevel,
        method: String,
        path: String,
    },

    #[error("blocked: {method} {path} is permanently disabled, at every access level")]
    Forbidden { method: String, path: String },

    #[error("{method} {url} failed: HTTP {status}: {body}")]
    Api {
        method: String,
        url: String,
        status: u16,
        body: String,
    },

    #[error("network error calling {url}: {source}")]
    Http { url: String, source: reqwest::Error },

    #[error("invalid --site value {input:?}: {reason}")]
    InvalidSite { input: String, reason: String },

    #[error("the MCP server stopped: {0}")]
    Mcp(String),
}

impl Error {
    /// True when the failure means "sign in to Atlassian in Edge again".
    pub fn is_auth_failure(&self) -> bool {
        matches!(
            self,
            Self::SessionExpired { .. } | Self::NoSessionCookie { .. }
        )
    }

    /// HTTP status, when the error came back from Atlassian.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Api { status, .. } => Some(*status),
            _ => None,
        }
    }
}
