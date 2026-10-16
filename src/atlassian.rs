//! The Atlassian Cloud HTTP client, including the read-only endpoint allowlist.
//!
//! Two independent things keep this server read-only:
//!
//! 1. Only read tools are registered (see [`crate::tools`]).
//! 2. Every request must match [`READONLY_ENDPOINTS`], and the match is on the
//!    *endpoint*, not just the verb — Jira's JQL search is a `POST` that reads.
//!
//! Tool arguments are percent-encoded into single path segments
//! ([`path_segment`]), so a tool argument can never escape the endpoint it belongs to.

use crate::cli::AccessLevel;
use crate::{Error, Result};
use serde_json::Value;
use std::time::Duration;
use url::Url;

/// Identify ourselves honestly rather than impersonating a browser.
pub const USER_AGENT: &str = concat!("omb-atlassian-mcp/", env!("CARGO_PKG_VERSION"));

/// How much of an error body to surface in a message.
const MAX_ERROR_BODY: usize = 600;

/// How long to wait on Atlassian before giving up.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

// Endpoints used by the read tools. Kept as constants so the allowlist and the tools
// cannot drift apart silently.
pub const JIRA_MYSELF: &str = "/rest/api/3/myself";
pub const JIRA_ISSUE_PREFIX: &str = "/rest/api/3/issue/";
pub const JIRA_PROJECT_SEARCH: &str = "/rest/api/3/project/search";
pub const JIRA_SEARCH_JQL: &str = "/rest/api/3/search/jql";
pub const JIRA_SEARCH_LEGACY: &str = "/rest/api/3/search";
pub const CONFLUENCE_SEARCH: &str = "/wiki/rest/api/search";
pub const CONFLUENCE_PAGES: &str = "/wiki/api/v2/pages";
pub const CONFLUENCE_SPACES: &str = "/wiki/api/v2/spaces";

/// One entry of the allowlist: a method and a path prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub method: &'static str,
    pub prefix: &'static str,
}

/// Everything the `readonly` level may call.
///
/// The two `POST`s are read-only searches: Jira's `/search/jql` (the endpoint that
/// replaced the removed `/search`, which is kept as a fallback for sites that predate
/// the migration) and nothing else.
pub const READONLY_ENDPOINTS: &[Endpoint] = &[
    // Identity
    Endpoint {
        method: "GET",
        prefix: JIRA_MYSELF,
    },
    // Jira reads. `JIRA_ISSUE_PREFIX` covers /issue/{key} and /issue/{key}/comment.
    Endpoint {
        method: "GET",
        prefix: JIRA_ISSUE_PREFIX,
    },
    Endpoint {
        method: "GET",
        prefix: JIRA_PROJECT_SEARCH,
    },
    // Jira JQL search: a POST that only reads.
    Endpoint {
        method: "POST",
        prefix: JIRA_SEARCH_JQL,
    },
    Endpoint {
        method: "POST",
        prefix: JIRA_SEARCH_LEGACY,
    },
    // Confluence reads: v1 CQL search, v2 pages (children/footer-comments included),
    // v2 spaces.
    Endpoint {
        method: "GET",
        prefix: CONFLUENCE_SEARCH,
    },
    Endpoint {
        method: "GET",
        prefix: CONFLUENCE_PAGES,
    },
    Endpoint {
        method: "GET",
        prefix: CONFLUENCE_SPACES,
    },
];

/// The allowlist for an access level.
///
/// Levels that are not built yet produce an error rather than a wider or narrower
/// allowlist, so a mistake in argument handling cannot silently change the policy.
pub fn allowed_endpoints(level: AccessLevel) -> Result<&'static [Endpoint]> {
    match level {
        AccessLevel::Readonly => Ok(READONLY_ENDPOINTS),
        other => Err(Error::UnimplementedLevel(other)),
    }
}

/// A validated Atlassian Cloud site URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    url: Url,
}

impl Site {
    /// Parse and validate `--site`.
    ///
    /// Only `https://<something>.atlassian.net` is accepted: the session cookie is a
    /// bearer credential, and pinning the host is what stops it from being sent
    /// somewhere unintended.
    pub fn parse(input: &str) -> Result<Self> {
        let invalid = |reason: String| Error::InvalidSite {
            input: input.to_string(),
            reason,
        };

        let mut url = Url::parse(input).map_err(|e| invalid(e.to_string()))?;
        if url.scheme() != "https" {
            return Err(invalid(format!(
                "the scheme must be https, not {:?}",
                url.scheme()
            )));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(invalid(
                "it must be a bare site URL, without a query string or fragment".to_string(),
            ));
        }

        let host = url
            .host_str()
            .ok_or_else(|| invalid("it has no host".to_string()))?;
        if host != "atlassian.net" && !host.ends_with(".atlassian.net") {
            return Err(invalid(format!(
                "{host:?} is not an Atlassian Cloud host; this server only supports \
                 Atlassian Cloud (*.atlassian.net), because it replays a session cookie"
            )));
        }

        // Drop any path: `--site` identifies the tenant, not a page.
        url.set_path("");
        url.set_query(None);
        url.set_fragment(None);
        Ok(Self { url })
    }

    /// The site host, e.g. `acme.atlassian.net`.
    pub fn host(&self) -> &str {
        self.url.host_str().unwrap_or_default()
    }

    /// `https://host[:port]`, without a trailing slash.
    pub fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }

    /// Build an absolute URL for a path returned by the allowlist.
    pub fn url_for(&self, path: &str) -> Url {
        let mut url = self.url.clone();
        url.set_path(path);
        url
    }
}

/// Percent-encode a tool argument into a single, inert path segment.
///
/// `.` is encoded too, so a value like `../admin` cannot become a dot-segment that the
/// URL parser resolves away.
pub fn path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Whether `path` is covered by `prefix`, respecting segment boundaries so that
/// `/rest/api/3/issue/` cannot be satisfied by `/rest/api/3/issue-evil`.
fn path_matches(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => prefix.ends_with('/') || rest.starts_with('/') || rest.starts_with('?'),
        None => false,
    }
}

/// Whether the path contains a `.` or `..` segment.
///
/// Checked before the allowlist match, because the allowlist sees the raw path while a
/// URL parser (or the server) may resolve dot-segments afterwards. Rejecting them here
/// means the path that was checked is the path that gets sent. No tool ever produces
/// one: [`path_segment`] percent-encodes `.`.
fn has_dot_segment(path: &str) -> bool {
    path.split('/')
        .any(|segment| segment == "." || segment == "..")
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// An authenticated, policy-checked Atlassian Cloud client.
pub struct Client {
    http: reqwest::Client,
    site: Site,
    level: AccessLevel,
    endpoints: &'static [Endpoint],
    cookie_header: String,
}

impl Client {
    /// Build a client for `site` at `level`, authenticating with `cookie_header`.
    pub fn new(site: Site, level: AccessLevel, cookie_header: String) -> Result<Self> {
        let endpoints = allowed_endpoints(level)?;
        let http = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|source| Error::Http {
                url: site.origin(),
                source,
            })?;
        Ok(Self {
            http,
            site,
            level,
            endpoints,
            cookie_header,
        })
    }

    pub fn site(&self) -> &Site {
        &self.site
    }

    pub fn level(&self) -> AccessLevel {
        self.level
    }

    /// Refuse anything outside the allowlist for this access level.
    pub fn check_allowed(&self, method: &str, path: &str) -> Result<()> {
        let allowed = !has_dot_segment(path)
            && self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.method == method && path_matches(path, endpoint.prefix));
        if allowed {
            Ok(())
        } else {
            Err(Error::Blocked {
                level: self.level,
                method: method.to_string(),
                path: path.to_string(),
            })
        }
    }

    /// `GET path` and decode the JSON body.
    pub async fn get_json(&self, path: &str, query: &[(&str, String)]) -> Result<Value> {
        self.send(reqwest::Method::GET, path, query, None).await
    }

    /// `POST path` with a JSON body and decode the JSON response.
    pub async fn post_json(&self, path: &str, body: &Value) -> Result<Value> {
        self.send(reqwest::Method::POST, path, &[], Some(body))
            .await
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        self.check_allowed(method.as_str(), path)?;

        let url = self.site.url_for(path);
        let mut request = self
            .http
            .request(method.clone(), url.clone())
            .query(query)
            .header("Cookie", &self.cookie_header)
            .header("Accept", "application/json")
            // Atlassian bypasses its XSRF check for non-browser callers that declare
            // themselves with this header; required for the POST search endpoints.
            .header("X-Atlassian-Token", "no-check");
        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await.map_err(|source| Error::Http {
            url: url.to_string(),
            source,
        })?;

        let status = response.status();
        let text = response.text().await.map_err(|source| Error::Http {
            url: url.to_string(),
            source,
        })?;

        if !status.is_success() {
            return Err(Error::Api {
                method: method.as_str().to_string(),
                url: url.to_string(),
                status: status.as_u16(),
                body: truncate(&text, MAX_ERROR_BODY),
            });
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| Error::Api {
            method: method.as_str().to_string(),
            url: url.to_string(),
            status: status.as_u16(),
            body: format!(
                "the response was not valid JSON ({e}); body: {}",
                truncate(&text, MAX_ERROR_BODY)
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Client::new(
            Site::parse("https://acme.atlassian.net").unwrap(),
            AccessLevel::Readonly,
            "cloud.session.token=x".to_string(),
        )
        .unwrap()
    }

    #[test]
    fn site_accepts_cloud_hosts() {
        let site = Site::parse("https://acme.atlassian.net").unwrap();
        assert_eq!(site.host(), "acme.atlassian.net");
        assert_eq!(site.origin(), "https://acme.atlassian.net");
        assert_eq!(
            site.url_for("/rest/api/3/myself").as_str(),
            "https://acme.atlassian.net/rest/api/3/myself"
        );
    }

    #[test]
    fn site_normalises_paths_and_trailing_slashes() {
        for input in [
            "https://acme.atlassian.net/",
            "https://acme.atlassian.net/wiki/home",
        ] {
            let site = Site::parse(input).unwrap();
            assert_eq!(site.host(), "acme.atlassian.net");
            assert_eq!(
                site.url_for("/rest/api/3/myself").as_str(),
                "https://acme.atlassian.net/rest/api/3/myself"
            );
        }
    }

    #[test]
    fn site_rejects_anything_that_could_leak_the_cookie() {
        // not https
        assert!(Site::parse("http://acme.atlassian.net").is_err());
        // not Atlassian Cloud
        assert!(Site::parse("https://evil.example.com").is_err());
        assert!(Site::parse("https://atlassian.net.evil.com").is_err());
        assert!(Site::parse("https://notatlassian.net").is_err());
        // query/fragment are meaningless here
        assert!(Site::parse("https://acme.atlassian.net/?x=1").is_err());
        assert!(Site::parse("https://acme.atlassian.net/#f").is_err());
        // not a URL at all
        assert!(Site::parse("acme.atlassian.net").is_err());
    }

    #[test]
    fn path_segments_cannot_escape_their_endpoint() {
        assert_eq!(path_segment("ABC-1"), "ABC-1");
        assert_eq!(path_segment("10001"), "10001");
        for hostile in ["../admin", "a/b", "a?b=c", "a#b", "..", "a b", "a%2Fb"] {
            let encoded = path_segment(hostile);
            assert!(!encoded.contains('/'), "{hostile} -> {encoded}");
            assert!(!encoded.contains('.'), "{hostile} -> {encoded}");
            assert!(!encoded.contains('?'), "{hostile} -> {encoded}");
            assert!(!encoded.contains('#'), "{hostile} -> {encoded}");
            // A literal percent sign in the input must be escaped, never passed through
            // where it could combine with the surrounding encoding.
            if hostile.contains('%') {
                assert!(encoded.contains("%25"), "{hostile} -> {encoded}");
            }
        }
        assert_eq!(path_segment("../admin"), "%2E%2E%2Fadmin");
        assert_eq!(path_segment("a%2Fb"), "a%252Fb");
    }

    #[test]
    fn dot_segments_are_refused_even_though_the_allowlist_prefix_matches() {
        let client = client();
        // These match an allowlisted prefix, but would be resolved into a different
        // endpoint by a URL parser or by the server, so they must not pass the check.
        for path in [
            "/rest/api/3/myself/../../admin",
            "/wiki/api/v2/pages/../../../../admin",
            "/rest/api/3/issue/./ABC-1",
            "/wiki/api/v2/./spaces",
        ] {
            assert!(
                client.check_allowed("GET", path).is_err(),
                "{path} must not be allowed"
            );
        }
    }

    #[test]
    fn the_path_that_was_checked_is_the_path_that_is_sent() {
        // Whatever the allowlist accepts must survive URL construction unchanged, so a
        // check can never be invalidated between checking and sending.
        let site = Site::parse("https://acme.atlassian.net").unwrap();
        for path in [
            "/rest/api/3/myself",
            "/rest/api/3/issue/ABC-1",
            "/wiki/api/v2/pages/123/children",
        ] {
            assert_eq!(site.url_for(path).path(), path);
        }
    }

    #[test]
    fn readonly_allows_the_read_endpoints() {
        let client = client();
        for (method, path) in [
            ("GET", JIRA_MYSELF),
            ("GET", "/rest/api/3/issue/ABC-1"),
            ("GET", "/rest/api/3/issue/ABC-1/comment"),
            ("GET", JIRA_PROJECT_SEARCH),
            ("POST", JIRA_SEARCH_JQL),
            ("POST", JIRA_SEARCH_LEGACY),
            ("GET", CONFLUENCE_SEARCH),
            ("GET", "/wiki/api/v2/pages/123"),
            ("GET", "/wiki/api/v2/pages/123/children"),
            ("GET", "/wiki/api/v2/pages/123/footer-comments"),
            ("GET", CONFLUENCE_SPACES),
        ] {
            assert!(
                client.check_allowed(method, path).is_ok(),
                "{method} {path} should be allowed"
            );
        }
    }

    #[test]
    fn readonly_blocks_writes_and_unknown_endpoints() {
        let client = client();
        for (method, path) in [
            // write verbs on things we may read
            ("PUT", "/rest/api/3/issue/ABC-1"),
            ("DELETE", "/rest/api/3/issue/ABC-1"),
            ("POST", "/rest/api/3/issue/ABC-1"),
            ("POST", "/wiki/api/v2/pages"),
            ("PUT", "/wiki/api/v2/pages/123"),
            ("DELETE", "/wiki/api/v2/pages/123"),
            ("POST", "/wiki/rest/api/content"),
            // endpoints we never use
            ("GET", "/rest/api/3/user/search"),
            ("GET", "/rest/api/3/configuration"),
            ("GET", "/wiki/api/v2/blogposts"),
            ("GET", "/admin"),
            // prefix boundary traps
            ("GET", "/rest/api/3/issue-evil"),
            ("GET", "/wiki/api/v2/pagesX"),
            ("GET", "/rest/api/3/myself/../../admin"),
        ] {
            let error = client
                .check_allowed(method, path)
                .expect_err("this request should be blocked by the read-only allowlist");
            assert!(
                matches!(error, Error::Blocked { .. }),
                "{method} {path} produced {error:?}"
            );
        }
    }

    #[test]
    fn the_only_posts_in_the_readonly_allowlist_are_searches() {
        for endpoint in READONLY_ENDPOINTS {
            match endpoint.method {
                "GET" => {}
                "POST" => assert!(
                    endpoint.prefix.ends_with("/search")
                        || endpoint.prefix.ends_with("/search/jql"),
                    "unexpected POST endpoint in the read-only allowlist: {}",
                    endpoint.prefix
                ),
                other => panic!("unexpected method {other} in the read-only allowlist"),
            }
        }
    }

    #[test]
    fn unimplemented_levels_have_no_allowlist() {
        assert!(allowed_endpoints(AccessLevel::Readonly).is_ok());
        assert!(allowed_endpoints(AccessLevel::Full).is_err());
        assert!(allowed_endpoints(AccessLevel::ReadUpdate).is_err());
    }

    #[test]
    fn error_bodies_are_truncated_on_a_char_boundary() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("abcdef", 3), "abc…");
        // multi-byte characters must not be split
        assert_eq!(truncate("héllo", 2), "h…");
    }
}
