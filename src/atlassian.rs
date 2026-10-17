//! The Atlassian Cloud HTTP client.
//!
//! Every request is checked against [`crate::policy`] before it is sent. The policy names,
//! for each endpoint, the lowest access level allowed to call it; matching is by whole
//! path segments, and anything the policy does not name is refused at every level.
//!
//! Tool arguments are percent-encoded into single path segments
//! ([`path_segment`]), so a tool argument can never escape the endpoint it belongs to.

use crate::cli::AccessLevel;
use crate::policy;
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

// Paths used by the tools, kept as constants so the tools and the policy cannot drift
// apart silently.
pub const JIRA_MYSELF: &str = "/rest/api/3/myself";
pub const JIRA_ISSUE_PREFIX: &str = "/rest/api/3/issue/";
pub const JIRA_PROJECT_SEARCH: &str = "/rest/api/3/project/search";
pub const JIRA_SEARCH_JQL: &str = "/rest/api/3/search/jql";
pub const JIRA_SEARCH_LEGACY: &str = "/rest/api/3/search";
pub const CONFLUENCE_SEARCH: &str = "/wiki/rest/api/search";
pub const CONFLUENCE_PAGES: &str = "/wiki/api/v2/pages";
pub const CONFLUENCE_SPACES: &str = "/wiki/api/v2/spaces";

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

/// Whether the path contains a `.` or `..` segment.
///
/// Checked before the policy match, because the policy sees the raw path while a URL
/// parser (or the server) may resolve dot-segments afterwards. Rejecting them here
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
    cookie_header: String,
}

impl Client {
    /// Build a client for `site` at `level`, authenticating with `cookie_header`.
    pub fn new(site: Site, level: AccessLevel, cookie_header: String) -> Result<Self> {
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
            cookie_header,
        })
    }

    pub fn site(&self) -> &Site {
        &self.site
    }

    pub fn level(&self) -> AccessLevel {
        self.level
    }

    /// Refuse anything the policy does not permit at this session's level.
    ///
    /// The three refusals are deliberately distinguishable, because they mean different
    /// things to the user: an endpoint that would work at a higher level is a
    /// configuration choice, while an unlisted or `never` endpoint is not available at
    /// all.
    pub fn check_allowed(&self, method: &str, path: &str) -> Result<()> {
        if !has_dot_segment(path) {
            if policy::is_forbidden(method, path) {
                return Err(Error::Forbidden {
                    method: method.to_string(),
                    path: path.to_string(),
                });
            }
            if let Some(entry) = policy::policy_for(method, path) {
                return if self.level >= entry.level {
                    Ok(())
                } else {
                    Err(Error::RequiresLevel {
                        session: self.level,
                        required: entry.level,
                        method: method.to_string(),
                        path: path.to_string(),
                    })
                };
            }
        }
        Err(Error::Blocked {
            level: self.level,
            method: method.to_string(),
            path: path.to_string(),
        })
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

    /// `POST path` with query parameters and a JSON body.
    pub async fn post_json_with_query(
        &self,
        path: &str,
        query: &[(&str, String)],
        body: &Value,
    ) -> Result<Value> {
        self.send(reqwest::Method::POST, path, query, Some(body))
            .await
    }

    /// `PUT path` with a JSON body and decode the JSON response.
    pub async fn put_json(&self, path: &str, body: &Value) -> Result<Value> {
        self.send(reqwest::Method::PUT, path, &[], Some(body)).await
    }

    /// `DELETE path` and decode the JSON response, if any.
    pub async fn delete_json(&self, path: &str, query: &[(&str, String)]) -> Result<Value> {
        self.send(reqwest::Method::DELETE, path, query, None).await
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

        self.parse_response(method.as_str(), &url, response).await
    }

    /// Upload a text payload as a Confluence attachment.
    ///
    /// The content is supplied by the caller as a string, never as a path: this server
    /// deliberately has no way to read an arbitrary local file, so a tool cannot be
    /// turned into a file-exfiltration primitive.
    pub async fn upload_text_attachment(
        &self,
        path: &str,
        filename: &str,
        content: String,
        comment: Option<String>,
    ) -> Result<Value> {
        self.check_allowed("POST", path)?;

        let mut form = reqwest::multipart::Form::new()
            // The Confluence API requires `minorEdit` alongside the file part.
            .text("minorEdit", "false")
            .part(
                "file",
                reqwest::multipart::Part::text(content).file_name(filename.to_string()),
            );
        if let Some(comment) = comment {
            form = form.text("comment", comment);
        }

        let url = self.site.url_for(path);
        let response = self
            .http
            .post(url.clone())
            .header("Cookie", &self.cookie_header)
            .header("Accept", "application/json")
            .header("X-Atlassian-Token", "no-check")
            .multipart(form)
            .send()
            .await
            .map_err(|source| Error::Http {
                url: url.to_string(),
                source,
            })?;

        self.parse_response("POST", &url, response).await
    }

    /// Turn a response into a JSON value, or into an error that says what happened.
    async fn parse_response(
        &self,
        method: &str,
        url: &Url,
        response: reqwest::Response,
    ) -> Result<Value> {
        let status = response.status();
        let text = response.text().await.map_err(|source| Error::Http {
            url: url.to_string(),
            source,
        })?;

        if !status.is_success() {
            return Err(Error::Api {
                method: method.to_string(),
                url: url.to_string(),
                status: status.as_u16(),
                body: truncate(&text, MAX_ERROR_BODY),
            });
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| Error::Api {
            method: method.to_string(),
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
            AccessLevel::Read,
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

    fn client_at(level: AccessLevel) -> Client {
        Client::new(
            Site::parse("https://acme.atlassian.net").unwrap(),
            level,
            "cloud.session.token=x".to_string(),
        )
        .unwrap()
    }

    const LEVELS: [AccessLevel; 4] = [
        AccessLevel::Read,
        AccessLevel::Update,
        AccessLevel::Write,
        AccessLevel::Full,
    ];

    #[test]
    fn each_level_allows_exactly_what_the_ladder_says() {
        // (method, path, lowest level that may call it)
        let cases = [
            ("GET", "/rest/api/3/issue/ABC-1", AccessLevel::Read),
            ("POST", "/rest/api/3/search/jql", AccessLevel::Read),
            ("GET", "/wiki/api/v2/pages/123", AccessLevel::Read),
            ("PUT", "/rest/api/3/issue/ABC-1", AccessLevel::Update),
            (
                "POST",
                "/rest/api/3/issue/ABC-1/transitions",
                AccessLevel::Update,
            ),
            ("PUT", "/wiki/api/v2/pages/123", AccessLevel::Update),
            ("POST", "/rest/api/3/issue", AccessLevel::Write),
            ("DELETE", "/rest/api/3/issue/ABC-1", AccessLevel::Write),
            ("DELETE", "/wiki/api/v2/pages/123", AccessLevel::Write),
            ("POST", "/rest/api/3/user", AccessLevel::Full),
            ("POST", "/wiki/api/v2/spaces", AccessLevel::Full),
        ];

        for (method, path, required) in cases {
            for level in LEVELS {
                let result = client_at(level).check_allowed(method, path);
                if level >= required {
                    assert!(
                        result.is_ok(),
                        "{method} {path} at '{level}' should be allowed, got {result:?}"
                    );
                } else {
                    match result.expect_err("should be refused") {
                        Error::RequiresLevel {
                            required: needed, ..
                        } => assert_eq!(
                            needed, required,
                            "{method} {path} at '{level}' named the wrong requirement"
                        ),
                        other => panic!("{method} {path} at '{level}' gave {other:?}"),
                    }
                }
            }
        }
    }

    #[test]
    fn unlisted_endpoints_are_blocked_at_every_level() {
        for level in LEVELS {
            for (method, path) in [
                ("GET", "/rest/api/3/configuration"),
                ("POST", "/wiki/rest/api/content"),
                ("PUT", "/rest/api/3/user"),
                ("GET", "/admin"),
                ("PATCH", "/rest/api/3/issue/ABC-1"),
            ] {
                let error = client_at(level)
                    .check_allowed(method, path)
                    .expect_err("not on the allowlist");
                assert!(
                    matches!(error, Error::Blocked { .. }),
                    "{method} {path} at '{level}' produced {error:?}"
                );
            }
        }
    }

    #[test]
    fn never_endpoints_are_forbidden_at_every_level() {
        for level in LEVELS {
            let error = client_at(level)
                .check_allowed("POST", "/wiki/api/v2/pages/123/redact")
                .expect_err("redaction is never allowed");
            assert!(
                matches!(error, Error::Forbidden { .. }),
                "'{level}' produced {error:?}"
            );
        }
    }

    #[test]
    fn a_parent_path_does_not_imply_its_sub_resources() {
        // Segment matching, not prefix matching: each of these differs from an
        // allowlisted pattern by at least one whole segment.
        let client = client_at(AccessLevel::Full);
        for (method, path) in [
            ("POST", "/rest/api/3/issue/ABC-1"), // no such endpoint; create is POST /issue
            ("GET", "/rest/api/3/issue/ABC-1/"), // trailing slash is an empty segment
            ("GET", "/rest/api/3/myself/extra"), // one segment too many
            ("PUT", "/rest/api/3/issue"),        // one segment too few
        ] {
            assert!(
                client.check_allowed(method, path).is_err(),
                "{method} {path} must not be allowed"
            );
        }
    }

    #[test]
    fn the_only_posts_at_read_level_are_known_read_operations() {
        // Every POST at read level must be justified here. A new one has to be added
        // deliberately, so a mutating POST cannot slip into the read level unnoticed.
        const READ_ONLY_POSTS: [&str; 3] = [
            "/rest/api/3/search",
            "/rest/api/3/search/jql",
            "/rest/api/3/jql/parse",
        ];
        for entry in crate::policy::ENDPOINT_POLICY {
            if entry.level == AccessLevel::Read && entry.method == "POST" {
                assert!(
                    READ_ONLY_POSTS.contains(&entry.pattern),
                    "unexpected POST at read level: {}",
                    entry.pattern
                );
            }
        }
    }

    #[test]
    fn error_bodies_are_truncated_on_a_char_boundary() {
        assert_eq!(truncate("abc", 10), "abc");
        assert_eq!(truncate("abcdef", 3), "abc…");
        // multi-byte characters must not be split
        assert_eq!(truncate("héllo", 2), "h…");
    }
}
