//! A manually supplied session cookie.
//!
//! `--session-cookie-file` is the escape hatch for profiles this server cannot decrypt —
//! notably Windows app-bound (`v20`) cookies — and the simplest way to use the server
//! without touching a browser at all.
//!
//! The file holds either a raw `Cookie:` header value or a JSON object mapping cookie
//! names to values:
//!
//! ```text
//! cloud.session.token=abc; tenant.session.token=def
//! ```
//!
//! ```json
//! { "cloud.session.token": "abc", "tenant.session.token": "def" }
//! ```

use crate::session::SESSION_COOKIE_NAMES;
use crate::{Error, Result};
use std::path::Path;

/// A parsed cookie file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieFile {
    /// Ready-to-send `Cookie` header value.
    pub header: String,
    /// The cookie names it carried.
    pub names: Vec<String>,
}

/// Read and validate the cookie file at `path`.
pub fn read(path: &Path) -> Result<CookieFile> {
    warn_if_readable_by_others(path);
    let contents = std::fs::read_to_string(path).map_err(|e| Error::CookieFile {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    parse(&contents).map_err(|reason| Error::CookieFile {
        path: path.display().to_string(),
        reason,
    })
}

/// Parse either supported format.
pub fn parse(contents: &str) -> std::result::Result<CookieFile, String> {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err("the file is empty".to_string());
    }

    let mut pairs = if trimmed.starts_with('{') || trimmed.starts_with('[') {
        from_json(trimmed)?
    } else {
        from_header(trimmed)?
    };
    if pairs.is_empty() {
        return Err("no cookies found".to_string());
    }

    // Deterministic order, so the same file always produces the same header.
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let names: Vec<String> = pairs.iter().map(|(name, _)| name.clone()).collect();
    if !names
        .iter()
        .any(|name| SESSION_COOKIE_NAMES.contains(&name.as_str()))
    {
        return Err(format!(
            "it must contain one of {SESSION_COOKIE_NAMES:?}, otherwise there is nothing to \
             authenticate with"
        ));
    }

    let header = pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    Ok(CookieFile { header, names })
}

fn from_header(contents: &str) -> std::result::Result<Vec<(String, String)>, String> {
    let value = contents
        .strip_prefix("Cookie:")
        .or_else(|| contents.strip_prefix("cookie:"))
        .unwrap_or(contents);

    let mut pairs = Vec::new();
    for part in value.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| format!("{part:?} is not in name=value form"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err("a cookie has an empty name".to_string());
        }
        pairs.push((name.to_string(), value.trim().to_string()));
    }
    Ok(pairs)
}

fn from_json(contents: &str) -> std::result::Result<Vec<(String, String)>, String> {
    let value: serde_json::Value =
        serde_json::from_str(contents).map_err(|e| format!("not valid JSON: {e}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "the JSON must be an object mapping cookie names to values".to_string())?;

    let mut pairs = Vec::new();
    for (name, value) in object {
        let value = value
            .as_str()
            .ok_or_else(|| format!("cookie {name:?} must have a string value"))?;
        pairs.push((name.clone(), value.to_string()));
    }
    Ok(pairs)
}

/// The file is a bearer credential; nudge the user if it is wider than it needs to be.
#[cfg(unix)]
fn warn_if_readable_by_others(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            crate::log!(
                "warning: {} is readable by other users (mode {:o}); consider: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_readable_by_others(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_header_is_parsed() {
        let file = parse("cloud.session.token=abc; tenant.session.token=def").unwrap();
        assert_eq!(
            file.header,
            "cloud.session.token=abc; tenant.session.token=def"
        );
        assert_eq!(file.names, SESSION_COOKIE_NAMES);
    }

    #[test]
    fn a_cookie_prefix_and_arbitrary_whitespace_are_tolerated() {
        let file = parse("Cookie:  cloud.session.token=abc ;\n  other=1 \n").unwrap();
        assert!(file.header.contains("cloud.session.token=abc"));
        assert!(file.header.contains("other=1"));
    }

    #[test]
    fn json_is_accepted_too() {
        let file =
            parse(r#"{ "tenant.session.token": "def", "cloud.session.token": "abc" }"#).unwrap();
        // Sorted, so the header is stable regardless of the JSON order.
        assert_eq!(
            file.header,
            "cloud.session.token=abc; tenant.session.token=def"
        );
    }

    #[test]
    fn values_may_contain_equals_signs() {
        let file = parse("cloud.session.token=abc==; x=y").unwrap();
        assert!(file.header.contains("cloud.session.token=abc=="));
    }

    #[test]
    fn a_file_without_a_session_cookie_is_rejected() {
        let error = parse("some.other.cookie=1").unwrap_err();
        assert!(error.contains("cloud.session.token"), "got: {error}");
    }

    #[test]
    fn malformed_input_is_explained() {
        assert!(parse("").unwrap_err().contains("empty"));
        assert!(parse("   \n ").unwrap_err().contains("empty"));
        assert!(parse("nonsense").unwrap_err().contains("name=value"));
        assert!(parse("=value").unwrap_err().contains("empty name"));
        assert!(
            parse(r#"{"cloud.session.token": 1}"#)
                .unwrap_err()
                .contains("string value")
        );
        assert!(parse("[1,2]").unwrap_err().contains("object"));
        assert!(parse("{oops").unwrap_err().contains("JSON"));
    }

    #[test]
    fn a_missing_file_is_a_cookie_file_error() {
        let error = read(Path::new("/nonexistent/cookies.txt")).unwrap_err();
        assert!(matches!(error, Error::CookieFile { .. }), "got {error:?}");
    }

    #[test]
    fn a_real_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cookies.txt");
        std::fs::write(&path, "cloud.session.token=abc\n").unwrap();
        let file = read(&path).unwrap();
        assert_eq!(file.header, "cloud.session.token=abc");
    }
}
