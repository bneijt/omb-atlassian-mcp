//! The endpoint policy: which access level may call what.
//!
//! The table itself lives in [`data`] — generated from the classification in
//! `docs/access-levels.md`. This module holds the matching logic and its invariants.
//!
//! Matching is by whole segments, never by prefix: `{}` matches exactly one non-empty
//! segment, so `/rest/api/3/issue/{}` authorises `/rest/api/3/issue/ABC-1` but not
//! `/rest/api/3/issue/ABC-1/transitions`. When two patterns both match, the one with
//! more literal segments wins (`/project/search` beats `/project/{}`).

mod data;

pub use data::{ENDPOINT_POLICY, EndpointPolicy, NEVER_ENDPOINTS};

/// Whether a policy pattern matches a concrete request path.
///
/// Both are split on `/` and must have the same number of segments. A pattern segment
/// of `{}` matches exactly one non-empty segment; anything else must match literally.
pub fn pattern_matches(pattern: &str, path: &str) -> bool {
    let mut pattern_segments = pattern.split('/');
    let mut path_segments = path.split('/');
    loop {
        match (pattern_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some(expected), Some(actual)) => {
                if expected == "{}" {
                    if actual.is_empty() {
                        return false;
                    }
                } else if expected != actual {
                    return false;
                }
            }
            // Different segment counts: not the same endpoint.
            _ => return false,
        }
    }
}

/// Number of literal (non-`{}`) segments — higher is more specific.
fn specificity(pattern: &str) -> usize {
    pattern
        .split('/')
        .filter(|segment| *segment != "{}")
        .count()
}

/// The policy row that governs `method` + `path`.
///
/// Returns the most specific match. `None` means the endpoint is not on the allowlist
/// at any level.
pub fn policy_for(method: &str, path: &str) -> Option<&'static EndpointPolicy> {
    ENDPOINT_POLICY
        .iter()
        .filter(|entry| entry.method == method && pattern_matches(entry.pattern, path))
        .max_by_key(|entry| specificity(entry.pattern))
}

/// Whether this endpoint is one that no access level may call.
///
/// Checked before [`policy_for`], so a broad policy row can never shadow a `never`
/// entry.
pub fn is_forbidden(method: &str, path: &str) -> bool {
    NEVER_ENDPOINTS
        .iter()
        .any(|(never_method, pattern)| *never_method == method && pattern_matches(pattern, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::AccessLevel;

    #[test]
    fn patterns_match_whole_segments_only() {
        assert!(pattern_matches(
            "/rest/api/3/issue/{}",
            "/rest/api/3/issue/ABC-1"
        ));
        assert!(pattern_matches(
            "/rest/api/3/issue/{}",
            "/rest/api/3/issue/10001"
        ));
        // one segment too many
        assert!(!pattern_matches(
            "/rest/api/3/issue/{}",
            "/rest/api/3/issue/ABC-1/transitions"
        ));
        // one segment too few
        assert!(!pattern_matches(
            "/rest/api/3/issue/{}",
            "/rest/api/3/issue"
        ));
        // `{}` needs a non-empty segment
        assert!(!pattern_matches(
            "/rest/api/3/issue/{}",
            "/rest/api/3/issue/"
        ));
        // literals must match exactly
        assert!(!pattern_matches("/rest/api/3/myself", "/rest/api/3/issue"));
        // a wildcard in the pattern does not make the rest of the path optional
        assert!(!pattern_matches(
            "/wiki/api/v2/pages/{}/children",
            "/wiki/api/v2/pages/123/descendants"
        ));
    }

    #[test]
    fn the_most_specific_pattern_wins() {
        // A literal endpoint beats a wildcard of the same length.
        let search = policy_for("GET", "/rest/api/3/project/search").expect("project search");
        assert_eq!(search.pattern, "/rest/api/3/project/search");
        let one = policy_for("GET", "/rest/api/3/project/ABC").expect("one project");
        assert_eq!(one.pattern, "/rest/api/3/project/{}");
    }

    #[test]
    fn levels_come_from_the_table() {
        let cases = [
            ("GET", "/rest/api/3/issue/ABC-1", AccessLevel::Read),
            ("PUT", "/rest/api/3/issue/ABC-1", AccessLevel::Update),
            (
                "POST",
                "/rest/api/3/issue/ABC-1/transitions",
                AccessLevel::Update,
            ),
            ("POST", "/rest/api/3/issue", AccessLevel::Write),
            ("DELETE", "/rest/api/3/issue/ABC-1", AccessLevel::Write),
            ("PUT", "/wiki/api/v2/pages/123", AccessLevel::Update),
            ("POST", "/wiki/api/v2/pages", AccessLevel::Write),
            ("DELETE", "/wiki/api/v2/pages/123", AccessLevel::Write),
            ("POST", "/rest/api/3/user", AccessLevel::Full),
            (
                "PUT",
                "/wiki/api/v2/pages/123/restriction-state",
                AccessLevel::Full,
            ),
        ];
        for (method, path, expected) in cases {
            let entry = policy_for(method, path)
                .unwrap_or_else(|| panic!("no policy row for {method} {path}"));
            assert_eq!(entry.level, expected, "{method} {path}");
        }
    }

    #[test]
    fn unknown_endpoints_have_no_policy() {
        for (method, path) in [
            ("GET", "/rest/api/3/configuration"),
            ("POST", "/wiki/rest/api/content"),
            ("PUT", "/rest/api/3/user"),
            ("GET", "/admin"),
            ("GET", "/rest/api/3/issue"),
        ] {
            assert!(
                policy_for(method, path).is_none(),
                "{method} {path} must not be on the allowlist"
            );
        }
    }

    #[test]
    fn never_endpoints_are_forbidden_and_not_in_the_policy() {
        assert!(NEVER_ENDPOINTS.len() >= 4);
        for (method, pattern) in NEVER_ENDPOINTS {
            // Build a concrete path from the pattern so it can be matched.
            let concrete = pattern.replace("{}", "abc");
            assert!(
                is_forbidden(method, &concrete),
                "{method} {pattern} should be forbidden"
            );
            assert!(
                policy_for(method, &concrete).is_none(),
                "{method} {pattern} must never appear in the policy"
            );
        }
    }

    #[test]
    fn no_two_patterns_match_the_same_path_with_equal_specificity() {
        // Mirrors the generator's ambiguity check: if two rows could both claim a path
        // and are equally specific, the winner would be arbitrary.
        let compatible = |a: &str, b: &str| {
            let a: Vec<&str> = a.split('/').collect();
            let b: Vec<&str> = b.split('/').collect();
            a.len() == b.len()
                && a.iter()
                    .zip(&b)
                    .all(|(x, y)| x == y || *x == "{}" || *y == "{}")
        };
        for (i, a) in ENDPOINT_POLICY.iter().enumerate() {
            for b in &ENDPOINT_POLICY[i + 1..] {
                let ambiguous = a.method == b.method
                    && compatible(a.pattern, b.pattern)
                    && specificity(a.pattern) == specificity(b.pattern);
                assert!(
                    !ambiguous,
                    "rows {} {} and {} {} are ambiguous",
                    a.method, a.pattern, b.method, b.pattern
                );
            }
        }
    }

    #[test]
    fn every_method_is_one_we_can_send() {
        for entry in ENDPOINT_POLICY {
            assert!(
                matches!(entry.method, "GET" | "POST" | "PUT" | "DELETE"),
                "unexpected method {} on {}",
                entry.method,
                entry.pattern
            );
        }
    }
}
