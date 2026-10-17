//! The classification document and the enforced policy must agree exactly.
//!
//! `docs/access-levels.md` is the reviewed proposal and `src/policy/data.rs` is what the
//! server enforces. They are generated from the same data, but nothing stops a later
//! edit to one of them — so this test compares them row by row.

use omb_atlassian_mcp::cli::AccessLevel;
use omb_atlassian_mcp::policy::{ENDPOINT_POLICY, NEVER_ENDPOINTS};
use std::collections::BTreeSet;

const DOC: &str = include_str!("../docs/access-levels.md");

/// A `(level, method, path)` triple read from the document.
type Row = (String, String, String);

/// Everything the document says, parsed.
struct Documented {
    rows: BTreeSet<Row>,
    never: BTreeSet<(String, String)>,
    /// `(level, endpoint count)` taken from the section headings.
    counts: Vec<(String, usize)>,
}

fn documented() -> Documented {
    let mut rows = BTreeSet::new();
    let mut never = BTreeSet::new();
    let mut counts = Vec::new();
    let mut section: Option<String> = None;

    for line in DOC.lines() {
        let line = line.trim();

        // Section headings carry the level and the number of endpoints it covers:
        //   ## `update` — 25 endpoints
        if let Some(rest) = line.strip_prefix("## `")
            && let Some((level, tail)) = rest.split_once('`')
        {
            let count = tail
                .split('—')
                .nth(1)
                .and_then(|text| text.split_whitespace().next())
                .and_then(|number| number.parse::<usize>().ok());
            if let Some(count) = count {
                counts.push((level.to_string(), count));
            }
            section = Some(level.to_string());
            continue;
        }

        // Table rows look like: | `GET` | `/rest/api/3/myself` | who ... |
        if !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 2 {
            continue;
        }
        let method = cells[0].trim_matches('`');
        let path = cells[1].trim_matches('`');
        // Only endpoint rows: the prose tables in the document put non-paths here.
        if !path.starts_with('/') {
            continue;
        }
        match section.as_deref() {
            Some("never") => {
                never.insert((method.to_string(), path.to_string()));
            }
            Some(level) => {
                rows.insert((level.to_string(), method.to_string(), path.to_string()));
            }
            None => {}
        }
    }

    Documented {
        rows,
        never,
        counts,
    }
}

#[test]
fn policy_matches_the_documented_classification() {
    let Documented {
        rows: doc_rows,
        never: doc_never,
        counts: doc_counts,
    } = documented();

    // Guard against a parsing regression quietly making the comparison vacuous.
    assert!(
        doc_rows.len() > 100,
        "only parsed {} rows from the document; the parser is probably broken",
        doc_rows.len()
    );

    let code_rows: BTreeSet<Row> = ENDPOINT_POLICY
        .iter()
        .map(|entry| {
            (
                entry.level.to_string(),
                entry.method.to_string(),
                entry.pattern.to_string(),
            )
        })
        .collect();

    let only_in_doc: Vec<&Row> = doc_rows.difference(&code_rows).collect();
    let only_in_code: Vec<&Row> = code_rows.difference(&doc_rows).collect();
    assert!(
        only_in_doc.is_empty() && only_in_code.is_empty(),
        "the document and the policy disagree\n  only in docs: {only_in_doc:?}\n  only in code: {only_in_code:?}"
    );

    // The counts written in the headings must match reality.
    for (level, documented_count) in &doc_counts {
        let actual = if level == "never" {
            NEVER_ENDPOINTS.len()
        } else {
            ENDPOINT_POLICY
                .iter()
                .filter(|entry| entry.level.to_string() == *level)
                .count()
        };
        assert_eq!(
            actual, *documented_count,
            "the '{level}' heading claims {documented_count} endpoints but there are {actual}"
        );
    }

    let code_never: BTreeSet<(String, String)> = NEVER_ENDPOINTS
        .iter()
        .map(|(method, pattern)| (method.to_string(), pattern.to_string()))
        .collect();
    assert_eq!(
        doc_never, code_never,
        "the never-allowed list disagrees between the document and the policy"
    );
}

#[test]
fn every_level_appears_in_the_document() {
    let Documented {
        rows: doc_rows,
        counts: doc_counts,
        ..
    } = documented();
    for level in [
        AccessLevel::Read,
        AccessLevel::Update,
        AccessLevel::Write,
        AccessLevel::Full,
    ] {
        assert!(
            doc_counts
                .iter()
                .any(|(name, _)| *name == level.to_string()),
            "the document has no section for '{level}'"
        );
        assert!(
            doc_rows
                .iter()
                .any(|(name, _, _)| *name == level.to_string()),
            "the '{level}' section has no endpoints"
        );
    }
}
