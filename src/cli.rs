//! Command-line interface.

use clap::{Parser, ValueEnum};
use std::fmt;

/// How much the agent is allowed to do on your behalf.
///
/// The ordering of the variants is meaningful: `Read < Update < Write < Full`, and each
/// level is cumulative — every level includes everything the level below it allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AccessLevel {
    /// Read everything the signed-in user can read. No changes of any kind.
    Read,
    /// `read`, plus changing content that already exists — rewriting an issue or a page,
    /// transitioning, assigning, editing a comment or a property. Cannot create or
    /// delete anything. Not implemented yet.
    Update,
    /// `update`, plus creating and deleting content — issues, pages, blog posts,
    /// comments, attachments, sprints. Not implemented yet.
    Write,
    /// `write`, plus administration: users and profiles, permissions, security and
    /// project/space configuration. Not implemented yet.
    Full,
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Update => "update",
            Self::Write => "write",
            Self::Full => "full",
        })
    }
}

impl AccessLevel {
    /// Whether this level may change existing content (but not create or delete it).
    pub fn can_update(self) -> bool {
        self >= Self::Update
    }

    /// Whether this level may create or delete content.
    pub fn can_write(self) -> bool {
        self >= Self::Write
    }
}

/// A local MCP server that reads Atlassian Cloud (Confluence and Jira) using the
/// session cookie from your Microsoft Edge profile.
#[derive(Debug, Parser)]
#[command(name = "omb-atlassian-mcp", version, about, long_about = None)]
pub struct Args {
    /// Atlassian Cloud site base URL, e.g. https://your-org.atlassian.net
    #[arg(long, value_name = "URL")]
    pub site: String,

    /// Maximum access the agent may use.
    #[arg(long, value_enum, default_value_t = AccessLevel::Read)]
    pub access_level: AccessLevel,

    /// Edge profile directory name inside the Edge configuration directory.
    #[arg(long, value_name = "PROFILE", default_value = "Default")]
    pub profile: String,

    /// Verify the Edge session by calling /rest/api/3/myself, print the result, and exit.
    #[arg(long)]
    pub check: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_is_the_default() {
        let args = Args::parse_from(["omb-atlassian-mcp", "--site", "https://x.atlassian.net"]);
        assert_eq!(args.access_level, AccessLevel::Read);
        assert_eq!(args.profile, "Default");
        assert!(!args.check);
    }

    /// The names on the command line are part of the interface; lock them down.
    #[test]
    fn every_level_has_the_expected_cli_name() {
        for (name, expected) in [
            ("read", AccessLevel::Read),
            ("update", AccessLevel::Update),
            ("write", AccessLevel::Write),
            ("full", AccessLevel::Full),
        ] {
            let args = Args::parse_from([
                "omb-atlassian-mcp",
                "--site",
                "https://x.atlassian.net",
                "--access-level",
                name,
            ]);
            assert_eq!(args.access_level, expected, "CLI name {name:?}");
            assert_eq!(expected.to_string(), name, "Display for {name:?}");
        }
    }

    #[test]
    fn levels_are_ordered_from_read_to_full() {
        assert!(AccessLevel::Read < AccessLevel::Update);
        assert!(AccessLevel::Update < AccessLevel::Write);
        assert!(AccessLevel::Write < AccessLevel::Full);

        assert!(!AccessLevel::Read.can_update());
        assert!(AccessLevel::Update.can_update());
        assert!(AccessLevel::Write.can_update());
        assert!(AccessLevel::Full.can_update());

        assert!(!AccessLevel::Update.can_write());
        assert!(AccessLevel::Write.can_write());
        assert!(AccessLevel::Full.can_write());
    }

    #[test]
    fn update_is_accepted_from_the_command_line() {
        let args = Args::parse_from([
            "omb-atlassian-mcp",
            "--site",
            "https://x.atlassian.net",
            "--access-level",
            "update",
            "--profile",
            "Profile 2",
        ]);
        assert_eq!(args.access_level, AccessLevel::Update);
        assert_eq!(args.profile, "Profile 2");
    }

    #[test]
    fn site_is_required() {
        assert!(Args::try_parse_from(["omb-atlassian-mcp"]).is_err());
    }
}
