//! Command-line interface.

use clap::{Parser, ValueEnum};
use std::fmt;

/// How much the agent is allowed to do on your behalf.
///
/// The ordering of the variants is meaningful: `Readonly < ReadUpdate < Full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AccessLevel {
    /// Read everything the signed-in user can read. No writes of any kind.
    Readonly,
    /// `readonly` plus modifying existing content. Not implemented yet.
    ReadUpdate,
    /// Unrestricted create/delete/administer. Not implemented yet.
    Full,
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Readonly => "readonly",
            Self::ReadUpdate => "read-update",
            Self::Full => "full",
        })
    }
}

impl AccessLevel {
    /// Whether this level has actually been built.
    pub fn is_implemented(self) -> bool {
        matches!(self, Self::Readonly)
    }

    /// Reject levels that are declared but not built, rather than silently
    /// downgrading (or, worse, upgrading) the agent's reach.
    pub fn ensure_implemented(self) -> crate::Result<Self> {
        if self.is_implemented() {
            Ok(self)
        } else {
            Err(crate::Error::UnimplementedLevel(self))
        }
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
    #[arg(long, value_enum, default_value_t = AccessLevel::Readonly)]
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
    fn readonly_is_the_default() {
        let args = Args::parse_from(["omb-atlassian-mcp", "--site", "https://x.atlassian.net"]);
        assert_eq!(args.access_level, AccessLevel::Readonly);
        assert_eq!(args.profile, "Default");
        assert!(!args.check);
    }

    #[test]
    fn access_levels_are_accepted_and_ordered() {
        let args = Args::parse_from([
            "omb-atlassian-mcp",
            "--site",
            "https://x.atlassian.net",
            "--access-level",
            "read-update",
            "--profile",
            "Profile 2",
        ]);
        assert_eq!(args.access_level, AccessLevel::ReadUpdate);
        assert_eq!(args.profile, "Profile 2");

        assert!(AccessLevel::Readonly < AccessLevel::ReadUpdate);
        assert!(AccessLevel::ReadUpdate < AccessLevel::Full);
    }

    #[test]
    fn unimplemented_levels_are_rejected() {
        assert!(AccessLevel::Readonly.ensure_implemented().is_ok());
        assert!(AccessLevel::ReadUpdate.ensure_implemented().is_err());
        assert!(AccessLevel::Full.ensure_implemented().is_err());
    }

    #[test]
    fn site_is_required() {
        assert!(Args::try_parse_from(["omb-atlassian-mcp"]).is_err());
    }
}
