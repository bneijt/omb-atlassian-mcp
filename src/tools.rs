//! The MCP tool surface.
//!
//! Every tool here reads. That is the first of the three layers that keep `readonly`
//! read-only: only read tools are registered, every request they make must match the
//! client's endpoint allowlist, and no write code path exists.
//!
//! [`TOOL_SPECS`] classifies each tool with the minimum access level it needs, and a
//! test asserts that the classification matches the router exactly — so adding a tool
//! without deciding whether it writes fails the build's test suite.

use crate::atlassian::{
    CONFLUENCE_PAGES, CONFLUENCE_SEARCH, CONFLUENCE_SPACES, Client, JIRA_ISSUE_PREFIX, JIRA_MYSELF,
    JIRA_PROJECT_SEARCH, JIRA_SEARCH_JQL, JIRA_SEARCH_LEGACY, path_segment,
};
use crate::cli::AccessLevel;
use crate::{SERVER_NAME, SERVER_VERSION};
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

/// How a tool is classified for access-level purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: &'static str,
    pub min_level: AccessLevel,
}

/// Every tool the server registers, and the level it requires.
pub const TOOL_SPECS: &[ToolSpec] = &[
    ToolSpec {
        name: "get_myself",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "search_issues",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "get_issue",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "list_projects",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "get_issue_comments",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "search_pages",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "get_page",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "list_spaces",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "get_page_children",
        min_level: AccessLevel::Readonly,
    },
    ToolSpec {
        name: "list_page_comments",
        min_level: AccessLevel::Readonly,
    },
];

/// Arguments for `search_issues`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SearchIssuesArgs {
    /// JQL query, e.g. `project = ABC AND status != Done ORDER BY updated DESC`.
    pub jql: String,
    /// Maximum number of issues to return. Defaults to 25.
    #[serde(default)]
    pub max_results: Option<u32>,
    /// Fields to include, e.g. `["summary", "status", "assignee"]`.
    /// Defaults to all navigable fields.
    #[serde(default)]
    pub fields: Option<Vec<String>>,
    /// `nextPageToken` from a previous response, to fetch the next page.
    #[serde(default)]
    pub next_page_token: Option<String>,
}

/// Arguments for `get_issue`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetIssueArgs {
    /// Issue key or id, e.g. `ABC-123`.
    pub issue: String,
    /// Fields to include, e.g. `["summary", "description"]`.
    #[serde(default)]
    pub fields: Option<Vec<String>>,
}

/// Arguments for `list_projects`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListProjectsArgs {
    /// Maximum number of projects to return. Defaults to 50.
    #[serde(default)]
    pub max_results: Option<u32>,
    /// Filter projects whose name or key contains this text.
    #[serde(default)]
    pub query: Option<String>,
}

/// Arguments for `get_issue_comments`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetIssueCommentsArgs {
    /// Issue key or id, e.g. `ABC-123`.
    pub issue: String,
    /// Maximum number of comments to return. Defaults to 50.
    #[serde(default)]
    pub max_results: Option<u32>,
}

/// Arguments for `search_pages`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SearchPagesArgs {
    /// CQL query, e.g. `space = ENG AND title ~ "release notes"`.
    pub cql: String,
    /// Maximum number of results to return. Defaults to 25.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for `get_page`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetPageArgs {
    /// Confluence page id, e.g. `123456`.
    pub page_id: String,
}

/// Arguments for `list_spaces`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListSpacesArgs {
    /// Maximum number of spaces to return. Defaults to 25.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for `get_page_children`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetPageChildrenArgs {
    /// Confluence page id whose child pages should be listed.
    pub page_id: String,
    /// Maximum number of children to return. Defaults to 25.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for `list_page_comments`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListPageCommentsArgs {
    /// Confluence page id whose footer comments should be listed.
    pub page_id: String,
    /// Maximum number of comments to return. Defaults to 25.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The MCP server: a read-only Atlassian client plus the tool router.
#[derive(Clone)]
pub struct AtlassianServer {
    client: Arc<Client>,
    level: AccessLevel,
    tool_router: ToolRouter<Self>,
}

impl AtlassianServer {
    /// Build the server for an already-authenticated client.
    pub fn new(client: Client, level: AccessLevel) -> Self {
        Self {
            client: Arc::new(client),
            level,
            tool_router: Self::tool_router(),
        }
    }

    /// The access level this server is running at.
    pub fn level(&self) -> AccessLevel {
        self.level
    }

    /// The underlying client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    fn ok(value: Value) -> CallToolResult {
        let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
        CallToolResult::success(vec![ContentBlock::text(text)])
    }

    fn fail(error: impl std::fmt::Display) -> CallToolResult {
        // Tool-level error: the agent sees this text and can react to it.
        CallToolResult::error(vec![ContentBlock::text(error.to_string())])
    }

    fn render(result: crate::Result<Value>) -> CallToolResult {
        match result {
            Ok(value) => Self::ok(value),
            Err(error) => Self::fail(error),
        }
    }
}

#[tool_router]
impl AtlassianServer {
    /// Identify the Atlassian user whose Edge session is being used.
    #[tool(
        name = "get_myself",
        annotations(read_only_hint = true),
        description = "Identify the Atlassian user whose Edge browser session this server is using, \
                       including their account id, name and email. Useful to confirm which account \
                       the agent is acting as."
    )]
    pub async fn get_myself(&self) -> CallToolResult {
        Self::render(self.client.get_json(JIRA_MYSELF, &[]).await)
    }

    /// Search Jira issues with JQL.
    #[tool(
        name = "search_issues",
        annotations(read_only_hint = true),
        description = "Search Jira issues across all projects the signed-in user can read, using JQL. \
                       Returns issues plus a next_page_token for pagination. Read-only."
    )]
    pub async fn search_issues(
        &self,
        Parameters(args): Parameters<SearchIssuesArgs>,
    ) -> CallToolResult {
        let mut body = json!({
            "jql": args.jql,
            "maxResults": args.max_results.unwrap_or(25),
        });
        if let Some(fields) = args.fields {
            body["fields"] = json!(fields);
        }
        if let Some(token) = args.next_page_token {
            body["nextPageToken"] = json!(token);
        }

        match self.client.post_json(JIRA_SEARCH_JQL, &body).await {
            Ok(value) => Self::ok(value),
            // Atlassian removed the old search endpoint in favour of /search/jql. A site
            // that predates the migration answers 404 (or 410 once removed) there, so
            // fall back to the legacy endpoint before giving up.
            Err(error) if matches!(error.status(), Some(404) | Some(410)) => {
                crate::log!(
                    "{JIRA_SEARCH_JQL} returned HTTP {:?}; falling back to {JIRA_SEARCH_LEGACY}",
                    error.status()
                );
                Self::render(self.client.post_json(JIRA_SEARCH_LEGACY, &body).await)
            }
            Err(error) => Self::fail(error),
        }
    }

    /// Read a single Jira issue.
    #[tool(
        name = "get_issue",
        annotations(read_only_hint = true),
        description = "Read one Jira issue by key or id, optionally limiting which fields are returned. \
                       Read-only."
    )]
    pub async fn get_issue(&self, Parameters(args): Parameters<GetIssueArgs>) -> CallToolResult {
        let path = format!("{JIRA_ISSUE_PREFIX}{}", path_segment(&args.issue));
        let query: Vec<(&str, String)> = match args.fields {
            Some(fields) if !fields.is_empty() => vec![("fields", fields.join(","))],
            _ => Vec::new(),
        };
        Self::render(self.client.get_json(&path, &query).await)
    }

    /// List Jira projects.
    #[tool(
        name = "list_projects",
        annotations(read_only_hint = true),
        description = "List the Jira projects the signed-in user can see, optionally filtered by a \
                       search term. Read-only."
    )]
    pub async fn list_projects(
        &self,
        Parameters(args): Parameters<ListProjectsArgs>,
    ) -> CallToolResult {
        let mut query = vec![("maxResults", args.max_results.unwrap_or(50).to_string())];
        if let Some(text) = args.query {
            query.push(("query", text));
        }
        Self::render(self.client.get_json(JIRA_PROJECT_SEARCH, &query).await)
    }

    /// Read the comments on a Jira issue.
    #[tool(
        name = "get_issue_comments",
        annotations(read_only_hint = true),
        description = "Read the comments on a Jira issue. Read-only."
    )]
    pub async fn get_issue_comments(
        &self,
        Parameters(args): Parameters<GetIssueCommentsArgs>,
    ) -> CallToolResult {
        let path = format!("{JIRA_ISSUE_PREFIX}{}/comment", path_segment(&args.issue));
        let query = vec![("maxResults", args.max_results.unwrap_or(50).to_string())];
        Self::render(self.client.get_json(&path, &query).await)
    }

    /// Search Confluence pages with CQL.
    #[tool(
        name = "search_pages",
        annotations(read_only_hint = true),
        description = "Search Confluence content with CQL, e.g. `space = ENG AND title ~ \"release\"`. \
                       Returns matching pages. Read-only."
    )]
    pub async fn search_pages(
        &self,
        Parameters(args): Parameters<SearchPagesArgs>,
    ) -> CallToolResult {
        let query = vec![
            ("cql", args.cql),
            ("limit", args.limit.unwrap_or(25).to_string()),
        ];
        Self::render(self.client.get_json(CONFLUENCE_SEARCH, &query).await)
    }

    /// Read a Confluence page, including its storage-format body.
    #[tool(
        name = "get_page",
        annotations(read_only_hint = true),
        description = "Read one Confluence page by id, including its body in storage format. Read-only."
    )]
    pub async fn get_page(&self, Parameters(args): Parameters<GetPageArgs>) -> CallToolResult {
        let path = format!("{CONFLUENCE_PAGES}/{}", path_segment(&args.page_id));
        let query = vec![("body-format", "storage".to_string())];
        Self::render(self.client.get_json(&path, &query).await)
    }

    /// List Confluence spaces.
    #[tool(
        name = "list_spaces",
        annotations(read_only_hint = true),
        description = "List the Confluence spaces the signed-in user can see. Read-only."
    )]
    pub async fn list_spaces(
        &self,
        Parameters(args): Parameters<ListSpacesArgs>,
    ) -> CallToolResult {
        let query = vec![("limit", args.limit.unwrap_or(25).to_string())];
        Self::render(self.client.get_json(CONFLUENCE_SPACES, &query).await)
    }

    /// List the child pages of a Confluence page.
    #[tool(
        name = "get_page_children",
        annotations(read_only_hint = true),
        description = "List the direct child pages of a Confluence page. Read-only."
    )]
    pub async fn get_page_children(
        &self,
        Parameters(args): Parameters<GetPageChildrenArgs>,
    ) -> CallToolResult {
        let path = format!(
            "{CONFLUENCE_PAGES}/{}/children",
            path_segment(&args.page_id)
        );
        let query = vec![("limit", args.limit.unwrap_or(25).to_string())];
        Self::render(self.client.get_json(&path, &query).await)
    }

    /// List the footer comments on a Confluence page.
    #[tool(
        name = "list_page_comments",
        annotations(read_only_hint = true),
        description = "List the footer comments on a Confluence page. Read-only."
    )]
    pub async fn list_page_comments(
        &self,
        Parameters(args): Parameters<ListPageCommentsArgs>,
    ) -> CallToolResult {
        let path = format!(
            "{CONFLUENCE_PAGES}/{}/footer-comments",
            path_segment(&args.page_id)
        );
        let query = vec![
            ("limit", args.limit.unwrap_or(25).to_string()),
            ("body-format", "storage".to_string()),
        ];
        Self::render(self.client.get_json(&path, &query).await)
    }
}

/// Providing `get_info` stops `#[tool_handler]` from generating one, which would
/// otherwise report rmcp's own build metadata as the server name.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for AtlassianServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
            .with_instructions(
                "Read-only access to your Atlassian Cloud site (Confluence and Jira), acting as \
                 the user whose Edge browser session is signed in. Use search_issues with JQL for \
                 Jira and search_pages with CQL for Confluence. Nothing this server exposes can \
                 modify your data."
                    .to_string(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlassian::Site;

    fn server() -> AtlassianServer {
        let client = Client::new(
            Site::parse("https://acme.atlassian.net").unwrap(),
            AccessLevel::Readonly,
            "cloud.session.token=x".to_string(),
        )
        .unwrap();
        AtlassianServer::new(client, AccessLevel::Readonly)
    }

    #[test]
    fn every_registered_tool_is_classified() {
        let registered: Vec<String> = AtlassianServer::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();

        for name in &registered {
            assert!(
                TOOL_SPECS.iter().any(|spec| spec.name == name),
                "tool {name:?} is registered but missing from TOOL_SPECS; \
                 classify it (does it write?) before shipping it"
            );
        }
        for spec in TOOL_SPECS {
            assert!(
                registered.iter().any(|name| name == spec.name),
                "TOOL_SPECS lists {:?} but the router does not register it",
                spec.name
            );
        }
        assert_eq!(registered.len(), TOOL_SPECS.len());
    }

    #[test]
    fn only_readonly_tools_exist_while_only_readonly_is_implemented() {
        for spec in TOOL_SPECS {
            assert_eq!(
                spec.min_level,
                AccessLevel::Readonly,
                "tool {:?} needs a level that is not implemented yet",
                spec.name
            );
        }
    }

    #[test]
    fn the_server_reports_the_level_it_runs_at() {
        let server = server();
        assert_eq!(server.level(), AccessLevel::Readonly);
        assert_eq!(server.client().level(), AccessLevel::Readonly);
    }

    #[test]
    fn tools_publish_their_read_only_annotation() {
        for tool in AtlassianServer::tool_router().list_all() {
            let annotations = tool
                .annotations
                .unwrap_or_else(|| panic!("tool {} has no annotations", tool.name));
            assert_eq!(
                annotations.read_only_hint,
                Some(true),
                "tool {} is not marked read-only",
                tool.name
            );
        }
    }

    #[test]
    fn tool_arguments_cannot_escape_their_endpoint() {
        // The path a tool builds is always allowlisted, whatever the argument says.
        let server = server();
        let hostile = format!("{JIRA_ISSUE_PREFIX}{}", path_segment("../../admin"));
        assert!(!hostile.contains(".."));
        assert!(server.client().check_allowed("GET", &hostile).is_ok());
    }
}
