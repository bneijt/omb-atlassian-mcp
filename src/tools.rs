//! The MCP tool surface.
//!
//! Every tool declares the minimum access level it needs in [`TOOL_SPECS`]. At startup
//! the router disables every tool above the session's level, so the tool is absent from
//! `tools/list` *and* rejected if called anyway.
//!
//! That is only the first layer: the HTTP client independently enforces
//! [`crate::policy`] on every request, so a mistake in a tool cannot become a write the
//! level forbids. A test ties each tool to the policy row for the endpoint it uses, and
//! fails if the declared level and the policy disagree.

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

/// A tool, the level it requires, and the endpoint it calls.
///
/// The endpoint is recorded so that a test can prove the declared level matches the
/// policy row — the two cannot disagree silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: &'static str,
    pub min_level: AccessLevel,
    pub method: &'static str,
    /// `{}` stands for one path segment, as in [`crate::policy`].
    pub path: &'static str,
}

/// Every tool the server can register, with its minimum level.
pub const TOOL_SPECS: &[ToolSpec] = &[
    // ----- read -----
    ToolSpec {
        name: "get_myself",
        min_level: AccessLevel::Read,
        method: "GET",
        path: JIRA_MYSELF,
    },
    ToolSpec {
        name: "search_issues",
        min_level: AccessLevel::Read,
        method: "POST",
        path: JIRA_SEARCH_JQL,
    },
    ToolSpec {
        name: "get_issue",
        min_level: AccessLevel::Read,
        method: "GET",
        path: "/rest/api/3/issue/{}",
    },
    ToolSpec {
        name: "list_projects",
        min_level: AccessLevel::Read,
        method: "GET",
        path: JIRA_PROJECT_SEARCH,
    },
    ToolSpec {
        name: "get_issue_comments",
        min_level: AccessLevel::Read,
        method: "GET",
        path: "/rest/api/3/issue/{}/comment",
    },
    ToolSpec {
        name: "search_pages",
        min_level: AccessLevel::Read,
        method: "GET",
        path: CONFLUENCE_SEARCH,
    },
    ToolSpec {
        name: "get_page",
        min_level: AccessLevel::Read,
        method: "GET",
        path: "/wiki/api/v2/pages/{}",
    },
    ToolSpec {
        name: "list_spaces",
        min_level: AccessLevel::Read,
        method: "GET",
        path: CONFLUENCE_SPACES,
    },
    ToolSpec {
        name: "get_page_children",
        min_level: AccessLevel::Read,
        method: "GET",
        path: "/wiki/api/v2/pages/{}/children",
    },
    ToolSpec {
        name: "list_page_comments",
        min_level: AccessLevel::Read,
        method: "GET",
        path: "/wiki/api/v2/pages/{}/footer-comments",
    },
    // ----- update -----
    ToolSpec {
        name: "update_issue",
        min_level: AccessLevel::Update,
        method: "PUT",
        path: "/rest/api/3/issue/{}",
    },
    ToolSpec {
        name: "transition_issue",
        min_level: AccessLevel::Update,
        method: "POST",
        path: "/rest/api/3/issue/{}/transitions",
    },
    ToolSpec {
        name: "assign_issue",
        min_level: AccessLevel::Update,
        method: "PUT",
        path: "/rest/api/3/issue/{}/assignee",
    },
    ToolSpec {
        name: "update_comment",
        min_level: AccessLevel::Update,
        method: "PUT",
        path: "/rest/api/3/issue/{}/comment/{}",
    },
    ToolSpec {
        name: "update_page",
        min_level: AccessLevel::Update,
        method: "PUT",
        path: "/wiki/api/v2/pages/{}",
    },
    // ----- write -----
    ToolSpec {
        name: "create_issue",
        min_level: AccessLevel::Write,
        method: "POST",
        path: "/rest/api/3/issue",
    },
    ToolSpec {
        name: "delete_issue",
        min_level: AccessLevel::Write,
        method: "DELETE",
        path: "/rest/api/3/issue/{}",
    },
    ToolSpec {
        name: "add_comment",
        min_level: AccessLevel::Write,
        method: "POST",
        path: "/rest/api/3/issue/{}/comment",
    },
    ToolSpec {
        name: "delete_comment",
        min_level: AccessLevel::Write,
        method: "DELETE",
        path: "/rest/api/3/issue/{}/comment/{}",
    },
    ToolSpec {
        name: "create_page",
        min_level: AccessLevel::Write,
        method: "POST",
        path: "/wiki/api/v2/pages",
    },
    ToolSpec {
        name: "delete_page",
        min_level: AccessLevel::Write,
        method: "DELETE",
        path: "/wiki/api/v2/pages/{}",
    },
    // ----- full -----
    ToolSpec {
        name: "create_project",
        min_level: AccessLevel::Full,
        method: "POST",
        path: "/rest/api/3/project",
    },
    ToolSpec {
        name: "create_space",
        min_level: AccessLevel::Full,
        method: "POST",
        path: "/wiki/api/v2/spaces",
    },
    ToolSpec {
        name: "add_group_member",
        min_level: AccessLevel::Full,
        method: "POST",
        path: "/rest/api/3/group/user",
    },
    ToolSpec {
        name: "remove_group_member",
        min_level: AccessLevel::Full,
        method: "DELETE",
        path: "/rest/api/3/group/user",
    },
];

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

/// Arguments for `search_issues`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SearchIssuesArgs {
    /// JQL query, e.g. `project = ABC AND status != Done ORDER BY updated DESC`.
    pub jql: String,
    /// Maximum number of issues to return. Defaults to 25.
    #[serde(default)]
    pub max_results: Option<u32>,
    /// Fields to include, e.g. `["summary", "status", "assignee"]`.
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

/// Arguments for `update_issue`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateIssueArgs {
    /// Issue key or id, e.g. `ABC-123`.
    pub issue: String,
    /// Fields to set, as a JSON object, e.g. `{"summary": "New title"}`.
    /// Rich-text fields (`description`, `environment`) may be plain strings.
    pub fields: Value,
}

/// Arguments for `transition_issue`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TransitionIssueArgs {
    /// Issue key or id.
    pub issue: String,
    /// Transition id from the issue's available transitions.
    pub transition_id: String,
    /// Fields to set as part of the transition, if the workflow asks for them.
    #[serde(default)]
    pub fields: Option<Value>,
}

/// Arguments for `assign_issue`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AssignIssueArgs {
    /// Issue key or id.
    pub issue: String,
    /// Atlassian account id to assign to. Omit to unassign.
    #[serde(default)]
    pub account_id: Option<String>,
}

/// Arguments for `update_comment`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateCommentArgs {
    /// Issue key or id.
    pub issue: String,
    /// Comment id.
    pub comment_id: String,
    /// New body. A plain string is wrapped as a single paragraph; an object is sent as
    /// Atlassian Document Format unchanged.
    pub body: Value,
}

/// Arguments for `update_page`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdatePageArgs {
    /// Confluence page id.
    pub page_id: String,
    /// New title.
    pub title: String,
    /// New body in Confluence storage format.
    pub body: String,
    /// The page's current version number **plus one**. Re-read the page to get it.
    pub version: u64,
    /// Optional version message.
    #[serde(default)]
    pub version_message: Option<String>,
}

/// Arguments for `create_issue`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateIssueArgs {
    /// Project key, e.g. `ABC`.
    pub project_key: String,
    /// Issue type name, e.g. `Task` or `Bug`.
    pub issue_type: String,
    /// Issue summary (the title).
    pub summary: String,
    /// Description, as plain text.
    #[serde(default)]
    pub description: Option<String>,
    /// Labels to apply.
    #[serde(default)]
    pub labels: Option<Vec<String>>,
    /// Account id to assign the new issue to.
    #[serde(default)]
    pub assignee_account_id: Option<String>,
}

/// Arguments for `delete_issue`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteIssueArgs {
    /// Issue key or id.
    pub issue: String,
    /// Also delete the issue's sub-tasks. Defaults to false.
    #[serde(default)]
    pub delete_subtasks: Option<bool>,
}

/// Arguments for `add_comment`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AddCommentArgs {
    /// Issue key or id.
    pub issue: String,
    /// Comment body. A plain string is wrapped as a single paragraph; an object is sent
    /// as Atlassian Document Format unchanged.
    pub body: Value,
}

/// Arguments for `delete_comment`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteCommentArgs {
    /// Issue key or id.
    pub issue: String,
    /// Comment id.
    pub comment_id: String,
}

/// Arguments for `create_page`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreatePageArgs {
    /// Numeric id of the space to create the page in.
    pub space_id: String,
    /// Page title.
    pub title: String,
    /// Page body in Confluence storage format.
    pub body: String,
    /// Optional parent page id.
    #[serde(default)]
    pub parent_id: Option<String>,
}

/// Arguments for `delete_page`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeletePageArgs {
    /// Confluence page id.
    pub page_id: String,
}

/// Arguments for `create_project`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateProjectArgs {
    /// Project key, e.g. `ABC`.
    pub key: String,
    /// Project name.
    pub name: String,
    /// Project type: `software`, `service_desk` or `business`. Defaults to `software`.
    #[serde(default)]
    pub project_type_key: Option<String>,
    /// Account id of the project lead.
    #[serde(default)]
    pub lead_account_id: Option<String>,
    /// Project template key, e.g. `com.pyxis.greenhopper.jira:gh-simplified-agility-kanban`.
    #[serde(default)]
    pub project_template_key: Option<String>,
}

/// Arguments for `create_space`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateSpaceArgs {
    /// Space name.
    pub name: String,
    /// Optional space key. Atlassian generates one when omitted.
    #[serde(default)]
    pub key: Option<String>,
}

/// Arguments for `add_group_member` and `remove_group_member`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GroupMemberArgs {
    /// Group id (the opaque id, not the group name).
    pub group_id: String,
    /// Atlassian account id of the user.
    pub account_id: String,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// The MCP server: an authenticated Atlassian client plus the tool router.
#[derive(Clone)]
pub struct AtlassianServer {
    client: Arc<Client>,
    level: AccessLevel,
    tool_router: ToolRouter<Self>,
}

impl AtlassianServer {
    /// Build the server for an already-authenticated client, hiding every tool the
    /// session's level does not reach.
    pub fn new(client: Client, level: AccessLevel) -> Self {
        let mut tool_router = Self::tool_router();
        for spec in TOOL_SPECS {
            if spec.min_level > level {
                tool_router.disable_route(spec.name);
            }
        }
        Self {
            client: Arc::new(client),
            level,
            tool_router,
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

    /// Names of the tools the agent can actually see, sorted as MCP lists them.
    pub fn visible_tool_names(&self) -> Vec<String> {
        self.tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect()
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

/// Jira Cloud v3 expects rich text as an Atlassian Document. So that a plain-language
/// agent can just send prose, a JSON string is wrapped in a single paragraph; anything
/// else (an object) is assumed to be ADF already and passed through untouched.
fn rich_text(value: Value) -> Value {
    match value {
        Value::String(text) => json!({
            "type": "doc",
            "version": 1,
            "content": [{
                "type": "paragraph",
                "content": [{ "type": "text", "text": text }]
            }]
        }),
        other => other,
    }
}

#[tool_router]
impl AtlassianServer {
    // ------------------------------ read ------------------------------

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
                       Returns issues plus a next_page_token for pagination."
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
                       The response includes the transitions the issue can move to."
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
                       search term."
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
        description = "Read the comments on a Jira issue."
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
                       Returns matching pages."
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
        description = "Read one Confluence page by id, including its body in storage format and its \
                       current version number (needed by update_page)."
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
        description = "List the Confluence spaces the signed-in user can see."
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
        description = "List the direct child pages of a Confluence page."
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
        description = "List the footer comments on a Confluence page."
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

    // ----------------------------- update -----------------------------

    /// Rewrite fields on an existing Jira issue.
    #[tool(
        name = "update_issue",
        annotations(read_only_hint = false),
        description = "Rewrite fields on an existing Jira issue (summary, description, labels, ...). \
                       Cannot create or delete issues. Rich-text fields accept plain text."
    )]
    pub async fn update_issue(
        &self,
        Parameters(args): Parameters<UpdateIssueArgs>,
    ) -> CallToolResult {
        let Value::Object(fields) = args.fields else {
            return Self::fail("fields must be a JSON object, e.g. {\"summary\": \"New title\"}");
        };
        // Rich-text fields may arrive as plain strings; wrap them so Jira accepts them.
        let mut fields = fields;
        for key in ["description", "environment"] {
            if let Some(value) = fields.remove(key) {
                fields.insert(key.to_string(), rich_text(value));
            }
        }

        let path = format!("{JIRA_ISSUE_PREFIX}{}", path_segment(&args.issue));
        Self::render(
            self.client
                .put_json(&path, &json!({ "fields": fields }))
                .await,
        )
    }

    /// Move an existing Jira issue to another status.
    #[tool(
        name = "transition_issue",
        annotations(read_only_hint = false),
        description = "Move an existing Jira issue to another status using a transition id from the \
                       issue's available transitions."
    )]
    pub async fn transition_issue(
        &self,
        Parameters(args): Parameters<TransitionIssueArgs>,
    ) -> CallToolResult {
        let path = format!(
            "{JIRA_ISSUE_PREFIX}{}/transitions",
            path_segment(&args.issue)
        );
        let mut body = json!({ "transition": { "id": args.transition_id } });
        if let Some(fields) = args.fields {
            body["fields"] = fields;
        }
        Self::render(self.client.post_json(&path, &body).await)
    }

    /// Assign or unassign an existing Jira issue.
    #[tool(
        name = "assign_issue",
        annotations(read_only_hint = false),
        description = "Assign an existing Jira issue to an account id, or unassign it by omitting the \
                       account id."
    )]
    pub async fn assign_issue(
        &self,
        Parameters(args): Parameters<AssignIssueArgs>,
    ) -> CallToolResult {
        let path = format!("{JIRA_ISSUE_PREFIX}{}/assignee", path_segment(&args.issue));
        let body = json!({ "accountId": args.account_id });
        Self::render(self.client.put_json(&path, &body).await)
    }

    /// Rewrite an existing Jira comment.
    #[tool(
        name = "update_comment",
        annotations(read_only_hint = false),
        description = "Rewrite the body of an existing Jira comment."
    )]
    pub async fn update_comment(
        &self,
        Parameters(args): Parameters<UpdateCommentArgs>,
    ) -> CallToolResult {
        let path = format!(
            "{JIRA_ISSUE_PREFIX}{}/comment/{}",
            path_segment(&args.issue),
            path_segment(&args.comment_id)
        );
        let body = json!({ "body": rich_text(args.body) });
        Self::render(self.client.put_json(&path, &body).await)
    }

    /// Rewrite an existing Confluence page.
    #[tool(
        name = "update_page",
        annotations(read_only_hint = false),
        description = "Rewrite an existing Confluence page. Requires the page's current version number \
                       plus one; read the page first to get it. Cannot create or delete pages."
    )]
    pub async fn update_page(
        &self,
        Parameters(args): Parameters<UpdatePageArgs>,
    ) -> CallToolResult {
        if args.version == 0 {
            return Self::fail("version must be the page's current version number plus one");
        }
        let path = format!("{CONFLUENCE_PAGES}/{}", path_segment(&args.page_id));
        let mut body = json!({
            "id": args.page_id,
            "status": "current",
            "title": args.title,
            "body": { "representation": "storage", "value": args.body },
            "version": { "number": args.version },
        });
        if let Some(message) = args.version_message {
            body["version"]["message"] = json!(message);
        }
        Self::render(self.client.put_json(&path, &body).await)
    }

    // ------------------------------ write ------------------------------

    /// Create a new Jira issue.
    #[tool(
        name = "create_issue",
        annotations(read_only_hint = false),
        description = "Create a new Jira issue in a project. Requires write access."
    )]
    pub async fn create_issue(
        &self,
        Parameters(args): Parameters<CreateIssueArgs>,
    ) -> CallToolResult {
        let mut fields = json!({
            "project": { "key": args.project_key },
            "issuetype": { "name": args.issue_type },
            "summary": args.summary,
        });
        if let Some(description) = args.description {
            fields["description"] = rich_text(Value::String(description));
        }
        if let Some(labels) = args.labels {
            fields["labels"] = json!(labels);
        }
        if let Some(account_id) = args.assignee_account_id {
            fields["assignee"] = json!({ "accountId": account_id });
        }
        Self::render(
            self.client
                .post_json("/rest/api/3/issue", &json!({ "fields": fields }))
                .await,
        )
    }

    /// Delete a Jira issue.
    #[tool(
        name = "delete_issue",
        annotations(read_only_hint = false, destructive_hint = true),
        description = "Delete a Jira issue, optionally together with its sub-tasks. This cannot be \
                       undone."
    )]
    pub async fn delete_issue(
        &self,
        Parameters(args): Parameters<DeleteIssueArgs>,
    ) -> CallToolResult {
        let path = format!("{JIRA_ISSUE_PREFIX}{}", path_segment(&args.issue));
        let query = vec![(
            "deleteSubtasks",
            args.delete_subtasks.unwrap_or(false).to_string(),
        )];
        Self::render(self.client.delete_json(&path, &query).await)
    }

    /// Add a comment to a Jira issue.
    #[tool(
        name = "add_comment",
        annotations(read_only_hint = false),
        description = "Add a comment to a Jira issue. A plain string is sent as a single paragraph."
    )]
    pub async fn add_comment(
        &self,
        Parameters(args): Parameters<AddCommentArgs>,
    ) -> CallToolResult {
        let path = format!("{JIRA_ISSUE_PREFIX}{}/comment", path_segment(&args.issue));
        let body = json!({ "body": rich_text(args.body) });
        Self::render(self.client.post_json(&path, &body).await)
    }

    /// Delete a Jira comment.
    #[tool(
        name = "delete_comment",
        annotations(read_only_hint = false, destructive_hint = true),
        description = "Delete a comment from a Jira issue. This cannot be undone."
    )]
    pub async fn delete_comment(
        &self,
        Parameters(args): Parameters<DeleteCommentArgs>,
    ) -> CallToolResult {
        let path = format!(
            "{JIRA_ISSUE_PREFIX}{}/comment/{}",
            path_segment(&args.issue),
            path_segment(&args.comment_id)
        );
        Self::render(self.client.delete_json(&path, &[]).await)
    }

    /// Create a new Confluence page.
    #[tool(
        name = "create_page",
        annotations(read_only_hint = false),
        description = "Create a new Confluence page in a space. Requires write access."
    )]
    pub async fn create_page(
        &self,
        Parameters(args): Parameters<CreatePageArgs>,
    ) -> CallToolResult {
        let mut body = json!({
            "spaceId": args.space_id,
            "status": "current",
            "title": args.title,
            "body": { "representation": "storage", "value": args.body },
        });
        if let Some(parent_id) = args.parent_id {
            body["parentId"] = json!(parent_id);
        }
        Self::render(self.client.post_json(CONFLUENCE_PAGES, &body).await)
    }

    /// Trash a Confluence page.
    #[tool(
        name = "delete_page",
        annotations(read_only_hint = false, destructive_hint = true),
        description = "Move a Confluence page to the trash. It can be restored from the trash, but \
                       nothing here can purge it permanently."
    )]
    pub async fn delete_page(
        &self,
        Parameters(args): Parameters<DeletePageArgs>,
    ) -> CallToolResult {
        let path = format!("{CONFLUENCE_PAGES}/{}", path_segment(&args.page_id));
        Self::render(self.client.delete_json(&path, &[]).await)
    }

    // ------------------------------ full -------------------------------

    /// Create a Jira project.
    #[tool(
        name = "create_project",
        annotations(read_only_hint = false),
        description = "Create a Jira project. Administration: requires full access."
    )]
    pub async fn create_project(
        &self,
        Parameters(args): Parameters<CreateProjectArgs>,
    ) -> CallToolResult {
        let mut body = json!({ "key": args.key, "name": args.name });
        if let Some(kind) = args.project_type_key {
            body["projectTypeKey"] = json!(kind);
        }
        if let Some(lead) = args.lead_account_id {
            body["leadAccountId"] = json!(lead);
        }
        if let Some(template) = args.project_template_key {
            body["projectTemplateKey"] = json!(template);
        }
        Self::render(self.client.post_json("/rest/api/3/project", &body).await)
    }

    /// Create a Confluence space.
    #[tool(
        name = "create_space",
        annotations(read_only_hint = false),
        description = "Create a Confluence space. Administration: requires full access."
    )]
    pub async fn create_space(
        &self,
        Parameters(args): Parameters<CreateSpaceArgs>,
    ) -> CallToolResult {
        let mut body = json!({ "name": args.name });
        if let Some(key) = args.key {
            body["key"] = json!(key);
        }
        Self::render(self.client.post_json(CONFLUENCE_SPACES, &body).await)
    }

    /// Add a user to a Jira group.
    #[tool(
        name = "add_group_member",
        annotations(read_only_hint = false),
        description = "Add a user to a Jira group. Changes who can do what, so it requires full \
                       access."
    )]
    pub async fn add_group_member(
        &self,
        Parameters(args): Parameters<GroupMemberArgs>,
    ) -> CallToolResult {
        let query = [("groupId", args.group_id)];
        let body = json!({ "accountId": args.account_id });
        Self::render(
            self.client
                .post_json_with_query("/rest/api/3/group/user", &query, &body)
                .await,
        )
    }

    /// Remove a user from a Jira group.
    #[tool(
        name = "remove_group_member",
        annotations(read_only_hint = false, destructive_hint = true),
        description = "Remove a user from a Jira group, taking away whatever that group granted. \
                       Requires full access."
    )]
    pub async fn remove_group_member(
        &self,
        Parameters(args): Parameters<GroupMemberArgs>,
    ) -> CallToolResult {
        let query = [("accountId", args.account_id), ("groupId", args.group_id)];
        Self::render(
            self.client
                .delete_json("/rest/api/3/group/user", &query)
                .await,
        )
    }
}

/// Providing `get_info` stops `#[tool_handler]` from generating one, which would
/// otherwise report rmcp's own build metadata as the server name.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for AtlassianServer {
    fn get_info(&self) -> ServerConfig {
        let scope = match self.level {
            AccessLevel::Read => "read-only: you cannot change anything",
            AccessLevel::Update => {
                "read and update: you may rewrite existing issues and pages, but cannot create or \
                 delete anything"
            }
            AccessLevel::Write => {
                "read, update, create and delete content, but you cannot administer the site"
            }
            AccessLevel::Full => "full access, including administration",
        };
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(SERVER_NAME, SERVER_VERSION))
            .with_instructions(format!(
                "Access to your Atlassian Cloud site (Confluence and Jira), acting as the user whose \
                 Edge browser session is signed in. This session is at access level '{}' ({}). Use \
                 search_issues with JQL for Jira and search_pages with CQL for Confluence.",
                self.level, scope
            ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atlassian::Site;
    use crate::policy;

    fn server_at(level: AccessLevel) -> AtlassianServer {
        let client = Client::new(
            Site::parse("https://acme.atlassian.net").unwrap(),
            level,
            "cloud.session.token=x".to_string(),
        )
        .unwrap();
        AtlassianServer::new(client, level)
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

    /// The declared level of a tool must be exactly the level its endpoint requires.
    /// This is what keeps the tool surface and the policy from drifting apart.
    #[test]
    fn every_tool_endpoint_is_governed_by_its_declared_level() {
        for spec in TOOL_SPECS {
            let concrete = spec.path.replace("{}", "X1");
            let entry = policy::policy_for(spec.method, &concrete).unwrap_or_else(|| {
                panic!(
                    "tool {} uses {} {}, which is not on the allowlist",
                    spec.name, spec.method, spec.path
                )
            });
            assert_eq!(
                entry.level, spec.min_level,
                "tool {} declares {} but {} {} requires {}",
                spec.name, spec.min_level, spec.method, spec.path, entry.level
            );
        }
    }

    #[test]
    fn tool_visibility_follows_the_level() {
        for (level, count) in [
            (AccessLevel::Read, 10),
            (AccessLevel::Update, 15),
            (AccessLevel::Write, 21),
            (AccessLevel::Full, 25),
        ] {
            let visible = server_at(level).visible_tool_names();
            assert_eq!(
                visible.len(),
                count,
                "'{level}' sees {} tools: {visible:?}",
                visible.len()
            );
        }

        // Specific edges of the ladder.
        let read = server_at(AccessLevel::Read).visible_tool_names();
        assert!(!read.contains(&"update_issue".to_string()));
        assert!(!read.contains(&"create_issue".to_string()));
        assert!(!read.contains(&"create_project".to_string()));

        let update = server_at(AccessLevel::Update).visible_tool_names();
        assert!(update.contains(&"update_issue".to_string()));
        assert!(!update.contains(&"create_issue".to_string()));

        let write = server_at(AccessLevel::Write).visible_tool_names();
        assert!(write.contains(&"create_issue".to_string()));
        assert!(!write.contains(&"create_project".to_string()));

        let full = server_at(AccessLevel::Full).visible_tool_names();
        assert!(full.contains(&"create_project".to_string()));
        assert!(full.contains(&"remove_group_member".to_string()));
    }

    #[test]
    fn read_only_annotations_match_the_level() {
        for tool in AtlassianServer::tool_router().list_all() {
            let spec = TOOL_SPECS
                .iter()
                .find(|spec| spec.name == tool.name)
                .unwrap_or_else(|| panic!("tool {} is unclassified", tool.name));
            let annotations = tool
                .annotations
                .unwrap_or_else(|| panic!("tool {} has no annotations", tool.name));
            let expected = spec.min_level == AccessLevel::Read;
            assert_eq!(
                annotations.read_only_hint,
                Some(expected),
                "tool {} should{} be marked read-only",
                tool.name,
                if expected { "" } else { " not" }
            );
        }
    }

    #[test]
    fn the_four_levels_are_all_represented_by_tools() {
        for level in [
            AccessLevel::Read,
            AccessLevel::Update,
            AccessLevel::Write,
            AccessLevel::Full,
        ] {
            assert!(
                TOOL_SPECS.iter().any(|spec| spec.min_level == level),
                "no tool requires '{level}'"
            );
        }
    }

    #[test]
    fn the_server_reports_the_level_it_runs_at() {
        for level in [
            AccessLevel::Read,
            AccessLevel::Update,
            AccessLevel::Write,
            AccessLevel::Full,
        ] {
            let server = server_at(level);
            assert_eq!(server.level(), level);
            assert_eq!(server.client().level(), level);
        }
    }

    #[test]
    fn tool_arguments_cannot_escape_their_endpoint() {
        let server = server_at(AccessLevel::Full);
        let hostile = format!("{JIRA_ISSUE_PREFIX}{}", path_segment("../../admin"));
        assert!(!hostile.contains(".."));
        assert!(server.client().check_allowed("GET", &hostile).is_ok());
    }

    #[test]
    fn plain_text_is_wrapped_as_a_document_and_adf_is_left_alone() {
        let wrapped = rich_text(Value::String("hello".into()));
        assert_eq!(wrapped["type"], "doc");
        assert_eq!(wrapped["content"][0]["type"], "paragraph");
        assert_eq!(wrapped["content"][0]["content"][0]["text"], "hello");

        let adf = json!({"type": "doc", "version": 1, "content": []});
        assert_eq!(rich_text(adf.clone()), adf);
    }
}
