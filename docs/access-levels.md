# Access levels and endpoint classification

> **Status: implemented.** `--access-level` accepts `read`, `update`, `write` and
> `full`; the tables below are the policy the server enforces, and a test fails if
> this page and the code drift apart.

## The four levels

Levels are cumulative: `read` ⊂ `update` ⊂ `write` ⊂ `full`.

| Level | Grants | Endpoints |
| --- | --- | --- |
| `read` | Everything that only reads. No changes. | 69 |
| `update` | `read`, plus **changing what already exists** — rewriting an issue or page, transitioning, assigning, editing a comment. Cannot create or delete anything. | 25 |
| `write` | `update`, plus **creating and deleting content** — issues, pages, blog posts, comments, attachments, worklogs, links, sprints. | 27 |
| `full` | `write`, plus **administration** — people and groups, permissions and security, schema and configuration. | 78 |

The one-line version: **`update` changes things that exist; `write` adds and removes them.**

### Worked examples

| Action | Endpoint | Level |
| --- | --- | --- |
| Read a ticket | `GET /rest/api/3/issue/{}` | `read` |
| Rewrite a ticket body | `PUT /rest/api/3/issue/{}` | `update` |
| Create a ticket | `POST /rest/api/3/issue` | `write` |
| Delete a ticket | `DELETE /rest/api/3/issue/{}` | `write` |
| Read a page | `GET /wiki/api/v2/pages/{}` | `read` |
| Rewrite a page | `PUT /wiki/api/v2/pages/{}` | `update` |
| Create a page | `POST /wiki/api/v2/pages` | `write` |
| Trash a page | `DELETE /wiki/api/v2/pages/{}` | `write` |
| Add someone to a group | `POST /rest/api/3/group/user` | `full` |

### A correction worth knowing

An early draft of this page put "update a user profile" (`PUT /rest/api/3/user`) in
`full`. **That endpoint does not exist.** Jira Cloud's user endpoint is `GET`,
`POST` (create) and `DELETE` only, and profile edits for both Jira and Confluence
happen on `id.atlassian.com` — a host this server cannot reach by design. So `full`
covers *administration of people* (creating users, creating groups, adding and
removing members), not profile rewriting.

## How the split was drawn

- **`PUT` / `PATCH` on an existing entity** → `update`.
- **A `POST` that creates a new entity** → `write`.
- **A `DELETE`** → `write`. Deleting is not updating.
- **A `POST` that is a state change on an existing entity** — transition, assign,
  rank, move between sprint and backlog, watch, vote, add a label → `update`.

`full` is the only level that touches identity, permissions or schema:

1. It changes **identity** — users, groups, membership.
2. It changes **who can see or do what** — permission schemes, space permissions,
   project roles, security levels, page restrictions, classifications.
3. It changes **schema or shared configuration** — projects/spaces themselves, issue
   types, fields, screens, workflows, statuses, priorities, resolutions,
   versions/components, notification schemes, webhooks, dashboards, templates.
4. It has **blast radius beyond one item** — bulk operations, irreversible purges.

Reads that *interpret content* stay in `read`; reads that expose the *security or ops
configuration* (audit logs) are `full`.

## How it is enforced

`src/policy/data.rs` holds this table; `src/policy.rs` matches requests against it.

- **Patterns match whole segments.** `{}` matches exactly one non-empty segment, so
  `/rest/api/3/issue/{}` matches `/rest/api/3/issue/ABC-1` but **not**
  `/rest/api/3/issue/ABC-1/transitions`. There is no prefix matching, so a row can
  never accidentally authorise a sub-resource.
- **A literal segment beats a wildcard**, so `GET /rest/api/3/project/search` is
  preferred over the equally-long `GET /rest/api/3/project/{}`. Two patterns that
  match with equal specificity are rejected at generation time.
- **Unlisted means denied** at every level. New endpoints are inert until classified.
- **`never` endpoints are checked first**, so no policy row can shadow them.
- A refusal says which level would be needed:

  ```
  blocked: POST /rest/api/3/issue requires access level 'write' or higher; this session is 'read'
  ```

- Tool visibility follows the same table: a tool whose minimum level is above the
  session's is disabled in the MCP router, so it is absent from `tools/list` *and*
  rejected if called.

## `read` — 69 endpoints

**Jira**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `GET` | `/rest/api/3/myself` | who the session belongs to |
| `GET` | `/rest/api/3/issue/{}` | read one issue |
| `GET` | `/rest/api/3/issue/{}/comment` | issue comments |
| `GET` | `/rest/api/3/issue/{}/worklog` | logged work |
| `GET` | `/rest/api/3/issue/{}/transitions` | transitions available to you |
| `GET` | `/rest/api/3/issue/{}/changelog` | change history |
| `GET` | `/rest/api/3/issue/{}/watchers` | who watches an issue |
| `GET` | `/rest/api/3/issue/{}/remotelink` | remote links |
| `GET` | `/rest/api/3/issue/{}/editmeta` | which fields are editable |
| `POST` | `/rest/api/3/search/jql` | JQL search (a POST that only reads) |
| `POST` | `/rest/api/3/jql/parse` | validate a JQL query (a POST that only reads) |
| `GET` | `/rest/api/3/project/search` | list projects |
| `GET` | `/rest/api/3/project/{}` | one project |
| `GET` | `/rest/api/3/project/{}/components` | components |
| `GET` | `/rest/api/3/project/{}/versions` | versions |
| `GET` | `/rest/api/3/project/{}/statuses` | statuses per issue type |
| `GET` | `/rest/api/3/project/{}/role` | project roles |
| `GET` | `/rest/api/3/issuetype` | issue types |
| `GET` | `/rest/api/3/status` | statuses |
| `GET` | `/rest/api/3/status/{}` | one status |
| `GET` | `/rest/api/3/priority` | priorities |
| `GET` | `/rest/api/3/resolution` | resolutions |
| `GET` | `/rest/api/3/field` | fields |
| `GET` | `/rest/api/3/user/search` | find users |
| `GET` | `/rest/api/3/user` | one user |
| `GET` | `/rest/api/3/user/assignable/search` | users assignable to an issue |
| `GET` | `/rest/api/3/group` | groups |
| `GET` | `/rest/api/3/group/member` | group members |
| `GET` | `/rest/api/3/filter/search` | saved filters |
| `GET` | `/rest/api/3/filter/{}` | one filter |
| `GET` | `/rest/api/3/attachment/{}` | attachment metadata |
| `GET` | `/rest/api/3/attachment/content/{}` | attachment bytes |
| `GET` | `/rest/api/3/dashboard` | dashboards |

**Jira Software**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `GET` | `/rest/agile/1.0/board` | boards |
| `GET` | `/rest/agile/1.0/board/{}` | one board |
| `GET` | `/rest/agile/1.0/board/{}/backlog` | backlog |
| `GET` | `/rest/agile/1.0/board/{}/sprint` | sprints |
| `GET` | `/rest/agile/1.0/board/{}/issue` | issues on a board |
| `GET` | `/rest/agile/1.0/board/{}/epic` | epics |
| `GET` | `/rest/agile/1.0/board/{}/version` | versions on a board |
| `GET` | `/rest/agile/1.0/board/{}/configuration` | board configuration |
| `GET` | `/rest/agile/1.0/sprint/{}` | one sprint |
| `GET` | `/rest/agile/1.0/sprint/{}/issue` | issues in a sprint |
| `GET` | `/rest/agile/1.0/epic/{}` | one epic |
| `GET` | `/rest/agile/1.0/epic/{}/issue` | issues in an epic |

**Confluence**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `GET` | `/wiki/rest/api/search` | CQL search |
| `GET` | `/wiki/rest/api/content/search` | content search (CQL) |
| `GET` | `/wiki/rest/api/user/current` | current user |
| `GET` | `/wiki/rest/api/user` | one user |
| `GET` | `/wiki/rest/api/settings/systemInfo` | instance information |
| `GET` | `/wiki/api/v2/pages` | list pages |
| `GET` | `/wiki/api/v2/pages/{}` | one page, incl. storage-format body |
| `GET` | `/wiki/api/v2/pages/{}/children` | child pages |
| `GET` | `/wiki/api/v2/pages/{}/ancestors` | ancestors |
| `GET` | `/wiki/api/v2/pages/{}/descendants` | descendants |
| `GET` | `/wiki/api/v2/pages/{}/attachments` | page attachments |
| `GET` | `/wiki/api/v2/pages/{}/labels` | page labels |
| `GET` | `/wiki/api/v2/pages/{}/properties` | page properties |
| `GET` | `/wiki/api/v2/pages/{}/versions` | page versions |
| `GET` | `/wiki/api/v2/pages/{}/footer-comments` | footer comments |
| `GET` | `/wiki/api/v2/pages/{}/inline-comments` | inline comments |
| `GET` | `/wiki/api/v2/spaces` | list spaces |
| `GET` | `/wiki/api/v2/spaces/{}` | one space |
| `GET` | `/wiki/api/v2/spaces/{}/pages` | pages in a space |
| `GET` | `/wiki/api/v2/blogposts` | list blog posts |
| `GET` | `/wiki/api/v2/blogposts/{}` | one blog post |
| `GET` | `/wiki/api/v2/footer-comments/{}` | one footer comment |
| `GET` | `/wiki/api/v2/inline-comments/{}` | one inline comment |
| `GET` | `/wiki/api/v2/attachments/{}` | attachment metadata |

## `update` — 25 endpoints

Changes to existing content, and nothing else. This is the level for editorial work —
rewriting descriptions, moving issues through a workflow — without letting the agent
mint new tickets.

**Jira**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `PUT` | `/rest/api/3/issue/{}` | rewrite an existing issue |
| `POST` | `/rest/api/3/issue/{}/transitions` | transition an issue to another status |
| `PUT` | `/rest/api/3/issue/{}/assignee` | assign or reassign an issue |
| `PUT` | `/rest/api/3/issue/{}/comment/{}` | edit an existing comment |
| `PUT` | `/rest/api/3/issue/{}/worklog/{}` | edit an existing worklog |
| `POST` | `/rest/api/3/issue/{}/watchers` | watch an issue |
| `DELETE` | `/rest/api/3/issue/{}/watchers` | stop watching an issue |
| `POST` | `/rest/api/3/issue/{}/votes` | vote on an issue |
| `DELETE` | `/rest/api/3/issue/{}/votes` | remove your vote |
| `PUT` | `/rest/api/3/issue/{}/properties/{}` | set an existing issue property |
| `POST` | `/rest/api/3/issue/{}/notify` | email an issue's watchers |
| `PUT` | `/rest/api/3/filter/{}` | edit an existing saved filter |

**Jira Software**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `PUT` | `/rest/agile/1.0/sprint/{}` | edit an existing sprint |
| `POST` | `/rest/agile/1.0/sprint/{}/issue` | move existing issues into a sprint |
| `POST` | `/rest/agile/1.0/backlog/issue` | move existing issues to the backlog |
| `PUT` | `/rest/agile/1.0/issue/rank` | rank existing issues |

**Confluence**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `PUT` | `/wiki/api/v2/pages/{}` | rewrite an existing page |
| `PUT` | `/wiki/api/v2/blogposts/{}` | rewrite an existing blog post |
| `PUT` | `/wiki/api/v2/footer-comments/{}` | edit an existing footer comment |
| `PUT` | `/wiki/api/v2/inline-comments/{}` | edit an existing inline comment |
| `PUT` | `/wiki/api/v2/pages/{}/properties/{}` | edit an existing page property |
| `POST` | `/wiki/rest/api/content/{}/label` | add a label to an existing page |
| `DELETE` | `/wiki/rest/api/content/{}/label/{}` | remove a label from a page |
| `POST` | `/wiki/rest/api/user/watch/content/{}` | watch a page |
| `DELETE` | `/wiki/rest/api/user/watch/content/{}` | stop watching a page |

## `write` — 27 endpoints

Creates a new entry, or deletes one. **Attachment upload** has no Confluence v2
endpoint, so it goes through v1.

**Jira**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `POST` | `/rest/api/3/issue` | create an issue |
| `DELETE` | `/rest/api/3/issue/{}` | delete an issue |
| `POST` | `/rest/api/3/issue/{}/comment` | create a comment |
| `DELETE` | `/rest/api/3/issue/{}/comment/{}` | delete a comment |
| `POST` | `/rest/api/3/issue/{}/worklog` | log work (creates a worklog) |
| `DELETE` | `/rest/api/3/issue/{}/worklog/{}` | delete a worklog |
| `POST` | `/rest/api/3/issue/{}/attachments` | upload a new attachment |
| `DELETE` | `/rest/api/3/attachment/{}` | delete an attachment |
| `POST` | `/rest/api/3/issueLink` | create a link between issues |
| `DELETE` | `/rest/api/3/issueLink/{}` | delete a link between issues |
| `DELETE` | `/rest/api/3/issue/{}/properties/{}` | delete an issue property |
| `POST` | `/rest/api/3/filter` | create a saved filter |
| `DELETE` | `/rest/api/3/filter/{}` | delete a saved filter |

**Jira Software**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `POST` | `/rest/agile/1.0/sprint` | create a sprint |
| `DELETE` | `/rest/agile/1.0/sprint/{}` | delete a sprint |

**Confluence**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `POST` | `/wiki/api/v2/pages` | create a page |
| `DELETE` | `/wiki/api/v2/pages/{}` | trash a page |
| `POST` | `/wiki/api/v2/blogposts` | create a blog post |
| `DELETE` | `/wiki/api/v2/blogposts/{}` | trash a blog post |
| `POST` | `/wiki/api/v2/footer-comments` | create a footer comment |
| `DELETE` | `/wiki/api/v2/footer-comments/{}` | delete a footer comment |
| `POST` | `/wiki/api/v2/inline-comments` | create an inline comment |
| `DELETE` | `/wiki/api/v2/inline-comments/{}` | delete an inline comment |
| `DELETE` | `/wiki/api/v2/attachments/{}` | delete an attachment |
| `POST` | `/wiki/api/v2/pages/{}/properties` | create a page property |
| `DELETE` | `/wiki/api/v2/pages/{}/properties/{}` | delete a page property |
| `POST` | `/wiki/rest/api/content/{}/child/attachment` | upload an attachment (v2 has no upload) |

## `full` — 78 endpoints

Administration. Confluence v2 has no space update/delete — both are v1 — and Jira
moved status management to `/rest/api/3/statuses`.

**Jira**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `POST` | `/rest/api/3/user` | create a user |
| `DELETE` | `/rest/api/3/user` | delete a user |
| `POST` | `/rest/api/3/group` | create a group |
| `DELETE` | `/rest/api/3/group` | delete a group |
| `POST` | `/rest/api/3/group/user` | add a user to a group |
| `DELETE` | `/rest/api/3/group/user` | remove a user from a group |
| `POST` | `/rest/api/3/project` | create a project |
| `PUT` | `/rest/api/3/project/{}` | update a project |
| `DELETE` | `/rest/api/3/project/{}` | delete a project |
| `POST` | `/rest/api/3/project/{}/archive` | archive a project |
| `POST` | `/rest/api/3/version` | create a version |
| `PUT` | `/rest/api/3/version/{}` | edit a version |
| `DELETE` | `/rest/api/3/version/{}` | delete a version |
| `POST` | `/rest/api/3/component` | create a component |
| `PUT` | `/rest/api/3/component/{}` | edit a component |
| `DELETE` | `/rest/api/3/component/{}` | delete a component |
| `POST` | `/rest/api/3/role` | create a project role |
| `DELETE` | `/rest/api/3/role/{}` | delete a project role |
| `POST` | `/rest/api/3/role/{}/actors` | add an actor to a role |
| `DELETE` | `/rest/api/3/role/{}/actors` | remove an actor from a role |
| `POST` | `/rest/api/3/permissionscheme` | create a permission scheme |
| `PUT` | `/rest/api/3/permissionscheme/{}` | update a permission scheme |
| `DELETE` | `/rest/api/3/permissionscheme/{}` | delete a permission scheme |
| `POST` | `/rest/api/3/permissionscheme/{}/permission` | grant a permission |
| `POST` | `/rest/api/3/issuesecurityschemes` | create a security scheme |
| `PUT` | `/rest/api/3/issuesecurityschemes/{}` | update a security scheme |
| `PUT` | `/rest/api/3/issuesecurityschemes/{}/level` | add or update a security level |
| `DELETE` | `/rest/api/3/issuesecurityschemes/{}/level/{}` | delete a security level |
| `PUT` | `/rest/api/3/issuesecurityschemes/{}/level/{}/member` | add a member to a security level |
| `PUT` | `/rest/api/3/issuesecurityschemes/level/default` | set the default security level |
| `POST` | `/rest/api/3/notificationscheme` | create a notification scheme |
| `PUT` | `/rest/api/3/notificationscheme/{}` | update a notification scheme |
| `POST` | `/rest/api/3/issuetype` | create an issue type |
| `PUT` | `/rest/api/3/issuetype/{}` | update an issue type |
| `DELETE` | `/rest/api/3/issuetype/{}` | delete an issue type |
| `POST` | `/rest/api/3/field` | create a custom field |
| `PUT` | `/rest/api/3/field/{}` | update a custom field |
| `DELETE` | `/rest/api/3/field/{}` | delete a custom field |
| `POST` | `/rest/api/3/screens` | create a screen |
| `PUT` | `/rest/api/3/screens/{}` | update a screen |
| `DELETE` | `/rest/api/3/screens/{}` | delete a screen |
| `POST` | `/rest/api/3/workflows/create` | create a workflow |
| `POST` | `/rest/api/3/workflows/update` | update a workflow |
| `DELETE` | `/rest/api/3/workflow/{}` | delete a workflow |
| `POST` | `/rest/api/3/workflowscheme` | create a workflow scheme |
| `PUT` | `/rest/api/3/workflowscheme/{}` | update a workflow scheme |
| `POST` | `/rest/api/3/statuses` | create a status |
| `PUT` | `/rest/api/3/statuses` | update statuses |
| `DELETE` | `/rest/api/3/statuses` | delete statuses |
| `POST` | `/rest/api/3/priority` | create a priority |
| `PUT` | `/rest/api/3/priority/{}` | update a priority |
| `POST` | `/rest/api/3/resolution` | create a resolution |
| `PUT` | `/rest/api/3/resolution/{}` | update a resolution |
| `POST` | `/rest/api/3/webhook` | register a webhook |
| `DELETE` | `/rest/api/3/webhook` | delete a webhook |
| `POST` | `/rest/api/3/dashboard` | create a dashboard |
| `PUT` | `/rest/api/3/dashboard/{}` | update a dashboard |
| `PUT` | `/rest/api/3/announcementBanner` | set the announcement banner |
| `PUT` | `/rest/api/3/application-properties/{}` | change an application property |
| `GET` | `/rest/api/3/auditing/record` | audit log (security configuration) |
| `POST` | `/rest/api/3/bulk/issues/delete` | bulk delete issues |

**Confluence**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `POST` | `/wiki/api/v2/spaces` | create a space |
| `POST` | `/wiki/api/v2/spaces/{}/role-assignments` | assign space roles |
| `PUT` | `/wiki/api/v2/pages/{}/restriction-state` | change who can see a page |
| `PUT` | `/wiki/api/v2/blogposts/{}/restriction-state` | change who can see a blog post |
| `PUT` | `/wiki/api/v2/pages/{}/classification-level` | set a page's data classification |
| `PUT` | `/wiki/api/v2/spaces/{}/classification-level/default` | set a space's default classification |
| `PUT` | `/wiki/rest/api/space/{}` | update a space |
| `DELETE` | `/wiki/rest/api/space/{}` | delete a space |
| `POST` | `/wiki/rest/api/space/{}/permission` | grant a space permission |
| `PUT` | `/wiki/rest/api/space/{}/settings` | change space settings |
| `POST` | `/wiki/rest/api/template` | create a template |
| `PUT` | `/wiki/rest/api/template` | update a template |
| `GET` | `/wiki/rest/api/audit` | audit log (security configuration) |
| `POST` | `/wiki/rest/api/group` | create a group |
| `DELETE` | `/wiki/rest/api/group/by-id` | delete a group |
| `POST` | `/wiki/rest/api/group/userByGroupId` | add a user to a group |
| `DELETE` | `/wiki/rest/api/group/userByGroupId` | remove a user from a group |

## `never` — 4 endpoints

Exposed at *no* level, and checked before the allowlist. These are not "more admin":
they either move data off the site in bulk, are irreversible in a legally sensitive
way, or have semantics we cannot bound.

**Jira**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `POST` | `/rest/api/3/agents/bulk/invoke/batch` | invoke AI agents: blast radius undefined |
| `GET` | `/rest/api/3/redact/status/{}` | GDPR redaction job status |

**Confluence**

| Method | Endpoint | What it does |
| --- | --- | --- |
| `POST` | `/wiki/api/v2/pages/{}/redact` | redact page content: destructive, legally sensitive |
| `GET` | `/wiki/rest/api/audit/export` | bulk audit-log export: exfiltration path |

Also permanently out of reach by construction: anything on `id.atlassian.com`,
`admin.atlassian.com` or `api.atlassian.com`. `--site` must be an `*.atlassian.net`
host, so organization administration, API-token management and OAuth app registration
can never be called by this server.

## Deliberately not exposed

- **Permanent purge of Confluence content.** Only v2 trash is available; the
  irreversible purge lives behind the v1 content endpoint, which this policy does not
  include.
- **Attachment upload for Jira is allowlisted but has no tool yet**; the same for most
  of the `full` surface. The policy is the security boundary; tools cover the
  operations the agent actually gets.

## What `--access-level` actually gives you

| Level | Tools the agent sees |
| --- | --- |
| `read` | the 10 read tools |
| `update` | + `update_issue`, `transition_issue`, `assign_issue`, `update_comment`, `update_page` |
| `write` | + `create_issue`, `delete_issue`, `add_comment`, `delete_comment`, `create_page`, `delete_page` |
| `full` | + `create_project`, `create_space`, `add_group_member`, `remove_group_member` |

## Verification

Every method/path pair was machine-checked against the published OpenAPI documents;
the generator refuses to emit anything if a pair is absent, duplicated, or ambiguous:

- [Jira Cloud REST API v3](https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json)
- [Jira Software (Agile) API 1.0](https://developer.atlassian.com/cloud/jira/software/swagger.v3.json)
- [Confluence Cloud REST API v1](https://developer.atlassian.com/cloud/confluence/swagger.v3.json)
- [Confluence Cloud REST API v2](https://developer.atlassian.com/cloud/confluence/openapi-v2.json)

The check caught several wrong recollections (and one nonexistent endpoint) before
they reached the policy — including `/rest/api/3/status` for writes (really
`/statuses`), `PUT /workflow/{}` (really `POST /workflows/update`),
`GET /rest/api/3/audit` (really `/auditing/record`), `PUT` for Confluence space
permissions (really `POST`), and `PUT /rest/api/3/user`, which does not exist at all.

It also established that the published v1 Confluence spec does **not** carry the core
`/wiki/rest/api/content` CRUD endpoints, so this policy uses v2 for all page
read/update/create/trash rather than claiming endpoints it cannot verify.

