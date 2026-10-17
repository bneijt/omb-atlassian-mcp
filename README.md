# omb-atlassian-mcp

**omb** = *on my behalf*.

A small local [MCP](https://modelcontextprotocol.io) server that lets an AI agent read your
Atlassian products — **Confluence** and **Jira** — acting *as you*.

Instead of asking you to mint an API token or register an OAuth app, it reads the Atlassian
session cookie that already exists in your **Microsoft Edge** profile and replays it against
Atlassian Cloud. If you are logged into Atlassian in Edge, the agent inherits exactly the
access you have, and nothing more.

> **Status: all four access levels are implemented.** What the agent may do is bounded by
> `--access-level`, and every endpoint the server can call is classified in
> [docs/access-levels.md](docs/access-levels.md).

## Usage

```sh
omb-atlassian-mcp --site https://<your-org>.atlassian.net [--access-level <LEVEL>]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--site <URL>` | *required* | Your Atlassian Cloud site. Must be `https://<something>.atlassian.net`. |
| `--access-level <LEVEL>` | `read` | `read`, `update`, `write`, or `full`. See below. |
| `--profile <NAME>` | `Default` | Which Edge profile to read cookies from. |
| `--check` | off | Verify the session against Atlassian, print the identity, and exit. |

`--access-level` defaults to the least-privilege level, so you must opt in explicitly to
anything that could modify your data.

### Wiring it into an MCP client

```json
{
  "mcpServers": {
    "atlassian": {
      "command": "/path/to/omb-atlassian-mcp",
      "args": ["--site", "https://your-org.atlassian.net"]
    }
  }
}
```

### Verifying it works

```sh
# Confirm the Edge cookie is found, decrypts, and authenticates:
omb-atlassian-mcp --site https://your-org.atlassian.net --check
```

`--check` calls `/rest/api/3/myself` and prints your Atlassian identity. It is the fastest
way to tell a cookie problem apart from an MCP-client problem. Diagnostics always go to
**stderr**; stdout carries only the MCP protocol.

## Access levels

Levels are cumulative: `read` ⊂ `update` ⊂ `write` ⊂ `full`. The per-endpoint
classification the server enforces is in [docs/access-levels.md](docs/access-levels.md),
and a test fails if that document and the code drift apart.

| Level | Meaning | Tools |
| --- | --- | --- |
| `read` | Read everything the signed-in user can read, across Confluence and Jira. No changes of any kind. | 10 |
| `update` | `read`, plus changing content that already exists — rewriting an issue or page, transitioning, assigning, editing a comment, moving and ranking issues, labels, page properties. **No creates, no deletes.** | 22 |
| `write` | `update`, plus creating and deleting content — issues, pages, comments, sprints, attachments. No administration. | 33 |
| `full` | `write`, plus administration: users and groups, permissions, project and space configuration. | 37 |

A tool above the session's level is not merely refused: it is never registered, so it does
not appear in `tools/list` at all.

## How it works

### 1. Authentication via the Edge session cookie

Scope: **Linux**, **Atlassian Cloud** (`*.atlassian.net`) only.

1. Locate the Edge profile's cookie database, `~/.config/microsoft-edge{,-beta,-dev,-nightly}/<profile>/Cookies`
   (also the Flatpak location under `~/.var/app/com.microsoft.Edge/`), defaulting to the
   `Default` profile. Edge stores it as an ordinary SQLite database.
2. Copy the database (plus its `-wal`/`-shm` sidecars) to a private temporary directory,
   because Edge holds a lock on the original while it runs.
3. Select the Cloud session cookies whose domain covers `--site`: `cloud.session.token` and
   `tenant.session.token`, then drop any that Edge has already expired.
4. Decrypt them:
   - key = `PBKDF2-HMAC-SHA1(password, "saltysalt", 1 iteration)`, 16 bytes;
   - password from the OS keyring (Secret Service / KWallet), falling back to Chromium's
     built-in `peanuts` password — which is what `--password-store=basic` uses;
   - AES-128-CBC, IV = sixteen spaces, PKCS#7 padding, `v10`/`v11` value tag;
   - strip the leading `SHA256(host_key)` that cookie database v24+ prepends.
5. Send the cookies as a `Cookie` header. They are never written to disk, never logged, and
   the temp copy is deleted as soon as the values are read.

No browser automation (no Playwright/Selenium): the browser is only the *source* of the
cookie, and all Atlassian traffic is plain HTTP from this process.

### 2. Access-level enforcement

Each level is enforced in two independent layers, so a bug in one does not become a write:

1. **Tool surface** — every tool declares the minimum level it needs in `TOOL_SPECS`, and
   tools above the session's level are disabled in the MCP router: absent from
   `tools/list`, and rejected if called by name anyway. A test fails if a registered tool
   is unclassified.
2. **Endpoint policy** — every request is matched against a table of
   `(method, path pattern, required level)`. Matching is by whole path segments, never by
   prefix, so `/rest/api/3/issue/{}` does not authorise
   `/rest/api/3/issue/ABC-1/transitions`. Anything not in the table is refused at every
   level, and a small `never` list is checked first.

A refusal names the level that would be needed:

```
blocked: POST /rest/api/3/issue requires access level 'write' or higher; this session is 'read'
```

A test ties each tool to the policy row for the endpoint it calls, so a tool cannot claim
`update` while using a `write` endpoint.

Tool arguments are percent-encoded into single path segments, so no argument can escape the
endpoint it belongs to.

### 3. Tool surface

| Level | Tools |
| --- | --- |
| `read` | `get_myself`, `search_issues` (JQL), `get_issue`, `list_projects`, `get_issue_comments`, `search_pages` (CQL), `get_page`, `list_spaces`, `get_page_children`, `list_page_comments` |
| `update` | `update_issue`, `transition_issue`, `assign_issue`, `update_comment`, `update_page`, `update_sprint`, `add_issues_to_sprint`, `move_issues_to_backlog`, `rank_issue`, `add_page_label`, `remove_page_label`, `update_page_property` |
| `write` | `create_issue`, `delete_issue`, `add_comment`, `delete_comment`, `create_page`, `delete_page`, `create_sprint`, `delete_sprint`, `upload_attachment`, `add_page_property`, `delete_page_property` |
| `full` | `create_project`, `create_space`, `add_group_member`, `remove_group_member` |

Read tools are annotated `readOnlyHint: true`, deletions `destructiveHint: true`.

`upload_attachment` takes the file contents **inline as text**, never a path: the server has
no way to read a local file, so a tool cannot become a file-exfiltration primitive. Binary
uploads are not exposed.

Jira Cloud takes rich text as [ADF](https://developer.atlassian.com/cloud/jira/platform/apis/document/structure/);
so that an agent can just send prose, a plain string is wrapped as a single paragraph, and
an object is passed through as ADF.

## Non-goals

- Any change to your data while running as `read`.
- API tokens, personal access tokens, or OAuth app registration.
- Driving a browser to obtain or refresh the session.
- Listening on a network port — the transport is local `stdio`.
- Caching or archiving Atlassian content on disk.

## Security notes

- A session cookie is a bearer credential equivalent to your logged-in browser. Anyone who
  reads it can act as you until it expires.
- `--level update`, `write` or `full` means the agent can change real data. `read` is the
  default precisely so that has to be a deliberate choice.
- `--site` must be an `*.atlassian.net` host. That check is what stops the cookie from being
  sent somewhere else; it is deliberately not overridable.
- The server is local-only and speaks MCP over `stdio` to a single client process.
- Cookie values are redacted from all logs and error messages; only cookie *names* are ever
  printed.
- Expired or revoked sessions surface as a clear error asking you to sign in to Atlassian in
  Edge again — there is no silent retry loop.
- The OS keyring may prompt to unlock. The lookup is best-effort with a 5-second cap and
  falls back to the built-in key, so a locked keyring degrades rather than hangs.
- SSO, MFA and CAPTCHA challenges stay in Edge's court; this tool cannot and will not solve
  them.

## Building and testing

Requires a Rust toolchain (edition 2024, i.e. Rust 1.85+), Edge installed and signed in to
Atlassian, and — only for the keyring path — a running Secret Service.

```sh
cargo build --release
cargo test
cargo run -- --site https://<your-org>.atlassian.net --check
```

The test suite needs neither Edge nor an Atlassian account: it writes a synthetic,
Chromium-shaped cookie database (including the real `SHA256(host_key)` value prefix), checks
decryption round-trips and known-answer vectors for the key derivation, drives the real
binary over stdio through a full MCP handshake at every access level, and compares the
enforced endpoint policy against [docs/access-levels.md](docs/access-levels.md) row by row.

## Decisions

1. **Platform** — Linux only. Other platforms fail with a clear error rather than a partial
   implementation.
2. **Deployment** — Atlassian Cloud only. Data Center/Server (`JSESSIONID`) is out of scope.
3. **Base URL** — passed explicitly via `--site`; never auto-detected from the Edge profile.
4. **MCP SDK** — the official `rmcp` crate, with `stdio` as the only transport.
5. **Access levels** — four cumulative levels, `read` by default. The endpoint policy lives
   in [docs/access-levels.md](docs/access-levels.md) and `src/policy/data.rs`; `read`,
   `update`, `write` and `full` all ship tools.
6. **Endpoint matching** — whole path segments with `{}` for one segment, never prefixes, so
   an allowlisted parent cannot imply its sub-resources.

## Open questions

1. **`update` vs `write` split** — `update` changes existing content but cannot create or
   delete; `write` adds and removes entries. Two consequences worth a second look: creating
   a comment is `write` while editing one is `update`, and Jira transitions are `update`
   even though workflow post-functions can create sub-tasks. See
   [docs/access-levels.md](docs/access-levels.md).
2. **Write-path safeguards** — for the levels that write, should every write require an
   explicit per-call confirmation, and if so, in what form?
