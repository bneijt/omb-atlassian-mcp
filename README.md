# omb-atlassian-mcp

**omb** = *on my behalf*.

A small local [MCP](https://modelcontextprotocol.io) server that lets an AI agent read your
Atlassian products — **Confluence** and **Jira** — acting *as you*.

Instead of asking you to mint an API token or register an OAuth app, it reads the Atlassian
session cookie that already exists in your **Microsoft Edge** profile and replays it against
Atlassian Cloud. If you are logged into Atlassian in Edge, the agent inherits exactly the
access you have, and nothing more.

> **Status: `readonly` is implemented.** `read-update` and `full` are accepted by the CLI
> but refused at startup, so an unimplemented level can never widen what the agent may do.

## Usage

```sh
omb-atlassian-mcp --site https://<your-org>.atlassian.net [--access-level <LEVEL>]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--site <URL>` | *required* | Your Atlassian Cloud site. Must be `https://<something>.atlassian.net`. |
| `--access-level <LEVEL>` | `readonly` | `readonly`, `read-update`, or `full`. Only `readonly` is implemented. |
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

| Level | Meaning | Status |
| --- | --- | --- |
| `readonly` | Read everything the signed-in user can read, across Confluence and Jira. No writes of any kind. | **implemented** |
| `read-update` | `readonly`, plus modifying existing content. No creates, no deletes. | refused at startup |
| `full` | Unrestricted: create, delete, administer. | refused at startup |

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

### 2. Read-only enforcement

`readonly` is enforced in three independent layers, so a bug in one does not become a write:

1. **Tool surface** — only read tools are registered. `TOOL_SPECS` classifies every tool
   with the minimum level it needs, and a test fails if a registered tool is unclassified,
   so a write tool cannot be added without deciding that it writes.
2. **Endpoint allowlist** — every request must match a fixed `(method, path prefix)` list.
   This is an *endpoint* allowlist rather than a verb allowlist, because Jira's JQL search
   is a `POST` that reads:
   - `GET /rest/api/3/myself`, `/issue/{key}`, `/issue/{key}/comment`, `/project/search`
   - `POST /rest/api/3/search/jql` (Jira's JQL search)
   - `GET /wiki/rest/api/search` (CQL), `/wiki/api/v2/pages[/{id}[/children|/footer-comments]]`,
     `/wiki/api/v2/spaces`
3. **No write code paths** — the mutating client methods and tools do not exist.

Tool arguments are percent-encoded into single path segments, so no argument can escape the
endpoint it belongs to.

### 3. Tool surface

| Product | Tools |
| --- | --- |
| Identity | `get_myself` |
| Jira | `search_issues` (JQL, returns a `next_page_token`), `get_issue`, `list_projects`, `get_issue_comments` |
| Confluence | `search_pages` (CQL), `get_page` (body in storage format), `list_spaces`, `get_page_children`, `list_page_comments` |

Every tool is annotated `readOnlyHint: true` so MCP clients can render it accordingly.

## Non-goals

- Any write operation while running as `readonly`.
- API tokens, personal access tokens, or OAuth app registration.
- Driving a browser to obtain or refresh the session.
- Listening on a network port — the transport is local `stdio`.
- Caching or archiving Atlassian content on disk.

## Security notes

- A session cookie is a bearer credential equivalent to your logged-in browser. Anyone who
  reads it can act as you until it expires.
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
decryption round-trips and known-answer vectors for the key derivation, and drives the real
binary over stdio through a full MCP handshake.

## Decisions

1. **Platform** — Linux only. Other platforms fail with a clear error rather than a partial
   implementation.
2. **Deployment** — Atlassian Cloud only. Data Center/Server (`JSESSIONID`) is out of scope.
3. **Base URL** — passed explicitly via `--site`; never auto-detected from the Edge profile.
4. **MCP SDK** — the official `rmcp` crate, with `stdio` as the only transport.
5. **Access levels** — `readonly` is implemented and is the default; the other levels fail
   closed until they are built.

## Open questions

1. **`read-update` semantics** — is "modify existing content, no create/delete" the right
   middle tier, or should it be defined differently?
2. **Write-path safeguards** — for the levels that write, should every write require an
   explicit per-call confirmation, and if so, in what form?
