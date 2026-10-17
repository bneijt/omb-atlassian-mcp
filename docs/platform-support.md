# Plan: macOS and Windows support

> **Status: implemented.** The server builds and runs on Linux, macOS and Windows, and
> `--session-cookie-file` covers profiles whose cookies cannot be decrypted (Windows
> app-bound `v20`). `v20` decryption itself remains out of scope (see
> [Decisions](#decisions)).

## The short version

- **macOS is straightforward.** Same Chromium cookie encryption as Linux, a different
  Keychain lookup and a different iteration count. Roughly a day.
- **Windows is two problems.** The older `v10` scheme (DPAPI + AES-256-GCM) is a day's work.
  The scheme current Edge uses (`v20`, app-bound encryption) needs Administrator rights and
  depends on undocumented internals that changed twice in the last year — so it is replaced
  by a **manual cookie fallback** the user can supply from Edge's DevTools.

## What is Linux-specific today

| Area | File | Linux assumption |
| --- | --- | --- |
| Profile discovery | `edge.rs` | `~/.config/microsoft-edge*`, Flatpak paths, `$XDG_CONFIG_HOME` |
| Key retrieval | `keyring.rs` | Secret Service over D-Bus (`secret-service` crate) |
| Decryption | `decrypt.rs` | PBKDF2 1 iteration + AES-128-CBC (`v10`/`v11`) |
| Error text / docs | `error.rs`, README | "only Linux is supported" |

Everything else — the access-level policy, the tool surface, the session handling, the MCP
transport — is already platform-independent and does not change.

## Verified platform mechanics

Facts below were checked against Chromium's cookie store, the Chromium-based browser tooling
that ships today, and published `v20` research. They are the part of this plan worth
reviewing closely, because they decide the effort.

| | Linux (today) | macOS | Windows |
| --- | --- | --- | --- |
| Cookie DB | `~/.config/microsoft-edge{,-beta,-dev,-nightly}/<profile>/Cookies` | `~/Library/Application Support/Microsoft Edge{ Beta,Dev,Canary}/<profile>/Cookies` | `%LOCALAPPDATA%\Microsoft\Edge{ Beta,Dev,SxS}\User Data\<profile>\Cookies` **and** `...\<profile>\Network\Cookies` |
| Key source | Secret Service / KWallet | login Keychain, generic password `"Microsoft Edge Safe Storage"` (account `Microsoft Edge`) | `Local State` → `os_crypt.encrypted_key` (base64, `DPAPI` prefix) → `CryptUnprotectData` with the **user** scope |
| Key derivation | PBKDF2-HMAC-SHA1, salt `saltysalt`, **1** iteration, 16 B | PBKDF2-HMAC-SHA1, salt `saltysalt`, **1003** iterations, 16 B | none (DPAPI returns the 32-byte key directly) |
| Cipher (normal cookies) | AES-128-CBC, IV = 16 spaces, PKCS#7, `v10`/`v11` | identical to Linux | **AES-256-GCM**, `v10`; nonce = first 12 bytes, tag = last 16 |
| Domain binding | `SHA256(host_key)` prefix stripped after verification | same | same |
| App-bound (`v20`) | — | — | `os_crypt.app_bound_encrypted_key`: SYSTEM DPAPI → user DPAPI → a key baked into `elevation_service.exe`. **Requires Administrator**, algorithm changed in Chromium 133 and 137. Out of scope. |

Notes that matter:

- **The `SHA256(host_key)` prefix is in the cookie store, not the OS layer**, so the existing
  verification and stripping logic is reused unchanged on both new platforms.
- **Windows cookie values may be legacy DPAPI blobs** (pre-`v10`), `v10` (AES-GCM), or `v20`
  (app-bound). All three need detecting, and only the first two can be decrypted.
- **macOS reads may prompt.** The Keychain item is owned by Edge; another process reading it
  triggers an "allow access" dialog the first time (naming `security`, or the binary if we
  use the API). A headless run cannot answer it.

## The manual cookie fallback (decided)

A platform-independent source of truth for the session cookie, so Windows stays usable when
Edge uses `v20` — and so any user can bypass browser extraction entirely.

- **Flag:** `--session-cookie-file <PATH>`.
- **Precedence:** if given, Edge extraction is skipped entirely (explicit beats implicit). If
  not given, the platform extractor runs; if it finds `v20` values it fails with a message
  naming this flag.
- **Format** — accepts either shape, so a user can paste what DevTools gives them:
  - a raw `Cookie:` header value (`cloud.session.token=…; tenant.session.token=…`), with an
    optional leading `Cookie:` label;
  - or a JSON object mapping cookie names to values.
  It must contain at least one of `cloud.session.token` / `tenant.session.token`, otherwise
  it is rejected — a silent empty header would fail later and more confusingly.
- **Security:** the file is a bearer credential. It is read once at startup, never logged
  (only cookie *names* are printed, as today), and on Unix the server warns if the file is
  group- or world-readable. An environment variable was considered and rejected: process
  environment is readable by other processes of the same user, whereas a `0600` file is not.
- **Getting the value on Windows:** Edge DevTools → Application → Cookies →
  `https://<site>/` → copy `cloud.session.token`.

This lives in `session.rs` (or a small `session/cookie_source.rs`) and is fully testable on
Linux, which also means it can land **before** any Windows work.

## Target architecture

Split the platform layer behind one small interface, so the rest of the crate never grows a
`#[cfg]`:

```
src/browser/
  mod.rs        // pub fn discover(profile) -> Profile; pub struct Decryptor
  paths.rs      // pure: (os, home, local_app_data, profile) -> candidate paths   [testable everywhere]
  cookie_db.rs  // SQLite reading, copy-aside, host matching (today's edge.rs)     [platform-free]
  linux.rs      // Secret Service + CBC(1)          [cfg(linux)]
  macos.rs      // Keychain + CBC(1003)             [cfg(macos)]
  windows.rs    // Local State + DPAPI + AES-GCM    [cfg(windows)]
```

- `Decryptor` is an enum with one variant per platform, created by `mod.rs`. Callers receive
  `Decryptor::decrypt(&self, blob, host_key) -> Result<String>`, so `session.rs` is unchanged
  except for naming.
- `paths.rs` takes its inputs as parameters rather than reading the environment, so every
  platform's path table is unit-tested from any host.
- `decrypt.rs` keeps the shared Chromium primitives (`cbc_decrypt`, `gcm_decrypt`,
  `strip_domain_hash`, `derive_key`) and stays platform-neutral.

Dependency changes:

```toml
[target.'cfg(target_os = "linux")'.dependencies]
secret-service = { version = "5", features = ["rt-tokio-crypto-rust"] }

[target.'cfg(target_os = "windows")'.dependencies]
aes-gcm = "0.10"
base64 = "0.22"
windows-sys = { version = "0.59", features = ["Win32_Security_Cryptography", "Win32_Foundation"] }
```

macOS needs no new dependency if the Keychain read shells out to `/usr/bin/security` (present
on every macOS). A native `security-framework` read is possible but not worth a dependency for
one lookup.

## Phases

| Phase | Work | Status |
| --- | --- | --- |
| **0. Decouple** | Split `edge.rs`/`keyring.rs` into `browser/` as above; move `secret-service` behind a target dependency. **No behaviour change**, Linux tests stay green. | done |
| **1. Cookie fallback** | `--session-cookie-file`, both formats, validation, redaction, Unix permission warning, tests. Useful on its own; no platform work. | done |
| **2. macOS** | `paths.rs` macOS table; `macos.rs` Keychain + 1003-iteration CBC; known-answer test for the KDF; account/service fallbacks (`Microsoft Edge Safe Storage`, `Chromium Safe Storage`, `Chrome Safe Storage`). | done |
| **3. Windows base** | `paths.rs` Windows table (`Network\Cookies` and legacy); `Local State` parsing; DPAPI unwrap; AES-GCM `v10`; legacy DPAPI-blob values; `v20` detected and rejected with a message naming `--session-cookie-file`. | done |
| **4. CI + release** | CI matrix on `ubuntu-latest`, `macos-latest`, `windows-latest`; release assets for each. | done |

## Testing strategy

The hard constraint: no macOS or Windows machine here, so the design must maximise what is
testable on Linux and leave only thin OS calls unverified locally.

| Piece | How it is tested |
| --- | --- |
| Cookie file | Parsing, both formats, missing session cookie, unreadable file, permission warning — all on Linux. |
| Path tables | Pure function, unit-tested on every OS with fake `home`/`local_app_data` values. |
| `SHA256(host_key)` stripping | Already tested; shared by all platforms. |
| macOS key derivation | Known-answer test with the 1003-iteration digest computed independently (as the 1-iteration vector is today). |
| macOS Keychain lookup | Behind a trait; a fake keychain in tests. The real lookup runs in the macOS CI job. |
| Windows `Local State` parsing | Pure JSON/base64/prefix logic, unit-tested everywhere. Only the DPAPI call is `#[cfg(windows)]`. |
| Windows AES-256-GCM | Round-trip test on every OS with a synthetic key, plus a malformed-tag test. |
| End-to-end | `tests/stdio_server.rs` today points `XDG_CONFIG_HOME` at a synthetic profile. Change the harness to set `HOME`, `XDG_CONFIG_HOME` and `LOCALAPPDATA` all to the temp dir, and set the profile up in the platform's layout — then the same test runs on all three runners. |

`--check` stays the user-facing smoke test on every platform.

**Where each piece actually runs.** The path tables, the cookie-file parsing, the
`Local State` parsing, the macOS key derivation and both ciphers are unit-tested on every
host, so most of the logic is covered on a Linux development machine. Two things can only
run on their own platform:

- the DPAPI FFI, type-checked against `windows-sys` 0.61 but only *executed* by the Windows
  CI job, which round-trips a value through `CryptProtectData` / `CryptUnprotectData`.
  It cannot even be linked on Linux, so a local `cargo clippy` never sees it: when
  changing it, mirror the two functions into a scratch crate that depends on `windows-sys`
  and run `cargo clippy -- -D warnings` there. That catches type and lint errors without
  waiting for CI;
- the macOS Keychain read, exercised only by the macOS CI job (the unit test that would
  touch the real Keychain is skipped there).

## CI and release

- **New `.github/workflows/ci.yml`** — on push/PR: `cargo fmt --check`, `cargo clippy
  --all-targets -- -D warnings`, `cargo test --locked` on the three OSes. This is the piece
  the repo is missing today, and it is what makes the other platforms trustworthy.
- **`release.yml`** grows into a matrix:

  | Asset | Runner |
  | --- | --- |
  | `omb-atlassian-mcp-linux-x86_64` | ubuntu-latest |
  | `omb-atlassian-mcp-macos-universal` (arm64 + x86_64 via `lipo`) | macos-latest |
  | `omb-atlassian-mcp-windows-x86_64.exe` | windows-latest |

  The publish step already fails on a missing asset, so a platform that stops building cannot
  quietly disappear from a release.

## Risks

1. **Windows `v20` is mitigated, not solved.** Users whose Edge uses app-bound encryption must
   supply the cookie by hand: a one-time copy from DevTools, repeated whenever the session
   expires. That is the accepted trade for not requiring Administrator.
2. **The cookie file adds a credential-handling path.** Redaction, a strict format check, and
   a file-permission warning are part of phase 1, not follow-ups.
3. **macOS Keychain prompts** may block a headless or agent-spawned server until someone
   clicks Allow. Needs a documented first-run step and a clear error if access is denied.
4. **Release matrix cost**: three jobs per tag instead of one, and macOS runners are slow to
   start. Acceptable for a tagged release.

## Decisions

1. **Windows app-bound (`v20`)** — **decided: `v10` support plus a manual cookie fallback.**
   `v20` decryption is not implemented; it needs Administrator and tracks undocumented Edge
   internals. The fallback keeps Windows usable either way.
2. **Cookie fallback transport** — **decided: a file, not an environment variable.** See
   [above](#the-manual-cookie-fallback-decided).
3. **macOS release shape** — assumed: one universal binary via `lipo`.
4. **Windows architecture** — assumed: x86_64 first; arm64 later if wanted.

Say so if either assumption is wrong; both are cheap to change before phase 4.
