//! macOS: the Chromium "Safe Storage" password lives in the login Keychain.
//!
//! Chromium stores it as a generic password whose *service* is `"<product> Safe
//! Storage"` and whose account is the product name. Reading it from another process may
//! ask the user to allow access the first time, and fails if access is denied.
//!
//! This module compiles on every platform (it only needs `std::process::Command`), so it
//! is type-checked everywhere; the real Keychain read only succeeds on macOS.

use super::Credentials;
use crate::decrypt::{KEYRING_FALLBACK_PASSWORDS, derive_key};

/// Keychain services to try, most likely first.
pub const SERVICES: [&str; 3] = [
    "Microsoft Edge Safe Storage",
    "Chromium Safe Storage",
    "Chrome Safe Storage",
];

/// The Keychain account Chromium uses.
const ACCOUNT: &str = "Microsoft Edge";

/// The keys to try for this platform, plus where they came from.
pub fn credentials() -> (Credentials, String) {
    let mut keys: Vec<[u8; 16]> = Vec::new();
    let mut source = format!("no Keychain entry for any of {SERVICES:?}; using the built-in key");

    'services: for service in SERVICES {
        // The account field is normally the product name, but older builds wrote the
        // entry without one, so both lookups are worth a try.
        for account in [Some(ACCOUNT), None] {
            if let Some(password) = keychain_password(service, account) {
                keys.push(derive_key(&password, super::ITERATIONS));
                source = format!("Keychain item {service:?}");
                break 'services;
            }
        }
    }

    for password in KEYRING_FALLBACK_PASSWORDS {
        let key = derive_key(password, super::ITERATIONS);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    (Credentials::Cbc(keys), source)
}

/// Read a generic password from the login Keychain.
///
/// `security -w` prints just the password, so no parsing beyond trimming is needed.
fn keychain_password(service: &str, account: Option<&str>) -> Option<String> {
    let mut command = std::process::Command::new("/usr/bin/security");
    command.args(["find-generic-password", "-s", service, "-w"]);
    if let Some(account) = account {
        command.args(["-a", account]);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_security_output(&output.stdout)
}

/// Turn `security`'s stdout into a password, rejecting empty output.
fn parse_security_output(stdout: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(stdout).ok()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_output_is_trimmed() {
        assert_eq!(
            parse_security_output(b"hunter2\n").as_deref(),
            Some("hunter2")
        );
        assert_eq!(
            parse_security_output(b"  spaced  ").as_deref(),
            Some("spaced")
        );
        assert_eq!(parse_security_output(b"\n").as_deref(), None);
        assert_eq!(parse_security_output(b"").as_deref(), None);
        assert_eq!(parse_security_output(&[0xff, 0xfe]).as_deref(), None);
    }

    /// On platforms without a Keychain the lookup must degrade to the built-in key
    /// rather than fail. (Not run on macOS, where it would touch the real Keychain.)
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_missing_keychain_falls_back_to_the_built_in_key() {
        let (credentials, source) = credentials();
        let Credentials::Cbc(keys) = credentials else {
            panic!("macOS should produce CBC keys");
        };
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], derive_key("peanuts", crate::browser::ITERATIONS));
        assert!(source.contains("no Keychain entry"), "got: {source}");
    }
}
