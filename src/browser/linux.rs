//! Linux: the Chromium "Safe Storage" password lives in the Secret Service.
//!
//! Chromium-based browsers on Linux protect the AES key behind a password stored in
//! gnome-keyring or KWallet, under the `application` attribute — for *every* Chromium
//! browser, including Edge, that value is `chromium`.
//!
//! When no keyring entry exists (headless machines, `--password-store=basic`), Chromium
//! falls back to the hard-coded password `peanuts`. The lookup is therefore genuinely
//! best-effort: failure is not an error, it just means fewer candidate keys.

use super::Credentials;
use crate::decrypt::{KEYRING_FALLBACK_PASSWORDS, LINUX_ITERATIONS, derive_key};
use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

/// Schema names Chromium has used for the "Safe Storage" entry.
const SCHEMAS: [&str; 2] = [
    "chrome_libsecret_os_crypt_password_v2",
    "chrome_libsecret_os_crypt_password_v1",
];

/// `application` attribute values worth trying. Chromium uses `chromium` regardless of
/// the vendor; the others are cheap insurance.
const APPLICATIONS: [&str; 4] = ["chromium", "chrome", "Microsoft Edge", "microsoft-edge"];

/// Cap the whole keyring probe: an unlocked keyring answers in milliseconds, while a
/// locked one can pop a dialog and block forever.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The keys to try for this platform, plus where they came from.
pub async fn credentials() -> (Credentials, String) {
    let lookup = safe_storage_passwords().await;
    let keys = keys_with(lookup.passwords());
    let source = format!("OS keyring ({})", lookup.describe());
    (Credentials::Cbc(keys), source)
}

/// Candidate keys for a set of keyring passwords: the keyring's own first, then the
/// built-in fallbacks, deduplicated.
pub fn keys_with(passwords: &[String]) -> Vec<[u8; 16]> {
    let mut keys: Vec<[u8; 16]> = passwords
        .iter()
        .map(|password| derive_key(password, LINUX_ITERATIONS))
        .collect();
    for password in KEYRING_FALLBACK_PASSWORDS {
        let key = derive_key(password, LINUX_ITERATIONS);
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

/// Outcome of the keyring probe.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyringLookup {
    /// Passwords recovered from the keyring (may be empty if no entry exists).
    Passwords(Vec<String>),
    /// The keyring could not be consulted; only the built-in fallbacks are available.
    Unavailable(String),
}

impl KeyringLookup {
    /// Human-readable summary for error messages.
    fn describe(&self) -> String {
        match self {
            Self::Passwords(p) if p.is_empty() => "no matching entry".to_string(),
            Self::Passwords(p) => format!("{} password(s) from the OS keyring", p.len()),
            Self::Unavailable(reason) => format!("unavailable ({reason})"),
        }
    }

    /// The recovered passwords, if any.
    fn passwords(&self) -> &[String] {
        match self {
            Self::Passwords(p) => p,
            Self::Unavailable(_) => &[],
        }
    }
}

/// Look up the Safe Storage password, giving up after [`PROBE_TIMEOUT`].
async fn safe_storage_passwords() -> KeyringLookup {
    match timeout(PROBE_TIMEOUT, lookup()).await {
        Ok(Ok(passwords)) => KeyringLookup::Passwords(passwords),
        Ok(Err(reason)) => KeyringLookup::Unavailable(reason),
        Err(_) => KeyringLookup::Unavailable(format!(
            "lookup timed out after {}s (locked keyring?)",
            PROBE_TIMEOUT.as_secs()
        )),
    }
}

async fn lookup() -> Result<Vec<String>, String> {
    let service = SecretService::connect(EncryptionType::Plain)
        .await
        .map_err(|e| e.to_string())?;

    let mut found: Vec<String> = Vec::new();
    for schema in SCHEMAS {
        for application in APPLICATIONS {
            // Strict search first (schema + application), then a looser application-only
            // search, which catches entries written by builds that used another schema.
            for attributes in [
                HashMap::from([("xdg:schema", schema), ("application", application)]),
                HashMap::from([("application", application)]),
            ] {
                let Ok(items) = service.search_items(attributes).await else {
                    continue;
                };
                for item in items.unlocked.iter() {
                    push_secret(&mut found, item).await;
                }
                for item in items.locked.iter() {
                    if item.unlock().await.is_ok() {
                        push_secret(&mut found, item).await;
                    }
                }
            }
        }
    }
    Ok(found)
}

async fn push_secret(found: &mut Vec<String>, item: &secret_service::Item<'_>) {
    if let Ok(secret) = item.get_secret().await
        && let Ok(password) = String::from_utf8(secret)
        && !password.is_empty()
        && !found.iter().any(|existing| existing == &password)
    {
        found.push(password);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_fallbacks_are_always_available() {
        let keys = keys_with(&[]);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], derive_key("peanuts", LINUX_ITERATIONS));
        assert_eq!(keys[1], derive_key("", LINUX_ITERATIONS));
    }

    #[test]
    fn keyring_passwords_come_first_and_are_not_duplicated() {
        let keys = keys_with(&["keyring-secret".to_string(), "peanuts".to_string()]);
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], derive_key("keyring-secret", LINUX_ITERATIONS));
        assert_eq!(keys[1], derive_key("peanuts", LINUX_ITERATIONS));
        assert_eq!(keys[2], derive_key("", LINUX_ITERATIONS));
    }

    #[test]
    fn describe_covers_all_cases() {
        assert_eq!(
            KeyringLookup::Passwords(vec![]).describe(),
            "no matching entry"
        );
        assert_eq!(
            KeyringLookup::Passwords(vec!["a".into(), "b".into()]).describe(),
            "2 password(s) from the OS keyring"
        );
        assert!(
            KeyringLookup::Unavailable("no dbus".into())
                .describe()
                .contains("no dbus")
        );
        assert!(
            KeyringLookup::Unavailable("x".into())
                .passwords()
                .is_empty()
        );
    }
}
