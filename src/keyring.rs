//! Best-effort lookup of Chromium's "Safe Storage" password in the OS keyring.
//!
//! On Linux, Chromium-based browsers protect the AES key that encrypts cookie values
//! with a password stored in the Secret Service (gnome-keyring, KWallet, ...). The
//! password lives under the `application` attribute — for *every* Chromium-based
//! browser on Linux, including Edge, that value is `chromium`.
//!
//! When no keyring entry exists (headless machines, `--password-store=basic`), Chromium
//! falls back to the hard-coded password `peanuts`. So this lookup is genuinely
//! best-effort: failure is not an error, it just means fewer candidate keys.

use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

/// Schema names Chromium has used for the "Safe Storage" entry.
const SCHEMAS: [&str; 2] = [
    "chrome_libsecret_os_crypt_password_v2",
    "chrome_libsecret_os_crypt_password_v1",
];

/// `application` attribute values worth trying. Chromium-on-Linux uses `chromium`
/// regardless of the vendor; the others are cheap insurance.
const APPLICATIONS: [&str; 4] = ["chromium", "chrome", "Microsoft Edge", "microsoft-edge"];

/// Cap the whole keyring probe: an unlocked keyring answers in milliseconds, while a
/// locked one can pop a dialog and block forever.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of the keyring probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringLookup {
    /// Passwords recovered from the keyring (may be empty if no entry exists).
    Passwords(Vec<String>),
    /// The keyring could not be consulted; only the built-in fallbacks are available.
    Unavailable(String),
}

impl KeyringLookup {
    /// Human-readable summary for error messages.
    pub fn describe(&self) -> String {
        match self {
            Self::Passwords(p) if p.is_empty() => "no matching entry".to_string(),
            Self::Passwords(p) => format!("{} password(s) from the OS keyring", p.len()),
            Self::Unavailable(reason) => format!("unavailable ({reason})"),
        }
    }

    /// The recovered passwords, if any.
    pub fn passwords(&self) -> &[String] {
        match self {
            Self::Passwords(p) => p,
            Self::Unavailable(_) => &[],
        }
    }
}

/// Look up the Safe Storage password, giving up after [`PROBE_TIMEOUT`].
pub async fn safe_storage_passwords() -> KeyringLookup {
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
            // Strict search first (schema + application), then a looser
            // application-only search, which catches entries written by builds that
            // used a different schema name.
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
    }

    #[test]
    fn unavailable_lookup_yields_no_passwords() {
        assert!(
            KeyringLookup::Unavailable("x".into())
                .passwords()
                .is_empty()
        );
        assert_eq!(
            KeyringLookup::Passwords(vec!["k".into()]).passwords(),
            ["k"]
        );
    }
}
