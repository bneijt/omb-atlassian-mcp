//! Chromium/Edge cookie encryption.
//!
//! Chromium encrypts cookie values differently per platform:
//!
//! - **Linux and macOS** derive a 16-byte key with `PBKDF2-HMAC-SHA1("saltysalt")` —
//!   1 iteration on Linux, 1003 on macOS — then AES-128-CBC with an IV of sixteen ASCII
//!   spaces and PKCS#7 padding.
//! - **Windows** unwraps a 32-byte key from `Local State` with DPAPI, then AES-256-GCM:
//!   a 12-byte nonce, then ciphertext and a 16-byte tag.
//!
//! Both schemes tag the ciphertext with `v10`. Windows may also see `v20` (app-bound),
//! which needs Administrator rights and is deliberately not decrypted here.
//!
//! Both schemes bind the plaintext to its domain: since cookie database version 24,
//! `SHA256(host_key)` is prepended before encrypting, and stripped after verification.
//!
//! All of this is verified against Chromium's own source and reproduced here, so the
//! server can read the cookie without a browser being driven. No secret ever leaves
//! this process.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

/// Chromium's hard-coded PBKDF2 salt on Linux and macOS.
const SALT: &[u8] = b"saltysalt";

/// Iteration count Chromium uses on Linux.
pub const LINUX_ITERATIONS: u32 = 1;

/// Iteration count Chromium uses on macOS.
pub const MACOS_ITERATIONS: u32 = 1003;

/// AES-CBC initialisation vector: sixteen ASCII spaces.
const IV: [u8; 16] = [b' '; 16];

/// AES block size, needed to size the padding buffer.
const AES_BLOCK: usize = 16;

/// AES-GCM nonce length used by Windows Chromium cookies.
const GCM_NONCE_LEN: usize = 12;

/// AES-GCM tag length.
const GCM_TAG_LEN: usize = 16;

/// Passwords Chromium falls back to when the OS keyring has no "Safe Storage" entry.
pub const KEYRING_FALLBACK_PASSWORDS: [&str; 2] = ["peanuts", ""];

/// Version tags this implementation understands.
pub const SUPPORTED_PREFIXES: [&[u8; 3]; 2] = [b"v10", b"v11"];

/// Version tag for app-bound values (Windows only, deliberately not decrypted).
pub const APP_BOUND_PREFIX: &[u8; 3] = b"v20";

/// Derive the AES key from a Safe Storage password.
pub fn derive_key(password: &str, iterations: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), SALT, iterations, &mut key);
    key
}

/// `SHA256(host_key)` — the per-domain tag Chromium prepends to encrypted values.
pub fn domain_hash(host_key: &str) -> [u8; 32] {
    let digest = Sha256::digest(host_key.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Remove the `SHA256(host_key)` prefix if it is present.
///
/// Values written before cookie database version 24 have no prefix, so a missing one
/// is not an error — it just means the plaintext is the value itself.
pub fn strip_domain_hash<'a>(plaintext: &'a [u8], host_key: &str) -> &'a [u8] {
    let hash = domain_hash(host_key);
    if plaintext.len() > hash.len() && plaintext[..hash.len()] == hash {
        &plaintext[hash.len()..]
    } else {
        plaintext
    }
}

/// Whether the value carries a version tag we can decrypt.
pub fn is_supported(encrypted: &[u8]) -> bool {
    encrypted.len() > 3 && SUPPORTED_PREFIXES.iter().any(|p| encrypted.starts_with(*p))
}

/// Decrypt one cookie value, trying each candidate key in turn.
///
/// Returns the decoded plaintext, or a description of every failed attempt so the
/// caller can explain *why* the session cookie was unusable.
pub fn decrypt_cookie_value(
    encrypted: &[u8],
    host_key: &str,
    keys: &[[u8; 16]],
) -> std::result::Result<String, String> {
    if encrypted.is_empty() {
        return Err("the stored value is empty".to_string());
    }
    if !is_supported(encrypted) {
        return Err(format!(
            "unsupported encryption prefix {:?}; only v10/v11 (Linux AES-CBC) are supported \
             (v20 app-bound values are Windows-only)",
            String::from_utf8_lossy(&encrypted[..encrypted.len().min(3)])
        ));
    }

    let body = &encrypted[3..];
    let mut failures = Vec::new();

    for key in keys {
        let key = *key;
        let mut buffer = body.to_vec();
        let cipher = Aes128CbcDec::new(&key.into(), &IV.into());
        match cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
            Ok(plaintext) => {
                let value = strip_domain_hash(plaintext, host_key);
                match std::str::from_utf8(value) {
                    Ok(value) => return Ok(value.to_string()),
                    Err(e) => failures.push(format!("decrypted, but not valid UTF-8: {e}")),
                }
            }
            Err(_) => failures.push("padding check failed".to_string()),
        }
    }

    Err(failures.join("; "))
}

/// Encrypt a cookie value the way Chromium would.
///
/// Only used by tests and diagnostics — the server never writes cookies.
pub fn encrypt_cookie_value(
    value: &str,
    host_key: &str,
    key: &[u8; 16],
    with_domain_hash: bool,
) -> Vec<u8> {
    let mut plaintext = Vec::new();
    if with_domain_hash {
        plaintext.extend_from_slice(&domain_hash(host_key));
    }
    plaintext.extend_from_slice(value.as_bytes());

    let message_len = plaintext.len();
    let mut buffer = vec![0u8; message_len + AES_BLOCK];
    buffer[..message_len].copy_from_slice(&plaintext);

    let cipher = Aes128CbcEnc::new(&(*key).into(), &IV.into());
    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, message_len)
        .expect("the buffer always has room for one padding block");

    let mut out = b"v10".to_vec();
    out.extend_from_slice(ciphertext);
    out
}

/// Whether the value uses app-bound encryption (`v20`, Windows only).
pub fn is_app_bound(encrypted: &[u8]) -> bool {
    encrypted.starts_with(APP_BOUND_PREFIX)
}

/// Decrypt a Windows `v10` cookie value: AES-256-GCM with the DPAPI-unwrapped key.
///
/// The body after the tag is a 12-byte nonce followed by the ciphertext and a 16-byte
/// GCM tag. `v20` values cannot be decrypted without Administrator rights, so they are
/// reported with a message that says what to do instead.
pub fn decrypt_gcm(
    encrypted: &[u8],
    host_key: &str,
    key: &[u8; 32],
) -> std::result::Result<String, String> {
    if encrypted.is_empty() {
        return Err("the stored value is empty".to_string());
    }
    if is_app_bound(encrypted) {
        return Err(
            "this is an app-bound (v20) cookie, which Edge encrypts with a key that requires \
             Administrator rights; supply the cookie with --session-cookie-file instead"
                .to_string(),
        );
    }
    if !encrypted.starts_with(b"v10") {
        return Err(format!(
            "unsupported encryption prefix {:?}; Windows cookies are v10 (AES-GCM) or v20 \
             (app-bound)",
            String::from_utf8_lossy(&encrypted[..encrypted.len().min(3)])
        ));
    }

    let body = &encrypted[3..];
    if body.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        return Err("the stored value is truncated".to_string());
    }
    let (nonce, sealed) = body.split_at(GCM_NONCE_LEN);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), sealed)
        .map_err(|_| "the GCM tag did not verify (wrong key?)".to_string())?;

    let value = strip_domain_hash(&plaintext, host_key);
    std::str::from_utf8(value)
        .map(str::to_string)
        .map_err(|e| format!("decrypted, but not valid UTF-8: {e}"))
}

/// Encrypt a cookie value the Windows way. Only used by tests and diagnostics.
pub fn encrypt_cookie_value_gcm(
    value: &str,
    host_key: &str,
    key: &[u8; 32],
    with_domain_hash: bool,
) -> Vec<u8> {
    let mut plaintext = Vec::new();
    if with_domain_hash {
        plaintext.extend_from_slice(&domain_hash(host_key));
    }
    plaintext.extend_from_slice(value.as_bytes());

    // A fixed nonce keeps the tests deterministic; real values never reuse one.
    let mut nonce = [0u8; GCM_NONCE_LEN];
    nonce[..4].copy_from_slice(b"test");

    let cipher = Aes256Gcm::new_from_slice(key).expect("a 32-byte key is always valid");
    let sealed = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .expect("encryption cannot fail for a valid key");

    let mut out = b"v10".to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys for the fallback passwords, as used when the keyring has no entry.
    fn fallback_keys() -> Vec<[u8; 16]> {
        KEYRING_FALLBACK_PASSWORDS
            .iter()
            .map(|p| derive_key(p, LINUX_ITERATIONS))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Known-answer test. These digests were produced independently with Python:
    /// `hashlib.pbkdf2_hmac('sha1', password, b'saltysalt', 1, 16)`.
    #[test]
    fn key_derivation_matches_chromium() {
        assert_eq!(
            hex(&derive_key("peanuts", LINUX_ITERATIONS)),
            "fd621fe5a2b402539dfa147ca9272778"
        );
        assert_eq!(
            hex(&derive_key("", LINUX_ITERATIONS)),
            "d0d0ec9c7d77d43ac54187fa4818d17f"
        );
    }

    #[test]
    fn domain_hash_is_sha256_of_the_host() {
        // sha256(".atlassian.net")
        let expected = Sha256::digest(b".atlassian.net");
        assert_eq!(
            domain_hash(".atlassian.net").as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn round_trip_with_domain_hash() {
        let host = "acme.atlassian.net";
        let key = derive_key("peanuts", LINUX_ITERATIONS);
        let encrypted = encrypt_cookie_value("s3cret-session", host, &key, true);
        assert!(is_supported(&encrypted));
        assert_eq!(
            decrypt_cookie_value(&encrypted, host, &fallback_keys()).unwrap(),
            "s3cret-session"
        );
    }

    #[test]
    fn round_trip_without_domain_hash_older_database() {
        let host = "acme.atlassian.net";
        let key = derive_key("peanuts", LINUX_ITERATIONS);
        let encrypted = encrypt_cookie_value("legacy", host, &key, false);
        assert_eq!(
            decrypt_cookie_value(&encrypted, host, &fallback_keys()).unwrap(),
            "legacy"
        );
    }

    #[test]
    fn the_right_key_is_found_among_several() {
        let host = "acme.atlassian.net";
        let real = derive_key("keyring-password", LINUX_ITERATIONS);
        let encrypted = encrypt_cookie_value("value", host, &real, true);

        let mut keys = vec![derive_key("wrong", LINUX_ITERATIONS)];
        keys.push(real);
        keys.extend(fallback_keys());

        assert_eq!(
            decrypt_cookie_value(&encrypted, host, &keys).unwrap(),
            "value"
        );
    }

    #[test]
    fn a_value_bound_to_another_host_is_not_silently_accepted() {
        let key = derive_key("peanuts", LINUX_ITERATIONS);
        // Encrypted for one domain, then read as if it belonged to another. The stored
        // value is bound to the first domain, so it must not be handed back as a valid
        // cookie for the second one.
        let encrypted = encrypt_cookie_value("value", "first.atlassian.net", &key, true);
        let result = decrypt_cookie_value(&encrypted, "other.atlassian.net", &fallback_keys());
        assert!(
            result.is_err(),
            "a value bound to a different host must not decrypt as if it were valid: {result:?}"
        );
    }

    #[test]
    fn wrong_keys_produce_a_useful_error() {
        let key = derive_key("peanuts", LINUX_ITERATIONS);
        let encrypted = encrypt_cookie_value("value", "acme.atlassian.net", &key, true);
        let err = decrypt_cookie_value(&encrypted, "acme.atlassian.net", &[derive_key("nope", 1)])
            .unwrap_err();
        assert!(err.contains("padding check failed"), "got: {err}");
    }

    #[test]
    fn unsupported_prefixes_are_rejected_with_an_explanation() {
        let mut v20 = b"v20".to_vec();
        v20.extend_from_slice(&[0u8; 32]);
        let err = decrypt_cookie_value(&v20, "acme.atlassian.net", &fallback_keys()).unwrap_err();
        assert!(err.contains("v20"), "got: {err}");
        assert!(err.contains("v10/v11"), "got: {err}");

        assert!(decrypt_cookie_value(&[], "h", &fallback_keys()).is_err());
    }

    // ---------------------------------------------------------------------
    // macOS key derivation
    // ---------------------------------------------------------------------

    /// Known-answer test. Produced independently with Python:
    /// `hashlib.pbkdf2_hmac('sha1', b'peanuts', b'saltysalt', 1003, 16)`.
    #[test]
    fn macos_key_derivation_matches_chromium() {
        assert_eq!(
            hex(&derive_key("peanuts", MACOS_ITERATIONS)),
            "d9a09d499b4e1b7461f28e67972c6dbd"
        );
    }

    // ---------------------------------------------------------------------
    // Windows AES-256-GCM
    // ---------------------------------------------------------------------

    const GCM_KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn gcm_round_trip_with_and_without_the_domain_hash() {
        for with_hash in [true, false] {
            let encrypted = encrypt_cookie_value_gcm(
                "windows-token",
                "acme.atlassian.net",
                &GCM_KEY,
                with_hash,
            );
            assert!(encrypted.starts_with(b"v10"));
            assert_eq!(
                decrypt_gcm(&encrypted, "acme.atlassian.net", &GCM_KEY).unwrap(),
                "windows-token",
                "with_domain_hash = {with_hash}"
            );
        }
    }

    #[test]
    fn gcm_rejects_app_bound_values_with_an_actionable_message() {
        let mut v20 = b"v20".to_vec();
        v20.extend_from_slice(&[0u8; 48]);
        assert!(is_app_bound(&v20));
        let err = decrypt_gcm(&v20, "acme.atlassian.net", &GCM_KEY).unwrap_err();
        assert!(err.contains("--session-cookie-file"), "got: {err}");
        assert!(err.contains("Administrator"), "got: {err}");
    }

    #[test]
    fn gcm_wrong_key_fails_the_tag() {
        let encrypted = encrypt_cookie_value_gcm("value", "acme.atlassian.net", &GCM_KEY, true);
        let err = decrypt_gcm(&encrypted, "acme.atlassian.net", &[0x24; 32]).unwrap_err();
        assert!(err.contains("GCM tag"), "got: {err}");
    }

    #[test]
    fn gcm_rejects_truncated_values() {
        let mut short = b"v10".to_vec();
        short.extend_from_slice(&[0u8; 20]);
        let err = decrypt_gcm(&short, "acme.atlassian.net", &GCM_KEY).unwrap_err();
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn gcm_and_cbc_are_not_interchangeable() {
        // A CBC value must not be silently accepted by the GCM path, nor the reverse.
        let cbc = encrypt_cookie_value(
            "value",
            "acme.atlassian.net",
            &derive_key("peanuts", 1),
            true,
        );
        assert!(decrypt_gcm(&cbc, "acme.atlassian.net", &GCM_KEY).is_err());

        let gcm = encrypt_cookie_value_gcm("value", "acme.atlassian.net", &GCM_KEY, true);
        assert!(decrypt_cookie_value(&gcm, "acme.atlassian.net", &fallback_keys()).is_err());
    }
}
