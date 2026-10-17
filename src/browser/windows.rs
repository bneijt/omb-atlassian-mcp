//! Windows: the key is DPAPI-protected in Edge's `Local State`.
//!
//! `os_crypt.encrypted_key` is base64 around a blob that carries a `DPAPI` marker; once
//! the marker is stripped, `CryptUnprotectData` unwraps it into the 32-byte
//! AES-256-GCM key that decrypts `v10` cookie values.
//!
//! Newer Edge may use app-bound encryption (`v20`) instead, whose key needs Administrator
//! rights and the browser's own elevation service. That is deliberately not decrypted
//! here: the caller is told to use `--session-cookie-file`.
//!
//! Everything in this module except [`dpapi_unprotect`] compiles and is tested on every
//! platform, so only the FFI call itself is Windows-only.

use super::Credentials;
use crate::decrypt;
use base64::Engine;
use serde_json::Value;
use std::path::Path;

/// Marker Chromium puts in front of the DPAPI-protected key.
const DPAPI_MARKER: &[u8] = b"DPAPI";

/// The keys to try for this platform, plus where they came from.
pub fn credentials(local_state: &Path) -> Result<(Credentials, String), String> {
    let text = std::fs::read_to_string(local_state)
        .map_err(|e| format!("could not read {}: {e}", local_state.display()))?;
    let json: Value = serde_json::from_str(&text)
        .map_err(|e| format!("could not parse {}: {e}", local_state.display()))?;

    let blob = dpapi_blob(&json)?;
    let key = dpapi_unprotect(&blob)?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| "the DPAPI key is not 32 bytes".to_string())?;
    Ok((
        Credentials::Gcm(key),
        "DPAPI key from Local State".to_string(),
    ))
}

/// The DPAPI blob inside a parsed `Local State` file.
pub fn dpapi_blob(json: &Value) -> Result<Vec<u8>, String> {
    let encoded = json["os_crypt"]["encrypted_key"].as_str().ok_or_else(|| {
        "Local State has no os_crypt.encrypted_key (Edge has not stored a key yet)".to_string()
    })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("os_crypt.encrypted_key is not valid base64: {e}"))?;
    let blob = decoded
        .strip_prefix(DPAPI_MARKER)
        .ok_or_else(|| "os_crypt.encrypted_key is not DPAPI-protected".to_string())?;
    if blob.is_empty() {
        return Err("os_crypt.encrypted_key is empty".to_string());
    }
    Ok(blob.to_vec())
}

/// Whether this profile also carries an app-bound key, which means cookies are likely
/// `v20` and cannot be decrypted without Administrator rights.
pub fn has_app_bound_key(json: &Value) -> bool {
    json["os_crypt"]["app_bound_encrypted_key"]
        .as_str()
        .is_some_and(|value| !value.is_empty())
}

/// Decrypt a legacy value: the whole blob is DPAPI-protected plaintext.
pub fn decrypt_legacy(blob: &[u8], host_key: &str) -> Result<String, String> {
    let plaintext = dpapi_unprotect(blob)?;
    let value = decrypt::strip_domain_hash(&plaintext, host_key);
    std::str::from_utf8(value)
        .map(str::to_string)
        .map_err(|e| format!("decrypted, but not valid UTF-8: {e}"))
}

/// Unwrap a DPAPI blob with the current user's master key.
///
/// This block only compiles on Windows, so a Linux `cargo clippy` never sees it. When
/// changing it, mirror it into a scratch crate (see the plan in
/// `docs/platform-support.md`) and run `cargo clippy -- -D warnings` there, or CI's
/// Windows job is the first thing to find the problem.
#[cfg(windows)]
fn dpapi_unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

    let input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(
            "DPAPI refused to decrypt the Edge key (is this the same Windows user that Edge \
             runs as?)"
                .to_string(),
        );
    }

    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe { LocalFree(output.pbData as *mut _) };
    Ok(bytes)
}

/// DPAPI has no meaning outside Windows; the code above still compiles there so that the
/// parsing and format logic can be tested everywhere.
#[cfg(not(windows))]
fn dpapi_unprotect(_blob: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI is only available on Windows".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn local_state(encrypted_key: &[u8], app_bound: bool) -> Value {
        let encoded = base64::engine::general_purpose::STANDARD.encode(encrypted_key);
        let mut os_crypt = json!({ "encrypted_key": encoded });
        if app_bound {
            os_crypt["app_bound_encrypted_key"] = json!("AAAA");
        }
        json!({ "os_crypt": os_crypt })
    }

    #[test]
    fn the_dpapi_marker_is_stripped() {
        let mut blob = b"DPAPI".to_vec();
        blob.extend_from_slice(&[1, 2, 3, 4]);
        let json = local_state(&blob, false);
        assert_eq!(dpapi_blob(&json).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn a_missing_or_malformed_key_is_explained() {
        let error = dpapi_blob(&json!({})).unwrap_err();
        assert!(error.contains("os_crypt.encrypted_key"), "got: {error}");

        let error =
            dpapi_blob(&json!({ "os_crypt": { "encrypted_key": "not base64!" } })).unwrap_err();
        assert!(error.contains("base64"), "got: {error}");

        let error = dpapi_blob(&json!({ "os_crypt": { "encrypted_key": "AAAA" } })).unwrap_err();
        assert!(error.contains("not DPAPI-protected"), "got: {error}");

        let error =
            dpapi_blob(&json!({ "os_crypt": { "encrypted_key": "RFBBUEk=" } })).unwrap_err();
        assert!(error.contains("empty"), "got: {error}");
    }

    #[test]
    fn app_bound_keys_are_detected() {
        let plain = local_state(b"DPAPIxx", false);
        assert!(!has_app_bound_key(&plain));
        let bound = local_state(b"DPAPIxx", true);
        assert!(has_app_bound_key(&bound));
    }

    #[test]
    fn parsing_is_platform_neutral_but_dpapi_is_not() {
        // The parse succeeds everywhere; unwrapping only works on Windows.
        let json = local_state(b"DPAPI0123456789", false);
        let blob = dpapi_blob(&json).unwrap();
        assert_eq!(blob, b"0123456789");
        let outcome = dpapi_unprotect(&blob);
        if cfg!(windows) {
            // On Windows this fails only because the bytes are not a real DPAPI blob.
            assert!(outcome.is_err());
        } else {
            assert!(outcome.unwrap_err().contains("only available on Windows"));
        }
    }

    /// Round-trip through the real DPAPI on Windows runners, which is the only place the
    /// FFI can be exercised.
    #[cfg(windows)]
    #[test]
    fn dpapi_round_trips_on_windows() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData};

        let secret = b"omb-atlassian-mcp";
        let input = CRYPT_INTEGER_BLOB {
            cbData: secret.len() as u32,
            pbData: secret.as_ptr() as *mut u8,
        };
        let mut protected = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut protected,
            )
        };
        assert_ne!(ok, 0, "CryptProtectData failed");
        let blob =
            unsafe { std::slice::from_raw_parts(protected.pbData, protected.cbData as usize) }
                .to_vec();
        unsafe { LocalFree(protected.pbData as *mut _) };

        assert_eq!(dpapi_unprotect(&blob).unwrap(), secret);
    }
}
