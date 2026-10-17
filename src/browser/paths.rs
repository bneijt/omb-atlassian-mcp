//! Where Edge keeps its profiles, per platform.
//!
//! The tables take their inputs as parameters and the platform to use as an argument, so
//! every platform's layout is unit-tested from any host.

use crate::{Error, Result};
use std::path::PathBuf;

/// Which platform's layout to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
}

impl Os {
    /// The platform this binary was built for.
    pub const CURRENT: Self = if cfg!(target_os = "macos") {
        Self::MacOs
    } else if cfg!(target_os = "windows") {
        Self::Windows
    } else {
        Self::Linux
    };
}

/// The environment locations that differ per platform.
#[derive(Debug, Default, Clone)]
pub struct Homes {
    pub home: Option<PathBuf>,
    /// `XDG_CONFIG_HOME` (Linux).
    pub config_home: Option<PathBuf>,
    /// `%LOCALAPPDATA%` (Windows).
    pub local_app_data: Option<PathBuf>,
}

impl Homes {
    /// Read the current process's environment.
    pub fn from_env() -> Self {
        Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
            config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            local_app_data: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        }
    }
}

/// Edge's release channels, as directory names, per platform.
fn channels(os: Os) -> &'static [&'static str] {
    match os {
        Os::Linux => &[
            "microsoft-edge",
            "microsoft-edge-beta",
            "microsoft-edge-dev",
            "microsoft-edge-nightly",
        ],
        Os::MacOs => &[
            "Microsoft Edge",
            "Microsoft Edge Beta",
            "Microsoft Edge Dev",
            "Microsoft Edge Canary",
        ],
        Os::Windows => &["Edge", "Edge Beta", "Edge Dev", "Edge SxS"],
    }
}

/// Edge's user-data roots for every channel, most likely first.
pub fn roots(os: Os, homes: &Homes) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    match os {
        Os::Linux => {
            let config = homes
                .config_home
                .clone()
                .or_else(|| homes.home.as_ref().map(|home| home.join(".config")));
            if let Some(config) = config {
                for channel in channels(os) {
                    roots.push(config.join(channel));
                }
            }
            // Flatpak installs keep their own config tree.
            if let Some(home) = &homes.home {
                for channel in channels(os) {
                    roots.push(
                        home.join(".var/app/com.microsoft.Edge/config")
                            .join(channel),
                    );
                }
            }
        }
        Os::MacOs => {
            if let Some(home) = &homes.home {
                for channel in channels(os) {
                    roots.push(home.join("Library/Application Support").join(channel));
                }
            }
        }
        Os::Windows => {
            if let Some(local) = &homes.local_app_data {
                for channel in channels(os) {
                    // `%LOCALAPPDATA%\Microsoft\Edge\User Data`
                    roots.push(local.join("Microsoft").join(channel).join("User Data"));
                }
            }
        }
    }
    roots
}

/// Candidate cookie databases for `profile`, most likely first.
pub fn cookie_candidates(os: Os, homes: &Homes, profile: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for root in roots(os, homes) {
        match os {
            // Modern Edge writes into `Network/`; older versions kept `Cookies` directly
            // in the profile directory, and a stale copy may still be there.
            Os::Windows => {
                candidates.push(root.join(profile).join("Network").join("Cookies"));
                candidates.push(root.join(profile).join("Cookies"));
            }
            _ => candidates.push(root.join(profile).join("Cookies")),
        }
    }
    candidates
}

/// Candidate `Local State` files. On Windows the DPAPI-protected key lives in one of
/// these.
pub fn local_state_candidates(os: Os, homes: &Homes) -> Vec<PathBuf> {
    roots(os, homes)
        .into_iter()
        .map(|root| root.join("Local State"))
        .collect()
}

/// The cookie database for `profile` on this machine.
pub fn cookie_db(profile: &str) -> Result<PathBuf> {
    let candidates = cookie_candidates(Os::CURRENT, &Homes::from_env(), profile);
    first_existing(&candidates).ok_or_else(|| Error::ProfileNotFound {
        searched: candidates.iter().map(|p| p.display().to_string()).collect(),
    })
}

/// The `Local State` file on this machine.
pub fn local_state() -> Result<PathBuf> {
    let candidates = local_state_candidates(Os::CURRENT, &Homes::from_env());
    first_existing(&candidates).ok_or_else(|| Error::NotFound {
        what: "Edge's Local State file".to_string(),
        searched: candidates.iter().map(|p| p.display().to_string()).collect(),
    })
}

fn first_existing(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.is_file()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn homes() -> Homes {
        Homes {
            home: Some(PathBuf::from("/home/u")),
            config_home: None,
            local_app_data: Some(PathBuf::from("/local/appdata")),
        }
    }

    /// Build the path a test expects, with this platform's separators.
    ///
    /// Comparing `PathBuf`s rather than `display()` strings keeps the assertions
    /// platform-independent: `Path` equality is defined over components, so `/a/b` and
    /// `\\a\\b` are the same path on Windows.
    fn expected(path: &str) -> PathBuf {
        PathBuf::from(path)
    }

    #[test]
    fn linux_paths_cover_channels_and_flatpak() {
        let candidates = cookie_candidates(Os::Linux, &homes(), "Default");
        assert!(candidates.contains(&expected("/home/u/.config/microsoft-edge/Default/Cookies")));
        assert!(candidates.contains(&expected(
            "/home/u/.config/microsoft-edge-beta/Default/Cookies"
        )));
        assert!(candidates.contains(&expected(
            "/home/u/.var/app/com.microsoft.Edge/config/microsoft-edge/Default/Cookies"
        )));
        // Linux has no `Network` subdirectory.
        assert!(!candidates.iter().any(|c| c.ends_with("Network/Cookies")));
    }

    #[test]
    fn xdg_config_home_overrides_dot_config_on_linux() {
        let homes = Homes {
            config_home: Some(PathBuf::from("/cfg")),
            ..homes()
        };
        let candidates = cookie_candidates(Os::Linux, &homes, "Default");
        assert!(candidates.contains(&expected("/cfg/microsoft-edge/Default/Cookies")));
        assert!(!candidates.iter().any(|c| c.starts_with("/home/u/.config")));
    }

    #[test]
    fn macos_paths_use_application_support() {
        let candidates = cookie_candidates(Os::MacOs, &homes(), "Default");
        assert!(candidates.contains(&expected(
            "/home/u/Library/Application Support/Microsoft Edge/Default/Cookies"
        )));
        assert!(candidates.contains(&expected(
            "/home/u/Library/Application Support/Microsoft Edge Canary/Default/Cookies"
        )));
    }

    #[test]
    fn windows_paths_prefer_network_and_cover_both_layouts() {
        let candidates = cookie_candidates(Os::Windows, &homes(), "Default");
        assert!(candidates.contains(&expected(
            "/local/appdata/Microsoft/Edge/User Data/Default/Network/Cookies"
        )));
        assert!(candidates.contains(&expected(
            "/local/appdata/Microsoft/Edge/User Data/Default/Cookies"
        )));
        // `Network/Cookies` must be tried before the legacy path.
        let network = candidates
            .iter()
            .position(|c| c.ends_with("Network/Cookies"))
            .unwrap();
        let legacy = candidates
            .iter()
            .position(|c| c.ends_with("User Data/Default/Cookies"))
            .unwrap();
        assert!(network < legacy);
    }

    #[test]
    fn windows_channels_match_the_edge_install_names() {
        let candidates = cookie_candidates(Os::Windows, &homes(), "Profile 2");
        assert!(candidates.contains(&expected(
            "/local/appdata/Microsoft/Edge Beta/User Data/Profile 2/Network/Cookies"
        )));
        assert!(candidates.contains(&expected(
            "/local/appdata/Microsoft/Edge SxS/User Data/Profile 2/Network/Cookies"
        )));
    }

    #[test]
    fn local_state_sits_at_each_root() {
        let linux = local_state_candidates(Os::Linux, &homes());
        assert!(linux.contains(&expected("/home/u/.config/microsoft-edge/Local State")));
        let windows = local_state_candidates(Os::Windows, &homes());
        assert!(windows.contains(&expected(
            "/local/appdata/Microsoft/Edge/User Data/Local State"
        )));
    }

    #[test]
    fn missing_homes_produce_no_candidates_rather_than_panicking() {
        let empty = Homes::default();
        for os in [Os::Linux, Os::MacOs, Os::Windows] {
            assert!(
                cookie_candidates(os, &empty, "Default").is_empty(),
                "{os:?}"
            );
        }
    }

    #[test]
    fn the_current_platform_is_one_we_support() {
        // `CURRENT` must not be something exotic; the dispatch below relies on it.
        assert!(matches!(Os::CURRENT, Os::Linux | Os::MacOs | Os::Windows));
    }
}
