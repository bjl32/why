//! Distribution detection, used only to phrase suggested next steps.
//!
//! `why` v0.1 does not query package databases (that is v0.2); it merely knows
//! which command the user would run to answer "which package ships this file?".

use std::fs;

/// Coarse distribution family, enough to pick a package search command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Arch,
    Debian,
    Fedora,
    Suse,
    Alpine,
    Gentoo,
    Unknown,
}

/// What `/etc/os-release` said about the running system.
#[derive(Debug, Clone)]
pub struct Distro {
    pub id: String,
    pub name: String,
    pub family: Family,
}

impl Distro {
    /// Reads `/etc/os-release`; never fails.
    pub fn detect() -> Self {
        let fields = read_os_release();
        let get = |key: &str| {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let id = get("ID");
        let name = {
            let pretty = get("PRETTY_NAME");
            if pretty.is_empty() {
                if id.is_empty() {
                    "this system".to_string()
                } else {
                    id.clone()
                }
            } else {
                pretty
            }
        };
        let family = family_of(&id, &get("ID_LIKE"));
        Distro { id, name, family }
    }

    /// The command that finds which package provides `library`.
    pub fn search_hint(&self, library: &str) -> String {
        match self.family {
            Family::Arch => format!("pacman -F {library}   (or: pkgfile {library})"),
            Family::Debian => format!("apt-file search {library}   (or: dpkg -S)"),
            Family::Fedora => format!("dnf provides '*/{library}'"),
            Family::Suse => format!("zypper search --provides {library}"),
            Family::Alpine => format!("apk search -v 'so:{library}'"),
            Family::Gentoo => format!("pkgfile {library}"),
            Family::Unknown => {
                format!("use your distribution's \"which package provides {library}\" search")
            }
        }
    }
}

fn read_os_release() -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let Ok(text) = fs::read_to_string("/etc/os-release") else {
        return fields;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        fields.push((key.trim().to_string(), value.to_string()));
    }
    fields
}

fn family_of(id: &str, id_like: &str) -> Family {
    let haystack = format!("{id} {id_like}").to_ascii_lowercase();
    if haystack.contains("debian") || haystack.contains("ubuntu") {
        Family::Debian
    } else if haystack.contains("fedora")
        || haystack.contains("rhel")
        || haystack.contains("centos")
    {
        Family::Fedora
    } else if haystack.contains("suse") {
        Family::Suse
    } else if haystack.contains("alpine") {
        Family::Alpine
    } else if haystack.contains("gentoo") {
        Family::Gentoo
    } else if haystack.contains("arch") {
        Family::Arch
    } else {
        Family::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_families() {
        assert_eq!(family_of("arch", "arch"), Family::Arch);
        assert_eq!(family_of("ubuntu", "debian"), Family::Debian);
        assert_eq!(family_of("fedora", ""), Family::Fedora);
        assert_eq!(family_of("alpine", ""), Family::Alpine);
        assert_eq!(family_of("", ""), Family::Unknown);
    }

    #[test]
    fn hints_mention_the_library() {
        let distro = Distro {
            id: "arch".into(),
            name: "Arch".into(),
            family: Family::Arch,
        };
        assert!(distro.search_hint("libfoo.so.1").contains("libfoo.so.1"));
    }
}
