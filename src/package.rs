//! Arch package ownership lookups.
//!
//! Package queries are deliberately best effort. The ELF diagnosis remains
//! useful when `pacman` is missing or its file database has not been synced.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::analyze::{Analysis, LibResolution};
use crate::distro::{Distro, Family};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageStatus {
    Available,
    Unavailable(String),
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    Installed(Vec<String>),
    SearchResults(Vec<String>),
    Unowned,
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFinding {
    pub subject: String,
    pub query: String,
    pub ownership: Ownership,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageReport {
    pub status: PackageStatus,
    pub findings: Vec<PackageFinding>,
}

impl PackageReport {
    pub fn unsupported(distro: &Distro) -> Self {
        Self {
            status: PackageStatus::Unsupported(distro.name.clone()),
            findings: Vec::new(),
        }
    }
}

struct Pacman {
    installed: HashMap<String, Ownership>,
    search: HashMap<String, Ownership>,
    warning: Option<String>,
}

impl Pacman {
    fn new() -> Result<Self, String> {
        if which_pacman().is_none() {
            return Err("pacman was not found on PATH".to_string());
        }
        Ok(Self {
            installed: HashMap::new(),
            search: HashMap::new(),
            warning: None,
        })
    }

    fn installed(&mut self, path: &Path) -> Ownership {
        let query = path.display().to_string();
        if let Some(result) = self.installed.get(&query) {
            return result.clone();
        }
        let result = run_query(
            &["-Qo", "--", &query],
            QueryKind::Installed,
            &mut self.warning,
        );
        self.installed.insert(query, result.clone());
        result
    }

    fn search(&mut self, name: &str) -> Ownership {
        if let Some(result) = self.search.get(name) {
            return result.clone();
        }
        let result = run_query(&["-F", "--", name], QueryKind::Search, &mut self.warning);
        self.search.insert(name.to_string(), result.clone());
        result
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    Installed,
    Search,
}

pub fn collect(analysis: &Analysis) -> PackageReport {
    let distro = Distro::detect();
    if distro.family != Family::Arch {
        return PackageReport::unsupported(&distro);
    }

    let mut pacman = match Pacman::new() {
        Ok(pacman) => pacman,
        Err(reason) => {
            return PackageReport {
                status: PackageStatus::Unavailable(reason),
                findings: Vec::new(),
            }
        }
    };
    let mut findings = Vec::new();

    findings.push(PackageFinding {
        subject: "target".to_string(),
        query: analysis.path.display().to_string(),
        ownership: pacman.installed(&analysis.path),
    });

    if let Some(interpreter) = &analysis.interpreter {
        let path = Path::new(&interpreter.path);
        let ownership = if interpreter.exists && path.is_absolute() {
            pacman.installed(path)
        } else if interpreter.path.is_empty() {
            Ownership::Unowned
        } else {
            pacman.search(&interpreter.path)
        };
        findings.push(PackageFinding {
            subject: "interpreter".to_string(),
            query: interpreter.path.clone(),
            ownership,
        });
    }

    for library in &analysis.libraries {
        let (query, ownership) = match &library.resolution {
            LibResolution::Found(path)
            | LibResolution::WrongArchitecture { path, .. }
            | LibResolution::Unusable { path, .. } => {
                (path.display().to_string(), pacman.installed(path))
            }
            LibResolution::Missing => (library.name.clone(), pacman.search(&library.name)),
        };
        findings.push(PackageFinding {
            subject: format!("library {}", library.name),
            query,
            ownership,
        });
    }

    let status = match pacman.warning {
        Some(warning) => PackageStatus::Unavailable(warning),
        None => PackageStatus::Available,
    };
    PackageReport { status, findings }
}

fn which_pacman() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join("pacman");
        (candidate.is_file() && is_executable(&candidate)).then_some(candidate)
    })
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn run_query(args: &[&str], kind: QueryKind, warning: &mut Option<String>) -> Ownership {
    let output = match Command::new("pacman").args(args).output() {
        Ok(output) => output,
        Err(error) => {
            *warning = Some(format!("could not run pacman: {error}"));
            return Ownership::Unavailable(error.to_string());
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let no_match = is_no_match(&stderr);
    let owners = match kind {
        QueryKind::Installed => parse_installed(&stdout),
        QueryKind::Search => parse_search(&stdout),
    };
    if !stderr.trim().is_empty()
        && !no_match
        && (kind == QueryKind::Search || !output.status.success())
    {
        let message = stderr.lines().next().unwrap_or("pacman reported a warning");
        *warning = Some(message.to_string());
    }
    if !owners.is_empty() {
        return match kind {
            QueryKind::Installed => Ownership::Installed(owners),
            QueryKind::Search => Ownership::SearchResults(owners),
        };
    }
    if output.status.success() || no_match {
        Ownership::Unowned
    } else {
        let reason = stderr
            .trim()
            .lines()
            .next()
            .unwrap_or("pacman query failed");
        Ownership::Unavailable(reason.to_string())
    }
}

fn parse_installed(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            line.split_once(" is owned by ")
                .map(|(_, owner)| owner.trim())
        })
        .map(str::to_string)
        .collect()
}

fn parse_search(output: &str) -> Vec<String> {
    let mut owners = Vec::new();
    for line in output.lines() {
        // File names are printed on indented lines by some pacman versions;
        // only a result header can identify a package.
        if line
            .chars()
            .next()
            .is_some_and(|character| character.is_whitespace())
        {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(package) = fields.next() else {
            continue;
        };
        if package.contains('/') {
            let package = package.trim_end_matches(':').to_string();
            if !owners.contains(&package) {
                owners.push(package);
            }
        }
    }
    owners
}

fn is_no_match(stderr: &str) -> bool {
    let text = stderr.to_ascii_lowercase();
    text.contains("no package owns")
        || text.contains("no results found")
        || text.contains("no files match")
        || text.contains("no files found")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_owner_output() {
        assert_eq!(
            parse_installed("/usr/lib/libc.so.6 is owned by glibc 2.44-1\n"),
            vec!["glibc 2.44-1"]
        );
    }

    #[test]
    fn parses_remote_owner_output() {
        assert_eq!(
            parse_search("core/glibc 2.44-1 usr/lib/libc.so.6\n    usr/lib/libc.so.6\n"),
            vec!["core/glibc"]
        );
    }

    #[test]
    fn ignores_search_warnings_and_file_lines() {
        assert!(parse_search(
            "warning: database file for 'core' does not exist\n    usr/lib/libc.so.6\n"
        )
        .is_empty());
    }

    #[test]
    fn recognises_pacman_no_match_messages() {
        assert!(is_no_match("error: No package owns /tmp/example"));
        assert!(is_no_match("error: No files match libmissing.so"));
        assert!(!is_no_match("warning: database file does not exist"));
    }
}
