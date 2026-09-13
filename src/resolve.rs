//! Dynamic-loader library search semantics.
//!
//! glibc looks for a `DT_NEEDED` object in this order:
//!
//! 1. `DT_RPATH` of the loading object (ignored when it has `DT_RUNPATH`)
//! 2. `LD_LIBRARY_PATH`
//! 3. `DT_RUNPATH` of the loading object
//! 4. the `ld.so` cache
//! 5. the default directories
//!
//! Reproducing that order is what lets `why` report the file the loader would
//! actually pick, and — more importantly — conclude confidently that a library
//! is missing rather than merely not being where the tool happened to look.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::elf::{Class, ElfFile};

/// One entry of the `ld.so` cache, as printed by `ldconfig -p`.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub name: String,
    pub arch: String,
    pub path: PathBuf,
}

/// Resolves `DT_NEEDED` names against the real search path.
pub struct Resolver {
    env_dirs: Vec<PathBuf>,
    cache: Vec<CacheEntry>,
    defaults: Vec<PathBuf>,
}

impl Resolver {
    /// Builds a resolver from the current environment and system state.
    pub fn new() -> Self {
        Self {
            env_dirs: env_dirs(),
            cache: ld_cache(),
            defaults: default_dirs(),
        }
    }

    /// The directories taken from `LD_LIBRARY_PATH`.
    pub fn env_dirs(&self) -> &[PathBuf] {
        &self.env_dirs
    }

    /// Finds `name`, searching `rpath` then `LD_LIBRARY_PATH` then `runpath`
    /// then the cache then the defaults. `rpath` should already be empty if the
    /// loading object has a `DT_RUNPATH`.
    pub fn search(&self, name: &str, rpath: &[PathBuf], runpath: &[PathBuf]) -> Option<PathBuf> {
        // A name containing a slash is used as a path verbatim.
        if name.contains('/') {
            let candidate = PathBuf::from(name);
            return candidate.is_file().then_some(candidate);
        }
        for dir in rpath
            .iter()
            .chain(self.env_dirs.iter())
            .chain(runpath.iter())
        {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        for entry in &self.cache {
            if entry.name == name && entry.path.is_file() {
                return Some(entry.path.clone());
            }
        }
        for dir in &self.defaults {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

fn env_dirs() -> Vec<PathBuf> {
    match std::env::var("LD_LIBRARY_PATH") {
        Ok(value) => value
            .split(':')
            .filter(|entry| !entry.is_empty())
            .map(PathBuf::from)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Runs `ldconfig -p` and parses its cache listing.
///
/// The cache is used rather than parsing `/etc/ld.so.cache` directly because
/// its binary format is private to glibc; shelling out to `ldconfig` keeps
/// this correct across versions. When `ldconfig` is unavailable the search
/// falls back to the configured directories.
fn ld_cache() -> Vec<CacheEntry> {
    for program in ["ldconfig", "/sbin/ldconfig", "/usr/sbin/ldconfig"] {
        let Ok(output) = Command::new(program).arg("-p").output() else {
            continue;
        };
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let entries = parse_ld_cache(&text);
            if !entries.is_empty() {
                return entries;
            }
        }
    }
    Vec::new()
}

fn parse_ld_cache(text: &str) -> Vec<CacheEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        // Format: "\tlibfoo.so.1 (libc6,x86-64) => /usr/lib/libfoo.so.1"
        let Some((name, rest)) = line.trim().split_once(" (") else {
            continue;
        };
        let Some((arch, path)) = rest.split_once(") => ") else {
            continue;
        };
        let path = path.trim();
        if path.is_empty() {
            continue;
        }
        entries.push(CacheEntry {
            name: name.trim().to_string(),
            arch: arch.trim().to_string(),
            path: PathBuf::from(path),
        });
    }
    entries
}

/// The default directories, plus anything configured in `ld.so.conf`.
fn default_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for dir in ["/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib"] {
        dirs.push(PathBuf::from(dir));
    }
    for triple in [
        "x86_64-linux-gnu",
        "i386-linux-gnu",
        "aarch64-linux-gnu",
        "arm-linux-gnueabihf",
        "riscv64-linux-gnu",
        "powerpc64le-linux-gnu",
        "s390x-linux-gnu",
        "loongarch64-linux-gnu",
    ] {
        dirs.push(Path::new("/lib").join(triple));
        dirs.push(Path::new("/usr/lib").join(triple));
    }
    dirs.extend(ld_so_conf_dirs());

    let mut seen = HashSet::new();
    dirs.retain(|dir| seen.insert(dir.clone()));
    dirs
}

fn ld_so_conf_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let mut seen = HashSet::new();
    parse_conf(Path::new("/etc/ld.so.conf"), &mut dirs, &mut seen, 0);
    dirs
}

fn parse_conf(path: &Path, dirs: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, depth: usize) {
    if depth > 8 || !seen.insert(path.to_path_buf()) {
        return;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("include") {
            for included in expand_include(rest.trim()) {
                parse_conf(&included, dirs, seen, depth + 1);
            }
        } else if line.starts_with('/') {
            dirs.push(PathBuf::from(line));
        }
    }
}

/// Expands the single `*` glob that `ld.so.conf` include lines use.
fn expand_include(pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') {
        return vec![PathBuf::from(pattern)];
    }
    let path = Path::new(pattern);
    let Some(dir) = path.parent() else {
        return Vec::new();
    };
    let Some(file) = path.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    let (prefix, suffix) = file.split_once('*').unwrap_or((file, ""));
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut matches = Vec::new();
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with(prefix) && name.ends_with(suffix) {
                matches.push(entry.path());
            }
        }
    }
    matches.sort();
    matches
}

/// Expands `$ORIGIN`, `$LIB` and `$PLATFORM` in rpath/runpath entries.
///
/// `$ORIGIN` is resolved exactly. `$LIB` and `$PLATFORM` are approximated from
/// the object's class and the host architecture, which covers the common cases;
/// they are rare outside build trees.
pub fn expand_dirs(elf: &ElfFile, raw: &[String]) -> Vec<PathBuf> {
    let origin = elf
        .path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let origin = origin.to_string_lossy().into_owned();
    let lib = match elf.class {
        Class::Elf64 if cfg!(target_arch = "x86_64") => "lib64",
        _ => "lib",
    };
    let platform = crate::elf::host_name();

    raw.iter()
        .map(|entry| {
            let expanded = entry
                .replace("${ORIGIN}", &origin)
                .replace("$ORIGIN", &origin)
                .replace("${LIB}", lib)
                .replace("$LIB", lib)
                .replace("${PLATFORM}", platform)
                .replace("$PLATFORM", platform);
            PathBuf::from(expanded)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ldconfig_output() {
        let text = "5630 libs found in cache `/etc/ld.so.cache'\n\
                    \tlibc.so.6 (libc6,x86-64) => /usr/lib/libc.so.6\n\
                    \tlibm.so.6 (libc6) => /usr/lib/libm.so.6\n\
                    garbage line\n";
        let entries = parse_ld_cache(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "libc.so.6");
        assert_eq!(entries[0].arch, "libc6,x86-64");
        assert_eq!(entries[0].path, PathBuf::from("/usr/lib/libc.so.6"));
    }

    #[test]
    fn expands_origin() {
        let mut elf = ElfFile::parse(&std::env::current_exe().unwrap()).unwrap();
        elf.path = PathBuf::from("/opt/app/bin/game");
        let dirs = expand_dirs(
            &elf,
            &["$ORIGIN/../lib".to_string(), "/usr/lib".to_string()],
        );
        assert_eq!(dirs[0], PathBuf::from("/opt/app/bin/../lib"));
        assert_eq!(dirs[1], PathBuf::from("/usr/lib"));
    }

    #[test]
    fn resolves_libc_through_the_cache() {
        let resolver = Resolver::new();
        let found = resolver.search("libc.so.6", &[], &[]);
        assert!(
            found.is_some(),
            "libc.so.6 should resolve on a glibc system"
        );
        assert!(found.unwrap().is_file());
    }

    #[test]
    fn does_not_invent_libraries() {
        let resolver = Resolver::new();
        assert!(resolver
            .search("libdefinitely-not-a-real-library.so.99", &[], &[])
            .is_none());
    }
}
