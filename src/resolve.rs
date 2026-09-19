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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::elf::reader::Endian;
use crate::elf::{Class, ElfFile};

/// One entry of the `ld.so` cache, as printed by `ldconfig -p`.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub name: String,
    pub arch: String,
    pub path: PathBuf,
}

/// The ELF class and machine a candidate library must have.
///
/// The dynamic loader refuses an object built for a different word size or
/// machine, so `why` has to as well: on a multilib system `/usr/lib` and
/// `/usr/lib32` can both contain `libc.so.6`, and choosing the wrong one
/// corrupts every symbol and version result downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfIdentity {
    pub class: Class,
    pub machine: u16,
}

impl ElfIdentity {
    /// The identity a `DT_NEEDED` entry must match.
    pub fn of(elf: &ElfFile) -> Self {
        Self {
            class: elf.class,
            machine: elf.machine,
        }
    }

    pub fn matches(self, other: Self) -> bool {
        self.class == other.class && self.machine == other.machine
    }
}

/// The outcome of looking for one `DT_NEEDED` name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchOutcome {
    /// A usable object was found.
    Found(PathBuf),
    /// A file with the right name exists, but it is built for another
    /// architecture, so the loader cannot use it.
    WrongArchitecture(PathBuf, ElfIdentity),
    /// A file with the right name exists, but it is not a loadable ELF object
    /// (not ELF at all, or unreadable).
    Unusable(PathBuf, &'static str),
    /// Nothing with that name exists anywhere in the search path.
    Missing,
}

/// Why a candidate could not be identified as an ELF object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifyError {
    /// The file could not be opened or read.
    Unreadable,
    /// The file does not begin with an ELF header.
    NotElf,
}

impl IdentifyError {
    /// A short phrase for the report.
    pub fn message(self) -> &'static str {
        match self {
            IdentifyError::Unreadable => "unreadable",
            IdentifyError::NotElf => "not an ELF object",
        }
    }
}

/// Reads just the ELF identity (class and machine) of a file.
///
/// Only the first 20 bytes are read, so this is cheap even for a huge library.
/// A file that is not an ELF object is an error, not "unknown": the loader
/// cannot use it, and reporting it as found would hide a broken library.
pub fn identify(path: &Path) -> Result<ElfIdentity, IdentifyError> {
    let mut file = fs::File::open(path).map_err(|_| IdentifyError::Unreadable)?;
    let mut header = [0u8; 20];
    file.read_exact(&mut header)
        .map_err(|_| IdentifyError::Unreadable)?;
    if &header[0..4] != b"\x7fELF" {
        return Err(IdentifyError::NotElf);
    }
    let class = match header[4] {
        1 => Class::Elf32,
        2 => Class::Elf64,
        _ => return Err(IdentifyError::NotElf),
    };
    let endian = match header[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        _ => return Err(IdentifyError::NotElf),
    };
    let machine = match endian {
        Endian::Little => u16::from_le_bytes([header[18], header[19]]),
        Endian::Big => u16::from_be_bytes([header[18], header[19]]),
    };
    Ok(ElfIdentity { class, machine })
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
    ///
    /// Candidates whose ELF class or machine does not match `wanted` are
    /// skipped, mirroring the loader. If only mismatched candidates exist, the
    /// first is reported as [`SearchOutcome::WrongArchitecture`] rather than
    /// being silently accepted.
    pub fn search(
        &self,
        name: &str,
        wanted: Option<ElfIdentity>,
        rpath: &[PathBuf],
        runpath: &[PathBuf],
    ) -> SearchOutcome {
        // A name containing a slash is used as a path verbatim.
        let candidates: Vec<PathBuf> = if name.contains('/') {
            vec![PathBuf::from(name)]
        } else {
            rpath
                .iter()
                .chain(self.env_dirs.iter())
                .chain(runpath.iter())
                .map(|dir| dir.join(name))
                .chain(
                    self.cache
                        .iter()
                        .filter(|entry| entry.name == name)
                        .map(|entry| entry.path.clone()),
                )
                .chain(self.defaults.iter().map(|dir| dir.join(name)))
                .collect()
        };

        let mut mismatched: Option<(PathBuf, ElfIdentity)> = None;
        let mut unusable: Option<(PathBuf, &'static str)> = None;
        for candidate in candidates {
            if !candidate.is_file() {
                continue;
            }
            match wanted {
                Some(want) => match identify(&candidate) {
                    Ok(found) if found.matches(want) => return SearchOutcome::Found(candidate),
                    Ok(found) => {
                        mismatched.get_or_insert((candidate, found));
                    }
                    // A file that is not an ELF object cannot be loaded. Keep
                    // looking: a real library with this name may follow it.
                    Err(reason) => {
                        unusable.get_or_insert((candidate, reason.message()));
                    }
                },
                None => return SearchOutcome::Found(candidate),
            }
        }

        // A wrong-architecture ELF is a more useful near-miss than a file that
        // is not ELF at all, so it wins when both were seen.
        match mismatched {
            Some((path, found)) => SearchOutcome::WrongArchitecture(path, found),
            None => match unusable {
                Some((path, reason)) => SearchOutcome::Unusable(path, reason),
                None => SearchOutcome::Missing,
            },
        }
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

    fn host_identity() -> ElfIdentity {
        let elf = ElfFile::parse(&std::env::current_exe().unwrap()).unwrap();
        ElfIdentity::of(&elf)
    }

    #[test]
    fn identifies_an_elf_file() {
        let path = std::env::current_exe().unwrap();
        let elf = ElfFile::parse(&path).unwrap();
        assert_eq!(identify(&path).unwrap(), ElfIdentity::of(&elf));
    }

    #[test]
    fn resolves_libc_through_the_cache() {
        let resolver = Resolver::new();
        let wanted = host_identity();
        match resolver.search("libc.so.6", Some(wanted), &[], &[]) {
            SearchOutcome::Found(path) => {
                assert!(path.is_file());
                assert_eq!(identify(&path).unwrap(), wanted);
            }
            other => panic!("libc.so.6 should resolve on a glibc system, got {other:?}"),
        }
    }

    #[test]
    fn never_returns_a_library_of_the_wrong_class() {
        // On a multilib system both libc.so.6 files exist; the loader picks by
        // class, so `why` must never hand a 32-bit program a 64-bit library.
        let resolver = Resolver::new();
        let wanted = ElfIdentity {
            class: Class::Elf32,
            machine: 0x03,
        };
        match resolver.search("libc.so.6", Some(wanted), &[], &[]) {
            SearchOutcome::Found(path) => {
                assert_eq!(identify(&path).unwrap(), wanted, "resolved {path:?}");
            }
            SearchOutcome::WrongArchitecture(_, found) => assert_ne!(found, wanted),
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[test]
    fn a_non_elf_file_is_not_a_resolution() {
        // A text file named like a library must not count as "found": the
        // loader cannot use it, so the analysis would wrongly succeed.
        let dir = std::env::temp_dir().join(format!("why-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("libfakeshadow.so.1");
        std::fs::write(&fake, b"this is not an ELF object, just text\n").unwrap();

        let resolver = Resolver::new();
        let outcome = resolver.search(
            "libfakeshadow.so.1",
            Some(host_identity()),
            std::slice::from_ref(&dir),
            &[],
        );
        assert!(
            matches!(outcome, SearchOutcome::Unusable(_, "not an ELF object")),
            "{outcome:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_real_library_behind_a_decoy_is_still_found() {
        // The decoy must not stop the search: the real file later in the path
        // is the one the loader would use.
        let base = std::env::temp_dir().join(format!("why-resolve-decoy-{}", std::process::id()));
        let decoy_dir = base.join("decoy");
        let real_dir = base.join("real");
        std::fs::create_dir_all(&decoy_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        std::fs::write(decoy_dir.join("libdecoy.so.1"), b"not elf\n").unwrap();
        std::fs::copy(
            std::env::current_exe().unwrap(),
            real_dir.join("libdecoy.so.1"),
        )
        .unwrap();

        let resolver = Resolver::new();
        let outcome = resolver.search(
            "libdecoy.so.1",
            Some(host_identity()),
            &[decoy_dir.clone(), real_dir.clone()],
            &[],
        );
        match outcome {
            SearchOutcome::Found(path) => {
                assert!(path.starts_with(&real_dir), "found {path:?}");
            }
            other => panic!("expected the real library, got {other:?}"),
        }

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn does_not_invent_libraries() {
        let resolver = Resolver::new();
        assert!(matches!(
            resolver.search("libdefinitely-not-a-real-library.so.99", None, &[], &[]),
            SearchOutcome::Missing
        ));
    }
}
