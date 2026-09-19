//! Turns ELF facts into findings a human can act on.
//!
//! The interesting part of a "why does this not start?" answer is not any
//! single check but the dependency graph: which object asked for what, in what
//! order, and where the chain breaks. This module walks that graph once,
//! breadth-first, and reuses each parsed object for every question afterwards.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::elf::{Binding, Class, ElfError, ElfFile, ElfType};
use crate::resolve::{expand_dirs, ElfIdentity, Resolver, SearchOutcome};

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Fine.
    Ok,
    /// Suspicious but not necessarily the cause.
    Warn,
    /// A concrete reason the program will not work.
    Fail,
    /// Context, not a judgement.
    Info,
}

impl Status {
    fn rank(self) -> u8 {
        match self {
            Status::Ok | Status::Info => 0,
            Status::Warn => 1,
            Status::Fail => 2,
        }
    }

    /// The more severe of two statuses.
    pub fn worse(self, other: Status) -> Status {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Why the target could not be read.
#[derive(Debug)]
pub enum AnalyzeError {
    Io(std::io::Error),
}

impl fmt::Display for AnalyzeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnalyzeError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AnalyzeError {}

/// What kind of thing was inspected.
#[derive(Debug, Clone)]
pub enum TargetKind {
    Elf(Box<ElfFile>),
    Script { interpreter: String },
    NotElf { description: String },
}

/// The architecture comparison.
#[derive(Debug, Clone)]
pub struct ArchFinding {
    pub name: &'static str,
    pub class: Class,
    /// `None` when the host architecture is not recognised.
    pub host_name: Option<&'static str>,
    /// Host word size in bits, when known.
    pub host_bits: Option<u32>,
    /// The host can run this program, natively or through a compatibility mode
    /// (for example 32-bit i386 on an x86-64 kernel).
    pub compatible: bool,
    /// Same machine *and* word size as the host.
    pub exact: bool,
}

/// Why an interpreter cannot serve as a loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpreterProblem {
    /// The loader is built for a different class or machine than the program.
    WrongArchitecture {
        found: &'static str,
        wanted: &'static str,
    },
    /// The loader is not a loadable ELF object at all (not ELF, truncated, or
    /// of a type the kernel will not run).
    NotLoadable(String),
}

/// The `PT_INTERP` (or shebang) interpreter.
#[derive(Debug, Clone)]
pub struct InterpreterFinding {
    pub path: String,
    pub exists: bool,
    pub executable: bool,
    /// Set when the interpreter cannot actually load the program.
    pub problem: Option<InterpreterProblem>,
}

/// Whether the file can actually be executed.
#[derive(Debug, Clone)]
pub struct PermissionFinding {
    pub path: String,
    pub executable: bool,
    /// The permission bits, for a `mode 0644` style message.
    pub mode: u32,
}

/// Where a `DT_NEEDED` object ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibResolution {
    Found(PathBuf),
    /// A file with the right name exists, but it is built for another machine
    /// or word size, so the loader cannot use it.
    WrongArchitecture {
        path: PathBuf,
        found: &'static str,
        wanted: &'static str,
    },
    /// A file with the right name exists, but it is not a loadable ELF object.
    Unusable {
        path: PathBuf,
        reason: String,
    },
    Missing,
}

/// One shared library, merged across every object that asks for it.
#[derive(Debug, Clone)]
pub struct LibraryFinding {
    pub name: String,
    pub needed_by: Vec<String>,
    pub resolution: LibResolution,
}

/// A symbol no object in the dependency graph defines.
#[derive(Debug, Clone)]
pub struct UnresolvedSymbol {
    pub name: String,
    pub version: Option<String>,
    pub object: String,
}

/// A versioned import the providing library does not define.
#[derive(Debug, Clone)]
pub struct VersionProblem {
    pub object: String,
    pub library: String,
    pub required: String,
    pub library_path: Option<String>,
    /// The closest older version the system does provide, for the classic
    /// "needs GLIBC_2.42, provides GLIBC_2.41" message.
    pub best_provided: Option<String>,
}

/// An environment variable that changes how programs start.
#[derive(Debug, Clone)]
pub struct EnvFinding {
    pub variable: String,
    pub value: String,
    pub note: String,
    pub status: Status,
}

/// Everything `why` learned about the target.
#[derive(Debug, Clone)]
pub struct Analysis {
    pub path: PathBuf,
    pub kind: TargetKind,
    /// Set when the target cannot be run at all (a relocatable object or a core
    /// dump). The message explains what it actually is.
    pub not_a_program: Option<String>,
    pub arch: Option<ArchFinding>,
    pub permissions: Option<PermissionFinding>,
    pub interpreter: Option<InterpreterFinding>,
    pub libraries: Vec<LibraryFinding>,
    pub unresolved: Vec<UnresolvedSymbol>,
    pub version_problems: Vec<VersionProblem>,
    pub env: Vec<EnvFinding>,
    pub notes: Vec<String>,
}

impl Analysis {
    /// True when `why` understood the file well enough to say something.
    pub fn is_analyzable(&self) -> bool {
        !matches!(self.kind, TargetKind::NotElf { .. })
    }

    /// Libraries the loader would not be able to find.
    pub fn missing_libraries(&self) -> impl Iterator<Item = &LibraryFinding> {
        self.libraries
            .iter()
            .filter(|library| matches!(library.resolution, LibResolution::Missing))
    }

    /// Libraries that cannot be used: missing, or present but wrong for this
    /// machine.
    pub fn unusable_libraries(&self) -> impl Iterator<Item = &LibraryFinding> {
        self.libraries
            .iter()
            .filter(|library| !matches!(library.resolution, LibResolution::Found(_)))
    }

    /// The number of concrete problems found.
    pub fn problem_count(&self) -> usize {
        let mut count = 0;
        if self.not_a_program.is_some() {
            count += 1;
        }
        if let Some(arch) = &self.arch {
            if !arch.compatible {
                count += 1;
            }
        }
        if let Some(permissions) = &self.permissions {
            if !permissions.executable {
                count += 1;
            }
        }
        if let Some(interpreter) = &self.interpreter {
            if !interpreter.exists || !interpreter.executable || interpreter.problem.is_some() {
                count += 1;
            }
        }
        count += self.unusable_libraries().count();
        count += self.unresolved.len();
        count += self.version_problems.len();
        count
    }

    pub fn has_failures(&self) -> bool {
        self.problem_count() > 0
    }

    /// `0` = nothing wrong, `1` = problems found, `2` = could not diagnose.
    pub fn exit_code(&self) -> u8 {
        if !self.is_analyzable() {
            2
        } else if self.has_failures() {
            1
        } else {
            0
        }
    }
}

/// Inspects `path` and returns the findings.
pub fn analyze(path: &Path) -> Result<Analysis, AnalyzeError> {
    if path.is_dir() {
        return Ok(plain(
            path,
            "this is a directory, not a program".to_string(),
        ));
    }
    let data = fs::read(path).map_err(AnalyzeError::Io)?;

    if data.starts_with(b"#!") {
        return Ok(analyze_script(path, &data));
    }

    // Resolve symlinks first so that $ORIGIN and the display path are both
    // sensible, while the report keeps showing the path the user typed.
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match ElfFile::parse_bytes(&canonical, &data) {
        Ok(elf) => Ok(analyze_elf(path, canonical, elf)),
        Err(ElfError::NotElf) => Ok(plain(path, describe_non_elf(&data))),
        Err(error) => Ok(plain(
            path,
            format!("an ELF file that could not be parsed ({error})"),
        )),
    }
}

fn plain(path: &Path, description: String) -> Analysis {
    Analysis {
        path: path.to_path_buf(),
        kind: TargetKind::NotElf { description },
        not_a_program: None,
        arch: None,
        permissions: None,
        interpreter: None,
        libraries: Vec::new(),
        unresolved: Vec::new(),
        version_problems: Vec::new(),
        env: Vec::new(),
        notes: Vec::new(),
    }
}

fn describe_non_elf(data: &[u8]) -> String {
    if data.is_empty() {
        return "an empty file".to_string();
    }
    if data.starts_with(b"\x7fELF") {
        return "an ELF file that could not be parsed".to_string();
    }
    let sample = &data[..data.len().min(512)];
    match std::str::from_utf8(sample) {
        Ok(text)
            if text
                .chars()
                .all(|c| !c.is_control() || c == '\n' || c == '\t' || c == '\r') =>
        {
            "a text file".to_string()
        }
        _ => "a binary file that is not ELF".to_string(),
    }
}

fn analyze_script(path: &Path, data: &[u8]) -> Analysis {
    let first_line = data.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let line = String::from_utf8_lossy(first_line);
    let shebang = line.trim_start_matches("#!").trim();

    let mut notes = Vec::new();
    let via_env = is_env_shebang(shebang);
    let command = if via_env {
        // `#!/usr/bin/env perl` names a command, not a path: resolving it is
        // the whole point of using env, so check PATH rather than /usr/bin/env.
        notes.push(
            "the shebang uses `env`, so the interpreter is resolved through PATH".to_string(),
        );
        env_command(shebang)
    } else {
        shebang.split_whitespace().next().unwrap_or("").to_string()
    };
    if via_env && command.chars().any(char::is_whitespace) {
        notes.push(format!(
            "`env` treats `{command}` as one command name; a shebang argument with spaces needs `-S` and no quoting"
        ));
    }

    Analysis {
        path: path.to_path_buf(),
        kind: TargetKind::Script {
            interpreter: command.clone(),
        },
        not_a_program: None,
        arch: None,
        permissions: permission_finding(path),
        interpreter: Some(interpreter_finding(&command, via_env)),
        libraries: Vec::new(),
        unresolved: Vec::new(),
        version_problems: Vec::new(),
        env: env_findings(),
        notes,
    }
}

/// True for `#!/usr/bin/env ...` shebangs.
fn is_env_shebang(shebang: &str) -> bool {
    match shebang.split_whitespace().next() {
        Some(program) => Path::new(program).file_name() == Some(std::ffi::OsStr::new("env")),
        None => false,
    }
}

/// The command named after `env`, skipping its options and `VAR=value` pairs.
///
/// The kernel passes the whole shebang tail as a single argument, so `env`
/// needs `-S` to split it; that split follows shell-like rules, so quotes group
/// words. Options are not uniform either: `-u`/`--unset` and `-C`/`--chdir`
/// take a value, which must be consumed or it is mistaken for the command.
fn env_command(shebang: &str) -> String {
    let mut fields = shell_split(shebang).into_iter();
    let _ = fields.next(); // the env program itself
    let mut expect_value = false;
    let mut options_done = false;

    for field in fields {
        if expect_value {
            expect_value = false;
            continue;
        }
        if options_done {
            return field;
        }
        if field == "--" {
            options_done = true;
            continue;
        }
        if field == "-S" || field == "--split-string" {
            // Everything after this is the command line to split.
            options_done = true;
            continue;
        }
        if let Some(value) = field.strip_prefix("--split-string=") {
            return shell_split(value).into_iter().next().unwrap_or_default();
        }
        if field.starts_with("--") {
            // `--unset=NAME` carries its value inline; the separate forms need
            // a lookahead.
            let name = field.split('=').next().unwrap_or(&field);
            if !field.contains('=') && matches!(name, "--unset" | "--chdir") {
                expect_value = true;
            }
            continue;
        }
        if field.starts_with('-') && field.len() > 1 {
            // Walk the short-option cluster: `u` and `C` take a value, `S`
            // means the rest is a command line to split.
            let mut chars = field[1..].chars().peekable();
            while let Some(flag) = chars.next() {
                if flag == 'S' {
                    let attached: String = chars.collect();
                    if attached.is_empty() {
                        options_done = true;
                    } else {
                        return shell_split(&attached)
                            .into_iter()
                            .next()
                            .unwrap_or_default();
                    }
                    break;
                }
                if flag == 'u' || flag == 'C' {
                    expect_value = chars.peek().is_none();
                    break;
                }
            }
            continue;
        }
        // A `VAR=value` assignment comes before the command.
        if field.contains('=') {
            continue;
        }
        return field;
    }
    String::new()
}

/// Splits a string the way `env -S` does: shell-like quoting and escapes.
fn shell_split(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut has_token = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if has_token {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            '\'' | '"' => {
                has_token = true;
                let quote = c;
                while let Some(q) = chars.next() {
                    if q == quote {
                        break;
                    }
                    if q == '\\' && quote == '"' {
                        if let Some(escaped) = chars.next() {
                            current.push(escaped);
                        }
                    } else {
                        current.push(q);
                    }
                }
            }
            '\\' => {
                has_token = true;
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            other => {
                has_token = true;
                current.push(other);
            }
        }
    }
    if has_token {
        tokens.push(current);
    }
    tokens
}

fn analyze_elf(display: &Path, canonical: PathBuf, elf: ElfFile) -> Analysis {
    let root = Box::new(elf);
    let mut notes = Vec::new();

    // A relocatable object or a core dump is not a program at all: saying
    // "no problems found" for one would contradict the report itself.
    let not_a_program = match root.etype {
        ElfType::Relocatable => {
            Some("this is a relocatable object (.o), not something that can be run".to_string())
        }
        ElfType::Core => Some("this is a core dump, not a program".to_string()),
        _ => None,
    };
    if root.etype == ElfType::Executable && root.interpreter.is_none() && !root.has_dynamic {
        notes.push(
            "statically linked: no dynamic loader and no shared library dependencies".to_string(),
        );
    }

    let arch = Some(arch_finding(&root));
    // A missing execute bit is a launch failure, not a footnote.
    let permissions = if root.is_runnable() {
        permission_finding(&canonical)
    } else {
        None
    };
    let interpreter = root.interpreter.as_deref().map(|path| {
        let mut finding = interpreter_finding(path, false);
        // A loader the kernel cannot exec (not ELF, truncated, wrong class or
        // machine) fails before any library is searched for.
        if finding.exists && finding.executable {
            finding.problem = interpreter_problem(&root, path);
        }
        finding
    });

    // Breadth-first walk of the DT_NEEDED graph. Each object is parsed once and
    // reused for the symbol and version questions below.
    let resolver = Resolver::new();
    let root_key = canonical;
    let root_rpath_global = if root.runpath.is_empty() {
        expand_dirs(&root, &root.rpath)
    } else {
        Vec::new()
    };

    let mut parsed: HashMap<PathBuf, Box<ElfFile>> = HashMap::new();
    let mut attempted: HashSet<PathBuf> = HashSet::new();
    let mut order: Vec<PathBuf> = Vec::new();
    let mut queue: VecDeque<(PathBuf, Box<ElfFile>)> = VecDeque::new();
    parsed.insert(root_key.clone(), root.clone());
    order.push(root_key.clone());
    queue.push_back((root_key.clone(), root.clone()));

    // Report the path the user typed for the root object, and resolved paths
    // for everything discovered along the way.
    let root_label = display.display().to_string();
    let label = |key: &PathBuf| -> String {
        if key == &root_key {
            root_label.clone()
        } else {
            key.display().to_string()
        }
    };

    let mut libraries: Vec<LibraryFinding> = Vec::new();
    let mut name_to_pos: HashMap<String, usize> = HashMap::new();

    while let Some((object_path, object)) = queue.pop_front() {
        let is_root = object_path == root_key;
        let (rpath, runpath) = load_dirs(&object, is_root, &root_rpath_global);
        for needed in &object.needed {
            // A DT_NEEDED name is only satisfied by an object of the same class
            // and machine: a 32-bit program cannot load the 64-bit libc.so.6
            // that happens to sit first in the cache.
            let outcome = resolver.search(needed, Some(ElfIdentity::of(&object)), &rpath, &runpath);
            let resolution = match &outcome {
                SearchOutcome::Found(path) => LibResolution::Found(path.clone()),
                SearchOutcome::WrongArchitecture(path, found) => LibResolution::WrongArchitecture {
                    path: path.clone(),
                    found: crate::elf::machine_name(found.machine),
                    wanted: crate::elf::machine_name(object.machine),
                },
                SearchOutcome::Unusable(path, reason) => LibResolution::Unusable {
                    path: path.clone(),
                    reason: (*reason).to_string(),
                },
                SearchOutcome::Missing => LibResolution::Missing,
            };

            match name_to_pos.get(needed).copied() {
                Some(index) => {
                    let parent = label(&object_path);
                    if !libraries[index].needed_by.contains(&parent) {
                        libraries[index].needed_by.push(parent);
                    }
                    if let (LibResolution::Found(previous), LibResolution::Found(current)) =
                        (&libraries[index].resolution, &resolution)
                    {
                        if canonical_key(previous) != canonical_key(current) {
                            notes.push(format!(
                                "{needed} resolves to more than one file ({} and {})",
                                previous.display(),
                                current.display()
                            ));
                        }
                    }
                    // Prefer the most usable outcome seen so far.
                    if resolution_rank(&resolution) > resolution_rank(&libraries[index].resolution)
                    {
                        libraries[index].resolution = resolution;
                    }
                }
                None => {
                    name_to_pos.insert(needed.clone(), libraries.len());
                    libraries.push(LibraryFinding {
                        name: needed.clone(),
                        needed_by: vec![label(&object_path)],
                        resolution,
                    });
                }
            }

            // Only a usable object can contribute symbols and versions, so only
            // a usable object is parsed and walked any further.
            if let SearchOutcome::Found(path) = &outcome {
                let key = canonical_key(path);
                // `attempted` also remembers failures, so a broken library is
                // not re-read once per object that needs it.
                if attempted.insert(key.clone()) {
                    match ElfFile::parse(&key) {
                        Ok(library) => {
                            let library = Box::new(library);
                            parsed.insert(key.clone(), library.clone());
                            order.push(key.clone());
                            queue.push_back((key, library));
                        }
                        Err(error) => {
                            let reason = format!("could not be parsed ({error})");
                            notes.push(format!("could not read {}: {error}", path.display()));
                            // An identifiable header that will not parse is still
                            // not loadable; downgrade it so the report and the
                            // exit status say so.
                            if let Some(index) = name_to_pos.get(needed).copied() {
                                let still_this = matches!(
                                    &libraries[index].resolution,
                                    LibResolution::Found(found) if canonical_key(found) == key
                                );
                                if still_this {
                                    libraries[index].resolution =
                                        LibResolution::Unusable { path: key, reason };
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // A symbol is resolved if some object in the graph defines it: that is the
    // global scope the loader builds before relocating. Definitions are matched
    // by name *and* version where both are known, so `foo@OTHER` cannot satisfy
    // an import of `foo@VER`.
    let mut provided_names: HashSet<&str> = HashSet::new();
    let mut unversioned_defs: HashSet<&str> = HashSet::new();
    let mut provided_versions: HashSet<(&str, &str)> = HashSet::new();
    for key in &order {
        let object = &parsed[key];
        for symbol in object.symbols.iter().filter(|s| s.satisfies()) {
            provided_names.insert(symbol.name.as_str());
            match object.defined_version_name(symbol.version_index) {
                Some(version) => {
                    provided_versions.insert((symbol.name.as_str(), version));
                }
                // Index 1 (global/base), or a version we could not name, is
                // treated as unversioned: it may satisfy a versioned import.
                None => {
                    unversioned_defs.insert(symbol.name.as_str());
                }
            }
        }
    }

    let mut unresolved = Vec::new();
    let mut seen_symbols = HashSet::new();
    for key in &order {
        let object = &parsed[key];
        for symbol in object.symbols.iter() {
            // Strong undefined imports must be resolved; weak ones may stay 0.
            if !symbol.undefined || !matches!(symbol.binding, Binding::Global) {
                continue;
            }
            let version = object.version_name(symbol.version_index);
            let satisfied = match version {
                Some(version) => {
                    provided_versions.contains(&(symbol.name.as_str(), version))
                        || unversioned_defs.contains(symbol.name.as_str())
                }
                // An unversioned reference binds to any definition of the name.
                None => provided_names.contains(symbol.name.as_str()),
            };
            if satisfied {
                continue;
            }
            if !seen_symbols.insert((
                key.clone(),
                symbol.name.clone(),
                version.map(str::to_string),
            )) {
                continue;
            }
            unresolved.push(UnresolvedSymbol {
                name: symbol.name.clone(),
                version: version.map(str::to_string),
                object: label(key),
            });
        }
    }
    unresolved.sort_by(|a, b| (&a.name, &a.object).cmp(&(&b.name, &b.object)));

    // Version requirements are checked per (object, providing library) pair,
    // which is exactly the granularity .gnu.version_r records.
    let resolution_of = |name: &str| -> Option<&LibResolution> {
        name_to_pos.get(name).map(|i| &libraries[*i].resolution)
    };
    let mut version_problems = Vec::new();
    let mut seen_versions = HashSet::new();
    for key in &order {
        let object = &parsed[key];
        for need in &object.version_needs {
            let Some(LibResolution::Found(library_path)) = resolution_of(&need.file) else {
                // A missing library is already reported as such.
                continue;
            };
            let Some(library) = parsed.get(&canonical_key(library_path)) else {
                continue;
            };
            for required in &need.versions {
                if library.defined_versions.iter().any(|v| v == required) {
                    continue;
                }
                if !seen_versions.insert((key.clone(), need.file.clone(), required.clone())) {
                    continue;
                }
                version_problems.push(VersionProblem {
                    object: label(key),
                    library: need.file.clone(),
                    required: required.clone(),
                    library_path: Some(library_path.display().to_string()),
                    best_provided: best_provided(&library.defined_versions, required),
                });
            }
        }
    }
    version_problems.sort_by(|a, b| (&a.library, &a.required).cmp(&(&b.library, &b.required)));

    Analysis {
        path: display.to_path_buf(),
        kind: TargetKind::Elf(root),
        not_a_program,
        arch,
        permissions,
        interpreter,
        libraries,
        unresolved,
        version_problems,
        env: env_findings(),
        notes,
    }
}

/// The search directories for one object's `DT_NEEDED` entries.
///
/// `DT_RPATH` is only honoured when the object has no `DT_RUNPATH`, and the
/// root's `DT_RPATH` keeps applying to the whole chain (the legacy behaviour).
fn load_dirs(
    object: &ElfFile,
    is_root: bool,
    root_rpath: &[PathBuf],
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut rpath = Vec::new();
    if !is_root {
        rpath.extend_from_slice(root_rpath);
    }
    if object.runpath.is_empty() {
        rpath.extend(expand_dirs(object, &object.rpath));
    }
    let runpath = expand_dirs(object, &object.runpath);
    (rpath, runpath)
}

/// Orders library outcomes by usefulness, so a good result is never replaced
/// by a worse one discovered later through another object.
fn resolution_rank(resolution: &LibResolution) -> u8 {
    match resolution {
        LibResolution::Found(_) => 3,
        LibResolution::WrongArchitecture { .. } => 2,
        LibResolution::Unusable { .. } => 1,
        LibResolution::Missing => 0,
    }
}

fn arch_finding(elf: &ElfFile) -> ArchFinding {
    let host = crate::elf::host_machine();
    let host_bits = host.map(|_| (std::mem::size_of::<usize>() * 8) as u32);
    let (compatible, exact) = arch_compatibility(host, host_bits, elf.machine, elf.class.bits());
    ArchFinding {
        name: crate::elf::machine_name(elf.machine),
        class: elf.class,
        host_name: host.map(crate::elf::machine_name),
        host_bits,
        compatible,
        exact,
    }
}

/// Decides whether a target can run on a host, and whether it matches exactly.
///
/// A target wider than the host process can never run, even when `e_machine` is
/// shared across word sizes (MIPS and RISC-V use one value for both 32- and
/// 64-bit). Narrower targets may run through compatibility support; the
/// interpreter check catches a missing loader.
fn arch_compatibility(
    host: Option<u16>,
    host_bits: Option<u32>,
    machine: u16,
    bits: u32,
) -> (bool, bool) {
    let exact = host == Some(machine) && host_bits == Some(bits);
    let compatible = match host {
        Some(host_machine) => {
            let width_ok = match host_bits {
                Some(host_width) => bits <= host_width,
                None => true,
            };
            width_ok && (host_machine == machine || runs_compatibly(host_machine, machine))
        }
        None => true,
    };
    (compatible, exact)
}

/// Names the architecture mismatch between a program and its loader, if any.
fn interpreter_arch_mismatch(
    program_machine: u16,
    program_class: Class,
    loader: &ElfIdentity,
) -> Option<(&'static str, &'static str)> {
    if loader.machine != program_machine || loader.class != program_class {
        Some((
            crate::elf::machine_name(loader.machine),
            crate::elf::machine_name(program_machine),
        ))
    } else {
        None
    }
}

/// Checks that a `PT_INTERP` target is an ELF object the kernel can load, of
/// the same class and machine as the program.
///
/// Reading just the identity is not enough: an executable text file or a
/// truncated ELF would pass that check but is rejected by the kernel.
fn interpreter_problem(program: &ElfFile, path: &str) -> Option<InterpreterProblem> {
    match ElfFile::parse(Path::new(path)) {
        Ok(loader) => {
            if !matches!(loader.etype, ElfType::Executable | ElfType::Shared) {
                return Some(InterpreterProblem::NotLoadable(format!(
                    "it is a {}, which cannot be used as a loader",
                    loader.kind()
                )));
            }
            let identity = ElfIdentity {
                class: loader.class,
                machine: loader.machine,
            };
            interpreter_arch_mismatch(program.machine, program.class, &identity)
                .map(|(found, wanted)| InterpreterProblem::WrongArchitecture { found, wanted })
        }
        Err(error) => Some(InterpreterProblem::NotLoadable(error.to_string())),
    }
}

/// Machine pairs whose host CPU can execute the target's code directly.
fn runs_compatibly(host: u16, target: u16) -> bool {
    matches!(
        (host, target),
        (0x003e, 0x0003) // x86-64 runs i386
            | (0x00b7, 0x0028) // AArch64 runs AArch32
            | (0x0015, 0x0014) // PowerPC64 runs 32-bit PowerPC
    )
}

fn interpreter_finding(command: &str, via_path: bool) -> InterpreterFinding {
    if via_path {
        return match find_on_path(command) {
            Some(found) => InterpreterFinding {
                path: found.display().to_string(),
                exists: true,
                executable: true,
                problem: None,
            },
            None => InterpreterFinding {
                path: command.to_string(),
                exists: false,
                executable: false,
                problem: None,
            },
        };
    }
    let candidate = Path::new(command);
    InterpreterFinding {
        path: command.to_string(),
        exists: candidate.exists(),
        executable: is_executable(candidate),
        problem: None,
    }
}

/// Resolves a bare command name through `PATH`, the way a shell would.
fn find_on_path(name: &str) -> Option<PathBuf> {
    if name.is_empty() {
        return None;
    }
    if name.contains('/') {
        let candidate = Path::new(name);
        return (candidate.is_file() && is_executable(candidate)).then(|| candidate.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(name);
        (candidate.is_file() && is_executable(&candidate)).then_some(candidate)
    })
}

fn permission_finding(path: &Path) -> Option<PermissionFinding> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).ok()?;
    let mode = metadata.permissions().mode() & 0o7777;
    Some(PermissionFinding {
        path: path.display().to_string(),
        executable: mode & 0o111 != 0,
        mode,
    })
}

fn env_findings() -> Vec<EnvFinding> {
    let mut findings = Vec::new();
    if let Ok(value) = std::env::var("LD_LIBRARY_PATH") {
        if !value.is_empty() {
            findings.push(EnvFinding {
                variable: "LD_LIBRARY_PATH".to_string(),
                value,
                note: "overrides the system library search path; a stale entry can load the wrong library".to_string(),
                status: Status::Warn,
            });
        }
    }
    if let Ok(value) = std::env::var("LD_PRELOAD") {
        if !value.is_empty() {
            findings.push(EnvFinding {
                variable: "LD_PRELOAD".to_string(),
                value,
                note: "injects extra libraries into the process; a broken preload is a common launch failure".to_string(),
                status: Status::Warn,
            });
        }
    }
    if let Ok(value) = std::env::var("LD_DEBUG") {
        if !value.is_empty() {
            findings.push(EnvFinding {
                variable: "LD_DEBUG".to_string(),
                value,
                note: "dynamic loader tracing is enabled".to_string(),
                status: Status::Info,
            });
        }
    }
    findings
}

/// The closest version the system does provide, for "provides 2.41" messages.
fn best_provided(provided: &[String], required: &str) -> Option<String> {
    let (prefix, required_number) = required.rsplit_once('.')?;
    let required_number: u32 = required_number.parse().ok()?;
    let prefix_dot = format!("{prefix}.");
    provided
        .iter()
        .filter_map(|version| {
            let number = version.strip_prefix(&prefix_dot)?.parse::<u32>().ok()?;
            (number < required_number).then_some((number, version.clone()))
        })
        .max_by_key(|(number, _)| *number)
        .map(|(_, version)| version)
}

fn canonical_key(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Whether the file has any execute bit set.
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_healthy_binary_has_no_problems() {
        let path = std::env::current_exe().expect("test binary");
        let analysis = analyze(&path).expect("analyze");
        assert!(analysis.is_analyzable());
        let missing: Vec<&str> = analysis
            .missing_libraries()
            .map(|l| l.name.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "unexpected missing libraries: {missing:?}"
        );
        let unresolved: Vec<&str> = analysis
            .unresolved
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert!(
            unresolved.is_empty(),
            "unexpected unresolved symbols: {unresolved:?}"
        );
        assert!(
            analysis.version_problems.is_empty(),
            "{:?}",
            analysis.version_problems
        );
        assert_eq!(analysis.exit_code(), 0);
    }

    #[test]
    fn a_missing_file_is_an_io_error() {
        assert!(analyze(Path::new("/definitely/not/a/real/path")).is_err());
    }

    #[test]
    fn a_directory_cannot_be_diagnosed() {
        let analysis = analyze(Path::new("/tmp")).expect("analyze");
        assert!(!analysis.is_analyzable());
        assert_eq!(analysis.exit_code(), 2);
    }

    #[test]
    fn detects_the_best_older_version() {
        let provided = vec![
            "GLIBC_2.2.5".to_string(),
            "GLIBC_2.41".to_string(),
            "GLIBC_2.34".to_string(),
        ];
        assert_eq!(
            best_provided(&provided, "GLIBC_2.42").as_deref(),
            Some("GLIBC_2.41")
        );
        assert_eq!(best_provided(&provided, "GLIBC_PRIVATE"), None);
    }

    #[test]
    fn recognises_compatible_machines() {
        // 32-bit i386 runs on an x86-64 kernel; the reverse does not hold.
        assert!(runs_compatibly(0x003e, 0x0003));
        assert!(runs_compatibly(0x00b7, 0x0028));
        assert!(!runs_compatibly(0x0003, 0x003e));
        assert!(!runs_compatibly(0x003e, 0x00b7));
    }

    #[test]
    fn a_wider_target_is_not_compatible_with_a_narrower_host() {
        // MIPS and RISC-V use one e_machine for both word sizes, so the class
        // has to decide: a 64-bit target cannot run on a 32-bit host process.
        let riscv = 0x00f3;
        assert!(arch_compatibility(Some(riscv), Some(64), riscv, 32).0);
        assert!(!arch_compatibility(Some(riscv), Some(32), riscv, 64).0);
        assert!(arch_compatibility(Some(riscv), Some(64), riscv, 64).1);

        // The classic x86 pair is unaffected.
        assert!(arch_compatibility(Some(0x003e), Some(64), 0x0003, 32).0);
        assert!(!arch_compatibility(Some(0x003e), Some(64), 0x00b7, 64).0);
    }

    #[test]
    fn detects_a_loader_of_the_wrong_architecture() {
        let loader = ElfIdentity {
            class: Class::Elf64,
            machine: 0x003e,
        };
        // A 32-bit program with a 64-bit loader is broken.
        assert!(interpreter_arch_mismatch(0x0003, Class::Elf32, &loader).is_some());
        // Same machine and class is fine.
        assert!(interpreter_arch_mismatch(0x003e, Class::Elf64, &loader).is_none());
        // Same machine but the wrong word size (x32-style) is still a mismatch.
        assert!(interpreter_arch_mismatch(0x003e, Class::Elf32, &loader).is_some());
    }

    #[test]
    fn skips_env_options_when_finding_the_interpreter() {
        assert_eq!(env_command("/usr/bin/env python3"), "python3");
        assert_eq!(env_command("/usr/bin/env -u FOO python3"), "python3");
        assert_eq!(env_command("/usr/bin/env -C /tmp python3"), "python3");
        assert_eq!(env_command("/usr/bin/env -uFOO python3"), "python3");
        assert_eq!(env_command("/usr/bin/env -C/tmp python3"), "python3");
        assert_eq!(env_command("/usr/bin/env --unset FOO python3"), "python3");
        assert_eq!(env_command("/usr/bin/env --unset=FOO python3"), "python3");
        assert_eq!(env_command("/usr/bin/env --chdir /tmp python3"), "python3");
        assert_eq!(env_command("/usr/bin/env VAR=1 python3"), "python3");
        assert_eq!(env_command("/usr/bin/env -S python3 -u"), "python3");
        assert_eq!(
            env_command("/usr/bin/env --split-string=python3 -u"),
            "python3"
        );
        assert_eq!(env_command("/usr/bin/env -i python3"), "python3");
        assert_eq!(env_command("/usr/bin/env -- python3"), "python3");
        // `-S` splits with shell rules: quotes are stripped and group words.
        assert_eq!(env_command("/usr/bin/env -S \"python3\" -O"), "python3");
        assert_eq!(env_command("/usr/bin/env -S python3 -O"), "python3");
        assert_eq!(env_command("/usr/bin/env -S 'python3' -O"), "python3");
        // A fully quoted command is one word, exactly as env sees it.
        assert_eq!(env_command("/usr/bin/env -S \"python3 -O\""), "python3 -O");
    }
}
