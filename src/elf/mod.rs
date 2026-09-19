//! A small, dependency-free ELF reader.
//!
//! `why` v0.1 only needs a handful of facts from an ELF object: the machine it
//! targets, how it is started (the interpreter), which shared objects it asks
//! for, and which symbols it expects those objects to provide. Everything else
//! — relocations, notes, debug info — is deliberately ignored.
//!
//! Both `ldd` and `readelf` already do this. Owning the parse keeps the tool
//! auditable, lets it work when those tools are missing or are themselves the
//! thing that is broken, and gives the report access to the raw facts.

pub mod reader;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use reader::{Bytes, Endian};

// e_ident indices.
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

// e_ident[EI_CLASS].
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

// e_ident[EI_DATA].
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

// Program header types.
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;

// Section header types.
pub const SHT_STRTAB: u32 = 3;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

// Dynamic table tags.
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS_1: i64 = 0x6fff_fffb;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERNEED: i64 = 0x6fff_fffe;

/// `DF_1_PIE`: this `ET_DYN` object is a position-independent executable.
const DF_1_PIE: u64 = 0x0800_0000;

// Section indices and symbol attributes.
const SHN_UNDEF: u16 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const STB_GNU_UNIQUE: u8 = 10;

/// Something went wrong while reading an ELF object.
#[derive(Debug)]
pub enum ElfError {
    /// The buffer does not start with the ELF magic.
    NotElf,
    /// The file ended before a structure the parser needed.
    Truncated(String),
    /// The file is ELF, but internally inconsistent.
    Malformed(String),
    /// The file could not be read from disk.
    Io(std::io::Error),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::NotElf => write!(f, "not an ELF file"),
            ElfError::Truncated(m) => write!(f, "truncated ELF file: {m}"),
            ElfError::Malformed(m) => write!(f, "malformed ELF file: {m}"),
            ElfError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ElfError {}

impl From<std::io::Error> for ElfError {
    fn from(error: std::io::Error) -> Self {
        ElfError::Io(error)
    }
}

impl From<reader::OutOfBounds> for ElfError {
    fn from(error: reader::OutOfBounds) -> Self {
        ElfError::Truncated(error.to_string())
    }
}

/// ELF word size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

impl Class {
    pub fn bits(self) -> u32 {
        match self {
            Class::Elf32 => 32,
            Class::Elf64 => 64,
        }
    }
}

/// The `e_type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    Relocatable,
    Executable,
    Shared,
    Core,
    Other(u16),
}

impl ElfType {
    fn from_raw(value: u16) -> Self {
        match value {
            1 => ElfType::Relocatable,
            2 => ElfType::Executable,
            3 => ElfType::Shared,
            4 => ElfType::Core,
            other => ElfType::Other(other),
        }
    }
}

/// Symbol binding (`st_info >> 4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    Local,
    Global,
    Weak,
    GnuUnique,
    Other(u8),
}

impl Binding {
    fn from_raw(value: u8) -> Self {
        match value {
            0 => Binding::Local,
            STB_GLOBAL => Binding::Global,
            STB_WEAK => Binding::Weak,
            STB_GNU_UNIQUE => Binding::GnuUnique,
            other => Binding::Other(other),
        }
    }

    /// Bindings that can satisfy another object's import.
    fn provides(self) -> bool {
        matches!(self, Binding::Global | Binding::Weak | Binding::GnuUnique)
    }
}

/// Symbol type (`st_info & 0x0f`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymType {
    NoType,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    GnuIfunc,
    Other(u8),
}

impl SymType {
    fn from_raw(value: u8) -> Self {
        match value {
            0 => SymType::NoType,
            1 => SymType::Object,
            2 => SymType::Func,
            3 => SymType::Section,
            4 => SymType::File,
            5 => SymType::Common,
            6 => SymType::Tls,
            10 => SymType::GnuIfunc,
            other => SymType::Other(other),
        }
    }
}

/// One entry of `.dynsym`.
#[derive(Debug, Clone)]
pub struct DynSymbol {
    pub name: String,
    pub binding: Binding,
    pub sym_type: SymType,
    /// `st_shndx == SHN_UNDEF`: this object imports the symbol.
    pub undefined: bool,
    /// Index into the GNU version tables (0 = local, 1 = global/base).
    pub version_index: u16,
}

impl DynSymbol {
    /// True when this symbol is a definition other objects may link against.
    pub fn satisfies(&self) -> bool {
        !self.undefined && self.binding.provides()
    }
}

/// A versioned import: `file` must provide each of `versions`.
///
/// This is the `GLIBC_2.42` machinery: an object records which symbol versions
/// it needs from which shared object.
#[derive(Debug, Clone)]
pub struct VersionNeed {
    pub file: String,
    pub versions: Vec<String>,
}

/// The parsed, useful subset of an ELF object.
#[derive(Debug, Clone)]
pub struct ElfFile {
    pub path: PathBuf,
    pub class: Class,
    pub endian: Endian,
    pub etype: ElfType,
    pub machine: u16,
    pub entry: u64,
    /// `PT_INTERP`: the dynamic loader that starts this program.
    pub interpreter: Option<String>,
    /// `DT_SONAME`: the name this object wants to be known by.
    pub soname: Option<String>,
    /// `DT_NEEDED`: shared objects this one imports.
    pub needed: Vec<String>,
    /// `DT_RPATH`: legacy search path (transitive, ignored if RUNPATH is set).
    pub rpath: Vec<String>,
    /// `DT_RUNPATH`: modern search path (applies to this object only).
    pub runpath: Vec<String>,
    /// True when the object has a `PT_DYNAMIC`/`.dynamic` table.
    pub has_dynamic: bool,
    /// `DT_FLAGS_1`; bit `DF_1_PIE` marks a position-independent executable.
    pub flags_1: u64,
    pub symbols: Vec<DynSymbol>,
    /// Versioned imports grouped by the object that must provide them.
    pub version_needs: Vec<VersionNeed>,
    /// Version names this object itself defines (from `.gnu.version_d`).
    pub defined_versions: Vec<String>,
    /// Version name/owner for each symbol version index.
    version_by_index: HashMap<u16, (String, String)>,
    /// Defined version names keyed by `.gnu.version` index.
    defined_version_map: HashMap<u16, String>,
}

impl ElfFile {
    /// Reads and parses a file from disk.
    pub fn parse(path: &Path) -> Result<Self, ElfError> {
        let data = fs::read(path)?;
        Self::parse_bytes(path, &data)
    }

    /// Parses an in-memory ELF image.
    pub fn parse_bytes(path: &Path, data: &[u8]) -> Result<Self, ElfError> {
        if data.len() < 16 || &data[0..4] != b"\x7fELF" {
            return Err(ElfError::NotElf);
        }
        let class = match data[EI_CLASS] {
            ELFCLASS32 => Class::Elf32,
            ELFCLASS64 => Class::Elf64,
            other => return Err(ElfError::Malformed(format!("unknown ELF class {other}"))),
        };
        let endian = match data[EI_DATA] {
            ELFDATA2LSB => Endian::Little,
            ELFDATA2MSB => Endian::Big,
            other => {
                return Err(ElfError::Malformed(format!(
                    "unknown ELF data encoding {other}"
                )))
            }
        };
        let b = Bytes::new(data, endian);
        let header = read_header(&b, class)?;

        // Section headers come first: when the in-header counts overflow, the
        // real values live in section 0.
        let mut shdrs: Vec<Shdr> = Vec::new();
        let mut shstrndx = header.shstrndx;
        let mut phnum = header.phnum;
        if header.shoff != 0 && header.shentsize >= expected_shdr_size(class) {
            let shdr0 = read_shdr(&b, class, header.shoff as usize)?;
            let shnum = if header.shnum == 0 {
                shdr0.sh_size as usize
            } else {
                header.shnum
            };
            if header.shstrndx == 0xffff {
                shstrndx = shdr0.sh_link as usize;
            }
            if header.phnum == 0xffff {
                phnum = shdr0.sh_info as usize;
            }
            for i in 0..shnum {
                let off = header.shoff as usize + i * header.shentsize;
                shdrs.push(read_shdr(&b, class, off)?);
            }
        }

        let mut phdrs: Vec<Phdr> = Vec::new();
        if header.phoff != 0 && header.phentsize >= expected_phdr_size(class) {
            for i in 0..phnum {
                let off = header.phoff as usize + i * header.phentsize;
                phdrs.push(read_phdr(&b, class, off)?);
            }
        }

        let shstr: &[u8] = if shstrndx != 0 && shstrndx < shdrs.len() {
            let s = &shdrs[shstrndx];
            b.slice(s.sh_offset as usize, s.sh_size as usize)
                .unwrap_or(&[])
        } else {
            &[]
        };

        let interpreter = phdrs
            .iter()
            .find(|p| p.p_type == PT_INTERP)
            .and_then(|p| {
                let bytes = b.slice(p.p_offset as usize, p.p_filesz as usize).ok()?;
                let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
                Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
            })
            .filter(|s| !s.is_empty());

        // The dynamic table is reachable through PT_DYNAMIC, or through the
        // .dynamic section on files whose program headers are unusual.
        let dyn_span = phdrs
            .iter()
            .find(|p| p.p_type == PT_DYNAMIC)
            .map(|p| (p.p_offset as usize, p.p_filesz as usize))
            .or_else(|| {
                section_by_type(&shdrs, SHT_DYNAMIC)
                    .map(|s| (s.sh_offset as usize, s.sh_size as usize))
            });
        let dynamic = match dyn_span {
            Some((off, size)) => read_dynamic(&b, class, off, size)?,
            None => Vec::new(),
        };
        let has_dynamic = !dynamic.is_empty();

        let strtab: &[u8] = if let Some(s) = section_by_name(&shdrs, shstr, endian, ".dynstr") {
            b.slice(s.sh_offset as usize, s.sh_size as usize)
                .unwrap_or(&[])
        } else if let Some(vaddr) = dyn_get(&dynamic, DT_STRTAB) {
            match vaddr_to_offset(&phdrs, vaddr) {
                Some(off) => {
                    let size = dyn_get(&dynamic, DT_STRSZ).unwrap_or(0) as usize;
                    if size > 0 {
                        b.slice(off, size).unwrap_or(&[])
                    } else {
                        b.raw().get(off..).unwrap_or(&[])
                    }
                }
                None => &[],
            }
        } else {
            &[]
        };
        let strtab_b = Bytes::new(strtab, endian);
        let dyn_str = |index: u64| -> Option<String> { strtab_b.cstr(index as usize) };

        let needed: Vec<String> = dynamic
            .iter()
            .filter(|(tag, _)| *tag == DT_NEEDED)
            .filter_map(|(_, value)| dyn_str(*value))
            .collect();
        let soname = dyn_get(&dynamic, DT_SONAME).and_then(dyn_str);
        let rpath = dyn_get(&dynamic, DT_RPATH)
            .and_then(dyn_str)
            .map(|s| split_paths(&s))
            .unwrap_or_default();
        let runpath = dyn_get(&dynamic, DT_RUNPATH)
            .and_then(dyn_str)
            .map(|s| split_paths(&s))
            .unwrap_or_default();
        let flags_1 = dyn_get(&dynamic, DT_FLAGS_1).unwrap_or(0);

        // Locate `.dynsym` and how many entries it has.
        let dynsym_sec = section_by_name(&shdrs, shstr, endian, ".dynsym")
            .or_else(|| section_by_type(&shdrs, SHT_DYNSYM));
        // The hash table states the symbol count independently of `.dynsym`'s
        // size, so it is a reliable cap when the section header is damaged.
        let hash_count = hash_symbol_count(&b, class, &phdrs, &dynamic);
        let (sym_off, sym_count, sym_stride) = if let Some(s) = dynsym_sec {
            let stride = if s.sh_entsize == 0 {
                default_sym_size(class)
            } else {
                s.sh_entsize as usize
            };
            let from_section = (s.sh_size as usize) / stride;
            let count = match hash_count {
                Some(hashed) => from_section.min(hashed),
                None => from_section,
            };
            (s.sh_offset as usize, count, stride)
        } else if let Some(vaddr) = dyn_get(&dynamic, DT_SYMTAB) {
            let off = vaddr_to_offset(&phdrs, vaddr).unwrap_or(0);
            let stride = dyn_get(&dynamic, DT_SYMENT)
                .map(|v| v as usize)
                .filter(|v| *v > 0)
                .unwrap_or_else(|| default_sym_size(class));
            (off, hash_count.unwrap_or(0), stride)
        } else {
            (0, 0, default_sym_size(class))
        };

        let versym = read_versym(&b, &shdrs, shstr, endian, &phdrs, &dynamic, sym_count);
        let symbols = if sym_count > 0 && sym_stride >= default_sym_size(class) {
            read_symbols(
                &b, class, sym_off, sym_count, sym_stride, &strtab_b, &versym,
            )
        } else {
            Vec::new()
        };

        let indexed_needs =
            read_version_needs(&b, &shdrs, shstr, endian, &phdrs, &dynamic, &strtab_b);
        let defined_entries =
            read_defined_versions(&b, &shdrs, shstr, endian, &phdrs, &dynamic, &strtab_b);
        let defined_version_map: HashMap<u16, String> = defined_entries.iter().cloned().collect();
        let defined_versions: Vec<String> =
            defined_entries.into_iter().map(|(_, name)| name).collect();

        // Flatten the raw tables into the public shape, keeping a lookup from
        // symbol version index to the (version name, owning object) pair.
        let mut version_by_index = HashMap::new();
        let mut version_needs = Vec::with_capacity(indexed_needs.len());
        for need in indexed_needs {
            for (index, name) in &need.indexed {
                version_by_index.insert(*index, (name.clone(), need.file.clone()));
            }
            version_needs.push(VersionNeed {
                file: need.file,
                versions: need.versions,
            });
        }

        Ok(ElfFile {
            path: path.to_path_buf(),
            class,
            endian,
            etype: header.etype,
            machine: header.machine,
            entry: header.entry,
            interpreter,
            soname,
            needed,
            rpath,
            runpath,
            has_dynamic,
            flags_1,
            symbols,
            version_needs,
            defined_versions,
            version_by_index,
            defined_version_map,
        })
    }

    /// A short human description of what kind of object this is.
    pub fn kind(&self) -> &'static str {
        match self.etype {
            ElfType::Executable if self.interpreter.is_some() => "dynamically linked executable",
            ElfType::Executable if self.has_dynamic => "executable without an interpreter",
            ElfType::Executable => "statically linked executable",
            ElfType::Shared if self.interpreter.is_some() => {
                "position-independent executable (PIE)"
            }
            ElfType::Shared if self.is_static_pie() => {
                "static position-independent executable (PIE)"
            }
            ElfType::Shared if self.soname.is_some() => "shared library",
            ElfType::Shared => "position-independent object",
            ElfType::Relocatable => "relocatable object",
            ElfType::Core => "core dump",
            ElfType::Other(_) => "ELF object",
        }
    }

    /// This program is started directly (as opposed to being a library).
    pub fn is_program(&self) -> bool {
        matches!(self.etype, ElfType::Executable | ElfType::Shared) && self.interpreter.is_some()
    }

    /// An `ET_DYN` executable that carries its own runtime (no `PT_INTERP`).
    ///
    /// `DT_FLAGS_1` with `DF_1_PIE` is authoritative; the fallback covers older
    /// toolchains that statically link a PIE without setting the flag.
    pub fn is_static_pie(&self) -> bool {
        self.etype == ElfType::Shared
            && self.interpreter.is_none()
            && (self.flags_1 & DF_1_PIE != 0 || (self.soname.is_none() && self.entry != 0))
    }

    /// The execute bit matters for this object: it is a program, not a library.
    ///
    /// A plain shared library is normally not executable, so only executables
    /// (static or dynamic), dynamic PIEs and static PIEs qualify.
    pub fn is_runnable(&self) -> bool {
        match self.etype {
            ElfType::Executable => true,
            ElfType::Shared => self.interpreter.is_some() || self.is_static_pie(),
            _ => false,
        }
    }

    /// The version name attached to a symbol, if it is versioned.
    pub fn version_name(&self, index: u16) -> Option<&str> {
        self.version_by_index
            .get(&index)
            .map(|(name, _)| name.as_str())
    }

    /// The object that must provide the version attached to a symbol.
    pub fn version_file(&self, index: u16) -> Option<&str> {
        self.version_by_index
            .get(&index)
            .map(|(_, file)| file.as_str())
    }

    /// The name of a version this object defines, by `.gnu.version` index.
    pub fn defined_version_name(&self, index: u16) -> Option<&str> {
        self.defined_version_map.get(&index).map(String::as_str)
    }
}

/// `VersionNeed` plus the version indices it maps, used while parsing.
#[derive(Debug, Clone)]
struct IndexedVersionNeed {
    file: String,
    versions: Vec<String>,
    indexed: Vec<(u16, String)>,
}

// ---------------------------------------------------------------------------
// Raw structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Header {
    etype: ElfType,
    machine: u16,
    entry: u64,
    phoff: u64,
    shoff: u64,
    phentsize: usize,
    phnum: usize,
    shentsize: usize,
    shnum: usize,
    shstrndx: usize,
}

#[derive(Debug, Clone, Copy)]
struct Phdr {
    p_type: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
}

#[derive(Debug, Clone, Copy)]
struct Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_entsize: u64,
}

fn expected_phdr_size(class: Class) -> usize {
    match class {
        Class::Elf32 => 32,
        Class::Elf64 => 56,
    }
}

fn expected_shdr_size(class: Class) -> usize {
    match class {
        Class::Elf32 => 40,
        Class::Elf64 => 64,
    }
}

fn default_sym_size(class: Class) -> usize {
    match class {
        Class::Elf32 => 16,
        Class::Elf64 => 24,
    }
}

fn read_header(b: &Bytes<'_>, class: Class) -> Result<Header, ElfError> {
    let minimum = match class {
        Class::Elf32 => 52,
        Class::Elf64 => 64,
    };
    if b.len() < minimum {
        return Err(ElfError::Truncated(format!(
            "ELF header is {} bytes, expected at least {minimum}",
            b.len()
        )));
    }
    let etype = ElfType::from_raw(b.u16(16)?);
    let machine = b.u16(18)?;
    let (entry, phoff, shoff) = match class {
        Class::Elf64 => (b.u64(24)?, b.u64(32)?, b.u64(40)?),
        Class::Elf32 => (b.u32(24)? as u64, b.u32(28)? as u64, b.u32(32)? as u64),
    };
    let (phentsize_off, shentsize_off) = match class {
        Class::Elf64 => (54usize, 58usize),
        Class::Elf32 => (42usize, 46usize),
    };
    let phentsize = b.u16(phentsize_off)? as usize;
    let phnum = b.u16(phentsize_off + 2)? as usize;
    let shentsize = b.u16(shentsize_off)? as usize;
    let shnum = b.u16(shentsize_off + 2)? as usize;
    let shstrndx = b.u16(shentsize_off + 4)? as usize;

    Ok(Header {
        etype,
        machine,
        entry,
        phoff,
        shoff,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    })
}

fn read_phdr(b: &Bytes<'_>, class: Class, off: usize) -> Result<Phdr, ElfError> {
    let p_type = b.u32(off)?;
    let (p_offset, p_vaddr, p_filesz) = match class {
        Class::Elf64 => (b.u64(off + 8)?, b.u64(off + 16)?, b.u64(off + 32)?),
        Class::Elf32 => (
            b.u32(off + 4)? as u64,
            b.u32(off + 8)? as u64,
            b.u32(off + 16)? as u64,
        ),
    };
    Ok(Phdr {
        p_type,
        p_offset,
        p_vaddr,
        p_filesz,
    })
}

fn read_shdr(b: &Bytes<'_>, class: Class, off: usize) -> Result<Shdr, ElfError> {
    let sh_name = b.u32(off)?;
    let sh_type = b.u32(off + 4)?;
    let (sh_offset, sh_size, sh_link, sh_info, sh_entsize) = match class {
        Class::Elf64 => (
            b.u64(off + 24)?,
            b.u64(off + 32)?,
            b.u32(off + 40)?,
            b.u32(off + 44)?,
            b.u64(off + 56)?,
        ),
        Class::Elf32 => (
            b.u32(off + 16)? as u64,
            b.u32(off + 20)? as u64,
            b.u32(off + 24)?,
            b.u32(off + 28)?,
            b.u32(off + 36)? as u64,
        ),
    };
    Ok(Shdr {
        sh_name,
        sh_type,
        sh_offset,
        sh_size,
        sh_link,
        sh_info,
        sh_entsize,
    })
}

fn read_dynamic(
    b: &Bytes<'_>,
    class: Class,
    off: usize,
    size: usize,
) -> Result<Vec<(i64, u64)>, ElfError> {
    let stride = match class {
        Class::Elf64 => 16,
        Class::Elf32 => 8,
    };
    let count = size / stride;
    let mut entries = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let at = off + i * stride;
        let (tag, value) = match class {
            Class::Elf64 => (b.u64(at)? as i64, b.u64(at + 8)?),
            Class::Elf32 => (b.u32(at)? as i32 as i64, b.u32(at + 4)? as u64),
        };
        if tag == DT_NULL {
            break;
        }
        entries.push((tag, value));
    }
    Ok(entries)
}

/// Maps a virtual address to a file offset using the loadable segments.
fn vaddr_to_offset(phdrs: &[Phdr], vaddr: u64) -> Option<usize> {
    phdrs.iter().find_map(|p| {
        if p.p_type == PT_LOAD && vaddr >= p.p_vaddr && vaddr < p.p_vaddr.saturating_add(p.p_filesz)
        {
            Some((p.p_offset + (vaddr - p.p_vaddr)) as usize)
        } else {
            None
        }
    })
}

fn dyn_get(dynamic: &[(i64, u64)], tag: i64) -> Option<u64> {
    dynamic.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
}

fn section_by_name<'a>(
    shdrs: &'a [Shdr],
    shstr: &[u8],
    endian: Endian,
    name: &str,
) -> Option<&'a Shdr> {
    let b = Bytes::new(shstr, endian);
    shdrs
        .iter()
        .find(|s| b.cstr(s.sh_name as usize).as_deref() == Some(name))
}

fn section_by_type(shdrs: &[Shdr], sh_type: u32) -> Option<&Shdr> {
    shdrs.iter().find(|s| s.sh_type == sh_type)
}

/// Splits a `DT_RPATH`/`DT_RUNPATH`/`LD_LIBRARY_PATH` value.
pub fn split_paths(value: &str) -> Vec<String> {
    value
        .split(':')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

fn read_versym(
    b: &Bytes<'_>,
    shdrs: &[Shdr],
    shstr: &[u8],
    endian: Endian,
    phdrs: &[Phdr],
    dynamic: &[(i64, u64)],
    sym_count: usize,
) -> Vec<u16> {
    let section = section_by_name(shdrs, shstr, endian, ".gnu.version")
        .or_else(|| section_by_type(shdrs, SHT_GNU_VERSYM));
    let (offset, count) = if let Some(s) = section {
        (s.sh_offset as usize, (s.sh_size as usize) / 2)
    } else if let Some(off) = dyn_get(dynamic, DT_VERSYM).and_then(|v| vaddr_to_offset(phdrs, v)) {
        (off, sym_count)
    } else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(count.min(65536));
    for i in 0..count {
        match b.u16(offset + i * 2) {
            Ok(v) => out.push(v),
            Err(_) => break,
        }
    }
    out
}

fn read_symbols(
    b: &Bytes<'_>,
    class: Class,
    offset: usize,
    count: usize,
    stride: usize,
    strtab: &Bytes<'_>,
    versym: &[u16],
) -> Vec<DynSymbol> {
    // `count` comes from untrusted metadata and may be absurd. A symbol table
    // cannot extend past the end of the file, so clamp it and stop at the first
    // read that falls off the end instead of treating it as an empty symbol and
    // looping on.
    let stride = stride.max(1);
    let available = b.len().saturating_sub(offset);
    let count = count.min(available / stride + 1);
    let mut out = Vec::with_capacity(count.min(100_000));
    for i in 0..count {
        let at = match i
            .checked_mul(stride)
            .and_then(|delta| offset.checked_add(delta))
        {
            Some(at) => at,
            None => break,
        };
        let (name_off, info, shndx) = match class {
            Class::Elf64 => match (b.u32(at), b.u8(at + 4), b.u16(at + 6)) {
                (Ok(name), Ok(info), Ok(shndx)) => (name, info, shndx),
                _ => break,
            },
            Class::Elf32 => match (b.u32(at), b.u8(at + 12), b.u16(at + 14)) {
                (Ok(name), Ok(info), Ok(shndx)) => (name, info, shndx),
                _ => break,
            },
        };
        if name_off == 0 {
            continue;
        }
        let name = match strtab.cstr(name_off as usize) {
            Some(name) if !name.is_empty() => name,
            _ => continue,
        };
        out.push(DynSymbol {
            name,
            binding: Binding::from_raw(info >> 4),
            sym_type: SymType::from_raw(info & 0x0f),
            undefined: shndx == SHN_UNDEF,
            // Bit 15 marks a non-default version; the index is the rest.
            version_index: versym.get(i).copied().unwrap_or(0) & 0x7fff,
        });
    }
    out
}

fn read_version_needs(
    b: &Bytes<'_>,
    shdrs: &[Shdr],
    shstr: &[u8],
    endian: Endian,
    phdrs: &[Phdr],
    dynamic: &[(i64, u64)],
    strtab: &Bytes<'_>,
) -> Vec<IndexedVersionNeed> {
    let span = section_by_name(shdrs, shstr, endian, ".gnu.version_r")
        .or_else(|| section_by_type(shdrs, SHT_GNU_VERNEED))
        .map(|s| (s.sh_offset as usize, s.sh_size as usize));
    let (offset, size) = match span {
        Some(span) => span,
        None => match dyn_get(dynamic, DT_VERNEED).and_then(|v| vaddr_to_offset(phdrs, v)) {
            Some(off) => (off, b.len().saturating_sub(off)),
            None => return Vec::new(),
        },
    };
    if offset >= b.len() {
        return Vec::new();
    }
    let region = Bytes::new(
        b.slice(offset, size.min(b.len() - offset)).unwrap_or(&[]),
        endian,
    );

    let mut needs: Vec<IndexedVersionNeed> = Vec::new();
    let mut pos = 0usize;
    for _ in 0..4096 {
        let (count, file_off, aux_rel, next) = match (
            region.u16(pos + 2),
            region.u32(pos + 4),
            region.u32(pos + 8),
            region.u32(pos + 12),
        ) {
            (Ok(c), Ok(f), Ok(a), Ok(n)) => (c as usize, f as usize, a as usize, n as usize),
            _ => break,
        };
        let file = strtab.cstr(file_off).unwrap_or_default();
        let mut versions = Vec::new();
        let mut indexed = Vec::new();
        let mut aux = pos + aux_rel;
        for _ in 0..count {
            match (
                region.u16(aux + 6),
                region.u32(aux + 8),
                region.u32(aux + 12),
            ) {
                (Ok(index), Ok(name_off), Ok(next_aux)) => {
                    if let Some(name) = strtab.cstr(name_off as usize) {
                        indexed.push((index, name.clone()));
                        versions.push(name);
                    }
                    if next_aux == 0 {
                        break;
                    }
                    aux += next_aux as usize;
                }
                _ => break,
            }
        }
        if !file.is_empty() {
            needs.push(IndexedVersionNeed {
                file,
                versions,
                indexed,
            });
        }
        if next == 0 {
            break;
        }
        pos += next;
    }

    needs
}

/// Returns the version-index -> (name, file) mapping as well, folded into the
/// `VersionNeed` list above. This helper only collects defined version names.
/// Reads `.gnu.version_d`, returning each defined version's index and name.
///
/// The index is the value that appears in `.gnu.version` for symbols defining
/// that version, which is what makes per-symbol version checks possible.
fn read_defined_versions(
    b: &Bytes<'_>,
    shdrs: &[Shdr],
    shstr: &[u8],
    endian: Endian,
    phdrs: &[Phdr],
    dynamic: &[(i64, u64)],
    strtab: &Bytes<'_>,
) -> Vec<(u16, String)> {
    let span = section_by_name(shdrs, shstr, endian, ".gnu.version_d")
        .or_else(|| section_by_type(shdrs, SHT_GNU_VERDEF))
        .map(|s| (s.sh_offset as usize, s.sh_size as usize));
    let (offset, size) = match span {
        Some(span) => span,
        None => match dyn_get(dynamic, DT_VERDEF).and_then(|v| vaddr_to_offset(phdrs, v)) {
            Some(off) => (off, b.len().saturating_sub(off)),
            None => return Vec::new(),
        },
    };
    if offset >= b.len() {
        return Vec::new();
    }
    let region = Bytes::new(
        b.slice(offset, size.min(b.len() - offset)).unwrap_or(&[]),
        endian,
    );

    let mut out = Vec::new();
    let mut pos = 0usize;
    for _ in 0..4096 {
        let (ndx, aux_rel, next) = match (
            region.u16(pos + 4),
            region.u32(pos + 12),
            region.u32(pos + 16),
        ) {
            (Ok(ndx), Ok(aux), Ok(next)) => (ndx, aux as usize, next as usize),
            _ => break,
        };
        // The first verdaux entry holds the version name; later ones name the
        // parent versions, which are already defined elsewhere.
        if let Ok(name_off) = region.u32(pos + aux_rel) {
            if let Some(name) = strtab.cstr(name_off as usize) {
                out.push((ndx, name));
            }
        }
        if next == 0 {
            break;
        }
        pos += next;
    }
    out
}

/// Determines the number of `.dynsym` entries from DT_HASH or DT_GNU_HASH.
///
/// Needed for binaries whose section headers were stripped: without them the
/// symbol count is only implied by the hash table.
fn hash_symbol_count(
    b: &Bytes<'_>,
    class: Class,
    phdrs: &[Phdr],
    dynamic: &[(i64, u64)],
) -> Option<usize> {
    if let Some(off) = dyn_get(dynamic, DT_HASH).and_then(|v| vaddr_to_offset(phdrs, v)) {
        // struct { uint32_t nbucket; uint32_t nchain; } and nchain is the
        // number of symbols.
        return b.u32(off + 4).ok().map(|n| n as usize);
    }
    if let Some(off) = dyn_get(dynamic, DT_GNU_HASH).and_then(|v| vaddr_to_offset(phdrs, v)) {
        return gnu_hash_symbol_count(b, class, off);
    }
    None
}

/// Walks the GNU hash chains to find the highest symbol index.
fn gnu_hash_symbol_count(b: &Bytes<'_>, class: Class, offset: usize) -> Option<usize> {
    let nbuckets = b.u32(offset).ok()? as usize;
    let symoffset = b.u32(offset + 4).ok()? as usize;
    let bloom_size = b.u32(offset + 8).ok()? as usize;
    let bloom_word = match class {
        Class::Elf64 => 8usize,
        Class::Elf32 => 4usize,
    };
    let buckets_off = offset + 16 + bloom_size.checked_mul(bloom_word)?;
    let chains_off = buckets_off.checked_add(nbuckets.checked_mul(4)?)?;

    let mut max_index = 0usize;
    for bucket in 0..nbuckets {
        let first = b.u32(buckets_off + bucket * 4).ok()? as usize;
        if first == 0 {
            continue;
        }
        if first < symoffset {
            return None;
        }
        let mut chain_pos = first - symoffset;
        loop {
            let value = b.u32(chains_off + chain_pos * 4).ok()?;
            max_index = max_index.max(symoffset + chain_pos + 1);
            if value & 1 == 1 {
                break;
            }
            chain_pos += 1;
            if chain_pos > 4_000_000 {
                return None;
            }
        }
    }
    (max_index > 0).then_some(max_index)
}

// ---------------------------------------------------------------------------
// Architecture names
// ---------------------------------------------------------------------------

/// The conventional name of an `e_machine` value.
pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x0003 => "i386",
        0x0008 => "MIPS",
        0x0014 => "PowerPC",
        0x0015 => "PowerPC64",
        0x0016 => "s390",
        0x0028 => "ARM",
        0x002a => "SuperH",
        0x0032 => "IA-64",
        0x003e => "x86-64",
        0x00b7 => "AArch64",
        0x00f3 => "RISC-V",
        0x0102 => "LoongArch",
        _ => "unknown architecture",
    }
}

/// The `e_machine` value matching the machine `why` itself runs on.
pub fn host_machine() -> Option<u16> {
    match std::env::consts::ARCH {
        "x86" => Some(0x0003),
        "x86_64" => Some(0x003e),
        "arm" => Some(0x0028),
        "aarch64" => Some(0x00b7),
        "riscv32" | "riscv64" => Some(0x00f3),
        "powerpc" => Some(0x0014),
        "powerpc64" => Some(0x0015),
        "s390x" => Some(0x0016),
        "loongarch64" => Some(0x0102),
        "mips" | "mips64" => Some(0x0008),
        _ => None,
    }
}

/// A human name for the host machine.
pub fn host_name() -> &'static str {
    host_machine().map(machine_name).unwrap_or("this machine")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_exe() -> PathBuf {
        std::env::current_exe().expect("test binary path")
    }

    #[test]
    fn parses_the_running_test_binary() {
        let elf = ElfFile::parse(&self_exe()).expect("parse test binary");
        assert!(matches!(elf.class, Class::Elf32 | Class::Elf64));
        assert!(elf.has_dynamic, "test binary should be dynamically linked");
        assert!(
            elf.interpreter.is_some(),
            "test binary should have an interpreter"
        );
        let interp = elf.interpreter.clone().unwrap();
        assert!(
            std::path::Path::new(&interp).exists(),
            "interpreter {interp} missing"
        );
        assert!(
            elf.needed.iter().any(|n| n.contains("libc")),
            "expected libc in {:?}",
            elf.needed
        );
        assert!(!elf.symbols.is_empty());
        assert!(elf.symbols.iter().any(|s| s.undefined));
    }

    #[test]
    fn recognises_a_static_pie() {
        let mut elf = ElfFile::parse(&self_exe()).expect("parse test binary");
        // Simulate `gcc -static-pie`: ET_DYN, no interpreter, DF_1_PIE set.
        elf.etype = ElfType::Shared;
        elf.interpreter = None;
        elf.soname = None;
        elf.entry = 0x1000;
        elf.flags_1 = DF_1_PIE;
        assert!(elf.is_static_pie());
        assert!(elf.is_runnable());
        assert_eq!(elf.kind(), "static position-independent executable (PIE)");

        // A plain shared library is not runnable.
        elf.flags_1 = 0;
        elf.entry = 0;
        elf.soname = Some("libexample.so.1".to_string());
        assert!(!elf.is_static_pie());
        assert!(!elf.is_runnable());
        assert_eq!(elf.kind(), "shared library");

        // A dynamic PIE (ET_DYN with an interpreter) is runnable too.
        elf.interpreter = Some("/lib64/ld-linux-x86-64.so.2".to_string());
        assert!(!elf.is_static_pie());
        assert!(elf.is_runnable());
        assert_eq!(elf.kind(), "position-independent executable (PIE)");
    }

    #[test]
    fn rejects_a_non_elf_file() {
        let err =
            ElfFile::parse_bytes(Path::new("/tmp/x"), b"hello world, not an elf").unwrap_err();
        assert!(matches!(err, ElfError::NotElf));
    }

    #[test]
    fn rejects_an_empty_file() {
        assert!(ElfFile::parse_bytes(Path::new("/tmp/x"), b"").is_err());
    }

    #[test]
    fn rejects_a_truncated_elf_header() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[EI_CLASS] = ELFCLASS64;
        data[EI_DATA] = ELFDATA2LSB;
        // e_phoff points far past the end of the buffer.
        data[32..40].copy_from_slice(&0xffff_ffffu64.to_le_bytes());
        data[54..56].copy_from_slice(&56u16.to_le_bytes());
        data[56..58].copy_from_slice(&1u16.to_le_bytes());
        assert!(ElfFile::parse_bytes(Path::new("/tmp/x"), &data).is_err());
    }

    #[test]
    fn symbol_reading_stops_at_the_end_of_the_buffer() {
        // Only two Elf64 entries fit, but the metadata claims a million. The
        // reader must stop at the end of the buffer rather than looping on
        // zero-filled reads.
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[24..28].copy_from_slice(&2u32.to_le_bytes());
        let b = Bytes::new(&data, Endian::Little);
        let strtab = Bytes::new(b"\0foo\0bar\0", Endian::Little);
        let symbols = read_symbols(&b, Class::Elf64, 0, 1_000_000, 24, &strtab, &[]);
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "foo");
    }

    #[test]
    fn splits_colon_separated_paths() {
        assert_eq!(split_paths("/a:/b::/c"), vec!["/a", "/b", "/c"]);
        assert!(split_paths("").is_empty());
    }

    #[test]
    fn names_common_machines() {
        assert_eq!(machine_name(0x3e), "x86-64");
        assert_eq!(machine_name(0xb7), "AArch64");
        assert_eq!(machine_name(0x1234), "unknown architecture");
    }
}
