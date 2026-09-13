//! `why` — a Linux program troubleshooter.
//!
//! Version 0.1 answers one question well: *why does this ELF program not
//! start?* It reads the ELF metadata itself (no `ldd`, no `readelf`), walks
//! the transitive dependency graph, and reports what is missing in plain
//! language instead of dumping raw diagnostics.
//!
//! The crate is split so that it can be embedded or tested without the CLI:
//!
//! * [`elf`] — a small, dependency-free ELF reader
//! * [`resolve`] — dynamic-loader library search path semantics
//! * [`analyze`] — turns ELF facts into findings
//! * [`report`] — renders findings for humans
//! * [`distro`] — package-manager hints for suggested next steps

pub mod analyze;
pub mod cli;
pub mod distro;
pub mod elf;
pub mod report;
pub mod resolve;

/// The version of `why`, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
