//! End-to-end tests that run the real `why` binary against real ELF files.
//!
//! The interesting case — a genuinely missing shared library — is produced by
//! patching the `DT_NEEDED` string of a copy of the test binary in place. That
//! keeps the offsets valid and needs no compiler or fixture at test time.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use why::analyze::{analyze, LibResolution};
use why::elf::{Binding, ElfFile};

fn why_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_why"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(why_binary())
        .args(args)
        .output()
        .expect("run why")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("why-test-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn replace_all(data: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), replacement.len());
    let mut out = Vec::with_capacity(data.len());
    let mut rest = data;
    while let Some(position) = find(rest, needle) {
        out.extend_from_slice(&rest[..position]);
        out.extend_from_slice(replacement);
        rest = &rest[position + needle.len()..];
    }
    out.extend_from_slice(rest);
    out
}

/// Copies the test binary and renames one of its `DT_NEEDED` entries to a
/// library that cannot exist, returning the (file, library) pair.
fn make_broken_binary(dir: &Path) -> Option<(PathBuf, String)> {
    let source = std::env::current_exe().ok()?;
    let elf = ElfFile::parse(&source).ok()?;
    let target = elf.needed.iter().find(|name| name.len() >= 6)?.clone();

    let bogus = format!("lib{}", "z".repeat(target.len() - 3));
    assert_eq!(bogus.len(), target.len());

    let data = fs::read(&source).ok()?;
    let patched = replace_all(
        &data,
        format!("{target}\0").as_bytes(),
        format!("{bogus}\0").as_bytes(),
    );

    let path = dir.join("broken");
    fs::write(&path, patched).ok()?;
    let mut permissions = fs::metadata(&path).ok()?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).ok()?;
    Some((path, bogus))
}

#[test]
fn prints_its_version() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "{stdout}");
}

#[test]
fn prints_help() {
    let output = run(&["--help"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("USAGE"));
}

#[test]
fn rejects_unknown_options() {
    let output = run(&["--definitely-not-an-option"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn requires_a_target() {
    let output = run(&[]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn reports_a_healthy_binary_as_clean() {
    let exe = std::env::current_exe().unwrap();
    let output = run(&["--no-color", exe.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("no problems found"), "{stdout}");
}

#[test]
fn exits_two_for_a_missing_file() {
    let output = run(&["/definitely/not/a/real/program"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read"));
}

#[test]
fn exits_two_for_a_non_elf_file() {
    let dir = temp_dir("nonelf");
    let file = dir.join("notes.txt");
    fs::write(&file, b"this is not an ELF program\n").unwrap();

    let output = run(&["--no-color", file.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(2), "{stdout}");
    assert!(stdout.contains("Not an ELF program"), "{stdout}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn detects_a_missing_shared_library() {
    let dir = temp_dir("missing-lib");
    let Some((path, bogus)) = make_broken_binary(&dir) else {
        // No suitable dynamic dependency to patch (for example a static test
        // binary); nothing to assert.
        return;
    };

    // Library level.
    let analysis = analyze(&path).expect("analyze broken binary");
    assert!(analysis.has_failures());
    assert!(
        analysis
            .missing_libraries()
            .any(|library| library.name == bogus
                && matches!(library.resolution, LibResolution::Missing)),
        "expected {bogus} to be missing: {:?}",
        analysis.libraries
    );
    assert_eq!(analysis.exit_code(), 1);

    // Command level.
    let output = run(&["--no-color", path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains(&bogus), "{stdout}");
    assert!(stdout.contains("MISSING"), "{stdout}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn reports_a_missing_execute_bit() {
    let dir = temp_dir("no-exec");
    let source = std::env::current_exe().unwrap();
    let path = dir.join("not-executable");
    fs::copy(&source, &path).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&path, permissions).unwrap();

    let analysis = analyze(&path).expect("analyze");
    assert_eq!(analysis.exit_code(), 1);
    assert!(!analysis.permissions.as_ref().unwrap().executable);

    let output = run(&["--no-color", path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("not executable"), "{stdout}");
    assert!(stdout.contains("chmod +x"), "{stdout}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn checks_the_env_interpreter_through_path() {
    let dir = temp_dir("env-path");
    let script = dir.join("script");
    fs::write(&script, b"#!/usr/bin/env why-no-such-interpreter\n").unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();

    let output = run(&["--no-color", script.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("not found on PATH"), "{stdout}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn detects_an_unresolved_symbol() {
    let dir = temp_dir("bad-symbol");
    let source = std::env::current_exe().unwrap();
    let elf = ElfFile::parse(&source).unwrap();
    let Some(target) = elf
        .symbols
        .iter()
        .find(|symbol| {
            symbol.undefined && matches!(symbol.binding, Binding::Global) && symbol.name.len() >= 6
        })
        .map(|symbol| symbol.name.clone())
    else {
        return;
    };
    let bogus = "z".repeat(target.len());

    let data = fs::read(&source).unwrap();
    let patched = replace_all(
        &data,
        format!("{target}\0").as_bytes(),
        format!("{bogus}\0").as_bytes(),
    );
    let path = dir.join("bad-symbol");
    fs::write(&path, patched).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).unwrap();

    let analysis = analyze(&path).unwrap();
    assert!(
        analysis
            .unresolved
            .iter()
            .any(|symbol| symbol.name == bogus),
        "expected {bogus} to be unresolved: {:?}",
        analysis.unresolved
    );
    assert_eq!(analysis.exit_code(), 1);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn verbose_lists_resolved_libraries() {
    let exe = std::env::current_exe().unwrap();
    let output = run(&["--no-color", "--verbose", exe.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("libc.so.6"), "{stdout}");
    assert!(stdout.contains("Library versions"), "{stdout}");
}

#[test]
fn reports_a_non_program_as_a_problem() {
    // A relocatable object cannot be run, so it must not end with
    // "no problems found" and exit 0.
    let candidates = ["/usr/lib/crt1.o", "/usr/lib32/crt1.o", "/lib/crt1.o"];
    let Some(object) = candidates.iter().find(|path| Path::new(path).exists()) else {
        return;
    };

    let output = run(&["--no-color", object]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("not runnable"), "{stdout}");
    assert!(!stdout.contains("no problems found"), "{stdout}");
}

#[test]
fn skips_env_options_in_a_shebang() {
    let dir = temp_dir("env-options");
    let script = dir.join("script");
    fs::write(&script, b"#!/usr/bin/env -u FOO why-no-such-interpreter\n").unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();

    let output = run(&["--no-color", script.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    // The command after `-u FOO` must be reported, not the option's argument.
    assert!(stdout.contains("why-no-such-interpreter"), "{stdout}");
    assert!(!stdout.contains("FOO"), "{stdout}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_non_elf_library_is_not_reported_as_resolved() {
    let dir = temp_dir("decoy-lib");
    let Some((path, bogus)) = make_broken_binary(&dir) else {
        return;
    };
    // Put a same-named text file on the search path: the loader cannot use it,
    // so it must not count as "resolved".
    let libdir = dir.join("libdir");
    fs::create_dir_all(&libdir).unwrap();
    fs::write(libdir.join(&bogus), b"not an ELF object\n").unwrap();

    let output = Command::new(why_binary())
        .env("LD_LIBRARY_PATH", &libdir)
        .args(["--no-color", path.to_str().unwrap()])
        .output()
        .expect("run why");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("UNUSABLE"), "{stdout}");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn reports_an_interpreter_that_is_not_a_loader() {
    let dir = temp_dir("bad-loader");
    let source = std::env::current_exe().unwrap();
    let elf = ElfFile::parse(&source).unwrap();
    let Some(interp) = elf.interpreter.clone() else {
        return;
    };

    // An executable that is not an ELF object at all.
    let loader = std::env::temp_dir().join(format!("why-loader-{}", std::process::id()));
    fs::write(&loader, b"#!/bin/sh\necho not a loader\n").unwrap();
    let mut permissions = fs::metadata(&loader).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&loader, permissions).unwrap();

    // Point PT_INTERP at it, padding to the original length so offsets hold.
    let mut replacement = loader.display().to_string().into_bytes();
    replacement.push(0);
    assert!(
        replacement.len() <= interp.len() + 1,
        "temp loader path is too long to patch in place"
    );
    replacement.resize(interp.len() + 1, 0);

    let data = fs::read(&source).unwrap();
    let patched = replace_all(&data, format!("{interp}\0").as_bytes(), &replacement);
    let path = dir.join("bad-loader");
    fs::write(&path, patched).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).unwrap();

    let output = run(&["--no-color", path.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    assert!(stdout.contains("not a valid loader"), "{stdout}");

    fs::remove_file(&loader).ok();
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn strips_quotes_in_an_env_split_string() {
    let dir = temp_dir("env-split");
    let script = dir.join("script");
    fs::write(
        &script,
        b"#!/usr/bin/env -S \"why-no-such-interpreter\" -O\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();

    let output = run(&["--no-color", script.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "{stdout}");
    // The quotes must not end up in the interpreter name.
    assert!(stdout.contains("why-no-such-interpreter"), "{stdout}");
    assert!(!stdout.contains('"'), "{stdout}");

    fs::remove_dir_all(&dir).ok();
}
