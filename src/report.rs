//! Renders an [`Analysis`] as something a human wants to read.
//!
//! The whole point of `why` is this module. Linux already has excellent tools
//! that emit raw diagnostics; the missing layer is a short, opinionated
//! explanation of what they mean.

use std::fmt::Write as _;
use std::io::{self, IsTerminal};

use crate::analyze::{
    Analysis, ArchFinding, LibResolution, LibraryFinding, PermissionFinding, Status, TargetKind,
    UnresolvedSymbol, VersionProblem,
};
use crate::cli::Options;
use crate::distro::Distro;
use crate::elf::{Class, ElfType};

/// Column where the right-hand status/value is aligned.
const VALUE_COLUMN: usize = 54;

/// Writes the report to stdout.
pub fn print(analysis: &Analysis, options: &Options) {
    let color =
        !options.no_color && std::env::var_os("NO_COLOR").is_none() && io::stdout().is_terminal();
    let painter = Painter { color };
    let mut out = String::new();
    render(&mut out, analysis, options, &painter);
    print!("{out}");
}

/// Writes the report into a string (used by tests and, later, reports).
pub fn to_string(analysis: &Analysis, options: &Options) -> String {
    let painter = Painter { color: false };
    let mut out = String::new();
    render(&mut out, analysis, options, &painter);
    out
}

struct Painter {
    color: bool,
}

impl Painter {
    fn wrap(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.wrap("1", text)
    }

    fn dim(&self, text: &str) -> String {
        self.wrap("2", text)
    }

    fn red(&self, text: &str) -> String {
        self.wrap("31", text)
    }

    fn green(&self, text: &str) -> String {
        self.wrap("32", text)
    }

    fn yellow(&self, text: &str) -> String {
        self.wrap("33", text)
    }

    fn cyan(&self, text: &str) -> String {
        self.wrap("36", text)
    }

    fn colorize(&self, status: Status, text: &str) -> String {
        match status {
            Status::Ok => self.green(text),
            Status::Warn => self.yellow(text),
            Status::Fail => self.red(text),
            Status::Info => self.cyan(text),
        }
    }
}

fn mark(painter: &Painter, status: Status, ascii: bool) -> String {
    let glyph = if ascii {
        match status {
            Status::Ok => "[ok]",
            Status::Warn => "[!]",
            Status::Fail => "[x]",
            Status::Info => "[-]",
        }
    } else {
        match status {
            Status::Ok => "✓",
            Status::Warn => "⚠",
            Status::Fail => "✗",
            Status::Info => "•",
        }
    };
    painter.colorize(status, glyph)
}

fn section(out: &mut String, painter: &Painter, status: Status, title: &str, ascii: bool) {
    let _ = writeln!(
        out,
        "{} {}",
        mark(painter, status, ascii),
        painter.bold(title)
    );
}

/// A `left          right` row with the right side aligned to [`VALUE_COLUMN`].
fn row(painter: &Painter, left: &str, right: &str, status: Status) -> String {
    let pad = VALUE_COLUMN
        .saturating_sub(left.chars().count() + right.chars().count())
        .max(2);
    format!(
        "  {left}{}{}",
        " ".repeat(pad),
        painter.colorize(status, right)
    )
}

fn render(out: &mut String, analysis: &Analysis, options: &Options, painter: &Painter) {
    let _ = writeln!(out, "{}", painter.bold("WHY DOES THIS PROGRAM NOT WORK?"));
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "  {}",
        painter.cyan(&analysis.path.display().to_string())
    );
    match &analysis.kind {
        TargetKind::Elf(elf) => {
            let _ = writeln!(
                out,
                "  {}",
                painter.dim(&format!(
                    "{} · {}-bit {}",
                    elf.kind(),
                    elf.class.bits(),
                    crate::elf::machine_name(elf.machine)
                ))
            );
        }
        TargetKind::Script { .. } => {
            let _ = writeln!(out, "  {}", painter.dim("script"));
        }
        TargetKind::NotElf { description } => {
            let _ = writeln!(out, "  {}", painter.dim(description));
        }
    }
    let _ = writeln!(out);

    if let TargetKind::NotElf { description } = &analysis.kind {
        section(
            out,
            painter,
            Status::Warn,
            "Not an ELF program",
            options.ascii,
        );
        let _ = writeln!(out, "  {description}");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "{}",
            painter.dim(
                "why v0.1 inspects ELF programs and scripts; other file types are not understood yet."
            )
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", summary_line(analysis, options, painter));
        return;
    }

    if let Some(not_a_program) = &analysis.not_a_program {
        render_file_type(out, not_a_program, analysis, options, painter);
    }
    if let Some(permissions) = &analysis.permissions {
        render_permissions(out, permissions, options, painter);
    }
    if let Some(arch) = &analysis.arch {
        render_arch(out, arch, options, painter);
    }
    render_interpreter(out, analysis, options, painter);
    render_libraries(out, analysis, options, painter);
    render_symbols(out, analysis, options, painter);
    render_versions(out, analysis, options, painter);
    render_environment(out, analysis, options, painter);
    render_notes(out, analysis, painter);
    render_suggestions(out, analysis, painter);
    let _ = writeln!(out, "{}", summary_line(analysis, options, painter));
}

fn render_file_type(
    out: &mut String,
    reason: &str,
    analysis: &Analysis,
    options: &Options,
    painter: &Painter,
) {
    section(out, painter, Status::Fail, "File type", options.ascii);
    let _ = writeln!(
        out,
        "{}",
        row(
            painter,
            &analysis.path.display().to_string(),
            "not runnable",
            Status::Fail
        )
    );
    let _ = writeln!(out, "      {reason}");
    let _ = writeln!(out);
}

fn render_permissions(
    out: &mut String,
    permissions: &PermissionFinding,
    options: &Options,
    painter: &Painter,
) {
    let status = if permissions.executable {
        Status::Ok
    } else {
        Status::Fail
    };
    section(out, painter, status, "Executable permission", options.ascii);
    let value = if permissions.executable {
        "executable".to_string()
    } else {
        format!("not executable (mode {:04o})", permissions.mode)
    };
    let _ = writeln!(out, "{}", row(painter, &permissions.path, &value, status));
    let _ = writeln!(out);
}

fn render_arch(out: &mut String, arch: &ArchFinding, options: &Options, painter: &Painter) {
    let bits = match arch.class {
        Class::Elf32 => 32,
        Class::Elf64 => 64,
    };
    let label = format!("{}, {bits}-bit", arch.name);
    // A different machine is not automatically broken: 32-bit i386 runs on
    // x86-64, it just needs the compatibility loader and libraries.
    let (status, value) = match arch.host_name {
        None => (Status::Info, "host architecture unknown".to_string()),
        Some(host) if arch.exact => (
            Status::Ok,
            format!("matches this system ({host}, {bits}-bit)"),
        ),
        Some(host) if arch.compatible => (
            Status::Warn,
            format!("compatible with {host} (needs multilib support)"),
        ),
        Some(host) => (Status::Fail, format!("this system is {host}")),
    };
    section(out, painter, status, "Architecture", options.ascii);
    let _ = writeln!(out, "{}", row(painter, &label, &value, status));
    let _ = writeln!(out);
}

fn render_interpreter(out: &mut String, analysis: &Analysis, options: &Options, painter: &Painter) {
    let title = match analysis.kind {
        TargetKind::Script { .. } => "Interpreter",
        _ => "ELF interpreter",
    };
    let Some(interpreter) = &analysis.interpreter else {
        if let TargetKind::Elf(elf) = &analysis.kind {
            let detail = match elf.etype {
                ElfType::Shared => "not applicable (shared library)",
                ElfType::Relocatable => "not applicable (relocatable object)",
                ElfType::Core => "not applicable (core dump)",
                _ => "not used (statically linked)",
            };
            section(out, painter, Status::Info, title, options.ascii);
            let _ = writeln!(out, "  {detail}");
            let _ = writeln!(out);
        }
        return;
    };

    let (status, value) = if !interpreter.exists {
        (Status::Fail, "MISSING")
    } else if !interpreter.executable {
        // A loader without the execute bit cannot start anything.
        (Status::Fail, "not executable")
    } else if interpreter.wrong_architecture.is_some() {
        // The kernel rejects a loader of the wrong class or machine.
        (Status::Fail, "wrong architecture")
    } else {
        (Status::Ok, "present")
    };
    section(out, painter, status, title, options.ascii);
    let _ = writeln!(out, "{}", row(painter, &interpreter.path, value, status));
    if let Some((found, wanted)) = interpreter.wrong_architecture {
        let _ = writeln!(out, "      built for {found}, but the program is {wanted}");
    }
    let _ = writeln!(out);
}

fn render_libraries(out: &mut String, analysis: &Analysis, options: &Options, painter: &Painter) {
    if !matches!(analysis.kind, TargetKind::Elf(_)) {
        return;
    }
    if analysis.libraries.is_empty() {
        section(
            out,
            painter,
            Status::Info,
            "Shared libraries",
            options.ascii,
        );
        let _ = writeln!(out, "  none (statically linked)");
        let _ = writeln!(out);
        return;
    }

    let unusable: Vec<&LibraryFinding> = analysis.unusable_libraries().collect();
    let resolved = analysis.libraries.len() - unusable.len();
    let status = if unusable.is_empty() {
        Status::Ok
    } else {
        Status::Fail
    };

    section(out, painter, status, "Shared libraries", options.ascii);
    let _ = writeln!(out, "  {resolved} resolved, {} unusable", unusable.len());
    for library in &unusable {
        match &library.resolution {
            LibResolution::WrongArchitecture {
                path,
                found,
                wanted,
            } => {
                let _ = writeln!(
                    out,
                    "{}",
                    row(painter, &library.name, "WRONG ARCH", Status::Fail)
                );
                let _ = writeln!(
                    out,
                    "      found {} ({found}), but a {wanted} object is required",
                    path.display()
                );
            }
            LibResolution::Unusable { path, reason } => {
                let _ = writeln!(
                    out,
                    "{}",
                    row(painter, &library.name, "UNUSABLE", Status::Fail)
                );
                let _ = writeln!(out, "      {} is {reason}", path.display());
            }
            _ => {
                let _ = writeln!(
                    out,
                    "{}",
                    row(painter, &library.name, "MISSING", Status::Fail)
                );
            }
        }
        for parent in &library.needed_by {
            let _ = writeln!(out, "      required by {parent}");
        }
    }
    if options.verbose {
        for library in analysis.libraries.iter() {
            if let LibResolution::Found(path) = &library.resolution {
                let _ = writeln!(
                    out,
                    "{}",
                    row(
                        painter,
                        &library.name,
                        &path.display().to_string(),
                        Status::Ok
                    )
                );
            }
        }
    }
    let _ = writeln!(out);
}

fn render_symbols(out: &mut String, analysis: &Analysis, options: &Options, painter: &Painter) {
    let TargetKind::Elf(elf) = &analysis.kind else {
        return;
    };
    if !elf.has_dynamic {
        section(
            out,
            painter,
            Status::Info,
            "Symbol dependencies",
            options.ascii,
        );
        let _ = writeln!(out, "  not applicable (statically linked)");
        let _ = writeln!(out);
        return;
    }
    if analysis.unresolved.is_empty() {
        section(
            out,
            painter,
            Status::Ok,
            "Symbol dependencies",
            options.ascii,
        );
        let _ = writeln!(out, "  every imported symbol is provided");
        let _ = writeln!(out);
        return;
    }

    section(
        out,
        painter,
        Status::Fail,
        "Symbol dependencies",
        options.ascii,
    );
    let count = analysis.unresolved.len();
    let _ = writeln!(out, "  {count} unresolved symbol{}", plural(count));
    let limit = if options.verbose { count } else { 20 };
    for symbol in analysis.unresolved.iter().take(limit) {
        let name = display_symbol(symbol);
        let _ = writeln!(out, "{}", row(painter, &name, &symbol.object, Status::Fail));
    }
    if count > limit {
        let _ = writeln!(out, "  … and {} more (use --verbose)", count - limit);
    }
    let _ = writeln!(out);
}

fn display_symbol(symbol: &UnresolvedSymbol) -> String {
    match &symbol.version {
        Some(version) => format!("{}@{version}", symbol.name),
        None => symbol.name.clone(),
    }
}

fn render_versions(out: &mut String, analysis: &Analysis, options: &Options, painter: &Painter) {
    let TargetKind::Elf(elf) = &analysis.kind else {
        return;
    };
    if analysis.version_problems.is_empty() {
        if options.verbose && !elf.version_needs.is_empty() {
            let total: usize = elf
                .version_needs
                .iter()
                .map(|need| need.versions.len())
                .sum();
            section(out, painter, Status::Ok, "Library versions", options.ascii);
            let _ = writeln!(out, "  {total} symbol version requirements satisfied");
            let _ = writeln!(out);
        }
        return;
    }

    section(
        out,
        painter,
        Status::Fail,
        "Library versions",
        options.ascii,
    );
    for problem in &analysis.version_problems {
        render_version_problem(out, problem, painter);
    }
    let _ = writeln!(out);
}

fn render_version_problem(out: &mut String, problem: &VersionProblem, painter: &Painter) {
    let provided = problem
        .best_provided
        .clone()
        .unwrap_or_else(|| "an older version".to_string());
    let _ = writeln!(
        out,
        "{}",
        row(
            painter,
            &problem.library,
            &format!("needs {}", problem.required),
            Status::Fail
        )
    );
    match &problem.library_path {
        Some(path) => {
            let _ = writeln!(
                out,
                "      required by {}; {} provides {provided}",
                problem.object, path
            );
        }
        None => {
            let _ = writeln!(
                out,
                "      required by {}; the system provides {provided}",
                problem.object
            );
        }
    }
}

fn render_environment(out: &mut String, analysis: &Analysis, options: &Options, painter: &Painter) {
    if analysis.env.is_empty() {
        if options.verbose {
            section(out, painter, Status::Ok, "Environment", options.ascii);
            let _ = writeln!(out, "  no relevant variables set");
            let _ = writeln!(out);
        }
        return;
    }

    let status = analysis
        .env
        .iter()
        .map(|finding| finding.status)
        .fold(Status::Ok, Status::worse);
    section(out, painter, status, "Environment", options.ascii);
    for finding in &analysis.env {
        let value = truncate(&finding.value, 60);
        let _ = writeln!(
            out,
            "{}",
            row(
                painter,
                &format!("{}={}", finding.variable, value),
                "set",
                finding.status
            )
        );
        let _ = writeln!(out, "      {}", painter.dim(&finding.note));
    }
    let _ = writeln!(out);
}

fn render_notes(out: &mut String, analysis: &Analysis, painter: &Painter) {
    if analysis.notes.is_empty() {
        return;
    }
    for note in &analysis.notes {
        let _ = writeln!(out, "{} {}", painter.dim("•"), painter.dim(note));
    }
    let _ = writeln!(out);
}

fn render_suggestions(out: &mut String, analysis: &Analysis, painter: &Painter) {
    let distro = Distro::detect();
    let steps = suggestions(analysis, &distro);
    if steps.is_empty() {
        return;
    }
    let _ = writeln!(out, "{}", painter.bold("Suggested next steps"));
    for (index, step) in steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {}", index + 1, step);
    }
    let _ = writeln!(out);
}

fn suggestions(analysis: &Analysis, distro: &Distro) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();

    if analysis.not_a_program.is_some() {
        steps.push(
            "Point `why` at the program that runs this file (the executable or the loader), not at the object itself"
                .to_string(),
        );
    }

    if let Some(permissions) = &analysis.permissions {
        if !permissions.executable {
            steps.push(format!(
                "Make the file executable: `chmod +x {}` (currently mode {:04o})",
                permissions.path, permissions.mode
            ));
        }
    }

    for library in analysis.missing_libraries() {
        let step = format!(
            "Find and install the package that provides {} — {}",
            library.name,
            distro.search_hint(&library.name)
        );
        if !steps.contains(&step) {
            steps.push(step);
        }
    }

    for library in analysis.unusable_libraries() {
        if let LibResolution::WrongArchitecture {
            path,
            found,
            wanted,
        } = &library.resolution
        {
            let step = format!(
                "{} ({}) is built for {found}, not {wanted}; install the {wanted} version of the package that provides it",
                library.name,
                path.display()
            );
            if !steps.contains(&step) {
                steps.push(step);
            }
        }
        if let LibResolution::Unusable { path, reason } = &library.resolution {
            let step = format!(
                "{} ({}) is {reason}; replace it or remove it from the search path",
                library.name,
                path.display()
            );
            if !steps.contains(&step) {
                steps.push(step);
            }
        }
    }

    if let Some(interpreter) = &analysis.interpreter {
        if !interpreter.exists {
            let message = match analysis.kind {
                // A bare name (from `#!/usr/bin/env`) is a PATH lookup, not a path.
                TargetKind::Script { .. } if !interpreter.path.contains('/') => format!(
                    "The interpreter `{}` was not found on PATH; install it or fix PATH",
                    interpreter.path
                ),
                TargetKind::Script { .. } => format!(
                    "The interpreter {} named on line 1 of the script does not exist; install whatever provides it",
                    interpreter.path
                ),
                _ => format!(
                    "Install the dynamic loader at {} (usually shipped with the C library; 32-bit programs need the multilib variant)",
                    interpreter.path
                ),
            };
            steps.push(message);
        }
        if let Some((found, wanted)) = interpreter.wrong_architecture {
            steps.push(format!(
                "The ELF interpreter {} is built for {found} but the program is {wanted}; the loader path is wrong (reinstall the program or the C library)",
                interpreter.path
            ));
        }
    }
    // Architecture advice is noise for something that is not a program.
    if analysis.not_a_program.is_none() {
        if let Some(arch) = &analysis.arch {
            if !arch.compatible {
                steps.push(format!(
                    "This program targets {} but the system is {}; install the matching runtime",
                    arch.name,
                    arch.host_name.unwrap_or("unknown")
                ));
            } else if !arch.exact {
                steps.push(
                    "This is a cross-architecture (for example 32-bit) program: it needs the compatibility loader and multilib libraries installed"
                        .to_string(),
                );
            }
        }
    }
    if !analysis.unresolved.is_empty() {
        steps.push(
            "Unresolved symbols usually mean the libraries on disk are older, newer, or partially upgraded — update or reinstall the packages that own them"
                .to_string(),
        );
    }
    if !analysis.version_problems.is_empty() {
        steps.push(
            "A required symbol version is missing, which is the signature of a partial system upgrade; finish the upgrade and try again"
                .to_string(),
        );
    }
    if analysis
        .env
        .iter()
        .any(|finding| finding.variable == "LD_LIBRARY_PATH")
    {
        steps.push(
            "Retry with `env -u LD_LIBRARY_PATH` to rule out a stale library override".to_string(),
        );
    }
    if steps.is_empty() && analysis.is_analyzable() {
        steps.push(
            "No problem was found in the ELF metadata; the failure is likely at runtime (arguments, configuration, permissions) or in an area `why` does not inspect yet — see TODO"
                .to_string(),
        );
    }
    steps
}

fn summary_line(analysis: &Analysis, options: &Options, painter: &Painter) -> String {
    if !analysis.is_analyzable() {
        return painter.dim("why v0.1 cannot diagnose this file");
    }
    let problems = analysis.problem_count();
    if problems == 0 {
        format!(
            "{} {}",
            mark(painter, Status::Ok, options.ascii),
            painter.green("no problems found")
        )
    } else {
        format!(
            "{} {}",
            mark(painter, Status::Fail, options.ascii),
            painter.red(&format!("{problems} problem{} found", plural(problems)))
        )
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut shortened: String = value.chars().take(max.saturating_sub(1)).collect();
    shortened.push('…');
    shortened
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;

    #[test]
    fn a_healthy_binary_reports_no_problems() {
        let path = std::env::current_exe().unwrap();
        let analysis = analyze(&path).unwrap();
        let options = Options {
            ascii: true,
            no_color: true,
            ..Options::default()
        };
        let text = to_string(&analysis, &options);
        assert!(text.contains("WHY DOES THIS PROGRAM NOT WORK?"));
        assert!(text.contains("no problems found"), "{text}");
        assert!(text.contains("Architecture"));
        assert!(text.contains("ELF interpreter"));
        assert!(text.contains("Shared libraries"));
    }

    #[test]
    fn non_elf_files_are_explained() {
        let dir = std::env::temp_dir().join(format!("why-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("notes.txt");
        std::fs::write(&file, b"just some text\n").unwrap();

        let analysis = analyze(&file).unwrap();
        let options = Options {
            ascii: true,
            no_color: true,
            ..Options::default()
        };
        let text = to_string(&analysis, &options);
        assert!(text.contains("Not an ELF program"), "{text}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn truncation_keeps_it_short() {
        assert_eq!(truncate("abcdef", 3), "ab…");
        assert_eq!(truncate("abc", 3), "abc");
    }
}
