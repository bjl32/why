//! Best-effort, batched Arch package ownership lookups.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    Installed,
    Search,
}

pub fn collect(analysis: &Analysis) -> PackageReport {
    if analysis.distro.family != Family::Arch {
        return PackageReport::unsupported(&analysis.distro);
    }
    let Some(executable) = which_pacman() else {
        return PackageReport {
            status: PackageStatus::Unavailable("pacman was not found on PATH".into()),
            findings: Vec::new(),
        };
    };
    collect_with(analysis, &executable)
}

fn collect_with(analysis: &Analysis, executable: &Path) -> PackageReport {
    let mut targets = vec![(
        "target".into(),
        analysis.path.display().to_string(),
        QueryKind::Installed,
    )];
    if let Some(interpreter) = &analysis.interpreter {
        if !interpreter.path.is_empty() {
            targets.push((
                "interpreter".into(),
                interpreter.path.clone(),
                if interpreter.exists {
                    QueryKind::Installed
                } else {
                    QueryKind::Search
                },
            ));
        }
    }
    for library in &analysis.libraries {
        let (query, kind) = match &library.resolution {
            LibResolution::Found(path)
            | LibResolution::WrongArchitecture { path, .. }
            | LibResolution::Unusable { path, .. } => {
                (path.display().to_string(), QueryKind::Installed)
            }
            LibResolution::Missing => (library.name.clone(), QueryKind::Search),
        };
        targets.push((format!("library {}", library.name), query, kind));
    }

    let mut results = [HashMap::new(), HashMap::new()];
    let mut warning = None;
    for (index, kind) in [QueryKind::Installed, QueryKind::Search]
        .into_iter()
        .enumerate()
    {
        let mut seen = HashSet::new();
        let queries: Vec<String> = targets
            .iter()
            .filter(|(_, _, query_kind)| *query_kind == kind)
            .map(|(_, query, _)| query.clone())
            .filter(|query| seen.insert(query.clone()))
            .collect();
        // Bound argv size for very large dependency graphs. Typical reports
        // need just one installed query and one file search, not one per file.
        let mut start = 0;
        while start < queries.len() {
            let mut end = start;
            let mut bytes = 0;
            while end < queries.len()
                && (end == start || bytes + queries[end].len() + 1 < 64 * 1024)
            {
                bytes += queries[end].len() + 1;
                end += 1;
            }
            let batch = &queries[start..end];
            let mut command = Command::new(executable);
            command.env("LC_ALL", "C").arg(match kind {
                QueryKind::Installed => "-Qo",
                QueryKind::Search => "-F",
            });
            if kind == QueryKind::Search {
                command.arg("--machinereadable");
            }
            command.args(["--color", "never", "--"]).args(batch);
            match command.output() {
                Ok(output) => {
                    results[index].extend(parse_batch(batch, kind, &output, &mut warning))
                }
                Err(error) => {
                    let reason = format!("could not run pacman: {error}");
                    warning = Some(reason.clone());
                    for query in batch {
                        results[index]
                            .insert(query.clone(), Ownership::Unavailable(reason.clone()));
                    }
                }
            }
            start = end;
        }
    }
    let findings = targets
        .into_iter()
        .map(|(subject, query, kind)| {
            let index = usize::from(kind == QueryKind::Search);
            let ownership = results[index][&query].clone();
            PackageFinding {
                subject,
                query,
                ownership,
            }
        })
        .collect();
    PackageReport {
        status: warning.map_or(PackageStatus::Available, PackageStatus::Unavailable),
        findings,
    }
}

fn which_pacman() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        use std::os::unix::fs::PermissionsExt;
        let candidate = dir.join("pacman");
        let metadata = fs::metadata(&candidate).ok()?;
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            // PATH can contain relative directories; retain an absolute path
            // and invoke precisely the executable we discovered.
            fs::canonicalize(candidate).ok()
        } else {
            None
        }
    })
}

fn parse_batch(
    queries: &[String],
    kind: QueryKind,
    output: &Output,
    warning: &mut Option<String>,
) -> HashMap<String, Ownership> {
    let mut owners: HashMap<String, Vec<String>> = HashMap::new();
    let mut known_unowned = HashSet::new();
    let mut aliases: HashMap<String, Vec<&String>> = HashMap::new();
    for query in queries {
        let keys = match kind {
            QueryKind::Installed => path_aliases(query),
            QueryKind::Search => vec![query.trim_start_matches('/').to_string()],
        };
        for key in keys {
            aliases.entry(key).or_default().push(query);
        }
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        match kind {
            QueryKind::Installed => {
                if let Some((path, owner)) = line.rsplit_once(" is owned by ") {
                    if let Some(targets) = aliases.get(path) {
                        for query in targets {
                            add_owner(&mut owners, query, owner.trim());
                        }
                    }
                }
            }
            QueryKind::Search => {
                // pacman -F --machinereadable: repo\0name\0version\0path\n.
                let fields: Vec<_> = line.split('\0').collect();
                if let [repo, package, _, path] = fields.as_slice() {
                    let owner = format!("{repo}/{package}");
                    // Full-path queries and basename queries may both match;
                    // index them once instead of scanning every query per hit.
                    for key in [*path, path.rsplit('/').next().unwrap_or(path)] {
                        if let Some(targets) = aliases.get(key) {
                            for query in targets {
                                add_owner(&mut owners, query, &owner);
                            }
                        }
                    }
                }
            }
        }
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut failure = None;
    for line in stderr.lines().filter(|line| !line.trim().is_empty()) {
        if let Some(query) = line.strip_prefix("error: No package owns ") {
            if queries.iter().any(|target| target == query) {
                known_unowned.insert(query.to_string());
                continue;
            }
        }
        failure.get_or_insert_with(|| line.to_string());
    }
    // With a synced files DB, -F returns 1 with no stderr for a miss.
    // A batch may also return 1 while yielding hits for its other targets.
    if !output.status.success() && output.status.code() != Some(1) {
        failure.get_or_insert_with(|| format!("pacman query failed ({})", output.status));
    }
    if let Some(reason) = &failure {
        *warning = Some(reason.clone());
    }
    queries
        .iter()
        .map(|query| {
            let ownership = match owners.remove(query) {
                Some(packages) => match kind {
                    QueryKind::Installed => Ownership::Installed(packages),
                    QueryKind::Search => Ownership::SearchResults(packages),
                },
                None if known_unowned.contains(query) => Ownership::Unowned,
                None => match &failure {
                    Some(reason) => Ownership::Unavailable(reason.clone()),
                    None if kind == QueryKind::Search => Ownership::Unowned,
                    None => {
                        let reason =
                            "pacman returned no ownership result for this path".to_string();
                        *warning = Some(reason.clone());
                        Ownership::Unavailable(reason)
                    }
                },
            };
            (query.clone(), ownership)
        })
        .collect()
}

fn add_owner(owners: &mut HashMap<String, Vec<String>>, query: &str, owner: &str) {
    if !owner.is_empty() {
        let packages = owners.entry(query.to_string()).or_default();
        if !packages.iter().any(|package| package == owner) {
            packages.push(owner.to_string());
        }
    }
}

fn path_aliases(query: &str) -> Vec<String> {
    let path = Path::new(query);
    let mut aliases = vec![query.to_string()];
    // pacman resolves directory aliases, preserving the final symlink:
    // its owner may differ from the owner of the symlink's target.
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Ok(canonical) = fs::canonicalize(parent) {
            aliases.push(canonical.join(name).display().to_string());
        }
    }
    aliases.sort();
    aliases.dedup();
    aliases
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{analyze, InterpreterFinding, LibraryFinding};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::process::ExitStatusExt;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("why-packages-{}-{name}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn output(code: i32, stdout: &str, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn parse(
        kind: QueryKind,
        queries: &[&str],
        code: i32,
        stdout: &str,
        stderr: &str,
    ) -> (HashMap<String, Ownership>, Option<String>) {
        let queries: Vec<_> = queries.iter().map(|query| query.to_string()).collect();
        let mut warning = None;
        let results = parse_batch(&queries, kind, &output(code, stdout, stderr), &mut warning);
        (results, warning)
    }

    #[test]
    fn search_silent_miss_is_not_a_query_failure() {
        let (results, warning) = parse(QueryKind::Search, &["libmissing.so"], 1, "", "");
        assert_eq!(results["libmissing.so"], Ownership::Unowned);
        assert_eq!(warning, None);
    }

    #[test]
    fn search_matches_multiple_queries_and_deduplicates_providers() {
        let (results, warning) = parse(QueryKind::Search,
            &["libc.so.6", "/usr/lib/libc.so.6", "ld-linux.so.2", "missing"], 1,
            "core\0glibc\x002.44-1\0usr/lib/libc.so.6\ncore\0glibc\x002.44-1\0usr/lib/libc.so.6\nmultilib\0lib32-glibc\x002.44-1\0usr/lib32/libc.so.6\ncore\0glibc\x002.44-1\0usr/lib/ld-linux.so.2\n", "");
        assert_eq!(
            results["libc.so.6"],
            Ownership::SearchResults(vec!["core/glibc".into(), "multilib/lib32-glibc".into()])
        );
        assert_eq!(
            results["/usr/lib/libc.so.6"],
            Ownership::SearchResults(vec!["core/glibc".into()])
        );
        assert_eq!(
            results["ld-linux.so.2"],
            Ownership::SearchResults(vec!["core/glibc".into()])
        );
        assert_eq!(results["missing"], Ownership::Unowned);
        assert_eq!(warning, None);
    }

    #[test]
    fn database_errors_preserve_successful_hits_but_not_false_misses() {
        for code in [0, 1] {
            let (results, warning) = parse(
                QueryKind::Search,
                &["libc.so.6", "libmissing.so"],
                code,
                "core\0glibc\x002.44-1\0usr/lib/libc.so.6\n",
                "warning: database file for 'extra' does not exist\n",
            );
            assert!(matches!(results["libc.so.6"], Ownership::SearchResults(_)));
            assert!(matches!(
                results["libmissing.so"],
                Ownership::Unavailable(_)
            ));
            assert!(warning.is_some());
        }
    }

    #[test]
    fn abnormal_status_without_stderr_is_a_query_failure() {
        let (results, warning) = parse(QueryKind::Search, &["missing"], 2, "", "");
        assert!(matches!(results["missing"], Ownership::Unavailable(_)));
        assert!(warning.is_some());
    }

    #[test]
    fn installed_batch_maps_directory_aliases_without_conflating_symlink_owners() {
        let temp = TempDir::new("aliases");
        fs::create_dir(temp.0.join("real")).unwrap();
        fs::write(temp.0.join("real/target"), "").unwrap();
        symlink("target", temp.0.join("real/link")).unwrap();
        symlink("real", temp.0.join("alias")).unwrap();
        let link = temp.0.join("alias/link").display().to_string();
        let target = temp.0.join("real/target").display().to_string();
        let unowned = temp.0.join("unowned").display().to_string();
        let stdout = format!(
            "{} is owned by links 1-1\n{} is owned by targets 2-1\n",
            temp.0.join("real/link").display(),
            target
        );
        let stderr = format!("error: No package owns {unowned}\n");
        let (results, warning) = parse(
            QueryKind::Installed,
            &[&link, &target, &unowned],
            1,
            &stdout,
            &stderr,
        );
        assert_eq!(
            results[&link],
            Ownership::Installed(vec!["links 1-1".into()])
        );
        assert_eq!(
            results[&target],
            Ownership::Installed(vec!["targets 2-1".into()])
        );
        assert_eq!(results[&unowned], Ownership::Unowned);
        assert_eq!(warning, None);
    }

    #[test]
    fn hundreds_of_libraries_use_two_pinned_executable_calls() {
        let temp = TempDir::new("batch");
        let executable = temp.0.join("not-named-pacman");
        fs::write(
            &executable,
            r#"#!/bin/sh
[ "$LC_ALL" = C ] || exit 2
operation=$1
while [ "$1" != -- ]; do shift; done
shift
printf '%s %s\n' "$operation" "$#" >> "$0.calls"
case "$operation" in
  -Qo) for target do printf '%s is owned by fixture 1-1\n' "$target"; done ;;
  -F) for target do printf 'core\000provider\0001-1\000usr/lib/%s\n' "$target"; done ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let mut analysis = analyze(&std::env::current_exe().unwrap()).unwrap();
        let before = analysis.exit_code();
        analysis.interpreter = None;
        analysis.libraries = (0..812)
            .map(|index| LibraryFinding {
                name: format!("lib{index}.so"),
                needed_by: vec![],
                resolution: LibResolution::Found(PathBuf::from(format!("/fake/lib{index}.so"))),
            })
            .collect();
        // A duplicate query must reuse the result, not duplicate argv.
        analysis.libraries.push(analysis.libraries[0].clone());
        analysis.libraries.push(LibraryFinding {
            name: "libmissing.so".into(),
            needed_by: vec![],
            resolution: LibResolution::Missing,
        });
        analysis.packages = Some(collect_with(&analysis, &executable));
        let report = analysis.packages.as_ref().unwrap();
        assert_eq!(report.status, PackageStatus::Available);
        assert!(report
            .findings
            .iter()
            .take(814)
            .all(|finding| finding.ownership == Ownership::Installed(vec!["fixture 1-1".into()])));
        assert_eq!(
            report.findings.last().unwrap().ownership,
            Ownership::SearchResults(vec!["core/provider".into()])
        );
        assert_eq!(
            fs::read_to_string(executable.with_file_name("not-named-pacman.calls")).unwrap(),
            "-Qo 813\n-F 1\n"
        );
        assert_eq!(before, 0);
        assert_eq!(analysis.exit_code(), 1); // only the deliberately missing library
        analysis.interpreter = Some(InterpreterFinding {
            path: "/missing/loader".into(),
            exists: false,
            executable: false,
            problem: None,
        });
        let code = analysis.exit_code();
        analysis.packages = Some(collect_with(&analysis, &temp.0.join("missing-executable")));
        assert!(matches!(
            analysis.packages.as_ref().unwrap().status,
            PackageStatus::Unavailable(_)
        ));
        assert_eq!(analysis.exit_code(), code);
    }

    #[test]
    fn real_pacman_with_isolated_synced_files_database() {
        let Some(pacman) = which_pacman() else {
            return; // Optional cross-check on systems without pacman.
        };
        let temp = TempDir::new("synced-db");
        let package = temp.0.join("glibc-2.44-1");
        let db = temp.0.join("db");
        fs::create_dir(&package).unwrap();
        fs::create_dir_all(db.join("sync")).unwrap();
        fs::write(
            package.join("desc"),
            "%NAME%\nglibc\n\n%VERSION%\n2.44-1\n\n",
        )
        .unwrap();
        fs::write(
            package.join("files"),
            "%FILES%\nusr/lib/libc.so.6\nusr/lib/ld-linux.so.2\n\n",
        )
        .unwrap();
        let config = temp.0.join("pacman.conf");
        fs::write(&config, "[options]\nArchitecture = auto\nSigLevel = Never\n[core]\nServer = https://unused.invalid/$repo/os/$arch\n").unwrap();
        let archive = Command::new("tar")
            .arg("-czf")
            .arg(db.join("sync/core.files"))
            .arg("-C")
            .arg(&temp.0)
            .arg("glibc-2.44-1")
            .output();
        let archive = match archive {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("could not build test files database: {error}"),
        };
        assert!(archive.status.success(), "{archive:?}");
        for (names, expected_code) in [
            (vec!["libc.so.6", "ld-linux.so.2", "/usr/lib/libc.so.6"], 0),
            (vec!["libmissing.so"], 1),
            (vec!["libc.so.6", "libmissing.so"], 1),
        ] {
            let output = Command::new(&pacman)
                .env("LC_ALL", "C")
                .args(["-F", "--machinereadable", "--color", "never", "--config"])
                .arg(&config)
                .arg("--dbpath")
                .arg(&db)
                .arg("--")
                .args(&names)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(expected_code), "{output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let queries: Vec<_> = names.iter().map(|name| name.to_string()).collect();
            let mut warning = None;
            let results = parse_batch(&queries, QueryKind::Search, &output, &mut warning);
            assert_eq!(warning, None);
            for name in names {
                let expected = if name == "libmissing.so" {
                    Ownership::Unowned
                } else {
                    Ownership::SearchResults(vec!["core/glibc".into()])
                };
                assert_eq!(results[name], expected, "{output:?}");
            }
        }
    }
}
