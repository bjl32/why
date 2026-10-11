# Contributing to why

Linux already has great diagnostic tools, but they mostly just dump data. `why` exists to bridge that gap and give you a straight answer to "why won't this run?".

Whether you're fixing a typo, adding a new check, or writing tests, your help is appreciated.

## The main rule: Explain, don't dump

Every change should end with a clear, human-readable answer, not a wall of raw tool output. If a feature spits out 800 lines and forces the user to figure it out themselves, it belongs in a different project.

What this means in practice:

- Always give a **suggested next step** the user can actually do.
- Say **"I don't know"** when you don't know. The tool uses explicit phrases like `not applicable`, `likely`, or `does not inspect yet` rather than hallucinating a cause.
- `✗` means *this is why it failed*. `⚠` means *this looks suspicious*. Don't blur the line between them.

## How you can help

- **Bug reports:** `why` gave the wrong answer, missed something obvious, panicked, or printed confusing garbage.
- **New checks:** Grab something from the [`TODO`](TODO) list.
- **Tests:** We always need more weird-but-real ELF files, edge cases, and cross-validation against reference tools.
- **Docs:** Better README wording, clearer examples, or more actionable "next steps".

Note that the roadmap is a sequence, not a menu. `why` intentionally keeps releases small. If you want to tackle something slated for a later version, open an issue first so we can make sure it's time to work on it.

## Getting help

For quick questions, half-baked ideas, or figuring out what to work on, jump into the [Discord](https://discord.gg/DWwzh2cQzf).

But if you have something reproducible—a wrong answer, a panic, a missing check—please open a GitHub issue. That way it's searchable and won't get buried in chat logs.

## Dev setup

You'll need Rust 1.70+ (check `rust-version` in `Cargo.toml`) and a Linux machine.

```console
$ git clone <your-fork>
$ cd why
$ cargo build
$ cargo test
$ cargo run -- ./some-program
```

We include our own ELF reader on purpose. It keeps the tool auditable, lets it build offline, and stops it from breaking if the user's system is missing `ldd` or `readelf`.

## Before you submit a PR

Make sure these three pass without warnings:

```console
$ cargo fmt
$ cargo clippy --all-targets
$ cargo test
```

If you're adding a new check, sanity-check it against the tool it's replacing:

```console
$ ldd -r ./your-test-program
$ cargo run -- --no-color ./your-test-program
```

For context, the symbol and missing-library checks here were validated against `ldd -r` across 4,745 binaries in `/usr/bin` with zero discrepancies. Please maintain that bar. A false positive is worse than a missing feature because it sends users down the wrong path.

## Codebase layout

```text
src/
  elf/          dependency-free ELF reader
    reader.rs     bounds-checked, endian-aware byte decoding
    mod.rs        headers, program/section headers, .dynamic, .dynsym,
                  .gnu.version_r/.gnu.version_d, DT_HASH/DT_GNU_HASH counts
  resolve.rs    dynamic-loader search-path semantics, ld.so.cache, ld.so.conf
  analyze.rs    the dependency walk and the checks
  report.rs     the human-readable report
  distro.rs     package-manager hints for "which package provides this?"
  cli.rs        argument parsing
```

The analysis does a breadth-first walk of `DT_NEEDED`, parses each object exactly once, and then answers symbol and version questions from that single graph. The parser never panics: every read is bounds-checked. A diagnostic tool needs to be able to look at a corrupt binary and just say "this is corrupt", not crash.

Nothing outside `src/elf/` should care about the raw layout of an ELF file. `analyze.rs` deals with parsed facts, and `report.rs` just formats the `Analysis` struct.

## Design rules

1. **Explain, don't dump.** (See above).
2. **Parse, don't guess.** Read the actual metadata. Don't try to infer it by scraping another tool's output if the bytes are right there.
3. **Never panic on untrusted input.** Every read in the ELF parser is bounds-checked and returns a `Result`. A panic on a bad binary is a bug.
4. **No dependencies without a reason.** Only pull in a new crate if it solves a real problem that would otherwise take a massive amount of code or maintenance.
5. **Linux and ELF first.** Other platforms and formats are out of scope for v0.2. If you want to add them, open a discussion first.
6. **Deterministic output.** Sort the findings so the reports are stable and easy to diff.
7. **Terminals are optional.** Respect `--no-color`, `NO_COLOR`, and `--ascii`. Never hardcode ANSI escapes.

## Adding a new check

Here is the general workflow, using a "missing interpreter" check as an example:

1. **Get the fact.** If it requires new ELF parsing, add it to `src/elf/mod.rs` behind a checked read and expose it on `ElfFile`. Otherwise, compute it in `src/analyze.rs` from existing parsed data.
2. **Model the finding.** Add a field to the `Analysis` struct in `src/analyze.rs` (or reuse one) and give it a `Status`.
3. **Make it count.** Include it in `Analysis::problem_count()` and `Analysis::exit_code()` so the tool's exit status is accurate.
4. **Render it.** Add a section in `src/report.rs` using the existing `section` and `row` helpers. Match the tone of the surrounding checks.
5. **Suggest a fix.** If there's an actionable next step, add it to `suggestions()` in `src/report.rs`.
6. **Test it.** Write a unit test for the fact itself. If it changes the final verdict, add an end-to-end test in `tests/cli.rs`.
7. **Document it.** Add a row to the "What v0.2 checks" table in the README, and cross it off the roadmap in `TODO`.

## Testing

Unit tests live next to the code they test. End-to-end tests live in `tests/cli.rs` and run the actual compiled binary.

We test the missing-library path without needing a compiler or committed binary fixtures. The test just copies the running test binary and patches one `DT_NEEDED` string in-place to a same-length name that can't possibly exist. The offsets stay valid, so you end up with a perfectly normal ELF file that references a library nobody has. We use this same trick for symbol and version names—it's the preferred way to test failure paths.

When writing tests, prefer these in order:

1. A synthetic case built directly in the test.
2. A patched copy of a real ELF file.
3. A committed binary fixture (only if the first two won't work).

## Filing a bug

Please include:

- `why --version`
- The exact command you ran and its output (piping through `--no-color` makes it easiest to paste).
- Your distro and architecture (`uname -a` or the contents of `/etc/os-release`).
- What you expected to happen vs. what actually happened.
- If `why` panicked or printed absolute nonsense, just say so—that's a bug in `why` itself.

*(Note: A packaged diagnostic bundle via `why --report` is on the roadmap but isn't implemented yet, so there's nothing extra to attach right now).*

## Commits and PRs

- Keep commits focused. One logical change per PR.
- Use imperative commit messages (`report missing DT_NEEDED`, not `Fixed stuff`), and link the issue if there is one.
- In the PR description, explain **what changed**, **why**, and **how you verified it** (paste the commands you ran).
- Add tests for any behavior changes. If you change a verdict without adding a test, we will ask you to add one.
- Don't commit `target/` or other build artifacts.