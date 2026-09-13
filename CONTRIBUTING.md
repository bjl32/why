# Contributing to why

Thanks for wanting to help. `why` exists because Linux has excellent diagnostic
tools but is missing a layer: something that turns all of their output into a
straight answer to *"why does this not work?"*.

Contributions of every size are welcome — bug reports, new checks, better
wording, tests, documentation.

## The one rule that matters

**Explain, don't dump.**

Any change should end in a short, human-readable statement, not in raw tool
output. If a feature would print 800 lines and leave the reader to work it out,
it belongs in a different project.

Corollaries:

- Every problem should come with a **suggested next step** a user can act on.
- Say **"I don't know"** when that is the truth. The report uses explicit
  wording such as `not applicable`, `likely` and `does not inspect yet` instead
  of inventing a cause.
- `✗` means *this is why it will not start*. `⚠` means *suspicious*. Keep that
  distinction meaningful.

## Ways to contribute

| | |
| --- | --- |
| **Bug reports** | `why` reached the wrong conclusion, missed something, panicked, or printed something confusing. |
| **New checks** | Pick an item from the roadmap in [`TODO`](TODO). |
| **Tests** | More weird-but-real ELF files, edge cases, cross-validation against reference tools. |
| **Docs** | README wording, examples, clearer suggested next steps. |

The roadmap is a *sequence*, not a menu — `why` deliberately keeps each version
small. If you want to work on something from a later version, open an issue
first so we can agree it is time.

## Questions and help

For quick questions, half-formed ideas, or help finding something to work on,
join the [Discord](https://discord.gg/DWwzh2cQzf). For anything reproducible —
a wrong answer, a panic, a missing check — please open a GitHub issue so it is
searchable and does not get lost in chat.

## Development setup

Rust 1.70 or newer (see `rust-version` in `Cargo.toml`), on Linux.

```console
$ git clone <your-fork>
$ cd why
$ cargo build
$ cargo test
$ cargo run -- ./some-program
```

v0.1 has **no external dependencies**. The ELF reader is deliberately part of
the project so the tool stays auditable, builds offline, and does not break when
`ldd`/`readelf` are missing — which, for a diagnostic tool, is exactly when they
matter most.

## Before you open a pull request

All three of these must be clean:

```console
$ cargo fmt
$ cargo clippy --all-targets
$ cargo test
```

If you added a check, also sanity-check it against the tool it replaces:

```console
$ ldd -r ./your-test-program
$ cargo run -- --no-color ./your-test-program
```

The symbol and missing-library checks in this repository were validated against
`ldd -r` over 4,745 binaries in `/usr/bin` with no discrepancies. Please keep
that standard: a false positive is worse than a missing feature, because it
sends someone down the wrong path.

## How it works

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

The analysis walks `DT_NEEDED` breadth-first, parses every object exactly once,
and then answers the symbol and version questions from that one graph. Parsing
never panics: every read is bounds-checked, because a diagnostic tool should be
able to look at a corrupt binary and say so.

Nothing outside `src/elf/` should need to know the layout of an ELF file.
`analyze.rs` works with the parsed facts, and `report.rs` only formats an
`Analysis`.

## Design principles

1. **Explain, don't dump.** See above.
2. **Parse, don't guess.** Read the metadata; do not infer it from a tool's
   output where the bytes are available.
3. **Never panic on untrusted input.** Every read in the ELF reader is
   bounds-checked and returns an error. A panic is a bug.
4. **No dependencies without a reason.** A new crate should solve a meaningful problem that would otherwise require substantially more code or maintenance.
5. **Linux and ELF first.** Other platforms and formats are out of scope for
   v0.1; guard such work behind a discussion.
6. **Deterministic output.** Sort findings so reports are stable and diffable.
7. **Terminals are optional.** Respect `--no-color`, `NO_COLOR` and `--ascii`;
   never hard-code ANSI escapes.

## Adding a check

Roughly the shape of a new check, using "missing interpreter" as an example:

1. **Get the fact.** If it needs new ELF parsing, add it to `src/elf/mod.rs`
   behind a checked read, and expose it on `ElfFile`. Otherwise compute it in
   `src/analyze.rs` from what is already parsed.
2. **Model the finding.** Add a field to `Analysis` in `src/analyze.rs` (or
   reuse an existing one) and give it a `Status`.
3. **Make it count.** Include it in `Analysis::problem_count()` and
   `Analysis::exit_code()` so the exit status is right.
4. **Render it.** Add a section in `src/report.rs` using the existing `section`
   and `row` helpers, and follow the wording of the neighbouring checks.
5. **Suggest a fix.** If there is an actionable next step, add it to
   `suggestions()` in `src/report.rs`.
6. **Test it.** Unit-test the fact itself. If it changes the verdict, add an
   end-to-end test in `tests/cli.rs`.
7. **Document it.** Add a row to the "What v0.1 checks" table in the README, and
   update the roadmap in `TODO` if the item is finished.

## Testing

Unit tests live next to the code they test; end-to-end tests live in
`tests/cli.rs` and run the real binary.

The missing-library path is tested without a compiler or a committed fixture:
the test copies the running test binary and patches one `DT_NEEDED` string in
place to a same-length name that cannot exist. Offsets stay valid, so the result
is a perfectly normal ELF that references a library nobody has. The same trick
works for symbol names and version names, and it is the preferred way to test a
failure path.

Prefer, in order:

1. A synthetic case built in the test.
2. A patched copy of a real ELF file.
3. A committed binary fixture — only if neither of the above works.

## Reporting a bug

Please include:

- `why --version`
- the exact command and the output (`why --no-color <program>` is easiest to
  paste)
- your distribution and architecture (`uname -a`, or the contents of
  `/etc/os-release`)
- what you expected and what happened instead
- if `why` itself panicked or printed nonsense, that is a bug in `why` — say so

A packaged diagnostic bundle (`why --report`) is on the roadmap but is **not**
implemented yet, so there is nothing to attach beyond the above.

## Commits and pull requests

- Keep commits focused; one logical change per pull request.
- Write imperative subjects (`report missing DT_NEEDED`, not `Fixed stuff`), and
  reference the issue where there is one.
- In the description, cover **what changed**, **why**, and **how you verified
  it** (the commands you ran).
- Add tests for behaviour changes. A change to a verdict without a test will be
  asked for one.
- Do not commit `target/` or other build output.