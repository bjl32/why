# why

A Linux troubleshooting tool that collects system, application, hardware, and
runtime diagnostics to identify and explain why something isn't working.

Linux already has an absurd collection of excellent diagnostic tools: `ldd`,
`readelf`, `strace`, `coredumpctl`, `journalctl`, `vulkaninfo`, `wayland-debug`.
The missing layer is usually:

> **"Okay, but what does all of this mean?"**

`why` is that layer. It runs the checks and then explains the result in plain
language instead of dumping 800 lines of diagnostic output.

## Status

This is **v0.1**, which covers the first stop on the evolution path in
[`TODO`](TODO): **ELF and shared libraries**.

ps. **PRs / Issues are welcome, join our [discord](https://discord.gg/DWwzh2cQzf)!**

```console
$ why ./some-broken-program
```

```text
WHY DOES THIS PROGRAM NOT WORK?

  ./some-broken-program
  position-independent executable (PIE) · 64-bit x86-64

✓ Architecture
  x86-64, 64-bit            matches this system (x86-64, 64-bit)

✓ ELF interpreter
  /lib64/ld-linux-x86-64.so.2                    present

✓ Shared libraries
  3 resolved, 0 unusable

✓ Symbol dependencies
  every imported symbol is provided

✗ Library versions
  libc.so.6                             needs GLIBC_2.99
      required by ./some-broken-program; /usr/lib/libc.so.6 provides GLIBC_2.44

Suggested next steps
  1. A required symbol version is missing, which is the signature of a partial system upgrade; finish the upgrade and try again

✗ 1 problem found
```

When everything checks out, the report says so and stops:

```text
✓ Architecture
  x86-64, 64-bit            matches this system (x86-64, 64-bit)

✓ ELF interpreter
  /lib64/ld-linux-x86-64.so.2                    present

✓ Shared libraries
  3 resolved, 0 unusable

✓ Symbol dependencies
  every imported symbol is provided

✓ no problems found
```

## What v0.1 checks

| Check | What it means |
| --- | --- |
| **File type** | A relocatable object (`.o`) or a core dump is not a program, so it is reported as *not runnable* rather than ending with "no problems found". |
| **Executable permission** | An ELF program without any execute bit fails at launch with exit 126, so a missing `+x` is reported as a problem rather than a footnote. Plain shared libraries are exempt. |
| **Architecture** | Compares `e_machine`/ELF class with the host. An exact mismatch is a failure, but a *compatible* one — 32-bit i386 on x86-64, for example — is a warning with a multilib hint rather than a false alarm. Where a machine value is shared across word sizes (MIPS, RISC-V), the class decides, so a 64-bit target on a 32-bit host is still a failure. |
| **ELF interpreter** | Resolves `PT_INTERP` (`/lib64/ld-linux-x86-64.so.2`) and checks that it exists, is executable, and is built for the same class and machine as the program — the kernel rejects a mismatched loader before any library is loaded. For shebang scripts, `#!/usr/bin/env foo` is resolved through `PATH`, including `env`'s own options (`-u`, `-C`, `--unset`, ...). |
| **Shared libraries** | Walks the transitive `DT_NEEDED` graph and resolves every library the way `ld.so` would: `DT_RPATH`, `LD_LIBRARY_PATH`, `DT_RUNPATH`, the `ld.so` cache, then the default directories. A candidate only counts if its ELF class and machine match the object that needs it, so a 32-bit program is never handed the 64-bit `libc.so.6`; a name that resolves only to the wrong architecture is `WRONG ARCH`, and a same-named file that is not a loadable ELF object (or will not parse) is `UNUSABLE`. |
| **Symbol dependencies** | Collects the global symbol scope of the whole dependency graph and reports imported (`STB_GLOBAL`, `SHN_UNDEF`) symbols that nobody defines. Imports are matched by name **and** symbol version where both are known, so `foo@OTHER` cannot satisfy an import of `foo@VER`. |
| **Library versions** | Checks every `.gnu.version_r` requirement against the `.gnu.version_d` definitions of the library that must provide it, so it can say *"needs `GLIBC_2.99`, provides `GLIBC_2.44`"*. |
| **Environment** | Flags `LD_LIBRARY_PATH`, `LD_PRELOAD` and `LD_DEBUG`, because they silently change which libraries get loaded. |

The ELF parsing is done in-process, so the answer does not depend on `ldd`,
`readelf` or `objdump` being installed or working.

## Not yet

Everything else on the roadmap is still in [`TODO`](TODO): package ownership
(v0.2), process/environment inspection (v0.3), Wayland/X11/Vulkan (v0.4),
Flatpak, Wine/Proton, kernel/journal/coredumps, automatic diagnosis and HTML
reports. When a target is clean but still fails, the report says the failure is
probably outside the ELF metadata rather than pretending to know more.

## Build

Rust 1.70+ and no dependencies:

```console
$ cargo build --release
$ ./target/release/why ./some-broken-program
```

or install it:

```console
$ cargo install --path .
```

## Usage

```text
why [OPTIONS] <PROGRAM>

OPTIONS:
    -v, --verbose    also list every library that was found
        --no-color   disable ANSI colours (also honours NO_COLOR)
        --ascii      use ASCII markers instead of ✓ ⚠ ✗
    -h, --help       print help
    -V, --version    print the version
```

### Exit status

| Code | Meaning |
| --- | --- |
| `0` | No problem found in the ELF metadata |
| `1` | A problem was found |
| `2` | The file could not be diagnosed (missing, not ELF, unreadable) |

That makes it usable in scripts:

```console
$ why ./game || echo "game is broken"
```

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

## Tests

```console
$ cargo test
$ cargo clippy --all-targets
```

The suite covers the parser (including truncated and non-ELF inputs), the
resolver, the report, and the CLI end to end. The missing-library path is tested
by patching a `DT_NEEDED` string in a copy of the test binary in place, so no
fixture or compiler is needed at test time.

The symbol and library checks were also cross-validated against `ldd -r` over
4,745 binaries in `/usr/bin` with no discrepancies.

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the
development setup, the project's design principles, and how to add a check.

## License

MIT — see [`LICENSE`](LICENSE).
