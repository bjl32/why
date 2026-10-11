# why

A Linux troubleshooting tool that collects system, application, hardware, and runtime diagnostics to explain why a program isn't working.

Linux already has plenty of excellent diagnostic tools (`ldd`, `readelf`, `strace`, `coredumpctl`, `journalctl`, `vulkaninfo`, `wayland-debug`). The problem is that they mostly just dump data. 

`why` bridges that gap. It runs the necessary checks and translates the results into a clear, plain-language explanation, rather than dumping hundreds of lines of raw output for the user to decipher.

## Status

This is **v0.2**, which currently covers ELF/shared-library diagnosis and Arch Linux package ownership lookups. 

*(We welcome PRs and issues. Feel free to join our [Discord](https://discord.gg/DWwzh2cQzf) to chat or ask questions.)*

## Example

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

## Installation

The package is available on the Arch AUR.

```console
$ yay -S why
```
*(Note: Other distributions are not yet supported.)*

## Building from source

```console
$ cargo build --release
$ ./target/release/why ./some-broken-program
```

Or install it locally:

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
| `0` | No problems found in the ELF metadata. |
| `1` | A problem was found. |
| `2` | The file could not be diagnosed (e.g., missing, not an ELF file, or unreadable). |

This exit code design makes it easy to use in shell scripts:

```console
$ why ./game || echo "game is broken"
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development setup, design principles, and instructions on how to add a new check.

## License

MIT — see [`LICENSE`](LICENSE).