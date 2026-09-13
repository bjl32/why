//! Command line parsing.
//!
//! Hand-rolled to keep the tool dependency-free. The surface is deliberately
//! small: one target, a couple of output switches.

use std::path::PathBuf;

/// Parsed command line.
#[derive(Debug, Default, Clone)]
pub struct Options {
    pub target: Option<PathBuf>,
    pub verbose: bool,
    pub no_color: bool,
    pub ascii: bool,
    pub show_help: bool,
    pub show_version: bool,
}

/// Parses arguments (without the program name).
pub fn parse<I, S>(args: I) -> Result<Options, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut options = Options::default();
    let mut positional_only = false;

    for arg in args {
        let arg = arg.into();
        if positional_only {
            set_target(&mut options, &arg)?;
            continue;
        }
        match arg.as_str() {
            "--" => positional_only = true,
            "-h" | "--help" => options.show_help = true,
            "-V" | "--version" => options.show_version = true,
            "-v" | "--verbose" => options.verbose = true,
            "--no-color" => options.no_color = true,
            "--ascii" => options.ascii = true,
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("unknown option '{other}'"));
            }
            other => set_target(&mut options, other)?,
        }
    }

    Ok(options)
}

fn set_target(options: &mut Options, value: &str) -> Result<(), String> {
    if options.target.is_some() {
        return Err(format!("unexpected extra argument '{value}'"));
    }
    options.target = Some(PathBuf::from(value));
    Ok(())
}

/// The `--help` text.
pub fn usage() -> String {
    format!(
        "\
why {version} — explains why a Linux program does not work

USAGE:
    why [OPTIONS] <PROGRAM>

OPTIONS:
    -v, --verbose    also list every library that was found
        --no-color   disable ANSI colours (also honours NO_COLOR)
        --ascii      use ASCII markers instead of ✓ ⚠ ✗
    -h, --help       print this help
    -V, --version    print the version

EXIT STATUS:
    0   no problem found in the ELF metadata
    1   a problem was found
    2   the file could not be diagnosed

EXAMPLES:
    why ./game
    why /usr/bin/BitComet
    why --verbose ./some-broken-program
",
        version = crate::VERSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_target_and_flags() {
        let options = parse(["--verbose", "/bin/ls"]).unwrap();
        assert!(options.verbose);
        assert_eq!(options.target, Some(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn double_dash_stops_flag_parsing() {
        let options = parse(["--", "--weird-name"]).unwrap();
        assert_eq!(options.target, Some(PathBuf::from("--weird-name")));
    }

    #[test]
    fn rejects_unknown_options() {
        assert!(parse(["--nope"]).is_err());
    }

    #[test]
    fn rejects_two_targets() {
        assert!(parse(["/bin/ls", "/bin/cat"]).is_err());
    }
}
