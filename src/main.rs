//! `why` — a Linux program troubleshooter.

use std::process::ExitCode;

use why::{analyze, cli, package, report};

fn main() -> ExitCode {
    let options = match cli::parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("why: {error}");
            eprintln!("Try `why --help` for usage.");
            return ExitCode::from(2);
        }
    };

    if options.show_help {
        print!("{}", cli::usage());
        return ExitCode::SUCCESS;
    }
    if options.show_version {
        println!("why {}", why::VERSION);
        return ExitCode::SUCCESS;
    }

    let Some(target) = options.target.clone() else {
        eprintln!("why: no program given");
        eprintln!("Try `why --help` for usage.");
        return ExitCode::from(2);
    };

    match analyze::analyze(&target) {
        Ok(mut analysis) => {
            match package::refresh_if_requested(&analysis) {
                Ok(true) => match analyze::analyze(&target) {
                    Ok(refreshed) => analysis = refreshed,
                    Err(error) => {
                        eprintln!("why: could not re-run analysis after pacman refresh: {error}")
                    }
                },
                Ok(false) => {}
                Err(error) => eprintln!("why: {error}"),
            }
            report::print(&analysis, &options);
            ExitCode::from(analysis.exit_code())
        }
        Err(error) => {
            eprintln!("why: cannot read {}: {error}", target.display());
            ExitCode::from(2)
        }
    }
}
