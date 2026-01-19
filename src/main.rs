//! atl-cli: Command-line tool for verifying ATL Protocol receipts
//!
//! # Usage
//!
//! ```bash
//! # Verify a single file against its receipt
//! atl-cli verify document.pdf document.pdf.atl
//!
//! # Verify with forced offline mode
//! atl-cli verify document.pdf document.pdf.atl --offline
//!
//! # Verify a batch of files
//! atl-cli verify ./files/ ./receipts/
//!
//! # Inspect receipt contents
//! atl-cli inspect document.pdf.atl
//!
//! # JSON output
//! atl-cli verify document.pdf document.pdf.atl --json
//! ```

mod cli;
mod commands;
mod error;
mod net;
mod output;
mod verify;

use error::ExitCode;

fn main() {
    let result = run();
    std::process::exit(result.code());
}

fn run() -> ExitCode {
    // Parse CLI arguments
    let args = match cli::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::Error;
        }
    };

    // Dispatch to command handler
    match commands::dispatch(&args) {
        Ok(()) => ExitCode::Valid,
        Err(e) => {
            if !args.quiet {
                eprintln!("{e}");
            }
            e.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_values() {
        assert_eq!(ExitCode::Valid.code(), 0);
        assert_eq!(ExitCode::Invalid.code(), 1);
        assert_eq!(ExitCode::Error.code(), 2);
    }
}
