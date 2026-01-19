//! CLI argument parsing using clap

pub mod args;

pub use args::{Args, Command, InspectArgs, VerifyArgs};
#[allow(unused_imports)]
pub use args::VerificationMode;

use crate::error::CliError;
use clap::Parser;

/// Parse CLI arguments from command line
pub fn parse() -> Result<Args, CliError> {
    Ok(Args::parse())
}

/// Parse CLI arguments from iterator (for testing)
#[allow(dead_code)]
pub fn parse_from<I, T>(iter: I) -> Result<Args, CliError>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    Args::try_parse_from(iter).map_err(|e| {
        CliError::InvalidReceiptFormat(format!("Failed to parse CLI arguments: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_parse_verify_single_file() {
        let args = parse_from(["atl-cli", "verify", "test.pdf", "test.pdf.atl"]).unwrap();
        if let Command::Verify(verify_args) = args.command {
            assert_eq!(verify_args.source, PathBuf::from("test.pdf"));
            assert_eq!(verify_args.receipt, PathBuf::from("test.pdf.atl"));
            assert!(!verify_args.offline);
            assert!(!verify_args.online);
        } else {
            panic!("Expected Verify command");
        }
    }

    #[test]
    fn test_parse_verify_offline() {
        let args =
            parse_from(["atl-cli", "verify", "test.pdf", "test.pdf.atl", "--offline"]).unwrap();
        if let Command::Verify(verify_args) = args.command {
            assert!(verify_args.offline);
            assert!(!verify_args.online);
        } else {
            panic!("Expected Verify command");
        }
    }

    #[test]
    fn test_parse_verify_online() {
        let args =
            parse_from(["atl-cli", "verify", "test.pdf", "test.pdf.atl", "--online"]).unwrap();
        if let Command::Verify(verify_args) = args.command {
            assert!(!verify_args.offline);
            assert!(verify_args.online);
        } else {
            panic!("Expected Verify command");
        }
    }

    #[test]
    fn test_offline_online_conflict() {
        // clap should reject this combination
        let result = parse_from([
            "atl-cli",
            "verify",
            "test.pdf",
            "test.pdf.atl",
            "--offline",
            "--online",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_inspect() {
        let args = parse_from(["atl-cli", "inspect", "test.pdf.atl"]).unwrap();
        if let Command::Inspect(inspect_args) = args.command {
            assert_eq!(inspect_args.receipt, PathBuf::from("test.pdf.atl"));
        } else {
            panic!("Expected Inspect command");
        }
    }

    #[test]
    fn test_global_flags() {
        let args = parse_from([
            "atl-cli",
            "--quiet",
            "--json",
            "verify",
            "test.pdf",
            "test.pdf.atl",
        ])
        .unwrap();
        assert!(args.quiet);
        assert!(args.json);
    }

    #[test]
    fn test_verbose_flag() {
        let args =
            parse_from(["atl-cli", "verify", "test.pdf", "test.pdf.atl", "--verbose"]).unwrap();
        if let Command::Verify(verify_args) = args.command {
            assert!(verify_args.verbose);
        } else {
            panic!("Expected Verify command");
        }
    }
}
