//! Error types and exit codes for atl-cli
//!
//! Exit codes:
//! - 0 = VALID (verification passed)
//! - 1 = INVALID (verification failed cryptographically)
//! - 2 = ERROR (runtime error)

use thiserror::Error;

/// Exit codes for the CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// All verifications passed
    Valid = 0,
    /// One or more verifications failed (cryptographic failure)
    Invalid = 1,
    /// Runtime error (file not found, parse error, etc.)
    Error = 2,
}

impl ExitCode {
    /// Convert to process exit code
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// CLI error type
#[derive(Debug, Error)]
pub enum CliError {
    /// Placeholder - will be expanded in ERROR-1
    #[error("not implemented")]
    NotImplemented,
}

impl CliError {
    /// Get the appropriate exit code for this error
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::Error
    }
}
