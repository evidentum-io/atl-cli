//! CLI argument parsing using clap

pub mod args;

pub use args::Args;

/// Parse CLI arguments
pub fn parse() -> Result<Args, crate::error::CliError> {
    todo!("Implement in CLI-1")
}
