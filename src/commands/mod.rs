//! Command implementations

pub mod inspect;
pub mod verify;

use crate::cli::{Args, Command};
use crate::error::CliError;

/// Dispatch to the appropriate command handler
pub fn dispatch(args: &Args) -> Result<(), CliError> {
    match &args.command {
        Command::Verify(verify_args) => verify::execute(verify_args, args),
        Command::Inspect(inspect_args) => inspect::execute(inspect_args, args),
    }
}
