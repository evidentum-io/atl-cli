//! Output formatting

pub mod human;
pub mod json;

use crate::cli::{Args, VerificationMode};
use crate::error::CliResult;
use crate::verify::batch::BatchVerificationResult;
use crate::verify::online::OnlineVerificationResult;
use crate::verify::single::SingleVerificationResult;

/// Print single file verification result
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_single_result(
    result: &SingleVerificationResult,
    args: &Args,
    mode: VerificationMode,
) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_single_result(result, mode)
    } else {
        human::print_single_result(result, args.use_color())
    }
}

/// Print single file result with online verification
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_single_online_result(result: &OnlineVerificationResult, args: &Args) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_single_online_result(result)
    } else {
        human::print_single_online_result(result, args.use_color())
    }
}

/// Print batch verification result
///
/// Output format determined by Args (human-readable or JSON)
pub fn print_batch_result(
    result: &BatchVerificationResult,
    args: &Args,
    mode: VerificationMode,
) -> CliResult<()> {
    if args.is_quiet() {
        return Ok(());
    }

    if args.use_json() {
        json::print_batch_result(result, mode)
    } else {
        human::print_batch_result(result, args.use_color())
    }
}
