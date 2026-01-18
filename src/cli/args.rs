//! CLI argument definitions
//!
//! Implementation pending: CLI-1

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// ATL Protocol receipt verification tool
#[derive(Parser, Debug)]
#[command(name = "atl")]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,

    /// Suppress output (only exit code)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,
}

/// Available commands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Verify file(s) against receipt(s)
    Verify {
        /// Source file or directory
        source: PathBuf,

        /// Receipt file or directory (.atl)
        receipt: PathBuf,

        /// Force offline mode (skip online verification)
        #[arg(long)]
        offline: bool,

        /// Force online mode (fail if no internet)
        #[arg(long)]
        online: bool,

        /// Show detailed verification steps
        #[arg(short, long)]
        verbose: bool,
    },

    /// Display receipt contents
    Inspect {
        /// Path to the .atl receipt file
        receipt: PathBuf,
    },
}
