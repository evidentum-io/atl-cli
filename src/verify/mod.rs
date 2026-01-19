//! Verification logic

pub mod batch;
pub mod consistency;
pub mod file;
pub mod single;

#[cfg(feature = "online")]
pub mod online;

// Re-export main verification functions and types
// These are used by other modules in the project (commands, output)
#[allow(unused_imports)]
pub use batch::{match_files_to_receipts, verify_batch, BatchItemResult, BatchVerificationResult};
#[allow(unused_imports)]
pub use consistency::{verify_consistency, ConsistencyResult};
#[allow(unused_imports)]
pub use file::{compare_hash, format_hash, hash_file, MAX_RECEIPT_SIZE, MAX_SOURCE_FILE_SIZE};
#[allow(unused_imports)]
pub use single::{load_receipt, verify_single, SingleVerificationResult};
