//! Verification logic

pub mod anchor;
pub mod batch;
pub mod consistency;
pub mod file;
pub mod single;
pub mod trust_store;
pub mod verdict;

#[cfg(feature = "online")]
pub mod online;

// Re-export main verification functions and types
// These are used by other modules in the project (commands, output)
#[allow(unused_imports)]
pub use anchor::{AnchorDetails, AnchorVerdict, AnchorVerificationResult};
#[allow(unused_imports)]
pub use batch::{match_files_to_receipts, verify_batch, BatchItemResult, BatchVerificationResult};
#[allow(unused_imports)]
pub use consistency::{verify_consistency, ConsistencyResult};
#[allow(unused_imports)]
pub use file::{compare_hash, format_hash, hash_file, MAX_RECEIPT_SIZE, MAX_SOURCE_FILE_SIZE};
#[allow(unused_imports)]
pub use single::{load_receipt, verify_single, ProofVerdict, SingleVerificationResult};
#[allow(unused_imports)]
pub use trust_store::{load_tsa_intermediates, load_tsa_trust_store};
#[allow(unused_imports)]
pub use verdict::{ReasonCode, ReceiptVerdict, Status};
