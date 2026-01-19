//! Log consistency verification (cross-receipt proofs)

use atl_core::{verify_cross_receipts, CrossReceiptVerificationResult};

use crate::error::CliResult;
use crate::verify::single::SingleVerificationResult;

/// Result of log consistency verification
#[derive(Debug)]
pub struct ConsistencyResult {
    /// All receipts from same log instance
    pub same_log: bool,
    /// History is consistent (no tampering)
    pub history_consistent: bool,
    /// Genesis super root (shared by all)
    pub genesis_super_root: Option<[u8; 32]>,
    /// Number of receipts checked
    pub receipt_count: usize,
    /// Cross-receipt verification results
    #[allow(dead_code)]
    pub cross_results: Vec<CrossReceiptVerificationResult>,
    /// Specific errors
    pub errors: Vec<String>,
}

impl ConsistencyResult {
    /// Check if log is consistent
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.same_log && self.history_consistent && self.errors.is_empty()
    }
}

/// Verify consistency across multiple receipts
///
/// This function checks that all receipts are from the same log instance
/// and that the log history is consistent (append-only, no tampering).
///
/// # Algorithm
///
/// 1. Check all receipts have the same genesis_super_root
/// 2. Sort receipts by super_tree_size
/// 3. Verify consistency proofs between consecutive pairs
///
/// # Arguments
///
/// * `results` - Array of single verification results
///
/// # Returns
///
/// Consistency result with detailed error information
///
/// # Errors
///
/// Returns error only if internal verification fails unexpectedly.
/// Consistency failures are reported in the result structure.
pub fn verify_consistency(results: &[SingleVerificationResult]) -> CliResult<ConsistencyResult> {
    if results.len() < 2 {
        return Ok(ConsistencyResult {
            same_log: true,
            history_consistent: true,
            genesis_super_root: results
                .first()
                .and_then(|r| r.receipt.super_proof.as_ref())
                .map(|sp| parse_hash(&sp.genesis_super_root)),
            receipt_count: results.len(),
            cross_results: vec![],
            errors: vec![],
        });
    }

    let mut same_log = true;
    let mut history_consistent = true;
    let mut errors = Vec::new();
    let mut cross_results = Vec::new();

    // Extract genesis from first receipt
    let first_genesis = results[0]
        .receipt
        .super_proof
        .as_ref()
        .map(|sp| &sp.genesis_super_root);

    // Check all have same genesis
    for result in results.iter().skip(1) {
        let genesis = result
            .receipt
            .super_proof
            .as_ref()
            .map(|sp| &sp.genesis_super_root);
        if genesis != first_genesis {
            same_log = false;
            errors.push(format!(
                "Different genesis: {} vs {}",
                first_genesis.unwrap_or(&"none".to_string()),
                genesis.unwrap_or(&"none".to_string())
            ));
        }
    }

    // Sort by super_tree_size for pairwise verification
    let mut sorted: Vec<_> = results.iter().collect();
    sorted.sort_by_key(|r| {
        r.receipt
            .super_proof
            .as_ref()
            .map_or(0, |sp| sp.super_tree_size)
    });

    // Verify consecutive pairs
    for window in sorted.windows(2) {
        let (a, b) = (window[0], window[1]);
        let result = verify_cross_receipts(&a.receipt, &b.receipt);
        if !result.is_valid() {
            history_consistent = false;
            for err in &result.errors {
                errors.push(format!("Cross-receipt error: {err:?}"));
            }
        }
        cross_results.push(result);
    }

    let genesis_super_root = first_genesis.map(|s| parse_hash(s));

    Ok(ConsistencyResult {
        same_log,
        history_consistent,
        genesis_super_root,
        receipt_count: results.len(),
        cross_results,
        errors,
    })
}

/// Parse hash string to bytes
///
/// # Arguments
///
/// * `hash_str` - Hash string in "sha256:hex" format
///
/// # Returns
///
/// 32-byte array. Returns zeros if parsing fails.
fn parse_hash(hash_str: &str) -> [u8; 32] {
    let hex_part = hash_str.strip_prefix("sha256:").unwrap_or(hash_str);
    let mut bytes = [0u8; 32];
    if let Ok(decoded) = hex::decode(hex_part) {
        if decoded.len() == 32 {
            bytes.copy_from_slice(&decoded);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistency_empty() {
        let results: Vec<SingleVerificationResult> = vec![];
        let consistency = verify_consistency(&results).unwrap();
        assert!(consistency.is_valid());
        assert_eq!(consistency.receipt_count, 0);
    }

    #[test]
    fn test_parse_hash_valid() {
        let hash_str = "sha256:abababababababababababababababababababababababababababababababab";
        let parsed = parse_hash(hash_str);
        assert_eq!(parsed[0], 0xab);
        assert_eq!(parsed[31], 0xab);
    }

    #[test]
    fn test_parse_hash_without_prefix() {
        let hash_str = "abababababababababababababababababababababababababababababababab";
        let parsed = parse_hash(hash_str);
        assert_eq!(parsed[0], 0xab);
    }

    #[test]
    fn test_parse_hash_invalid() {
        let hash_str = "invalid";
        let parsed = parse_hash(hash_str);
        assert_eq!(parsed, [0u8; 32]);
    }

    // Note: Full consistency tests with valid receipts are in integration tests
    // Unit tests here focus on simple cases and helper functions
}
