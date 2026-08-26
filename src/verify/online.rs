//! Online verification: the one thing that genuinely needs the network.
//!
//! RFC 3161 anchors are verified in full by [`crate::verify::anchor`], with
//! no network access at all. The only anchor type that needs to go online is
//! `bitcoin_ots`, and only to fetch the block whose Merkle root confirms the
//! OTS proof. This module does exactly that, in place, replacing each
//! `bitcoin_ots` anchor's network-free verdict with the confirmed one.

use std::time::Duration;

use atl_core::ReceiptAnchor;

use crate::error::CliResult;
use crate::verify::anchor::{
    prepare_bitcoin_ots, requires_network, AnchorDetails, AnchorVerdict, AnchorVerificationResult,
};
use crate::verify::single::SingleVerificationResult;
use crate::verify::verdict::ReasonCode;

/// Configuration for online verification
#[derive(Debug, Clone)]
pub struct OnlineConfig {
    /// Per-request timeout for Bitcoin block lookups.
    pub request_timeout: Duration,
}

impl Default for OnlineConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// `true` if any anchor in `receipt` needs network access to be verified to
/// completion.
///
/// A receipt anchored only by RFC 3161 is fully verifiable offline, so the
/// CLI must not probe connectivity for it — that probe was contacting
/// external hosts for a check that never leaves the process.
#[must_use]
pub fn receipt_requires_network(receipt: &atl_core::Receipt) -> bool {
    receipt.anchors.iter().any(requires_network)
}

/// Confirm one `bitcoin_ots` anchor against the real blockchain.
async fn verify_bitcoin_ots_online(
    target: &str,
    target_hash: &str,
    ots_proof: &str,
    super_root: Option<&str>,
    config: &OnlineConfig,
) -> AnchorVerificationResult {
    // Every network-free check first, sharing exactly the offline rules.
    let prepared = match prepare_bitcoin_ots(target, target_hash, ots_proof, super_root) {
        Ok(p) => p,
        Err(result) => return result,
    };

    let block_info = match crate::net::bitcoin::get_block_info(
        prepared.attestation.block_height,
        config.request_timeout,
    )
    .await
    {
        Ok(info) => info,
        Err(e) => {
            // The lookup was attempted and failed: nothing is refuted, the
            // confirmation simply could not be obtained.
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockUnavailable),
                timestamp_nanos: None,
                error: Some(e.to_string()),
                details: AnchorDetails::Bitcoin {
                    block_height: prepared.attestation.block_height,
                    block_timestamp_secs: 0,
                    target_hash: target_hash.to_string(),
                    operation_count: prepared.operation_count,
                    computed_root: prepared.computed_root,
                    block_merkle_root: None,
                    merkle_match: None,
                },
            };
        }
    };

    // CRITICAL: the OTS proof's root must equal the block's Merkle root.
    let merkle_match = prepared
        .attestation
        .verify_against_block(&block_info.merkle_root);

    let details = AnchorDetails::Bitcoin {
        block_height: block_info.height,
        block_timestamp_secs: block_info.timestamp_secs,
        target_hash: target_hash.to_string(),
        operation_count: prepared.operation_count,
        computed_root: prepared.computed_root,
        block_merkle_root: Some(format!("sha256:{}", block_info.merkle_root)),
        merkle_match: Some(merkle_match),
    };

    if merkle_match {
        AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Valid,
            timestamp_nanos: Some(block_info.timestamp_secs * 1_000_000_000),
            error: None,
            details,
        }
    } else {
        AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verdict: AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch),
            timestamp_nanos: None,
            error: Some(format!(
                "Merkle root mismatch: OTS proof does not match block {}",
                block_info.height
            )),
            details,
        }
    }
}

/// Upgrade every `bitcoin_ots` anchor in `result` from its network-free
/// verdict to a block-confirmed one.
///
/// RFC 3161 anchors are left exactly as they were: their verification is
/// complete already and going online could not change it. Callers re-read
/// [`SingleVerificationResult::verdict`] afterwards — the receipt status
/// follows from the updated anchors automatically.
///
/// # Errors
///
/// Never returns `Err` today; the signature keeps a `CliResult` so a future
/// hard failure (as opposed to an unconfirmed anchor) can be surfaced
/// without changing every caller.
pub async fn verify_anchors_online(
    result: &mut SingleVerificationResult,
    config: &OnlineConfig,
) -> CliResult<()> {
    let super_root = result
        .receipt
        .super_proof
        .as_ref()
        .map(|sp| sp.super_root.clone());

    for (index, anchor) in result.receipt.anchors.iter().enumerate() {
        let ReceiptAnchor::BitcoinOts {
            target,
            target_hash,
            ots_proof,
            ..
        } = anchor
        else {
            continue;
        };

        let confirmed = verify_bitcoin_ots_online(
            target,
            target_hash,
            ots_proof,
            super_root.as_deref(),
            config,
        )
        .await;

        if let Some(slot) = result.anchor_results.get_mut(index) {
            *slot = confirmed;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::verdict::Status;
    use atl_core::{
        CheckpointJson, Receipt, ReceiptEntry, ReceiptProof, SignatureStatus, VerificationResult,
    };
    use std::path::PathBuf;

    const TEST_ROOT_HASH: &str =
        "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const OTHER_HASH: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn create_test_receipt() -> Receipt {
        let test_uuid = "550e8400-e29b-41d4-a716-446655440000"
            .parse()
            .expect("Valid UUID");

        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: test_uuid,
                payload_hash: TEST_ROOT_HASH.to_string(),
                metadata_hash:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: TEST_ROOT_HASH.to_string(),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    tree_size: 1,
                    root_hash: TEST_ROOT_HASH.to_string(),
                    timestamp: 1_234_567_890,
                    signature: "base64:signature".to_string(),
                    key_id:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                },
                consistency_proof: None,
            },
            super_proof: None,
            anchors: vec![],
        }
    }

    fn create_test_single_result(valid: bool) -> SingleVerificationResult {
        SingleVerificationResult {
            source_path: PathBuf::from("test.txt"),
            receipt_path: PathBuf::from("test.atl"),
            file_hash: [0x12; 32],
            receipt: create_test_receipt(),
            file_hash_valid: valid,
            core_result: VerificationResult {
                is_valid: valid,
                leaf_hash: [0x12; 32],
                root_hash: [0x34; 32],
                tree_size: 1,
                timestamp: 1_234_567_890,
                signature_valid: valid,
                signature_status: if valid {
                    SignatureStatus::Verified
                } else {
                    SignatureStatus::Failed
                },
                inclusion_valid: valid,
                consistency_valid: None,
                super_inclusion_valid: valid,
                super_consistency_valid: valid,
                genesis_super_root: [0x00; 32],
                super_root: [0x56; 32],
                data_tree_index: 0,
                super_tree_size: 1,
                anchor_results: vec![],
                errors: vec![],
            },
            anchor_results: vec![],
        }
    }

    #[test]
    fn test_online_config_default() {
        let config = OnlineConfig::default();
        assert_eq!(config.request_timeout.as_secs(), 10);
    }

    #[test]
    fn test_online_config_clone_and_debug() {
        let config = OnlineConfig::default();
        let cloned = config.clone();
        assert_eq!(config.request_timeout, cloned.request_timeout);
        assert!(format!("{config:?}").contains("OnlineConfig"));
    }

    #[test]
    fn rfc3161_only_receipt_needs_no_network() {
        let mut receipt = create_test_receipt();
        receipt.anchors.push(ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: TEST_ROOT_HASH.to_string(),
            tsa_url: "https://example.invalid/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        });
        assert!(!receipt_requires_network(&receipt));
    }

    #[test]
    fn bitcoin_anchor_needs_network() {
        let mut receipt = create_test_receipt();
        receipt.anchors.push(ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: TEST_ROOT_HASH.to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            bitcoin_block_height: 800_000,
            bitcoin_block_time: "2024-01-01T00:00:00Z".to_string(),
            ots_proof: "base64:proof".to_string(),
        });
        assert!(receipt_requires_network(&receipt));
    }

    #[tokio::test]
    async fn online_pass_leaves_non_bitcoin_anchors_untouched() {
        // A receipt with no bitcoin anchors must come out of the online pass
        // byte-for-byte identical -- and, crucially, without any network
        // call having been made.
        let mut result = create_test_single_result(true);
        result.receipt.anchors.push(ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: OTHER_HASH.to_string(),
            tsa_url: "https://example.invalid/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        });
        result.anchor_results =
            crate::verify::anchor::verify_anchors_offline(&result.receipt, None);
        let before = result.anchor_results[0].verdict;

        verify_anchors_online(&mut result, &OnlineConfig::default())
            .await
            .expect("online pass must not fail");

        assert_eq!(result.anchor_results[0].verdict, before);
        assert_eq!(
            before,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch)
        );
    }

    #[test]
    fn unanchored_receipt_is_pending() {
        let result = create_test_single_result(true);
        assert_eq!(result.verdict().status, Status::Pending);
        assert!(result.is_lite_valid());
    }

    #[test]
    fn file_hash_mismatch_outranks_everything() {
        let result = create_test_single_result(false);
        let verdict = result.verdict();
        assert_eq!(verdict.status, Status::Invalid);
        assert_eq!(verdict.reason_code, Some(ReasonCode::FileHashMismatch));
    }
}
