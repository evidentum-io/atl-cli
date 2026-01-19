//! Online verification orchestration

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::single::SingleVerificationResult;
use std::time::Duration;

use atl_core::core::verify::anchors::bitcoin_ots::verify_ots_anchor_impl;
use atl_core::core::verify::anchors::rfc3161::verify_rfc3161_anchor_impl;
use atl_core::ReceiptAnchor;

/// Configuration for online verification
#[derive(Debug, Clone)]
pub struct OnlineConfig {
    pub request_timeout: Duration,
}

impl Default for OnlineConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// Result of online anchor verification
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AnchorVerificationResult {
    pub anchor_type: String,
    pub verified: bool,
    pub timestamp_nanos: Option<u64>,
    pub error: Option<String>,
    pub details: AnchorDetails,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AnchorDetails {
    Rfc3161 {
        algorithm_oid: String,
    },
    Bitcoin {
        block_height: u64,
        block_timestamp_secs: u64,
    },
    Unknown,
}

/// Extended verification result with online checks
#[derive(Debug)]
#[allow(dead_code)]
pub struct OnlineVerificationResult {
    pub offline: SingleVerificationResult,
    pub anchor_results: Vec<AnchorVerificationResult>,
    pub all_anchors_verified: bool,
    pub mode: VerificationMode,
}

impl OnlineVerificationResult {
    #[must_use]
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        self.offline.is_valid() && self.all_anchors_verified
    }
}

/// Verify RFC 3161 anchor using atl-core
#[allow(dead_code)]
fn verify_rfc3161(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    token_der: &str,
    data_tree_root: &str,
) -> AnchorVerificationResult {
    // Validate target
    if target != "data_tree_root" {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some(format!(
                "Invalid target '{}', expected 'data_tree_root'",
                target
            )),
            details: AnchorDetails::Unknown,
        };
    }

    // Validate target_hash matches data_tree_root
    if target_hash != data_tree_root {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("target_hash does not match data_tree_root".to_string()),
            details: AnchorDetails::Unknown,
        };
    }

    // Decode expected hash
    let hash_hex = target_hash.strip_prefix("sha256:").unwrap_or(target_hash);
    let expected_hash: [u8; 32] = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            return AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("Invalid hash length: {} bytes", b.len())),
                details: AnchorDetails::Unknown,
            }
        }
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("Invalid hex: {}", e)),
                details: AnchorDetails::Unknown,
            }
        }
    };

    // Ensure "base64:" prefix for atl-core
    let token_with_prefix = if token_der.starts_with("base64:") {
        token_der.to_string()
    } else {
        format!("base64:{}", token_der)
    };

    // CALL atl-core function
    let result = verify_rfc3161_anchor_impl(timestamp, &token_with_prefix, &expected_hash);

    AnchorVerificationResult {
        anchor_type: "rfc3161".to_string(),
        verified: result.is_valid,
        timestamp_nanos: result.timestamp,
        error: result.error,
        details: AnchorDetails::Rfc3161 {
            algorithm_oid: "2.16.840.1.101.3.4.2.1".to_string(), // SHA-256
        },
    }
}

/// Verify Bitcoin/OTS anchor using atl-core + Bitcoin API
#[allow(dead_code)]
async fn verify_bitcoin_ots(
    target: &str,
    target_hash: &str,
    ots_proof: &str,
    super_root: Option<&str>,
    config: &OnlineConfig,
) -> AnchorVerificationResult {
    // Validate target
    if target != "super_root" {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some(format!(
                "Invalid target '{}', expected 'super_root'",
                target
            )),
            details: AnchorDetails::Unknown,
        };
    }

    // Validate super_root exists
    let expected_super_root = match super_root {
        Some(sr) => sr,
        None => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some("Receipt has no super_proof".to_string()),
                details: AnchorDetails::Unknown,
            }
        }
    };

    // Validate target_hash matches super_root
    if target_hash != expected_super_root {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("target_hash does not match super_root".to_string()),
            details: AnchorDetails::Unknown,
        };
    }

    // Decode expected hash
    let hash_hex = target_hash.strip_prefix("sha256:").unwrap_or(target_hash);
    let expected_hash: [u8; 32] = match hex::decode(hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Ok(b) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("Invalid hash length: {} bytes", b.len())),
                details: AnchorDetails::Unknown,
            }
        }
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("Invalid hex: {}", e)),
                details: AnchorDetails::Unknown,
            }
        }
    };

    // CALL atl-core function for OTS parsing and verification
    let ots_result = match verify_ots_anchor_impl(ots_proof, &expected_hash) {
        Ok(r) => r,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("OTS verification failed: {}", e)),
                details: AnchorDetails::Unknown,
            }
        }
    };

    if ots_result.attestations.is_empty() {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("No Bitcoin attestations in OTS proof".to_string()),
            details: AnchorDetails::Unknown,
        };
    }

    // Get earliest attestation
    let earliest = ots_result
        .attestations
        .iter()
        .min_by_key(|a| a.block_height)
        .unwrap();

    // Fetch block timestamp via HTTP
    match crate::net::bitcoin::get_block_timestamp(earliest.block_height, config.request_timeout)
        .await
    {
        Ok(block_info) => {
            let timestamp_nanos = block_info.timestamp_secs * 1_000_000_000;
            AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: true,
                timestamp_nanos: Some(timestamp_nanos),
                error: None,
                details: AnchorDetails::Bitcoin {
                    block_height: block_info.height,
                    block_timestamp_secs: block_info.timestamp_secs,
                },
            }
        }
        Err(e) => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some(e.to_string()),
            details: AnchorDetails::Unknown,
        },
    }
}

/// Verify anchors online for single file
#[allow(dead_code)]
pub async fn verify_single_online(
    result: SingleVerificationResult,
    config: &OnlineConfig,
) -> CliResult<OnlineVerificationResult> {
    let mut anchor_results = Vec::new();

    let data_tree_root = &result.receipt.proof.root_hash;
    let super_root = result
        .receipt
        .super_proof
        .as_ref()
        .map(|sp| sp.super_root.as_str());

    for anchor in &result.receipt.anchors {
        let anchor_result = match anchor {
            ReceiptAnchor::Rfc3161 {
                target,
                target_hash,
                timestamp,
                token_der,
                ..
            } => verify_rfc3161(target, target_hash, timestamp, token_der, data_tree_root),
            ReceiptAnchor::BitcoinOts {
                target,
                target_hash,
                ots_proof,
                ..
            } => verify_bitcoin_ots(target, target_hash, ots_proof, super_root, config).await,
        };
        anchor_results.push(anchor_result);
    }

    let all_verified = anchor_results.iter().all(|r| r.verified);

    Ok(OnlineVerificationResult {
        offline: result,
        anchor_results,
        all_anchors_verified: all_verified,
        mode: VerificationMode::Online,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atl_core::{
        CheckpointJson, Receipt, ReceiptAnchor, ReceiptEntry, ReceiptProof, SignatureStatus,
        VerificationResult,
    };
    use std::path::PathBuf;

    fn create_test_receipt() -> Receipt {
        // Use a fixed UUID for testing (v4 format)
        let test_uuid = "550e8400-e29b-41d4-a716-446655440000"
            .parse()
            .expect("Valid UUID");

        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: test_uuid,
                payload_hash:
                    "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        .to_string(),
                metadata_hash:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash:
                    "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        .to_string(),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    tree_size: 1,
                    root_hash:
                        "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                            .to_string(),
                    timestamp: 1234567890,
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

    fn create_test_single_result(valid: bool) -> crate::verify::single::SingleVerificationResult {
        crate::verify::single::SingleVerificationResult {
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
                timestamp: 1234567890,
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
        }
    }

    #[test]
    fn test_online_config_default() {
        let config = OnlineConfig::default();
        assert_eq!(config.request_timeout.as_secs(), 10);
    }

    #[test]
    fn test_anchor_details_variants() {
        let rfc = AnchorDetails::Rfc3161 {
            algorithm_oid: "2.16.840.1.101.3.4.2.1".to_string(),
        };
        let bitcoin = AnchorDetails::Bitcoin {
            block_height: 800000,
            block_timestamp_secs: 1700000000,
        };
        let unknown = AnchorDetails::Unknown;

        // Just ensure variants construct properly
        match rfc {
            AnchorDetails::Rfc3161 { algorithm_oid } => {
                assert_eq!(algorithm_oid, "2.16.840.1.101.3.4.2.1");
            }
            _ => panic!("Wrong variant"),
        }
        match bitcoin {
            AnchorDetails::Bitcoin {
                block_height,
                block_timestamp_secs,
            } => {
                assert_eq!(block_height, 800000);
                assert_eq!(block_timestamp_secs, 1700000000);
            }
            _ => panic!("Wrong variant"),
        }
        match unknown {
            AnchorDetails::Unknown => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_anchor_verification_result_creation() {
        let result = AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: true,
            timestamp_nanos: Some(1234567890),
            error: None,
            details: AnchorDetails::Rfc3161 {
                algorithm_oid: "test".to_string(),
            },
        };
        assert_eq!(result.anchor_type, "rfc3161");
        assert!(result.verified);
        assert_eq!(result.timestamp_nanos, Some(1234567890));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_verify_rfc3161_invalid_target() {
        let result = verify_rfc3161(
            "wrong_target",
            "sha256:abc",
            "2024-01-01T00:00:00Z",
            "base64:token",
            "sha256:abc",
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result
            .error
            .unwrap()
            .contains("Invalid target 'wrong_target'"));
    }

    #[test]
    fn test_verify_rfc3161_hash_mismatch() {
        let result = verify_rfc3161(
            "data_tree_root",
            "sha256:abc",
            "2024-01-01T00:00:00Z",
            "base64:token",
            "sha256:different",
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result
            .error
            .unwrap()
            .contains("target_hash does not match data_tree_root"));
    }

    #[test]
    fn test_verify_rfc3161_invalid_hex() {
        let result = verify_rfc3161(
            "data_tree_root",
            "sha256:notvalidhex",
            "2024-01-01T00:00:00Z",
            "base64:token",
            "sha256:notvalidhex",
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("Invalid hex"));
    }

    #[test]
    fn test_verify_rfc3161_wrong_hash_length() {
        let result = verify_rfc3161(
            "data_tree_root",
            "sha256:aabb",
            "2024-01-01T00:00:00Z",
            "base64:token",
            "sha256:aabb",
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("Invalid hash length"));
    }

    #[tokio::test]
    async fn test_verify_bitcoin_ots_invalid_target() {
        let config = OnlineConfig::default();
        let result =
            verify_bitcoin_ots("wrong_target", "sha256:abc", "base64:proof", None, &config).await;
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result
            .error
            .unwrap()
            .contains("Invalid target 'wrong_target'"));
    }

    #[tokio::test]
    async fn test_verify_bitcoin_ots_no_super_root() {
        let config = OnlineConfig::default();
        let result =
            verify_bitcoin_ots("super_root", "sha256:abc", "base64:proof", None, &config).await;
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("no super_proof"));
    }

    #[tokio::test]
    async fn test_verify_bitcoin_ots_hash_mismatch() {
        let config = OnlineConfig::default();
        let result = verify_bitcoin_ots(
            "super_root",
            "sha256:abc",
            "base64:proof",
            Some("sha256:different"),
            &config,
        )
        .await;
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result
            .error
            .unwrap()
            .contains("target_hash does not match super_root"));
    }

    #[tokio::test]
    async fn test_verify_bitcoin_ots_invalid_hex() {
        let config = OnlineConfig::default();
        let result = verify_bitcoin_ots(
            "super_root",
            "sha256:notvalidhex",
            "base64:proof",
            Some("sha256:notvalidhex"),
            &config,
        )
        .await;
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("Invalid hex"));
    }

    #[tokio::test]
    async fn test_verify_bitcoin_ots_wrong_hash_length() {
        let config = OnlineConfig::default();
        let result = verify_bitcoin_ots(
            "super_root",
            "sha256:aabb",
            "base64:proof",
            Some("sha256:aabb"),
            &config,
        )
        .await;
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("Invalid hash length"));
    }

    #[test]
    fn test_online_verification_result_is_valid_both_true() {
        let single = create_test_single_result(true);

        let online = OnlineVerificationResult {
            offline: single,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: VerificationMode::Online,
        };
        assert!(online.is_valid());
    }

    #[test]
    fn test_online_verification_result_is_valid_offline_false() {
        let single = create_test_single_result(false);

        let online = OnlineVerificationResult {
            offline: single,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: VerificationMode::Online,
        };
        assert!(!online.is_valid());
    }

    #[test]
    fn test_online_verification_result_is_valid_anchors_false() {
        let single = create_test_single_result(true);

        let online = OnlineVerificationResult {
            offline: single,
            anchor_results: vec![],
            all_anchors_verified: false,
            mode: VerificationMode::Online,
        };
        assert!(!online.is_valid());
    }

    #[tokio::test]
    async fn test_verify_single_online_no_anchors() {
        let single = create_test_single_result(true);

        let config = OnlineConfig::default();
        let result = verify_single_online(single, &config).await;
        assert!(result.is_ok());
        let online = result.unwrap();
        assert!(online.anchor_results.is_empty());
        assert!(online.all_anchors_verified); // vacuously true for empty list
    }

    #[tokio::test]
    async fn test_verify_single_online_with_rfc3161_invalid() {
        let mut single = create_test_single_result(true);
        single.receipt.anchors.push(ReceiptAnchor::Rfc3161 {
            target: "wrong".to_string(),
            target_hash: "sha256:abc".to_string(),
            tsa_url: "https://example.com/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        });

        let config = OnlineConfig::default();
        let result = verify_single_online(single, &config).await;
        assert!(result.is_ok());
        let online = result.unwrap();
        assert_eq!(online.anchor_results.len(), 1);
        assert!(!online.anchor_results[0].verified);
        assert!(!online.all_anchors_verified);
    }

    #[tokio::test]
    async fn test_verify_single_online_with_bitcoin_ots_invalid() {
        let mut single = create_test_single_result(true);
        single.receipt.anchors.push(ReceiptAnchor::BitcoinOts {
            target: "wrong".to_string(),
            target_hash: "sha256:abc".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            bitcoin_block_height: 800000,
            bitcoin_block_time: "2024-01-01T00:00:00Z".to_string(),
            ots_proof: "base64:proof".to_string(),
        });

        let config = OnlineConfig::default();
        let result = verify_single_online(single, &config).await;
        assert!(result.is_ok());
        let online = result.unwrap();
        assert_eq!(online.anchor_results.len(), 1);
        assert!(!online.anchor_results[0].verified);
        assert!(!online.all_anchors_verified);
    }
}
