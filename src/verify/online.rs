//! Online verification orchestration

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::single::SingleVerificationResult;
use std::time::Duration;

use atl_core::core::verify::anchors::rfc3161::verify_rfc3161_anchor_impl;
use atl_core::core::verify::anchors::bitcoin_ots::verify_ots_anchor_impl;
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
    Rfc3161 { algorithm_oid: String },
    Bitcoin { block_height: u64, block_timestamp_secs: u64 },
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
            error: Some(format!("Invalid target '{}', expected 'super_root'", target)),
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
