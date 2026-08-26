//! Online verification orchestration

use crate::cli::VerificationMode;
use crate::error::CliResult;
use crate::verify::single::SingleVerificationResult;
use std::time::Duration;

use atl_core::core::verify::anchors::bitcoin_ots::verify_ots_anchor_impl;
use atl_core::core::verify::anchors::rfc3161::verify_rfc3161_token;
use atl_core::core::verify::iso8601::parse_iso8601_to_nanos;
use atl_core::{
    PathStatus, ReceiptAnchor, Revocation, Rfc3161AnchorFacts, TerminalAnchor, TrustStore,
    ANCHOR_TARGET_DATA_TREE_ROOT, ANCHOR_TARGET_SUPER_ROOT,
};
use subtle::ConstantTimeEq;

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
pub struct AnchorVerificationResult {
    pub anchor_type: String,
    /// Full aggregate success for this anchor. For RFC 3161 anchors this is
    /// [`Rfc3161AnchorFacts::is_fully_valid`] in disguise (equivalently,
    /// `details.rfc3161_trust() == Some(Rfc3161Trust::Trusted)`): a chain
    /// that terminates in [`TerminalAnchor::Assumed`] is cryptographically
    /// sound but this is `false` regardless, by construction — see
    /// [`AnchorDetails::rfc3161_trust`].
    pub verified: bool,
    pub timestamp_nanos: Option<u64>,
    pub error: Option<String>,
    pub details: AnchorDetails,
}

/// Tri-state trust outcome for an RFC 3161 anchor, computed once (in
/// [`AnchorDetails::rfc3161_trust`]) so the human-readable and JSON
/// renderers can never disagree about which state a receipt is in — see the
/// ATL trust-model doc's requirement that these three states are reported
/// honestly and identically everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rfc3161Trust {
    /// Every fact holds (`MessageImprint` match, CMS signature, chain
    /// validity at `genTime`, exclusive critical timeStamping EKU, complete
    /// path) AND the chain terminates at a certificate the caller's
    /// `--tsa-trust-store` names. This is the only state that contributes
    /// to `verified` / `all_anchors_verified` / `status: valid`.
    Trusted,
    /// Every cryptographic/structural fact holds, but the chain terminates
    /// in an unverified self-signed certificate nobody vouches for
    /// (`TerminalAnchor::Assumed`) — no `--tsa-trust-store` was supplied, or
    /// it didn't name this root. Per the ATL trust-model decisions, this
    /// NEVER satisfies aggregate success, however sound the math is.
    Assumed,
    /// Some fact failed outright (bad signature, broken chain, wrong
    /// imprint, missing EKU) or no terminal anchor was reached at all.
    Failed,
}

#[derive(Debug, Clone)]
pub enum AnchorDetails {
    /// The complete fact set from `atl-core`'s RFC 3161 verifier (see
    /// [`Rfc3161AnchorFacts`]), carried through unmodified rather than
    /// collapsed to a single `is_valid: bool` — this is what lets the CLI
    /// tell "Trusted" apart from "Assumed" instead of reporting both as one
    /// undifferentiated failure/success.
    Rfc3161 {
        imprint_matches_root: bool,
        cms_signature_valid: bool,
        chain_valid_at_gen_time: bool,
        timestamping_eku_ok: bool,
        path_status: PathStatus,
        terminal_anchor: Option<TerminalAnchor>,
        revocation: Revocation,
    },
    Bitcoin {
        block_height: u64,
        block_timestamp_secs: u64,
        /// Target hash being verified (with sha256: prefix)
        target_hash: String,
        /// Number of operations in OTS proof
        operation_count: usize,
        /// Computed merkle root from OTS proof (with sha256: prefix, 71 chars total)
        computed_root: String,
        /// Block merkle root from API (with sha256: prefix) - None if offline/error
        block_merkle_root: Option<String>,
        /// Whether computed_root matches block_merkle_root
        merkle_match: Option<bool>,
    },
    Unknown,
}

impl AnchorDetails {
    /// Classify an RFC 3161 anchor's facts into [`Rfc3161Trust`]. Returns
    /// `None` for any other anchor type (Bitcoin OTS has no comparable
    /// caller-supplied trust material — its trust comes entirely from the
    /// Bitcoin blockchain itself).
    ///
    /// This is the single place that decides what counts as "Trusted" vs
    /// "Assumed" vs "Failed"; [`AnchorVerificationResult::verified`], the
    /// human renderer, and the JSON renderer all derive their state from
    /// this method (directly or via `verified`) instead of re-deriving the
    /// classification, so they cannot drift apart.
    #[must_use]
    pub fn rfc3161_trust(&self) -> Option<Rfc3161Trust> {
        let Self::Rfc3161 {
            imprint_matches_root,
            cms_signature_valid,
            chain_valid_at_gen_time,
            timestamping_eku_ok,
            path_status,
            terminal_anchor,
            ..
        } = self
        else {
            return None;
        };

        let facts_sound = *imprint_matches_root
            && *cms_signature_valid
            && *chain_valid_at_gen_time
            && *timestamping_eku_ok
            && matches!(path_status, PathStatus::Complete);

        Some(match (facts_sound, terminal_anchor) {
            (true, Some(TerminalAnchor::Trusted { .. })) => Rfc3161Trust::Trusted,
            (true, Some(TerminalAnchor::Assumed { .. })) => Rfc3161Trust::Assumed,
            _ => Rfc3161Trust::Failed,
        })
    }
}

/// Extended verification result with online checks
#[derive(Debug)]
pub struct OnlineVerificationResult {
    pub offline: SingleVerificationResult,
    pub anchor_results: Vec<AnchorVerificationResult>,
    /// `true` only if every anchor in `anchor_results` has `verified ==
    /// true`. Per the ATL trust-model decisions, an RFC 3161 anchor stuck at
    /// `Rfc3161Trust::Assumed` never counts here, no matter how sound its
    /// cryptography is — this is the field that used to (wrongly) go `true`
    /// for an anchor nobody vouched for.
    pub all_anchors_verified: bool,
    #[allow(dead_code)]
    pub mode: VerificationMode,
}

impl OnlineVerificationResult {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.offline.is_valid() && self.all_anchors_verified
    }
}

/// Decode a `"sha256:<64 hex chars>"` string into a 32-byte hash.
///
/// Shared by both anchor types so `target_hash`, `proof.root_hash` and
/// `super_proof.super_root` are all parsed identically before being
/// compared.
///
/// This delegates to [`atl_core::core::checkpoint::parse_hash`] rather than
/// reimplementing hash-string parsing, so this crate's notion of "a valid
/// hash string" can never drift from what `atl-core` itself accepts.
/// `atl_core::parse_hash` requires the prefix to be exactly `"sha256:"`
/// (lowercase); it rejects `"SHA256:"`, any other case, and a missing
/// prefix, matching `hex::decode`'s existing case-insensitivity for the hex
/// digits themselves.
fn decode_hash_hex(s: &str) -> Result<[u8; 32], String> {
    atl_core::core::checkpoint::parse_hash(s).map_err(|e| e.to_string())
}

/// Constant-time 32-byte comparison.
///
/// `target_hash` values compared here are not secret (they are published
/// inside the receipt itself), but we still compare them in constant time
/// to match `atl-core`'s own internal pinning and this project's general
/// policy of never using `==` on hash/digest values.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Render a compact, human-readable summary of why an RFC 3161 anchor's
/// facts did not reach [`Rfc3161Trust::Trusted`], for
/// [`AnchorVerificationResult::error`].
///
/// This mirrors the shape of `atl-core`'s own (private) diagnostic text —
/// duplicated here only as *prose formatting*, not as a re-derivation of
/// any trust decision: every fact it reads was already computed by
/// `atl-core`'s `verify_rfc3161_token`, this function only describes them.
fn summarize_rfc3161(facts: &Rfc3161AnchorFacts) -> String {
    let mut reasons = Vec::new();
    if !facts.imprint_matches_root {
        reasons.push("messageImprint does not match the receipt's Data Tree root".to_string());
    }
    if !facts.cms_signature_valid {
        reasons.push(match &facts.diagnostic {
            Some(detail) => format!("CMS signature invalid: {detail}"),
            None => "CMS signature invalid".to_string(),
        });
    }
    if !facts.chain_valid_at_gen_time {
        reasons.push(format!(
            "certificate chain invalid at genTime (path_status: {:?})",
            facts.path_status
        ));
    }
    if !facts.timestamping_eku_ok {
        reasons.push(
            "signer certificate lacks the exclusive critical id-kp-timeStamping EKU".to_string(),
        );
    }
    match &facts.terminal_anchor {
        Some(TerminalAnchor::Assumed { sha256_fingerprint }) => {
            reasons.push(format!(
                "trust anchor not established: chain terminates in an unverified self-signed \
                 certificate (sha256:{}); this NEVER counts as valid — pass --tsa-trust-store \
                 to trust it",
                hex::encode(sha256_fingerprint)
            ));
        }
        None => {
            reasons.push("no terminal anchor reached (incomplete certificate chain)".to_string())
        }
        Some(TerminalAnchor::Trusted { .. }) => {}
    }
    if reasons.is_empty() {
        "verification did not reach aggregate success".to_string()
    } else {
        reasons.join("; ")
    }
}

/// Verify RFC 3161 anchor using atl-core
///
/// # Anchor pinning (ATL Protocol v2.0, "RFC 3161 Anchor", steps 1-2)
///
/// Steps 1 and 2 of the spec require verifying that `anchor.target` equals
/// `"data_tree_root"` and that `anchor.target_hash` equals `proof.root_hash`
/// *before* any cryptographic verification of the TSA token is attempted.
/// Without step 2 a genuine timestamp token minted for a completely
/// unrelated hash would be reported as proof for THIS receipt, since the
/// token only proves that the TSA once timestamped `anchor.target_hash` -
/// it says nothing about whether that hash has anything to do with the
/// receipt being verified.
///
/// `atl-core` performs exactly this pinning internally, in
/// `core::verify::helpers::verify_rfc3161_anchor` (reachable through the
/// public [`atl_core::AnchorVerificationContext`] / `VerifyOptions` path).
/// That helper module is declared `pub(in crate::core)`, so it is not
/// reachable from this crate directly - only the whole-receipt convenience
/// functions (`verify_receipt_anchor_only` and friends, used by
/// [`crate::verify::single::verify_single`] for the offline pass) can reach
/// it, and those collapse each anchor down to a bare `is_valid: bool` with
/// no TSA/OTS detail fields. This online path re-verifies anchors itself
/// (to add the rich [`Rfc3161AnchorFacts`] fields and Bitcoin block info
/// that the offline `VerificationResult` does not carry), so it has to
/// duplicate the target/`target_hash` pinning check rather than call into
/// `atl-core` for it. We keep the duplication to the lines below and use
/// the same `subtle` constant-time comparison `atl-core` uses internally.
///
/// # Trust
///
/// Steps 3-5 of the spec are: (3) decode `token_der`, (4) verify the TSA's
/// cryptographic signature over the token, (5) verify the token's
/// `messageImprint` matches `anchor.target_hash`. All three, plus
/// certificate-chain construction/validation and Extended Key Usage
/// checking, are performed by `atl_core::verify_rfc3161_token`, which
/// returns the full [`Rfc3161AnchorFacts`] rather than a verdict. Per the
/// ATL trust model (see `docs-md/atl-trust-model-decisions.md`), this crate
/// ships no TSA roots: without a caller-supplied `trust_store` (from
/// `--tsa-trust-store`), the best any anchor can reach is
/// [`Rfc3161Trust::Assumed`] — cryptographically sound, but nobody vouches
/// for the root — which never counts as `verified: true`.
fn verify_rfc3161(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    token_der: &str,
    data_tree_root: &str,
    trust_store: Option<&TrustStore>,
) -> AnchorVerificationResult {
    // STEP 1: Validate target
    if target != ANCHOR_TARGET_DATA_TREE_ROOT {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some(format!(
                "Invalid target '{}', expected '{}'",
                target, ANCHOR_TARGET_DATA_TREE_ROOT
            )),
            details: AnchorDetails::Unknown,
        };
    }

    // Decode the hash the anchor CLAIMS to be timestamping. This is
    // attacker-controlled input from the receipt itself - it is not yet
    // trusted to say anything about THIS receipt's Data Tree.
    let claimed_hash = match decode_hash_hex(target_hash) {
        Ok(h) => h,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(e),
                details: AnchorDetails::Unknown,
            }
        }
    };

    // Decode this receipt's actual Data Tree root from `proof.root_hash`.
    let expected_root = match decode_hash_hex(data_tree_root) {
        Ok(h) => h,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("invalid proof.root_hash: {e}")),
                details: AnchorDetails::Unknown,
            }
        }
    };

    // STEP 2: Pin the anchor to THIS receipt's Data Tree root. See the
    // doc comment on this function for why this duplicates atl-core logic
    // instead of calling into it.
    if !constant_time_eq(&claimed_hash, &expected_root) {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("target_hash does not match proof.root_hash".to_string()),
            details: AnchorDetails::Unknown,
        };
    }

    // Ensure "base64:" prefix for atl-core
    let token_with_prefix = if token_der.starts_with("base64:") {
        token_der.to_string()
    } else {
        format!("base64:{}", token_der)
    };

    // STEPS 3-5 plus trust (see the "Trust" section of this function's doc
    // comment). We pass the receipt's own root hash (now proven equal to
    // the anchor's claim) as the expected hash - not the anchor's claim
    // itself, so a future refactor here can't accidentally drop the
    // pinning check above and still "work". `trust_store` comes only from
    // `--tsa-trust-store`, never from anything inside the receipt or token.
    match verify_rfc3161_token(&token_with_prefix, &expected_root, trust_store) {
        Ok(facts) => {
            let details = AnchorDetails::Rfc3161 {
                imprint_matches_root: facts.imprint_matches_root,
                cms_signature_valid: facts.cms_signature_valid,
                chain_valid_at_gen_time: facts.chain_valid_at_gen_time,
                timestamping_eku_ok: facts.timestamping_eku_ok,
                path_status: facts.path_status,
                terminal_anchor: facts.terminal_anchor,
                revocation: facts.revocation,
            };
            let verified = details.rfc3161_trust() == Some(Rfc3161Trust::Trusted);
            let error = if verified {
                None
            } else {
                Some(summarize_rfc3161(&facts))
            };
            AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                verified,
                timestamp_nanos: facts.gen_time.or_else(|| parse_iso8601_to_nanos(timestamp)),
                error,
                details,
            }
        }
        Err(e) => AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: false,
            timestamp_nanos: parse_iso8601_to_nanos(timestamp),
            error: Some(e.to_string()),
            details: AnchorDetails::Unknown,
        },
    }
}

/// Verify Bitcoin/OTS anchor using atl-core + Bitcoin API
async fn verify_bitcoin_ots(
    target: &str,
    target_hash: &str,
    ots_proof: &str,
    super_root: Option<&str>,
    config: &OnlineConfig,
) -> AnchorVerificationResult {
    // Validate target
    if target != ANCHOR_TARGET_SUPER_ROOT {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some(format!(
                "Invalid target '{}', expected '{}'",
                target, ANCHOR_TARGET_SUPER_ROOT
            )),
            details: AnchorDetails::Unknown,
        };
    }

    // Validate super_root exists
    let Some(expected_super_root) = super_root else {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("Receipt has no super_proof".to_string()),
            details: AnchorDetails::Unknown,
        };
    };

    // Decode the hash the anchor CLAIMS to be timestamping (attacker-
    // controlled, from the receipt's own anchor entry) before comparing it
    // against anything, mirroring the RFC 3161 path above.
    let claimed_hash = match decode_hash_hex(target_hash) {
        Ok(h) => h,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(e),
                details: AnchorDetails::Unknown,
            }
        }
    };

    let expected_hash = match decode_hash_hex(expected_super_root) {
        Ok(h) => h,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("invalid super_proof.super_root: {e}")),
                details: AnchorDetails::Unknown,
            }
        }
    };

    // Validate target_hash matches super_proof.super_root, in constant time
    // (see `constant_time_eq` doc comment for why - not a secret, but this
    // keeps hash comparisons consistent across the whole file).
    if !constant_time_eq(&claimed_hash, &expected_hash) {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("target_hash does not match super_root".to_string()),
            details: AnchorDetails::Unknown,
        };
    }

    // CALL atl-core function for OTS parsing and verification
    let ots_result = match verify_ots_anchor_impl(ots_proof, &expected_hash) {
        Ok(r) => r,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                verified: false,
                timestamp_nanos: None,
                error: Some(format!("OTS verification failed: {e}")),
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

    // Check merkle path is not empty
    if earliest.merkle_path.is_empty() {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some("Empty merkle path in attestation".to_string()),
            details: AnchorDetails::Unknown,
        };
    }

    // Extract computed root (last hash, byte-reversed for display, with sha256: prefix)
    let computed_root = earliest
        .merkle_path
        .last()
        .map_or_else(String::new, |last_hash| {
            let mut reversed = *last_hash;
            reversed.reverse();
            format!("sha256:{}", hex::encode(reversed))
        });

    let operation_count = earliest.merkle_path.len();

    // Fetch block info with merkle_root
    let block_info =
        match crate::net::bitcoin::get_block_info(earliest.block_height, config.request_timeout)
            .await
        {
            Ok(info) => info,
            Err(e) => {
                // Return with partial data for offline-like display
                return AnchorVerificationResult {
                    anchor_type: "bitcoin_ots".to_string(),
                    verified: false,
                    timestamp_nanos: None,
                    error: Some(e.to_string()),
                    details: AnchorDetails::Bitcoin {
                        block_height: earliest.block_height,
                        block_timestamp_secs: 0,
                        target_hash: target_hash.to_string(),
                        operation_count,
                        computed_root,
                        block_merkle_root: None,
                        merkle_match: None,
                    },
                };
            }
        };

    // CRITICAL: Verify merkle root matches (using atl-core method)
    let merkle_match = earliest.verify_against_block(&block_info.merkle_root);

    if !merkle_match {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            verified: false,
            timestamp_nanos: None,
            error: Some(format!(
                "Merkle root mismatch: OTS proof does not match block {}",
                earliest.block_height
            )),
            details: AnchorDetails::Bitcoin {
                block_height: block_info.height,
                block_timestamp_secs: block_info.timestamp_secs,
                target_hash: target_hash.to_string(),
                operation_count,
                computed_root,
                block_merkle_root: Some(format!("sha256:{}", block_info.merkle_root)),
                merkle_match: Some(false),
            },
        };
    }

    // SUCCESS: Cryptographic verification complete
    let timestamp_nanos = block_info.timestamp_secs * 1_000_000_000;
    AnchorVerificationResult {
        anchor_type: "bitcoin_ots".to_string(),
        verified: true,
        timestamp_nanos: Some(timestamp_nanos),
        error: None,
        details: AnchorDetails::Bitcoin {
            block_height: block_info.height,
            block_timestamp_secs: block_info.timestamp_secs,
            target_hash: target_hash.to_string(),
            operation_count,
            computed_root,
            block_merkle_root: Some(format!("sha256:{}", block_info.merkle_root)),
            merkle_match: Some(true),
        },
    }
}

/// Verify anchors online for single file
///
/// `trust_store` carries whatever RFC 3161 trust material the caller passed
/// via `--tsa-trust-store` (or `None` if they passed nothing); it is
/// forwarded to every RFC 3161 anchor's verification unchanged and is never
/// derived from the receipt itself.
pub async fn verify_single_online(
    result: SingleVerificationResult,
    config: &OnlineConfig,
    trust_store: Option<&TrustStore>,
) -> CliResult<OnlineVerificationResult> {
    let mut anchor_results = Vec::new();

    let super_root = result
        .receipt
        .super_proof
        .as_ref()
        .map(|sp| sp.super_root.as_str());
    let data_tree_root = result.receipt.proof.root_hash.as_str();

    for anchor in &result.receipt.anchors {
        let anchor_result = match anchor {
            ReceiptAnchor::Rfc3161 {
                target,
                target_hash,
                timestamp,
                token_der,
                ..
            } => verify_rfc3161(
                target,
                target_hash,
                timestamp,
                token_der,
                data_tree_root,
                trust_store,
            ),
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

    /// `proof.root_hash` used by [`create_test_receipt`]. Reused wherever a
    /// test needs to construct an anchor that is (or deliberately isn't)
    /// pinned to it.
    const TEST_ROOT_HASH: &str =
        "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    /// A well-formed but different 32-byte hash, for negative tests.
    const OTHER_HASH: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // `decode_hash_hex` delegates entirely to `atl_core::core::checkpoint::
    // parse_hash` (see its doc comment); these tests pin that its observable
    // behavior actually matches atl-core's parser, since this crate accepts
    // no hash format atl-core itself would reject.

    #[test]
    fn test_decode_hash_hex_valid_lowercase() {
        let result = decode_hash_hex(TEST_ROOT_HASH);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_hash_hex_rejects_bare_hex_without_prefix() {
        // No "sha256:" prefix at all - atl-core's `parse_hash` rejects this,
        // and so must we (this is exactly the discrepancy this fix closes:
        // the old bespoke decoder in this file used to accept this).
        let bare = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = decode_hash_hex(bare);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing sha256: prefix"));
    }

    #[test]
    fn test_decode_hash_hex_rejects_uppercase_prefix() {
        // "SHA256:" (uppercase) is a different, unrecognized prefix to
        // atl-core's `parse_hash` - it does not case-fold the prefix.
        let uppercase_prefix =
            "SHA256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = decode_hash_hex(uppercase_prefix);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing sha256: prefix"));
    }

    #[test]
    fn test_decode_hash_hex_accepts_mixed_case_hex_digits() {
        // Unlike the prefix, the hex *digits* after it are case-insensitive
        // in both `hex::decode` and atl-core's `parse_hash` (which uses the
        // same `hex` crate) - "AbCd" and "abcd" decode to the same bytes.
        let mixed_case = "sha256:1234567890ABCDEF1234567890abcdef1234567890ABCDEF1234567890abcdef";
        let lower = decode_hash_hex(TEST_ROOT_HASH).expect("lowercase must parse");
        let mixed = decode_hash_hex(mixed_case).expect("mixed-case hex digits must parse");
        assert_eq!(lower, mixed);
    }

    #[test]
    fn test_decode_hash_hex_rejects_empty_string() {
        let result = decode_hash_hex("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing sha256: prefix"));
    }

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
            imprint_matches_root: true,
            cms_signature_valid: true,
            chain_valid_at_gen_time: true,
            timestamping_eku_ok: true,
            path_status: PathStatus::Complete,
            terminal_anchor: None,
            revocation: Revocation::NotChecked,
        };
        let bitcoin = AnchorDetails::Bitcoin {
            block_height: 800000,
            block_timestamp_secs: 1700000000,
            target_hash: "sha256:abc".to_string(),
            operation_count: 10,
            computed_root: "sha256:def".to_string(),
            block_merkle_root: Some("sha256:ghi".to_string()),
            merkle_match: Some(true),
        };
        let unknown = AnchorDetails::Unknown;

        // Just ensure variants construct properly
        match rfc {
            AnchorDetails::Rfc3161 {
                imprint_matches_root,
                ..
            } => {
                assert!(imprint_matches_root);
            }
            _ => panic!("Wrong variant"),
        }
        match bitcoin {
            AnchorDetails::Bitcoin {
                block_height,
                block_timestamp_secs,
                target_hash,
                operation_count,
                computed_root,
                block_merkle_root,
                merkle_match,
            } => {
                assert_eq!(block_height, 800000);
                assert_eq!(block_timestamp_secs, 1700000000);
                assert_eq!(target_hash, "sha256:abc");
                assert_eq!(operation_count, 10);
                assert_eq!(computed_root, "sha256:def");
                assert_eq!(block_merkle_root, Some("sha256:ghi".to_string()));
                assert_eq!(merkle_match, Some(true));
            }
            _ => panic!("Wrong variant"),
        }
        match unknown {
            AnchorDetails::Unknown => {}
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn rfc3161_trust_is_none_for_non_rfc3161_details() {
        assert_eq!(AnchorDetails::Unknown.rfc3161_trust(), None);
        let bitcoin = AnchorDetails::Bitcoin {
            block_height: 1,
            block_timestamp_secs: 1,
            target_hash: String::new(),
            operation_count: 0,
            computed_root: String::new(),
            block_merkle_root: None,
            merkle_match: None,
        };
        assert_eq!(bitcoin.rfc3161_trust(), None);
    }

    #[test]
    fn rfc3161_trust_is_trusted_only_when_sound_and_caller_trusted() {
        let sound_and_trusted = AnchorDetails::Rfc3161 {
            imprint_matches_root: true,
            cms_signature_valid: true,
            chain_valid_at_gen_time: true,
            timestamping_eku_ok: true,
            path_status: PathStatus::Complete,
            terminal_anchor: Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32],
            }),
            revocation: Revocation::NotChecked,
        };
        assert_eq!(
            sound_and_trusted.rfc3161_trust(),
            Some(Rfc3161Trust::Trusted)
        );
    }

    #[test]
    fn rfc3161_trust_is_assumed_when_sound_but_terminal_anchor_unverified() {
        // THE regression test for the bug this rewrite closes: a token can
        // be entirely cryptographically sound (imprint, CMS signature,
        // chain, EKU all valid) and STILL never be `Trusted` if nobody
        // vouches for the terminal certificate.
        let sound_but_assumed = AnchorDetails::Rfc3161 {
            imprint_matches_root: true,
            cms_signature_valid: true,
            chain_valid_at_gen_time: true,
            timestamping_eku_ok: true,
            path_status: PathStatus::Complete,
            terminal_anchor: Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [0u8; 32],
            }),
            revocation: Revocation::NotChecked,
        };
        assert_eq!(
            sound_but_assumed.rfc3161_trust(),
            Some(Rfc3161Trust::Assumed)
        );
    }

    #[test]
    fn rfc3161_trust_is_failed_when_any_fact_is_false_even_if_trusted_anchor() {
        // A `Trusted` terminal anchor does not paper over a broken fact
        // elsewhere in the chain (e.g. EKU missing) — a trusted root signing
        // a certificate that is not fit for timestamping must not verify.
        let broken_eku = AnchorDetails::Rfc3161 {
            imprint_matches_root: true,
            cms_signature_valid: true,
            chain_valid_at_gen_time: true,
            timestamping_eku_ok: false,
            path_status: PathStatus::Complete,
            terminal_anchor: Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32],
            }),
            revocation: Revocation::NotChecked,
        };
        assert_eq!(broken_eku.rfc3161_trust(), Some(Rfc3161Trust::Failed));
    }

    #[test]
    fn rfc3161_trust_is_failed_when_no_terminal_anchor_reached() {
        let no_anchor = AnchorDetails::Rfc3161 {
            imprint_matches_root: true,
            cms_signature_valid: true,
            chain_valid_at_gen_time: false,
            timestamping_eku_ok: true,
            path_status: PathStatus::Incomplete,
            terminal_anchor: None,
            revocation: Revocation::NotChecked,
        };
        assert_eq!(no_anchor.rfc3161_trust(), Some(Rfc3161Trust::Failed));
    }

    #[test]
    fn test_anchor_verification_result_creation() {
        let result = AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verified: true,
            timestamp_nanos: Some(1234567890),
            error: None,
            details: AnchorDetails::Rfc3161 {
                imprint_matches_root: true,
                cms_signature_valid: true,
                chain_valid_at_gen_time: true,
                timestamping_eku_ok: true,
                path_status: PathStatus::Complete,
                terminal_anchor: Some(TerminalAnchor::Trusted {
                    sha256_fingerprint: [0u8; 32],
                }),
                revocation: Revocation::NotChecked,
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
            TEST_ROOT_HASH,
            None,
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert!(result
            .error
            .unwrap()
            .contains("Invalid target 'wrong_target'"));
    }

    #[test]
    fn test_verify_rfc3161_invalid_hex() {
        let result = verify_rfc3161(
            "data_tree_root",
            "sha256:notvalidhex",
            "2024-01-01T00:00:00Z",
            "base64:token",
            TEST_ROOT_HASH,
            None,
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        // Message now comes from `atl_core::parse_hash` via `decode_hash_hex`.
        assert!(result.error.unwrap().contains("hex decode error"));
    }

    #[test]
    fn test_verify_rfc3161_wrong_hash_length() {
        let result = verify_rfc3161(
            "data_tree_root",
            "sha256:aabb",
            "2024-01-01T00:00:00Z",
            "base64:token",
            TEST_ROOT_HASH,
            None,
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        // Message now comes from `atl_core::parse_hash` via `decode_hash_hex`.
        assert!(result.error.unwrap().contains("invalid hash length"));
    }

    #[test]
    fn test_verify_rfc3161_target_hash_mismatch_fails() {
        // THE regression test for the anchor-pinning bug this fix preserves:
        // a well-formed `target_hash` that simply does not match
        // `proof.root_hash` MUST be rejected before any TSA token
        // verification is attempted, regardless of trust store. A genuine
        // timestamp token minted for a completely unrelated hash must never
        // be reported as proof for THIS receipt.
        let result = verify_rfc3161(
            "data_tree_root",
            OTHER_HASH, // does NOT match TEST_ROOT_HASH
            "2024-01-01T00:00:00Z",
            "base64:token",
            TEST_ROOT_HASH,
            None,
        );
        assert!(!result.verified);
        let error = result.error.expect("mismatch must produce an error");
        assert!(
            error.contains("target_hash does not match proof.root_hash"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_verify_rfc3161_invalid_root_hash() {
        // A malformed `proof.root_hash` (should never happen for a
        // structurally-valid receipt, but must fail closed, not panic).
        let result = verify_rfc3161(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "base64:token",
            "sha256:not-valid-hex",
            None,
        );
        assert!(!result.verified);
        let error = result
            .error
            .expect("invalid root hash must produce an error");
        assert!(
            error.contains("invalid proof.root_hash"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_verify_rfc3161_garbage_token_without_trust_store_fails() {
        // A token that doesn't even parse must fail closed (not panic, not
        // silently verify) with no trust store supplied.
        let result = verify_rfc3161(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "base64:c29tZXRva2Vu", // "sometoken", not valid CMS/DER
            TEST_ROOT_HASH,
            None,
        );
        assert!(!result.verified);
        assert!(result.error.is_some());
        assert_eq!(result.details.rfc3161_trust(), None);
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
        // Both values must be well-formed 32-byte hashes here: the mismatch
        // is now detected by decoding both sides and comparing bytes in
        // constant time, not by a raw string `!=` on the raw claims - so a
        // malformed claim would (correctly) be rejected as "invalid hex"
        // instead, which is covered separately by
        // `test_verify_bitcoin_ots_invalid_hex`.
        let config = OnlineConfig::default();
        let result = verify_bitcoin_ots(
            "super_root",
            TEST_ROOT_HASH,
            "base64:proof",
            Some(OTHER_HASH),
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
        // Message now comes from `atl_core::parse_hash` via `decode_hash_hex`.
        assert!(result.error.unwrap().contains("hex decode error"));
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
        // Message now comes from `atl_core::parse_hash` via `decode_hash_hex`.
        assert!(result.error.unwrap().contains("invalid hash length"));
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
        let result = verify_single_online(single, &config, None).await;
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
        let result = verify_single_online(single, &config, None).await;
        assert!(result.is_ok());
        let online = result.unwrap();
        assert_eq!(online.anchor_results.len(), 1);
        assert!(!online.anchor_results[0].verified);
        assert!(!online.all_anchors_verified);
    }

    #[tokio::test]
    async fn test_verify_single_online_rfc3161_target_hash_pinning_regression() {
        // Regression test for the anchor-pinning bug: `target` correctly
        // says "data_tree_root", but `target_hash` does NOT match this
        // receipt's `proof.root_hash` (TEST_ROOT_HASH). Before the fix,
        // `verify_single_online` never compared the anchor's `target_hash`
        // against the receipt's own root hash at all, so a TSA token
        // minted for a completely unrelated document could be reported as
        // valid for this receipt. It must now fail closed, and specifically
        // at the pinning step (not fall through to a TSA/token error).
        let mut single = create_test_single_result(true);
        assert_eq!(single.receipt.proof.root_hash, TEST_ROOT_HASH);
        single.receipt.anchors.push(ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: OTHER_HASH.to_string(), // does NOT match proof.root_hash
            tsa_url: "https://example.com/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        });

        let config = OnlineConfig::default();
        let online = verify_single_online(single, &config, None)
            .await
            .expect("verify_single_online must not error on a structurally valid receipt");

        assert_eq!(online.anchor_results.len(), 1);
        assert!(
            !online.anchor_results[0].verified,
            "anchor with mismatched target_hash must not verify"
        );
        assert!(!online.all_anchors_verified);
        assert!(!online.is_valid());
        let error = online.anchor_results[0]
            .error
            .as_deref()
            .expect("rejection must carry a reason");
        assert!(
            error.contains("target_hash does not match proof.root_hash"),
            "expected a pinning-specific error, got: {error}"
        );
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
        let result = verify_single_online(single, &config, None).await;
        assert!(result.is_ok());
        let online = result.unwrap();
        assert_eq!(online.anchor_results.len(), 1);
        assert!(!online.anchor_results[0].verified);
        assert!(!online.all_anchors_verified);
    }

    // Note: verify_merkle_root tests moved to atl-core (BitcoinAttestation::verify_against_block)

    #[test]
    fn should_reverse_bytes_for_computed_root_display() {
        // Arrange
        // Internal format (little-endian)
        let last_hash_hex = "6f20a87026e693f298b72fd96141f07e2628cb0553da748fcc9c1565ce6d822f";
        // Expected display format (big-endian, with sha256: prefix)
        let expected = "sha256:2f826dce65159ccc8f74da5305cb28267ef04161d92fb798f293e62670a8206f";

        let mut last_hash = [0u8; 32];
        hex::decode_to_slice(last_hash_hex, &mut last_hash).unwrap();

        // Act
        let mut reversed = last_hash;
        reversed.reverse();
        let result = format!("sha256:{}", hex::encode(reversed));

        // Assert
        assert_eq!(result, expected);
    }

    #[test]
    fn should_format_target_hash_with_sha256_prefix() {
        // Arrange
        let target_hash = "94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2";

        // Act
        let result = format!("sha256:{}", target_hash);

        // Assert
        assert_eq!(
            result,
            "sha256:94ee059335e587e501cc4bf90613e0814f00a7b08bc7c648fd865a2af6a22cc2"
        );
        assert_eq!(result.len(), 71); // "sha256:" (7) + 64 hex chars
    }

    #[test]
    fn should_populate_operation_count_from_merkle_path() {
        // Arrange
        let mut path = Vec::new();
        for _ in 0..39 {
            path.push([0u8; 32]);
        }

        // Act
        let count = path.len();

        // Assert
        assert_eq!(count, 39);
    }

    #[test]
    fn test_online_config_clone() {
        let config = OnlineConfig::default();
        let cloned = config.clone();
        assert_eq!(config.request_timeout, cloned.request_timeout);
    }

    #[test]
    fn test_online_config_debug() {
        let config = OnlineConfig::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("OnlineConfig"));
    }

    #[test]
    fn test_anchor_verification_result_clone() {
        let result = AnchorVerificationResult {
            anchor_type: "test".to_string(),
            verified: true,
            timestamp_nanos: Some(123),
            error: None,
            details: AnchorDetails::Unknown,
        };
        let cloned = result.clone();
        assert_eq!(cloned.anchor_type, "test");
        assert!(cloned.verified);
    }

    #[test]
    fn test_anchor_details_clone() {
        let rfc = AnchorDetails::Rfc3161 {
            imprint_matches_root: true,
            cms_signature_valid: true,
            chain_valid_at_gen_time: true,
            timestamping_eku_ok: true,
            path_status: PathStatus::Complete,
            terminal_anchor: None,
            revocation: Revocation::NotChecked,
        };
        let bitcoin = AnchorDetails::Bitcoin {
            block_height: 1,
            block_timestamp_secs: 2,
            target_hash: "hash".to_string(),
            operation_count: 3,
            computed_root: "root".to_string(),
            block_merkle_root: Some("merkle".to_string()),
            merkle_match: Some(true),
        };

        let rfc_cloned = rfc.clone();
        let bitcoin_cloned = bitcoin.clone();

        match rfc_cloned {
            AnchorDetails::Rfc3161 {
                imprint_matches_root,
                ..
            } => assert!(imprint_matches_root),
            _ => panic!("Wrong variant"),
        }

        match bitcoin_cloned {
            AnchorDetails::Bitcoin { block_height, .. } => assert_eq!(block_height, 1),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_online_verification_result_debug() {
        let single = create_test_single_result(true);
        let online = OnlineVerificationResult {
            offline: single,
            anchor_results: vec![],
            all_anchors_verified: true,
            mode: VerificationMode::Online,
        };
        let debug_str = format!("{:?}", online);
        assert!(debug_str.contains("OnlineVerificationResult"));
    }

    #[test]
    fn test_verify_rfc3161_with_base64_prefix() {
        // Test that base64: prefix is handled correctly. target_hash
        // matches TEST_ROOT_HASH so this clears the pinning check and
        // reaches (garbage-token) TSA verification.
        let result = verify_rfc3161(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "base64:c29tZXRva2Vu",
            TEST_ROOT_HASH,
            None,
        );
        // Will fail verification but should not fail on prefix handling
        assert!(!result.verified);
    }

    #[test]
    fn test_verify_rfc3161_without_base64_prefix() {
        // Test that missing base64: prefix is added. target_hash matches
        // TEST_ROOT_HASH so this clears the pinning check and reaches
        // (garbage-token) TSA verification.
        let result = verify_rfc3161(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "c29tZXRva2Vu",
            TEST_ROOT_HASH,
            None,
        );
        // Will fail verification but should not fail on prefix handling
        assert!(!result.verified);
    }
}
