//! Anchor verification and the per-anchor verdict every renderer reads.
//!
//! RFC 3161 verification is **pure computation**: decoding the token,
//! checking the CMS signature, and walking the certificate chain need no
//! network access whatsoever. It therefore runs on every verification,
//! offline and online alike, and lives here rather than in
//! [`crate::verify::online`]. Only `bitcoin_ots` anchors need the network,
//! and only to fetch the block whose Merkle root confirms the OTS proof.
//!
//! Per the ATL trust model (`docs-md/atl-trust-model-decisions.md`, decision
//! Р1) nothing in this module knows any identity: no root, no fingerprint,
//! no TSA name. All trust material arrives as a caller-supplied
//! [`TrustStore`], built from `--tsa-trust-store` / `--tsa-intermediates`.

use atl_core::core::ots::BitcoinAttestation;
use atl_core::core::verify::anchors::bitcoin_ots::verify_ots_anchor_impl;
use atl_core::core::verify::anchors::rfc3161::verify_rfc3161_token;
use atl_core::core::verify::iso8601::parse_iso8601_to_nanos;
use atl_core::{
    PathStatus, ReceiptAnchor, Revocation, Rfc3161AnchorFacts, TerminalAnchor, TrustStore,
    ANCHOR_TARGET_DATA_TREE_ROOT, ANCHOR_TARGET_SUPER_ROOT,
};
use subtle::ConstantTimeEq;

use crate::verify::verdict::ReasonCode;

/// Verdict for a single anchor.
///
/// The three states mirror [`crate::verify::verdict::Status`] minus
/// `Pending` (an anchor that exists is never "unanchored"):
/// `Invalid` means a fact about the anchor is false, `Untrusted` means every
/// fact holds but the check could not be completed with the material this
/// verifier was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// Every fact holds and the anchor reached a configured trust root.
    Valid,
    /// Nothing is refuted; trust material is missing on the verifier's side.
    Untrusted(ReasonCode),
    /// At least one fact about the anchor is false.
    Invalid(ReasonCode),
}

impl AnchorVerdict {
    /// `true` only for [`Self::Valid`].
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }

    /// The reason code, or `None` for [`Self::Valid`].
    #[must_use]
    pub const fn reason_code(self) -> Option<ReasonCode> {
        match self {
            Self::Valid => None,
            Self::Untrusted(code) | Self::Invalid(code) => Some(code),
        }
    }
}

/// Result of verifying one anchor.
#[derive(Debug, Clone)]
pub struct AnchorVerificationResult {
    /// `"rfc3161"` or `"bitcoin_ots"`.
    pub anchor_type: String,
    /// The single classification every consumer derives from.
    pub verdict: AnchorVerdict,
    /// Anchor-asserted time, in nanoseconds since the epoch.
    pub timestamp_nanos: Option<u64>,
    /// Human-readable elaboration. Never load-bearing: branch on
    /// [`Self::verdict`], not on this text.
    pub error: Option<String>,
    /// The full fact set, carried through rather than collapsed.
    pub details: AnchorDetails,
}

impl AnchorVerificationResult {
    /// `true` only when this anchor is fully accepted.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verdict.is_valid()
    }
}

/// Facts established about an anchor, reported rather than collapsed into a
/// single boolean — this is what lets the CLI tell "refuted" apart from
/// "not corroborated".
#[derive(Debug, Clone)]
pub enum AnchorDetails {
    /// The complete fact set from `atl-core`'s RFC 3161 verifier (see
    /// [`Rfc3161AnchorFacts`]).
    Rfc3161 {
        /// The token's `MessageImprint` matches the receipt's root hash.
        imprint_matches_root: bool,
        /// The CMS `SignerInfo` signature verified.
        cms_signature_valid: bool,
        /// Every link on the constructed path was valid at `genTime`.
        ///
        /// `atl-core` reports this as `false` whenever no complete path was
        /// built, so it is only a *refutation* when `path_status` is
        /// [`PathStatus::Invalid`] — see [`AnchorDetails::rfc3161_verdict`].
        chain_valid_at_gen_time: bool,
        /// The signer certificate carries the exclusive critical
        /// `id-kp-timeStamping` EKU.
        timestamping_eku_ok: bool,
        /// How chain construction terminated.
        path_status: PathStatus,
        /// The certificate the chain terminated at, if any.
        terminal_anchor: Option<TerminalAnchor>,
        /// Revocation status (always `NotChecked` today).
        revocation: Revocation,
    },
    /// Bitcoin OpenTimestamps anchor facts.
    Bitcoin {
        /// Block height named by the earliest attestation.
        block_height: u64,
        /// Block time in seconds, or `0` when no block was fetched.
        block_timestamp_secs: u64,
        /// The anchor's `target_hash`, as written in the receipt.
        target_hash: String,
        /// Number of hash operations in the OTS Merkle path.
        operation_count: usize,
        /// Merkle root computed from the OTS proof (`sha256:` prefixed).
        computed_root: String,
        /// The real block's Merkle root, or `None` if no block was fetched.
        block_merkle_root: Option<String>,
        /// Whether the two roots match, or `None` if no block was fetched.
        merkle_match: Option<bool>,
    },
    /// The anchor was rejected before any fact set could be established.
    Unknown,
}

impl AnchorDetails {
    /// Classify an RFC 3161 anchor's facts. Returns `None` for any other
    /// anchor type.
    ///
    /// This is the ONLY place the RFC 3161 trust decision is made; the
    /// per-anchor verdict, the receipt status, both renderers and the exit
    /// code are all derived from it.
    ///
    /// The order of the checks is load-bearing. `path_status` is inspected
    /// *before* `chain_valid_at_gen_time`, because `atl-core` sets that flag
    /// to `false` for an `Incomplete` path too — where it means "no path was
    /// validated", not "a path was found and rejected". Reading it as a
    /// refutation there is exactly the mistake that used to report a
    /// cross-signed Sectigo/DigiCert chain as broken evidence.
    #[must_use]
    pub fn rfc3161_verdict(&self) -> Option<AnchorVerdict> {
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

        // Facts that are outright false: the evidence is refuted.
        if !*imprint_matches_root {
            return Some(AnchorVerdict::Invalid(ReasonCode::TsaImprintMismatch));
        }
        if !*cms_signature_valid {
            return Some(AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid));
        }
        if !*timestamping_eku_ok {
            return Some(AnchorVerdict::Invalid(
                ReasonCode::TsaTimestampingEkuInvalid,
            ));
        }

        Some(match path_status {
            // A candidate link was found and failed validation.
            PathStatus::Invalid => AnchorVerdict::Invalid(ReasonCode::TsaChainInvalidAtGenTime),
            // Ran out of certificates before any terminal: a missing issuer,
            // not a broken one.
            PathStatus::Incomplete => AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete),
            PathStatus::Complete => {
                if *chain_valid_at_gen_time {
                    match terminal_anchor {
                        Some(TerminalAnchor::Trusted { .. }) => AnchorVerdict::Valid,
                        Some(TerminalAnchor::Assumed { .. }) => {
                            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted)
                        }
                        // `Complete` always carries a terminal in atl-core;
                        // treat the impossible case as missing material
                        // rather than as a refutation.
                        None => AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete),
                    }
                } else {
                    AnchorVerdict::Invalid(ReasonCode::TsaChainInvalidAtGenTime)
                }
            }
        })
    }

    /// Stable JSON/prose label for an RFC 3161 anchor's trust state,
    /// derived from [`Self::rfc3161_verdict`] so it can never disagree with
    /// the verdict, the status, or the exit code.
    #[must_use]
    pub fn rfc3161_trust_state(&self) -> Option<&'static str> {
        Some(match self.rfc3161_verdict()? {
            AnchorVerdict::Valid => "trusted",
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted) => "assumed",
            AnchorVerdict::Untrusted(_) => "incomplete",
            AnchorVerdict::Invalid(_) => "failed",
        })
    }

    /// The SHA-256 fingerprint (hex, no prefix) of the certificate a caller
    /// would have to add to `--tsa-trust-store` to turn an
    /// `Untrusted`/`Assumed` outcome into `Valid`. `None` when the chain
    /// never reached a terminal (nothing specific to name).
    #[must_use]
    pub fn untrusted_root_fingerprint(&self) -> Option<String> {
        match self {
            Self::Rfc3161 {
                terminal_anchor: Some(TerminalAnchor::Assumed { sha256_fingerprint }),
                ..
            } => Some(hex::encode(sha256_fingerprint)),
            _ => None,
        }
    }
}

/// Decode a `"sha256:<64 hex chars>"` string into a 32-byte hash.
///
/// Delegates to [`atl_core::core::checkpoint::parse_hash`] so this crate's
/// notion of "a valid hash string" can never drift from `atl-core`'s. The
/// prefix must be exactly `"sha256:"` (lowercase); the hex digits
/// themselves are case-insensitive.
fn decode_hash_hex(s: &str) -> Result<[u8; 32], String> {
    atl_core::core::checkpoint::parse_hash(s).map_err(|e| e.to_string())
}

/// Constant-time 32-byte comparison.
///
/// The hashes compared here are not secret (they are published inside the
/// receipt), but comparing them in constant time matches `atl-core`'s own
/// internal pinning and this project's policy of never using `==` on
/// hash/digest values.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Build a rejection result carrying no fact set.
fn rejected(
    anchor_type: &str,
    verdict: AnchorVerdict,
    timestamp_nanos: Option<u64>,
    error: String,
) -> AnchorVerificationResult {
    AnchorVerificationResult {
        anchor_type: anchor_type.to_string(),
        verdict,
        timestamp_nanos,
        error: Some(error),
        details: AnchorDetails::Unknown,
    }
}

/// Render a compact explanation of why an RFC 3161 anchor did not reach
/// `Valid`.
///
/// Prose only: every fact it reads was already computed by `atl-core`'s
/// `verify_rfc3161_token`, and the verdict was already decided by
/// [`AnchorDetails::rfc3161_verdict`]. This function re-derives nothing.
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
    if !facts.timestamping_eku_ok {
        reasons.push(
            "signer certificate lacks the exclusive critical id-kp-timeStamping EKU".to_string(),
        );
    }
    match facts.path_status {
        PathStatus::Invalid => {
            reasons.push("certificate chain invalid at genTime".to_string());
        }
        PathStatus::Incomplete => {
            reasons.push(
                "certificate chain incomplete: an issuer certificate is missing from the token \
                 -- supply it with --tsa-intermediates"
                    .to_string(),
            );
        }
        PathStatus::Complete => {}
    }
    match &facts.terminal_anchor {
        Some(TerminalAnchor::Assumed { sha256_fingerprint }) => {
            reasons.push(format!(
                "chain terminates in a certificate no trust store names (sha256:{}) -- supply it \
                 with --tsa-trust-store",
                hex::encode(sha256_fingerprint)
            ));
        }
        None | Some(TerminalAnchor::Trusted { .. }) => {}
    }
    if reasons.is_empty() {
        "verification did not reach aggregate success".to_string()
    } else {
        reasons.join("; ")
    }
}

/// Verify one RFC 3161 anchor. Entirely local: no network access.
///
/// # Anchor pinning (ATL Protocol v2.0, "RFC 3161 Anchor", steps 1-2)
///
/// Steps 1 and 2 require checking that `anchor.target` is `"data_tree_root"`
/// and that `anchor.target_hash` equals `proof.root_hash` *before* any
/// cryptographic verification. Without step 2 a genuine token minted for an
/// unrelated hash would be reported as proof for THIS receipt: the token
/// only proves the TSA once timestamped `anchor.target_hash`.
///
/// `atl-core` performs the same pinning internally in
/// `core::verify::helpers::verify_rfc3161_anchor`, but that module is
/// `pub(in crate::core)` and the reachable whole-receipt entry points
/// collapse each anchor to a bare `is_valid: bool`. This path needs the full
/// [`Rfc3161AnchorFacts`], so it duplicates the pinning check — kept to the
/// few lines below, using the same `subtle` constant-time comparison.
///
/// # Trust
///
/// Steps 3-5 (decode, verify the CMS signature, match the `messageImprint`)
/// plus chain construction, validity at `genTime` and EKU checking are all
/// performed by [`verify_rfc3161_token`]. `trust_store` comes only from the
/// caller's flags, never from the receipt or the token.
pub fn verify_rfc3161_anchor(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    token_der: &str,
    data_tree_root: &str,
    trust_store: Option<&TrustStore>,
) -> AnchorVerificationResult {
    // STEP 1: the anchor must target the Data Tree root.
    if target != ANCHOR_TARGET_DATA_TREE_ROOT {
        return rejected(
            "rfc3161",
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetInvalid),
            None,
            format!("Invalid target '{target}', expected '{ANCHOR_TARGET_DATA_TREE_ROOT}'"),
        );
    }

    // Attacker-controlled input from the receipt: not yet trusted to say
    // anything about THIS receipt's Data Tree.
    let claimed_hash = match decode_hash_hex(target_hash) {
        Ok(h) => h,
        Err(e) => {
            return rejected(
                "rfc3161",
                AnchorVerdict::Invalid(ReasonCode::AnchorHashMalformed),
                None,
                e,
            )
        }
    };

    let expected_root = match decode_hash_hex(data_tree_root) {
        Ok(h) => h,
        Err(e) => {
            return rejected(
                "rfc3161",
                AnchorVerdict::Invalid(ReasonCode::AnchorHashMalformed),
                None,
                format!("invalid proof.root_hash: {e}"),
            )
        }
    };

    // STEP 2: pin the anchor to THIS receipt's Data Tree root.
    if !constant_time_eq(&claimed_hash, &expected_root) {
        return rejected(
            "rfc3161",
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch),
            None,
            "target_hash does not match proof.root_hash".to_string(),
        );
    }

    let token_with_prefix = if token_der.starts_with("base64:") {
        token_der.to_string()
    } else {
        format!("base64:{token_der}")
    };

    // STEPS 3-5 plus trust. The receipt's own root hash (now proven equal to
    // the anchor's claim) is passed as the expected hash, not the anchor's
    // claim, so a future refactor cannot drop the pinning check above and
    // still appear to work.
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
            let verdict = details.rfc3161_verdict().unwrap_or(AnchorVerdict::Invalid(
                ReasonCode::ReceiptVerificationFailed,
            ));
            let error = if verdict.is_valid() {
                None
            } else {
                Some(summarize_rfc3161(&facts))
            };
            AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                verdict,
                timestamp_nanos: facts.gen_time.or_else(|| parse_iso8601_to_nanos(timestamp)),
                error,
                details,
            }
        }
        Err(e) => rejected(
            "rfc3161",
            AnchorVerdict::Invalid(ReasonCode::TsaTokenUnparsable),
            parse_iso8601_to_nanos(timestamp),
            e.to_string(),
        ),
    }
}

/// Everything a Bitcoin OTS anchor's local (network-free) pass establishes.
pub struct PreparedOts {
    /// Earliest Bitcoin attestation in the proof.
    pub attestation: BitcoinAttestation,
    /// Merkle root computed from the OTS proof, `sha256:` prefixed.
    pub computed_root: String,
    /// Number of hash operations in the OTS Merkle path.
    pub operation_count: usize,
}

/// Run every network-free check a `bitcoin_ots` anchor admits: target
/// pinning, OTS proof decoding, and extraction of the earliest attestation.
///
/// Returns `Err(result)` with a finished rejection when a check fails, so
/// both the offline and the online path share exactly these rules.
///
/// The `Err` variant is a full [`AnchorVerificationResult`] on purpose: a
/// rejected anchor must carry the same reported shape as an accepted one,
/// and boxing it here would buy a few stack bytes on a path that runs at
/// most a handful of times per receipt.
#[allow(clippy::result_large_err)]
pub fn prepare_bitcoin_ots(
    target: &str,
    target_hash: &str,
    ots_proof: &str,
    super_root: Option<&str>,
) -> Result<PreparedOts, AnchorVerificationResult> {
    if target != ANCHOR_TARGET_SUPER_ROOT {
        return Err(rejected(
            "bitcoin_ots",
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetInvalid),
            None,
            format!("Invalid target '{target}', expected '{ANCHOR_TARGET_SUPER_ROOT}'"),
        ));
    }

    let Some(expected_super_root) = super_root else {
        return Err(rejected(
            "bitcoin_ots",
            AnchorVerdict::Invalid(ReasonCode::SuperProofMissing),
            None,
            "Receipt has no super_proof".to_string(),
        ));
    };

    let claimed_hash = match decode_hash_hex(target_hash) {
        Ok(h) => h,
        Err(e) => {
            return Err(rejected(
                "bitcoin_ots",
                AnchorVerdict::Invalid(ReasonCode::AnchorHashMalformed),
                None,
                e,
            ))
        }
    };

    let expected_hash = match decode_hash_hex(expected_super_root) {
        Ok(h) => h,
        Err(e) => {
            return Err(rejected(
                "bitcoin_ots",
                AnchorVerdict::Invalid(ReasonCode::AnchorHashMalformed),
                None,
                format!("invalid super_proof.super_root: {e}"),
            ))
        }
    };

    if !constant_time_eq(&claimed_hash, &expected_hash) {
        return Err(rejected(
            "bitcoin_ots",
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch),
            None,
            "target_hash does not match super_root".to_string(),
        ));
    }

    let ots_result = match verify_ots_anchor_impl(ots_proof, &expected_hash) {
        Ok(r) => r,
        Err(e) => {
            return Err(rejected(
                "bitcoin_ots",
                AnchorVerdict::Invalid(ReasonCode::BitcoinOtsProofInvalid),
                None,
                format!("OTS verification failed: {e}"),
            ))
        }
    };

    let Some(earliest) = ots_result
        .attestations
        .iter()
        .min_by_key(|a| a.block_height)
    else {
        return Err(rejected(
            "bitcoin_ots",
            AnchorVerdict::Invalid(ReasonCode::BitcoinOtsProofInvalid),
            None,
            "No Bitcoin attestations in OTS proof".to_string(),
        ));
    };

    let Some(last_hash) = earliest.merkle_path.last() else {
        return Err(rejected(
            "bitcoin_ots",
            AnchorVerdict::Invalid(ReasonCode::BitcoinOtsProofInvalid),
            None,
            "Empty merkle path in attestation".to_string(),
        ));
    };

    // Bitcoin displays hashes byte-reversed relative to their internal form.
    let mut reversed = *last_hash;
    reversed.reverse();

    Ok(PreparedOts {
        computed_root: format!("sha256:{}", hex::encode(reversed)),
        operation_count: earliest.merkle_path.len(),
        attestation: earliest.clone(),
    })
}

/// Verify a `bitcoin_ots` anchor as far as is possible without the network.
///
/// A structurally sound OTS proof whose block was never fetched is
/// [`AnchorVerdict::Untrusted`], not `Valid`: the proof's computed Merkle
/// root has not been compared against any real block, so nothing external
/// corroborates it yet. Reporting it as accepted would be the same silent
/// overclaim as printing `mode: online` without going online.
pub fn verify_bitcoin_ots_offline(
    target: &str,
    target_hash: &str,
    ots_proof: &str,
    super_root: Option<&str>,
) -> AnchorVerificationResult {
    let prepared = match prepare_bitcoin_ots(target, target_hash, ots_proof, super_root) {
        Ok(p) => p,
        Err(result) => return result,
    };

    AnchorVerificationResult {
        anchor_type: "bitcoin_ots".to_string(),
        verdict: AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockNotChecked),
        timestamp_nanos: None,
        error: Some(
            "Bitcoin block not fetched: the OTS proof's merkle root was not confirmed against \
             the blockchain (re-run with network access)"
                .to_string(),
        ),
        details: AnchorDetails::Bitcoin {
            block_height: prepared.attestation.block_height,
            block_timestamp_secs: 0,
            target_hash: target_hash.to_string(),
            operation_count: prepared.operation_count,
            computed_root: prepared.computed_root,
            block_merkle_root: None,
            merkle_match: None,
        },
    }
}

/// `true` if verifying this anchor to completion requires network access.
///
/// Only `bitcoin_ots` does: RFC 3161 verification is pure computation. This
/// is what keeps `atl-cli` from probing connectivity for a receipt it can
/// fully verify offline.
#[must_use]
pub const fn requires_network(anchor: &ReceiptAnchor) -> bool {
    matches!(anchor, ReceiptAnchor::BitcoinOts { .. })
}

/// Verify every anchor in `receipt` with no network access.
///
/// RFC 3161 anchors are fully judged here; `bitcoin_ots` anchors get their
/// network-free verdict (see [`verify_bitcoin_ots_offline`]) which the
/// online pass later upgrades.
pub fn verify_anchors_offline(
    receipt: &atl_core::Receipt,
    trust_store: Option<&TrustStore>,
) -> Vec<AnchorVerificationResult> {
    let super_root = receipt
        .super_proof
        .as_ref()
        .map(|sp| sp.super_root.as_str());
    let data_tree_root = receipt.proof.root_hash.as_str();

    receipt
        .anchors
        .iter()
        .map(|anchor| match anchor {
            ReceiptAnchor::Rfc3161 {
                target,
                target_hash,
                timestamp,
                token_der,
                ..
            } => verify_rfc3161_anchor(
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
            } => verify_bitcoin_ots_offline(target, target_hash, ots_proof, super_root),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ROOT_HASH: &str =
        "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const OTHER_HASH: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn rfc3161_details(
        imprint: bool,
        cms: bool,
        chain: bool,
        eku: bool,
        path_status: PathStatus,
        terminal_anchor: Option<TerminalAnchor>,
    ) -> AnchorDetails {
        AnchorDetails::Rfc3161 {
            imprint_matches_root: imprint,
            cms_signature_valid: cms,
            chain_valid_at_gen_time: chain,
            timestamping_eku_ok: eku,
            path_status,
            terminal_anchor,
            revocation: Revocation::NotChecked,
        }
    }

    #[test]
    fn non_rfc3161_details_have_no_rfc3161_verdict() {
        assert_eq!(AnchorDetails::Unknown.rfc3161_verdict(), None);
        assert_eq!(AnchorDetails::Unknown.rfc3161_trust_state(), None);
    }

    #[test]
    fn trusted_terminal_with_sound_facts_is_valid() {
        let details = rfc3161_details(
            true,
            true,
            true,
            true,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [0u8; 32],
            }),
        );
        assert_eq!(details.rfc3161_verdict(), Some(AnchorVerdict::Valid));
        assert_eq!(details.rfc3161_trust_state(), Some("trusted"));
    }

    #[test]
    fn assumed_terminal_is_untrusted_not_invalid() {
        // Every cryptographic fact holds; only the trust root is missing.
        // This must NOT be reported as broken evidence.
        let details = rfc3161_details(
            true,
            true,
            true,
            true,
            PathStatus::Complete,
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [7u8; 32],
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("assumed"));
        assert_eq!(
            details.untrusted_root_fingerprint(),
            Some(hex::encode([7u8; 32]))
        );
    }

    #[test]
    fn incomplete_path_is_untrusted_not_invalid() {
        // The cross-signed Sectigo/DigiCert case: an issuer certificate is
        // missing from the token, so `chain_valid_at_gen_time` is false --
        // but nothing was refuted. This used to be reported as `Failed`.
        let details = rfc3161_details(true, true, false, true, PathStatus::Incomplete, None);
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("incomplete"));
        assert_eq!(details.untrusted_root_fingerprint(), None);
    }

    #[test]
    fn invalid_path_is_a_refutation() {
        let details = rfc3161_details(true, true, false, true, PathStatus::Invalid, None);
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::TsaChainInvalidAtGenTime))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("failed"));
    }

    #[test]
    fn false_facts_are_refutations_even_with_a_trusted_root() {
        let trusted = Some(TerminalAnchor::Trusted {
            sha256_fingerprint: [0u8; 32],
        });
        assert_eq!(
            rfc3161_details(false, true, true, true, PathStatus::Complete, trusted)
                .rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::TsaImprintMismatch))
        );
        assert_eq!(
            rfc3161_details(true, false, true, true, PathStatus::Complete, trusted)
                .rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid))
        );
        assert_eq!(
            rfc3161_details(true, true, true, false, PathStatus::Complete, trusted)
                .rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(
                ReasonCode::TsaTimestampingEkuInvalid
            ))
        );
    }

    #[test]
    fn wrong_target_is_rejected() {
        let result = verify_rfc3161_anchor(
            "wrong_target",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "base64:token",
            TEST_ROOT_HASH,
            None,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetInvalid)
        );
        assert!(!result.verified());
    }

    #[test]
    fn target_hash_mismatch_is_rejected_before_token_verification() {
        // A genuine token minted for an unrelated hash must never be
        // reported as proof for THIS receipt.
        let result = verify_rfc3161_anchor(
            "data_tree_root",
            OTHER_HASH,
            "2024-01-01T00:00:00Z",
            "base64:token",
            TEST_ROOT_HASH,
            None,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch)
        );
        assert!(result
            .error
            .unwrap()
            .contains("target_hash does not match proof.root_hash"));
    }

    #[test]
    fn malformed_hashes_are_rejected() {
        let bad_claim = verify_rfc3161_anchor(
            "data_tree_root",
            "sha256:notvalidhex",
            "2024-01-01T00:00:00Z",
            "base64:token",
            TEST_ROOT_HASH,
            None,
        );
        assert_eq!(
            bad_claim.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorHashMalformed)
        );

        let bad_root = verify_rfc3161_anchor(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "base64:token",
            "sha256:not-valid-hex",
            None,
        );
        assert_eq!(
            bad_root.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorHashMalformed)
        );
        assert!(bad_root.error.unwrap().contains("invalid proof.root_hash"));
    }

    #[test]
    fn garbage_token_is_unparsable_not_untrusted() {
        let result = verify_rfc3161_anchor(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "base64:c29tZXRva2Vu", // "sometoken": not CMS/DER
            TEST_ROOT_HASH,
            None,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::TsaTokenUnparsable)
        );
    }

    #[test]
    fn base64_prefix_is_optional() {
        let with = verify_rfc3161_anchor(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "base64:c29tZXRva2Vu",
            TEST_ROOT_HASH,
            None,
        );
        let without = verify_rfc3161_anchor(
            "data_tree_root",
            TEST_ROOT_HASH,
            "2024-01-01T00:00:00Z",
            "c29tZXRva2Vu",
            TEST_ROOT_HASH,
            None,
        );
        assert_eq!(with.verdict, without.verdict);
    }

    #[test]
    fn decode_hash_hex_matches_atl_core_rules() {
        assert!(decode_hash_hex(TEST_ROOT_HASH).is_ok());
        // No prefix, uppercase prefix, and empty string are all rejected.
        for bad in [
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "SHA256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "",
        ] {
            let err = decode_hash_hex(bad).expect_err("must be rejected");
            assert!(
                err.contains("missing sha256: prefix"),
                "unexpected error: {err}"
            );
        }
        // Hex digits themselves are case-insensitive.
        let mixed = "sha256:1234567890ABCDEF1234567890abcdef1234567890ABCDEF1234567890abcdef";
        assert_eq!(
            decode_hash_hex(mixed).unwrap(),
            decode_hash_hex(TEST_ROOT_HASH).unwrap()
        );
    }

    #[test]
    fn bitcoin_preflight_rejects_wrong_target_and_missing_super_proof() {
        let wrong_target = prepare_bitcoin_ots(
            "wrong",
            TEST_ROOT_HASH,
            "base64:proof",
            Some(TEST_ROOT_HASH),
        );
        let err = wrong_target.err().expect("must reject");
        assert_eq!(
            err.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetInvalid)
        );

        let no_super = prepare_bitcoin_ots("super_root", TEST_ROOT_HASH, "base64:proof", None);
        let err = no_super.err().expect("must reject");
        assert_eq!(
            err.verdict,
            AnchorVerdict::Invalid(ReasonCode::SuperProofMissing)
        );
    }

    #[test]
    fn bitcoin_preflight_rejects_hash_mismatch() {
        let err = prepare_bitcoin_ots(
            "super_root",
            TEST_ROOT_HASH,
            "base64:proof",
            Some(OTHER_HASH),
        )
        .err()
        .expect("must reject");
        assert_eq!(
            err.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch)
        );
    }

    #[test]
    fn requires_network_only_for_bitcoin() {
        let rfc = ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: TEST_ROOT_HASH.to_string(),
            tsa_url: "https://example.invalid/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        };
        let ots = ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: TEST_ROOT_HASH.to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            bitcoin_block_height: 800_000,
            bitcoin_block_time: "2024-01-01T00:00:00Z".to_string(),
            ots_proof: "base64:proof".to_string(),
        };
        assert!(!requires_network(&rfc));
        assert!(requires_network(&ots));
    }
}
