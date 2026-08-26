//! The single classification authority: receipt status, reason codes, and
//! the exit code each of them maps to.
//!
//! # Why this module exists
//!
//! Before this module, an RFC 3161 anchor whose cryptography was entirely
//! sound but whose terminal certificate nobody vouched for was reported as
//! `invalid` — the same word used for a receipt that had been *disproved*.
//! That conflates two states a client must be able to tell apart:
//!
//! - the evidence is refuted (something checkable is false), and
//! - the evidence is not refuted, but this verifier was never given the
//!   material needed to finish the check.
//!
//! [`Status`] separates them. Everything downstream — `verified`, both
//! renderers, and the process exit code — is derived from
//! [`ReceiptVerdict`], so no two of them can drift apart.
//!
//! # The dividing line
//!
//! [`Status::Invalid`] means at least one fact about the evidence is FALSE:
//! `imprint_matches_root == false`, `cms_signature_valid == false`,
//! `timestamping_eku_ok == false`, a certificate path that was found and
//! failed validation, `target_hash != proof.root_hash`, a broken inclusion
//! or Super-Tree proof, or a source file whose hash does not match the
//! receipt.
//!
//! [`Status::Untrusted`] means every checkable fact holds, but the chain did
//! not reach a trust root this verifier was configured with. Both
//! `TerminalAnchor::Assumed` (a self-signed terminal nobody vouched for) and
//! `PathStatus::Incomplete` (an issuer certificate is simply missing) land
//! here: nothing is refuted, material is missing on the verifier's side.
//!
//! [`Status::Pending`] is a receipt with no anchors at all (Receipt-Lite).
//!
//! [`Status::Valid`] is acceptance.
//!
//! # `PathStatus::Incomplete` and `chain_valid_at_gen_time`
//!
//! `atl-core` reports `chain_valid_at_gen_time == false` whenever the path
//! is `Incomplete`, because no complete path was validated. That flag being
//! `false` is therefore NOT by itself evidence that anything is wrong — it
//! is only a refutation when a candidate path was found and rejected, which
//! `atl-core` reports distinctly as `PathStatus::Invalid`. The classifier
//! below inspects `path_status` first for exactly this reason.

use crate::error::ExitCode;

/// Stable, machine-readable reason for a non-`Valid` outcome.
///
/// These strings are part of the CLI's contract: they are `snake_case`,
/// stable across releases, and safe to branch on in scripts. Human-readable
/// prose lives elsewhere and may change freely; these may not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    // --- Receipt-level refutations (Invalid) ---
    /// The source file's SHA-256 does not match `entry.payload_hash`.
    FileHashMismatch,
    /// The Merkle inclusion proof does not lead to `proof.root_hash`.
    InclusionProofInvalid,
    /// The Super-Tree inclusion proof failed.
    SuperInclusionProofInvalid,
    /// The Super-Tree consistency-to-origin proof failed.
    SuperConsistencyProofInvalid,
    /// `checkpoint.root_hash` disagrees with `proof.root_hash`.
    CheckpointRootHashMismatch,
    /// `checkpoint.tree_size` disagrees with `proof.tree_size`.
    CheckpointTreeSizeMismatch,
    /// The checkpoint signature was checked and did not verify.
    CheckpointSignatureInvalid,
    /// `entry.metadata_hash` does not match the canonicalized metadata.
    MetadataHashMismatch,
    /// The receipt is structurally malformed or of an unsupported version.
    ReceiptMalformed,
    /// Verification failed for a reason `atl-core` reported without a more
    /// specific mapping here.
    ReceiptVerificationFailed,

    // --- Anchor-level refutations (Invalid) ---
    /// The anchor's `target` field names something other than the anchor
    /// type's mandatory target.
    AnchorTargetInvalid,
    /// The anchor's `target_hash` is not a well-formed `sha256:` hash.
    AnchorHashMalformed,
    /// The anchor's `target_hash` does not equal the receipt's own root —
    /// the token proves a timestamp over some *other* data.
    AnchorTargetHashMismatch,
    /// The RFC 3161 token could not be decoded as CMS `SignedData` wrapping
    /// a `TSTInfo`.
    TsaTokenUnparsable,
    /// The token's `MessageImprint` does not match the receipt's root hash.
    TsaImprintMismatch,
    /// The CMS `SignerInfo` signature did not verify.
    CmsSignatureInvalid,
    /// The signer certificate lacks the exclusive critical
    /// `id-kp-timeStamping` EKU.
    TsaTimestampingEkuInvalid,
    /// A certificate path was found and rejected (bad signature, expired at
    /// `genTime`, `BasicConstraints`/`KeyUsage`/path-length violation, or an
    /// unrecognized critical extension).
    TsaChainInvalidAtGenTime,
    /// The receipt has a `bitcoin_ots` anchor but carries no `super_proof`
    /// for it to target.
    SuperProofMissing,
    /// The OTS proof itself is malformed or does not start from the
    /// expected hash.
    BitcoinOtsProofInvalid,
    /// The OTS proof's computed Merkle root does not match the real block's.
    BitcoinMerkleRootMismatch,

    // --- Trust material missing (Untrusted) ---
    /// Every fact holds, but the chain terminates in a certificate no
    /// caller-supplied trust store names.
    TsaRootNotTrusted,
    /// Every fact holds, but chain construction ran out of certificates
    /// before reaching any terminal — an issuer certificate is missing.
    TsaChainIncomplete,
    /// The OTS proof is structurally sound but no Bitcoin block was fetched,
    /// so its Merkle root was never confirmed against the chain.
    BitcoinBlockNotChecked,
    /// A Bitcoin block lookup was attempted and failed (network/API error),
    /// so the anchor could not be confirmed either way.
    BitcoinBlockUnavailable,

    // --- Receipt-level aggregates ---
    /// The receipt carries no anchors at all (Receipt-Lite).
    ReceiptUnanchored,
    /// At least one batch item was refuted.
    BatchItemsInvalid,
    /// No batch item was refuted, but at least one lacks a trust root.
    BatchItemsUntrusted,
    /// Cross-receipt log consistency verification failed.
    LogConsistencyFailed,
}

impl ReasonCode {
    /// The stable wire string for this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileHashMismatch => "file_hash_mismatch",
            Self::InclusionProofInvalid => "inclusion_proof_invalid",
            Self::SuperInclusionProofInvalid => "super_inclusion_proof_invalid",
            Self::SuperConsistencyProofInvalid => "super_consistency_proof_invalid",
            Self::CheckpointRootHashMismatch => "checkpoint_root_hash_mismatch",
            Self::CheckpointTreeSizeMismatch => "checkpoint_tree_size_mismatch",
            Self::CheckpointSignatureInvalid => "checkpoint_signature_invalid",
            Self::MetadataHashMismatch => "metadata_hash_mismatch",
            Self::ReceiptMalformed => "receipt_malformed",
            Self::ReceiptVerificationFailed => "receipt_verification_failed",
            Self::AnchorTargetInvalid => "anchor_target_invalid",
            Self::AnchorHashMalformed => "anchor_hash_malformed",
            Self::AnchorTargetHashMismatch => "anchor_target_hash_mismatch",
            Self::TsaTokenUnparsable => "tsa_token_unparsable",
            Self::TsaImprintMismatch => "tsa_imprint_mismatch",
            Self::CmsSignatureInvalid => "cms_signature_invalid",
            Self::TsaTimestampingEkuInvalid => "tsa_timestamping_eku_invalid",
            Self::TsaChainInvalidAtGenTime => "tsa_chain_invalid_at_gen_time",
            Self::SuperProofMissing => "super_proof_missing",
            Self::BitcoinOtsProofInvalid => "bitcoin_ots_proof_invalid",
            Self::BitcoinMerkleRootMismatch => "bitcoin_merkle_root_mismatch",
            Self::TsaRootNotTrusted => "tsa_root_not_trusted",
            Self::TsaChainIncomplete => "tsa_chain_incomplete",
            Self::BitcoinBlockNotChecked => "bitcoin_block_not_checked",
            Self::BitcoinBlockUnavailable => "bitcoin_block_unavailable",
            Self::ReceiptUnanchored => "receipt_unanchored",
            Self::BatchItemsInvalid => "batch_items_invalid",
            Self::BatchItemsUntrusted => "batch_items_untrusted",
            Self::LogConsistencyFailed => "log_consistency_failed",
        }
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The four terminal states a verification can end in.
///
/// Ordered by severity so aggregation over a batch is a `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// Accepted: every fact holds and every anchor reached a configured
    /// trust root.
    Valid,
    /// No anchors at all (Receipt-Lite). The proofs may still be sound; the
    /// receipt simply makes no external-time claim.
    Pending,
    /// Not refuted, not accepted: material is missing on the verifier's
    /// side (an untrusted terminal root, or an incomplete certificate path).
    Untrusted,
    /// Refuted: at least one checkable fact is false.
    Invalid,
}

impl Status {
    /// The stable wire string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Pending => "pending",
            Self::Untrusted => "untrusted",
            Self::Invalid => "invalid",
        }
    }

    /// The process exit code for this status.
    ///
    /// `Untrusted` gets its own code (3) precisely so a script can tell
    /// "this evidence is broken" (1) from "bring me the trust root" (3)
    /// without parsing JSON. `Pending` keeps the historical code 0.
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        match self {
            Self::Valid | Self::Pending => ExitCode::Valid,
            Self::Untrusted => ExitCode::Untrusted,
            Self::Invalid => ExitCode::Invalid,
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A [`Status`] together with the machine-readable reason that produced it.
///
/// `reason_code` is `None` exactly when `status == Status::Valid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptVerdict {
    /// The terminal state.
    pub status: Status,
    /// Why, in a form scripts can branch on.
    pub reason_code: Option<ReasonCode>,
}

impl ReceiptVerdict {
    /// The accepted verdict.
    pub const VALID: Self = Self {
        status: Status::Valid,
        reason_code: None,
    };

    /// A refuted verdict.
    #[must_use]
    pub const fn invalid(reason: ReasonCode) -> Self {
        Self {
            status: Status::Invalid,
            reason_code: Some(reason),
        }
    }

    /// A not-refuted-but-not-trusted verdict.
    #[must_use]
    pub const fn untrusted(reason: ReasonCode) -> Self {
        Self {
            status: Status::Untrusted,
            reason_code: Some(reason),
        }
    }

    /// The unanchored (Receipt-Lite) verdict.
    #[must_use]
    pub const fn pending() -> Self {
        Self {
            status: Status::Pending,
            reason_code: Some(ReasonCode::ReceiptUnanchored),
        }
    }

    /// `true` only for [`Status::Valid`]. Nothing else — in particular not
    /// [`Status::Untrusted`] — may ever be presented as a verified receipt.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self.status, Status::Valid)
    }

    /// The process exit code this verdict maps to.
    #[must_use]
    #[allow(dead_code)] // exercised by unit tests; the runtime path goes via
                        // `CliError::exit_code`, which reads the same `Status`
    pub const fn exit_code(self) -> ExitCode {
        self.status.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_never_maps_to_success() {
        let verdict = ReceiptVerdict::untrusted(ReasonCode::TsaRootNotTrusted);
        assert!(!verdict.is_valid());
        assert_ne!(verdict.exit_code(), ExitCode::Valid);
        assert_eq!(verdict.exit_code(), ExitCode::Untrusted);
        assert_eq!(verdict.status.as_str(), "untrusted");
    }

    #[test]
    fn exit_codes_are_the_documented_ones() {
        assert_eq!(ReceiptVerdict::VALID.exit_code().code(), 0);
        assert_eq!(ReceiptVerdict::pending().exit_code().code(), 0);
        assert_eq!(
            ReceiptVerdict::untrusted(ReasonCode::TsaChainIncomplete)
                .exit_code()
                .code(),
            3
        );
        assert_eq!(
            ReceiptVerdict::invalid(ReasonCode::FileHashMismatch)
                .exit_code()
                .code(),
            1
        );
    }

    #[test]
    fn severity_ordering_makes_invalid_dominate() {
        assert!(Status::Invalid > Status::Untrusted);
        assert!(Status::Untrusted > Status::Pending);
        assert!(Status::Pending > Status::Valid);
    }

    #[test]
    fn reason_codes_are_snake_case_and_unique() {
        let all = [
            ReasonCode::FileHashMismatch,
            ReasonCode::InclusionProofInvalid,
            ReasonCode::SuperInclusionProofInvalid,
            ReasonCode::SuperConsistencyProofInvalid,
            ReasonCode::CheckpointRootHashMismatch,
            ReasonCode::CheckpointTreeSizeMismatch,
            ReasonCode::CheckpointSignatureInvalid,
            ReasonCode::MetadataHashMismatch,
            ReasonCode::ReceiptMalformed,
            ReasonCode::ReceiptVerificationFailed,
            ReasonCode::AnchorTargetInvalid,
            ReasonCode::AnchorHashMalformed,
            ReasonCode::AnchorTargetHashMismatch,
            ReasonCode::TsaTokenUnparsable,
            ReasonCode::TsaImprintMismatch,
            ReasonCode::CmsSignatureInvalid,
            ReasonCode::TsaTimestampingEkuInvalid,
            ReasonCode::TsaChainInvalidAtGenTime,
            ReasonCode::SuperProofMissing,
            ReasonCode::BitcoinOtsProofInvalid,
            ReasonCode::BitcoinMerkleRootMismatch,
            ReasonCode::TsaRootNotTrusted,
            ReasonCode::TsaChainIncomplete,
            ReasonCode::BitcoinBlockNotChecked,
            ReasonCode::BitcoinBlockUnavailable,
            ReasonCode::ReceiptUnanchored,
            ReasonCode::BatchItemsInvalid,
            ReasonCode::BatchItemsUntrusted,
            ReasonCode::LogConsistencyFailed,
        ];

        let mut seen = std::collections::HashSet::new();
        for code in all {
            let s = code.as_str();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "reason code {s} is not snake_case"
            );
            assert!(seen.insert(s), "duplicate reason code: {s}");
        }
    }
}
