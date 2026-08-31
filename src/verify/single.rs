//! Single file verification logic

use std::path::Path;

use atl_core::{
    verify_receipt_with_options, Receipt, TrustStore, VerificationError, VerificationResult,
    VerifyOptions,
};

use crate::error::{CliError, CliResult};
use crate::verify::anchor::{verify_anchors_offline, AnchorVerdict, AnchorVerificationResult};
use crate::verify::file::{compare_hash, hash_file, MAX_RECEIPT_SIZE};
use crate::verify::policy::{AnchorPolicy, TrustAssessment};
use crate::verify::verdict::{ReasonCode, ReceiptVerdict, Status};

/// Super-Tree proof verdict — only constructible (and only exists at all)
/// when the receipt actually carries a `super_proof`.
///
/// Kept as its own type, rather than two loose `Option<bool>` fields on
/// [`ProofVerdict`], specifically so "has a `super_proof`" and "both of its
/// flags are populated" are tied together by the type system: there is no
/// way to construct a state where one of `inclusion_valid` /
/// `consistency_valid` is known and the other is not, or where a receipt
/// with no `super_proof` still carries `Some` super flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperProofVerdict {
    /// Super-Tree inclusion proof (data tree root included in super root) is valid.
    pub inclusion_valid: bool,
    /// Super-Tree consistency-to-origin proof is valid.
    pub consistency_valid: bool,
}

impl SuperProofVerdict {
    /// Both the inclusion and consistency checks passed.
    #[must_use]
    pub const fn valid(self) -> bool {
        self.inclusion_valid && self.consistency_valid
    }
}

/// Canonical cryptographic-proof verdict for a receipt.
///
/// This is the single source of truth for "did the inclusion / super-tree
/// proofs check out" — both the JSON and human-readable renderers must build
/// their flags from this struct instead of re-deriving them, so the two
/// output formats can never disagree.
///
/// `inclusion_valid` is the base Merkle inclusion proof against the log's
/// `data_tree_root`. It does NOT fold in trust-anchor / signature status —
/// an unanchored (Receipt-Lite) receipt can have `inclusion_valid: true`.
/// `super_proof` is `None` when the receipt carries no `super_proof` at all
/// (nothing to verify), and `Some(SuperProofVerdict)` otherwise — see
/// [`SuperProofVerdict`] for why this is nested rather than two `Option<bool>`
/// fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofVerdict {
    /// Base Merkle inclusion proof is valid.
    pub inclusion_valid: bool,
    /// Super-Tree verdict, or `None` if the receipt has no `super_proof`.
    pub super_proof: Option<SuperProofVerdict>,
}

impl ProofVerdict {
    /// Compute the canonical verdict from a core verification result and
    /// whether the receipt carries a `super_proof`.
    #[must_use]
    pub const fn compute(core_result: &VerificationResult, has_super_proof: bool) -> Self {
        let super_proof = if has_super_proof {
            Some(SuperProofVerdict {
                inclusion_valid: core_result.super_inclusion_valid,
                consistency_valid: core_result.super_consistency_valid,
            })
        } else {
            None
        };

        Self {
            inclusion_valid: core_result.inclusion_valid,
            super_proof,
        }
    }

    /// Honest aggregate over what was actually cryptographically checked:
    /// base inclusion AND (super proof, if the receipt has one).
    ///
    /// This is a statement about **proofs**, not about **trust**. It can be
    /// `true` for a receipt that is unanchored, whose checkpoint signature
    /// was never verified, or whose timestamp cannot be corroborated by any
    /// external anchor — none of that is checked here. A caller that wants
    /// to know whether a receipt should be *trusted* must look at `status`
    /// and the anchor verification results, not at this flag alone. Do not
    /// present `proofs_valid: true` to an end user as "receipt verified".
    #[must_use]
    pub fn proofs_valid(self) -> bool {
        self.inclusion_valid && self.super_proof.is_none_or(SuperProofVerdict::valid)
    }
}

/// Result of single file verification
#[derive(Debug, Clone)]
pub struct SingleVerificationResult {
    /// Path to source file
    pub source_path: std::path::PathBuf,
    /// Path to receipt file
    pub receipt_path: std::path::PathBuf,
    /// Computed file hash
    pub file_hash: [u8; 32],
    /// The parsed receipt
    pub receipt: Receipt,
    /// File hash matches payload_hash
    pub file_hash_valid: bool,
    /// Core verification result from atl-core
    pub core_result: VerificationResult,
    /// Per-anchor verdicts, computed by this crate rather than collapsed to
    /// `atl-core`'s `is_valid: bool` — this is what makes the difference
    /// between "refuted" and "no trust root configured" visible.
    ///
    /// RFC 3161 anchors are judged completely here (their verification is
    /// pure computation). `bitcoin_ots` anchors carry their network-free
    /// verdict until [`crate::verify::online`] upgrades them in place.
    pub anchor_results: Vec<AnchorVerificationResult>,
    /// The anchor quorum this receipt is judged against.
    ///
    /// Carried on the result rather than passed to [`Self::verdict`] so that
    /// every consumer -- both renderers, the batch aggregate, the exit code
    /// -- necessarily asks the same question of the same receipt. A policy
    /// threaded through call sites instead would be one more thing two
    /// callers could disagree about.
    pub policy: AnchorPolicy,
}

impl SingleVerificationResult {
    /// The single classification authority for one receipt.
    ///
    /// Every consumer — `is_valid`, both renderers, the batch aggregate and
    /// the process exit code — derives from this method. Nothing re-derives
    /// a status of its own.
    ///
    /// # Order of judgement
    ///
    /// 1. Everything [`Self::receipt_refutation`] covers — a source file
    ///    whose hash does not match, a structural failure `atl-core`
    ///    reported, a broken inclusion or Super-Tree proof — is a
    ///    refutation, and is checked first.
    /// 2. A refuted anchor makes the receipt [`Status::Invalid`] — before
    ///    anything else about the anchors is considered, and regardless of
    ///    the policy in force. A refutation is never policy-dependent.
    /// 3. A receipt with no anchors at all is [`Status::Untrusted`] with
    ///    reason `receipt_unanchored`: ATL v2.0 §5.5 requires at least one
    ///    *verified* anchor, and zero anchors yield zero verified ones. No
    ///    policy relaxes this — a quorum of one cannot be met by none.
    /// 4. Otherwise the [`TrustAssessment`] decides: if the policy's quorum
    ///    is satisfied the receipt is [`Status::Valid`], and if it is not,
    ///    [`Status::Untrusted`] carrying the first unresolved anchor's own
    ///    reason.
    ///
    /// # Why the refutation check moved above the unanchored check
    ///
    /// It cannot matter in practice — a receipt with no anchors has no
    /// anchor to refute — but the ordering is the rule this crate is built
    /// on, and a reader must be able to see it applied without first
    /// proving to themselves that the two cases are disjoint.
    #[must_use]
    pub fn verdict(&self) -> ReceiptVerdict {
        if let Some(reason) = self.receipt_refutation() {
            return ReceiptVerdict::invalid(reason);
        }

        // A refutation anywhere outranks every inability everywhere, and is
        // independent of the anchor policy: no quorum, however lenient,
        // accepts a fact that has been shown false.
        if let Some(reason) = self.anchor_results.iter().find_map(|a| match a.verdict {
            AnchorVerdict::Invalid(code) => Some(code),
            _ => None,
        }) {
            return ReceiptVerdict::invalid(reason);
        }

        // ATL v2.0 §5.5: no anchors means no verified anchors, and "a
        // receipt without any verified anchors SHOULD be treated as
        // untrustworthy".
        if self.receipt.anchors.is_empty() {
            return ReceiptVerdict::unanchored();
        }

        let assessment = self.assessment();
        if assessment.policy_satisfied() {
            return ReceiptVerdict::VALID;
        }
        assessment.unsatisfied_reason().map_or(
            // Unreachable: an unsatisfied policy over a non-empty anchor
            // list with nothing refuted means at least one anchor is
            // unresolved. Kept as the honest fallback rather than a panic.
            ReceiptVerdict::unanchored(),
            ReceiptVerdict::untrusted,
        )
    }

    /// Everything that refutes this receipt **without reference to its
    /// anchors**: a source file whose hash does not match, a structural
    /// failure `atl-core` reported, or a broken inclusion / Super-Tree
    /// proof.
    ///
    /// Split out of [`Self::verdict`] so that [`Self::assessment`] can be
    /// told about these refutations too. It used to see only
    /// `anchor_results`, so a receipt refuted for one of these reasons
    /// reported `evidence.established: true`, `policy.satisfied: true` and
    /// `coverage.complete: true` beside `status: "invalid"` — hand the tool
    /// the wrong source file and the trust block cheerfully announced that
    /// trust was established in it. The human renderer happened not to show
    /// it, because it stops early on a hash mismatch; the machine contract,
    /// which has no such accident to save it, published the lot.
    ///
    /// Kept free of any anchor reasoning so [`Self::assessment`] can call it
    /// without recursion: `verdict` needs the assessment, so the assessment
    /// must not need the verdict.
    ///
    /// # Order
    ///
    /// 1. A source file whose hash does not match the receipt refutes
    ///    everything downstream, so it is checked first.
    /// 2. Structural failures `atl-core` reported (checkpoint mismatch,
    ///    malformed receipt, …). `NoTrustAnchor` is not one of them: it only
    ///    means "zero anchors ended up valid", which this crate decides for
    ///    itself, with more information, from the per-anchor verdicts.
    /// 3. The proof flags, as defence in depth: `atl-core` reports each of
    ///    these as an error too, but a proof flag must never be able to be
    ///    false while the receipt is reported as anything but refuted.
    #[must_use]
    pub fn receipt_refutation(&self) -> Option<ReasonCode> {
        if !self.file_hash_valid {
            return Some(ReasonCode::FileHashMismatch);
        }

        if let Some(reason) = self.core_result.errors.iter().find_map(map_core_error) {
            return Some(reason);
        }

        let proofs = self.proof_verdict();
        if !proofs.inclusion_valid {
            return Some(ReasonCode::InclusionProofInvalid);
        }
        if let Some(super_proof) = proofs.super_proof {
            if !super_proof.inclusion_valid {
                return Some(ReasonCode::SuperInclusionProofInvalid);
            }
            if !super_proof.consistency_valid {
                return Some(ReasonCode::SuperConsistencyProofInvalid);
            }
        }

        None
    }

    /// The three axes — evidence, policy, coverage — for this receipt, under
    /// the policy it was verified with.
    ///
    /// The renderers publish these separately instead of collapsing them
    /// into the single verdict word, because they answer different
    /// questions and a caller may care about any of the three.
    ///
    /// [`Self::receipt_refutation`] is passed in so the axes agree with the
    /// **verdict** and not merely with the anchors: whatever refuted this
    /// receipt, no axis beside it may report achieved trust.
    #[must_use]
    pub fn assessment(&self) -> TrustAssessment {
        TrustAssessment::compute(&self.anchor_results, self.policy, self.receipt_refutation())
    }

    /// Check if the receipt was accepted.
    ///
    /// `true` only for [`Status::Valid`] — never for [`Status::Untrusted`],
    /// which now covers the unanchored receipt as well, and is not an
    /// acceptable outcome however sound the cryptography behind it is.
    #[must_use]
    #[allow(dead_code)] // exercised by unit tests; kept as the readable predicate
    pub fn is_valid(&self) -> bool {
        matches!(self.verdict().status, Status::Valid)
    }

    /// Compute the canonical cryptographic-proof verdict for this result.
    ///
    /// See [`ProofVerdict`] — this is the single source of truth JSON and
    /// human-readable renderers must use for `inclusion_valid` / super-tree
    /// flags, so the two output formats cannot structurally diverge.
    #[must_use]
    pub fn proof_verdict(&self) -> ProofVerdict {
        ProofVerdict::compute(&self.core_result, self.receipt.super_proof.is_some())
    }

    /// Check if this is a Receipt-Lite: cryptographically sound and carrying
    /// no anchors at all.
    ///
    /// Not a success predicate. Such a receipt is [`Status::Untrusted`] and
    /// exits 3; this only identifies *which* untrusted it is, so the
    /// renderers can explain the Receipt-Lite tier rather than send the
    /// reader looking for a certificate.
    ///
    /// # Why "no anchors at all" is required
    ///
    /// `atl-core`'s `NoTrustAnchor` error fires whenever zero anchors ended
    /// up valid — which is also what happens for a receipt that DOES carry
    /// an RFC 3161 anchor whose cryptography is sound but whose terminal
    /// certificate nobody vouches for. Describing that as "unanchored" would
    /// be false: the receipt is anchored, its anchor's root simply isn't
    /// trusted. That case has its own reason code, and this method is
    /// `false` for it.
    #[must_use]
    #[allow(dead_code)] // exercised by unit tests; kept as the readable predicate
    pub fn is_lite(&self) -> bool {
        self.verdict().reason_code == Some(ReasonCode::ReceiptUnanchored)
    }
}

/// Map an `atl-core` verification error to a stable reason code, or `None`
/// for errors that are not, by themselves, refutations of the evidence.
///
/// `NoTrustAnchor` and `AnchorFailed` are deliberately `None`: they report
/// the *aggregate* anchor outcome, which [`SingleVerificationResult::verdict`]
/// computes itself from the richer per-anchor verdicts. Mapping them here
/// would collapse "root not trusted" back into "refuted", which is precisely
/// the conflation this design removes.
fn map_core_error(error: &VerificationError) -> Option<ReasonCode> {
    match error {
        VerificationError::NoTrustAnchor | VerificationError::AnchorFailed { .. } => None,
        VerificationError::SignatureFailed => Some(ReasonCode::CheckpointSignatureInvalid),
        VerificationError::InclusionProofFailed { .. } => Some(ReasonCode::InclusionProofInvalid),
        VerificationError::SuperInclusionFailed { .. } => {
            Some(ReasonCode::SuperInclusionProofInvalid)
        }
        VerificationError::ConsistencyProofFailed { .. }
        | VerificationError::SuperConsistencyFailed { .. } => {
            Some(ReasonCode::SuperConsistencyProofInvalid)
        }
        VerificationError::RootHashMismatch => Some(ReasonCode::CheckpointRootHashMismatch),
        VerificationError::TreeSizeMismatch => Some(ReasonCode::CheckpointTreeSizeMismatch),
        VerificationError::MetadataHashMismatch { .. } => Some(ReasonCode::MetadataHashMismatch),
        VerificationError::InvalidReceipt(_)
        | VerificationError::InvalidHash { .. }
        | VerificationError::SuperDataMismatch { .. }
        | VerificationError::MissingSuperProof
        | VerificationError::UnsupportedVersion(_) => Some(ReasonCode::ReceiptMalformed),
    }
}

/// Load a receipt from file
///
/// # Arguments
///
/// * `path` - Path to the .atl receipt file
///
/// # Errors
///
/// Returns error if:
/// - File does not exist
/// - File exceeds size limit (10 MB)
/// - File cannot be parsed as JSON
/// - `spec_version` is not the revision this build implements
pub fn load_receipt(path: &Path) -> CliResult<Receipt> {
    // Check file exists
    if !path.exists() {
        return Err(CliError::ReceiptNotFound(path.to_path_buf()));
    }

    // Check file size
    let metadata = std::fs::metadata(path).map_err(|e| CliError::file_read_error(path, e))?;

    if metadata.len() > MAX_RECEIPT_SIZE {
        return Err(CliError::FileTooLarge {
            path: path.to_path_buf(),
            size_bytes: metadata.len(),
            max_bytes: MAX_RECEIPT_SIZE,
        });
    }

    // Read and parse
    let contents = std::fs::read_to_string(path).map_err(|e| CliError::file_read_error(path, e))?;

    let receipt: Receipt =
        serde_json::from_str(&contents).map_err(|e| CliError::ReceiptParseError(e.to_string()))?;

    // Validate version.
    //
    // Asked of `atl-core`, never decided here. This gate used to admit every
    // `2.x` while the core verifier admitted only `2.0.0`, so a `2.0.1`
    // receipt got through the door and was then reported as a *defective
    // receipt* (`receipt_malformed`, exit 1) rather than as a revision this
    // build does not implement. Two parts of one system disagreeing about
    // what they accept is how "could not check" became "checked and false".
    //
    // ATL v2.0 §4.2 defines `spec_version` and stops there: no compatibility
    // rule, no statement that a verifier must accept later revisions of the
    // same major version. With nothing written down to rely on, the accepted
    // set is exactly what this build implements -- see
    // `atl_core::is_supported_spec_version`.
    if !atl_core::is_supported_spec_version(&receipt.spec_version) {
        return Err(CliError::UnsupportedReceiptVersion {
            version: receipt.spec_version.clone(),
            expected: atl_core::RECEIPT_SPEC_VERSION.to_string(),
        });
    }

    Ok(receipt)
}

/// Verify a single file against its receipt
///
/// Uses ATL Protocol v2.0 anchor-only verification - NO PUBLIC KEY REQUIRED.
/// Trust is established through external anchors (RFC 3161, Bitcoin OTS).
///
/// # Verification Steps
///
/// 1. Load receipt from file
/// 2. Hash the source file (streaming SHA-256)
/// 3. Compare file hash with receipt's payload_hash
/// 4. Verify cryptographic proofs (metadata_hash, Merkle inclusion, Super-Tree)
///
/// # Arguments
///
/// * `source_path` - Path to the source file
/// * `receipt_path` - Path to the .atl receipt file
///
/// # Errors
///
/// Returns error if:
/// - Files cannot be read
/// - Receipt cannot be parsed
/// - File exceeds size limits
///
/// `policy` is the anchor quorum the caller selected (default: every anchor
/// the receipt presents must be verified; `--allow-single-anchor`: one is
/// enough). It changes only the *threshold for acceptance* -- never what is
/// checked, never what is reported, and never whether a refutation stands.
///
/// `trust_store` carries whatever RFC 3161 trust material the caller passed
/// via `--tsa-trust-store` / `--tsa-intermediates` (or `None` if they passed
/// nothing). RFC 3161 certificate-chain verification is pure computation --
/// no network access -- so every anchor is judged here, in this one pass,
/// and the result is identical whether or not the CLI later goes online.
/// Only `bitcoin_ots` anchors have anything left to do online.
pub fn verify_single(
    source_path: &Path,
    receipt_path: &Path,
    trust_store: Option<&TrustStore>,
    policy: AnchorPolicy,
) -> CliResult<SingleVerificationResult> {
    // Load receipt first (fast fail if invalid)
    let receipt = load_receipt(receipt_path)?;

    // Hash the source file
    let file_hash = hash_file(source_path)?;

    // Compare hash with receipt
    let file_hash_valid = compare_hash(&file_hash, &receipt.entry.payload_hash);

    // Verify the receipt's structure and proofs with atl-core. Anchors are
    // skipped here on purpose: `atl-core` collapses each one to a bare
    // `is_valid: bool`, which cannot distinguish a refuted anchor from one
    // whose root simply isn't in our trust store. This crate verifies them
    // itself, below, keeping the full fact set.
    let options = VerifyOptions {
        skip_anchors: true,
        ..Default::default()
    };
    let core_result = verify_receipt_with_options(&receipt, options)
        .map_err(|e| CliError::VerificationFailed(e.to_string()))?;

    // `trust_store` is threaded straight from the CLI flags -- never derived
    // from the receipt or the token itself (see the ATL trust-model
    // decisions doc: no identity lives in the protocol implementation).
    let anchor_results = verify_anchors_offline(&receipt, trust_store);

    Ok(SingleVerificationResult {
        source_path: source_path.to_path_buf(),
        receipt_path: receipt_path.to_path_buf(),
        file_hash,
        receipt,
        file_hash_valid,
        core_result,
        anchor_results,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_receipt() -> atl_core::Receipt {
        // Load a minimal valid receipt from test data
        serde_json::from_str(include_str!(
            "../../test_data/receipts/valid/document.pdf.atl"
        ))
        .expect("Failed to parse test receipt")
    }

    fn create_test_verification_result(is_valid: bool) -> atl_core::VerificationResult {
        // Create a real verification result using the test receipt
        let receipt = create_test_receipt();
        let mut result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Override is_valid for testing purposes
        result.is_valid = is_valid;
        if !is_valid {
            result
                .errors
                .push(atl_core::VerificationError::MetadataHashMismatch {
                    actual: "sha256:test".to_string(),
                    expected: "sha256:expected".to_string(),
                });
        }

        result
    }

    #[test]
    fn test_load_receipt_not_found() {
        let result = load_receipt(Path::new("/nonexistent/receipt.atl"));
        assert!(matches!(result, Err(CliError::ReceiptNotFound(_))));
    }

    /// A cryptographically sound receipt with no anchors is NOT accepted:
    /// ATL v2.0 §5.5 requires at least one verified anchor. It exits 3.
    #[test]
    fn test_single_verification_result_is_valid_true() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: true,
            core_result: create_test_verification_result(true),
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        assert!(!result.is_valid());
        assert_eq!(result.verdict(), ReceiptVerdict::unanchored());
    }

    #[test]
    fn test_single_verification_result_is_valid_false_hash_mismatch() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: false,
            core_result: create_test_verification_result(true),
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        assert!(!result.is_valid());
    }

    #[test]
    fn test_single_verification_result_is_valid_false_core_invalid() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: true,
            core_result: create_test_verification_result(false),
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        assert!(!result.is_valid());
    }

    #[test]
    fn test_single_verification_result_valid_with_no_trust_anchor() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate NoTrustAnchor scenario
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt,
            file_hash_valid: true,
            core_result,
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        // `NoTrustAnchor` is not itself a refutation -- this crate decides
        // the anchor outcome from its own per-anchor verdicts. But the
        // receipt still carries no anchors, so §5.5's floor is unmet and it
        // is untrusted rather than accepted.
        assert!(!result.is_valid());
        assert_eq!(result.verdict(), ReceiptVerdict::unanchored());
    }

    #[test]
    fn test_verify_single_result_clone() {
        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            receipt: create_test_receipt(),
            file_hash_valid: true,
            core_result: create_test_verification_result(true),
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        let cloned = result.clone();
        assert_eq!(result.source_path, cloned.source_path);
        assert_eq!(result.receipt_path, cloned.receipt_path);
        assert_eq!(result.file_hash, cloned.file_hash);
        assert_eq!(result.file_hash_valid, cloned.file_hash_valid);
    }

    #[test]
    fn test_is_lite_true() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate lite receipt condition
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        // ATL v2.0 §5.5: a Receipt-Lite has no verified anchor, so it is
        // untrusted (exit 3) -- identified as the Receipt-Lite case, but
        // never accepted.
        assert!(result.is_lite());
        assert!(!result.is_valid());
        assert_eq!(result.verdict().status, Status::Untrusted);
        assert_eq!(
            result.verdict().reason_code,
            Some(ReasonCode::ReceiptUnanchored)
        );
        assert_eq!(result.verdict().exit_code().code(), 3);
    }

    #[test]
    fn test_is_lite_false_hash_mismatch() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate lite receipt with hash mismatch
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: false, // Hash mismatch
            receipt,
            core_result,
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        assert!(!result.is_lite());
        assert!(!result.is_valid());
    }

    #[test]
    fn test_is_lite_false_proof_failed() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate failed proofs
        core_result.is_valid = false;
        core_result.inclusion_valid = false; // Proof failed
        core_result.errors = vec![atl_core::VerificationError::NoTrustAnchor];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        assert!(!result.is_lite());
        assert!(!result.is_valid());
    }

    #[test]
    fn test_is_lite_false_other_errors() {
        let receipt = create_test_receipt();
        let mut core_result =
            atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt");

        // Simulate other errors besides NoTrustAnchor
        core_result.is_valid = false;
        core_result.errors = vec![atl_core::VerificationError::MetadataHashMismatch {
            actual: "sha256:test".to_string(),
            expected: "sha256:expected".to_string(),
        }];

        let result = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };

        assert!(!result.is_lite());
        assert!(!result.is_valid());
    }

    // Note: Comprehensive tests with valid receipts are in integration tests
    // Unit tests here focus on error paths and logic branches

    // ========================================================================
    // ProofVerdict — canonical verdict model
    // ========================================================================
    //
    // These tests pin down the single source of truth both `output::json`
    // and `output::human` build their `inclusion_valid` / super-tree flags
    // from. Regression coverage for the underlying bug: neither renderer may
    // derive an `inclusion`-named field from the aggregate `is_valid` (too
    // strict for unanchored receipts), and neither may ignore a broken
    // super-tree proof when only the base inclusion proof is checked (too
    // lenient).

    fn base_core_result() -> atl_core::VerificationResult {
        // Real output of anchor-only verification against the bundled
        // valid+unanchored test receipt: base inclusion, super inclusion and
        // super consistency all genuinely pass; only `NoTrustAnchor` fires
        // because the receipt carries no anchors. `is_valid` is therefore
        // `false` at the core level even though every proof checks out —
        // exactly the case the old code conflated.
        let receipt = create_test_receipt();
        atl_core::verify_receipt_anchor_only(&receipt).expect("Failed to verify test receipt")
    }

    #[test]
    fn proof_verdict_no_super_proof_ignores_super_fields() {
        let mut core_result = base_core_result();
        core_result.inclusion_valid = true;

        let verdict = ProofVerdict::compute(&core_result, false);

        assert!(verdict.inclusion_valid);
        assert_eq!(verdict.super_proof, None);
        assert!(verdict.proofs_valid());
    }

    #[test]
    fn proof_verdict_no_super_proof_but_base_inclusion_broken_is_invalid() {
        let mut core_result = base_core_result();
        core_result.inclusion_valid = false;

        let verdict = ProofVerdict::compute(&core_result, false);

        assert!(!verdict.inclusion_valid);
        assert!(!verdict.proofs_valid());
    }

    #[test]
    fn proof_verdict_with_super_proof_all_valid() {
        let mut core_result = base_core_result();
        core_result.inclusion_valid = true;
        core_result.super_inclusion_valid = true;
        core_result.super_consistency_valid = true;

        let verdict = ProofVerdict::compute(&core_result, true);

        assert!(verdict.inclusion_valid);
        assert_eq!(
            verdict.super_proof,
            Some(SuperProofVerdict {
                inclusion_valid: true,
                consistency_valid: true,
            })
        );
        assert!(verdict.proofs_valid());
    }

    #[test]
    fn proof_verdict_with_super_proof_base_valid_but_super_inclusion_broken() {
        // Regression for the "online mode is too lenient" bug: base
        // inclusion alone must NOT be enough to call the proofs valid when a
        // super_proof is present and its inclusion check failed.
        let mut core_result = base_core_result();
        core_result.inclusion_valid = true;
        core_result.super_inclusion_valid = false;
        core_result.super_consistency_valid = true;

        let verdict = ProofVerdict::compute(&core_result, true);

        assert!(verdict.inclusion_valid);
        assert_eq!(
            verdict.super_proof,
            Some(SuperProofVerdict {
                inclusion_valid: false,
                consistency_valid: true,
            })
        );
        assert!(!verdict.proofs_valid());
    }

    #[test]
    fn proof_verdict_with_super_proof_base_valid_but_super_consistency_broken() {
        // Regression for the "matched fixture" gap flagged in review: a
        // super_proof whose *inclusion* is fine but whose *consistency to
        // origin* is broken must still fail `proofs_valid`, not just the
        // (more common) case where both super flags break together.
        let mut core_result = base_core_result();
        core_result.inclusion_valid = true;
        core_result.super_inclusion_valid = true;
        core_result.super_consistency_valid = false;

        let verdict = ProofVerdict::compute(&core_result, true);

        assert_eq!(
            verdict.super_proof,
            Some(SuperProofVerdict {
                inclusion_valid: true,
                consistency_valid: false,
            })
        );
        assert!(!verdict.proofs_valid());
    }

    #[test]
    fn proof_verdict_base_inclusion_broken_dominates_even_with_valid_super() {
        let mut core_result = base_core_result();
        core_result.inclusion_valid = false;
        core_result.super_inclusion_valid = true;
        core_result.super_consistency_valid = true;

        let verdict = ProofVerdict::compute(&core_result, true);

        assert!(!verdict.proofs_valid());
    }

    #[test]
    fn proof_verdict_is_not_derived_from_aggregate_is_valid() {
        // Regression for the "offline mode is too strict" bug: an unanchored
        // receipt has `core_result.is_valid == false` (no trust anchor) even
        // though every cryptographic proof is genuinely valid. The verdict
        // must reflect the real proof fields, not the aggregate.
        let mut core_result = base_core_result();
        core_result.is_valid = false;
        core_result.inclusion_valid = true;
        core_result.super_inclusion_valid = true;
        core_result.super_consistency_valid = true;

        let verdict = ProofVerdict::compute(&core_result, true);

        assert!(verdict.inclusion_valid);
        assert_eq!(
            verdict.super_proof,
            Some(SuperProofVerdict {
                inclusion_valid: true,
                consistency_valid: true,
            })
        );
        assert!(verdict.proofs_valid());
    }

    #[test]
    fn super_proof_verdict_partially_broken_is_never_reported_valid() {
        // Regression for the review finding: `ProofVerdict` used to hold two
        // independent `Option<bool>` fields, so a value like
        // `{ super_inclusion_valid: Some(true), super_consistency_valid: None }`
        // was constructible from outside the module (public fields) even
        // though `ProofVerdict::compute` never produces it, and
        // `proofs_valid()`'s `unwrap_or(true)` silently treated the missing
        // half as passing. `SuperProofVerdict` makes that state
        // unrepresentable: both flags live in one struct that only exists at
        // all when there IS a super_proof, so there is no "half-known" verdict
        // to construct. This test exhaustively checks all four combinations
        // reachable through the public API.
        for inclusion_valid in [true, false] {
            for consistency_valid in [true, false] {
                let verdict = ProofVerdict {
                    inclusion_valid: true,
                    super_proof: Some(SuperProofVerdict {
                        inclusion_valid,
                        consistency_valid,
                    }),
                };
                assert_eq!(
                    verdict.proofs_valid(),
                    inclusion_valid && consistency_valid,
                    "inclusion_valid={inclusion_valid} consistency_valid={consistency_valid}"
                );
            }
        }
    }

    #[test]
    fn single_verification_result_proof_verdict_uses_receipt_super_proof_presence() {
        // `SingleVerificationResult::proof_verdict()` must key `has_super_proof`
        // off `receipt.super_proof.is_some()`, not off the core result alone.
        let mut receipt = create_test_receipt();
        assert!(
            receipt.super_proof.is_some(),
            "fixture must carry a super_proof"
        );

        let mut core_result = base_core_result();
        core_result.inclusion_valid = true;
        core_result.super_inclusion_valid = false;
        core_result.super_consistency_valid = true;

        let result_with_super = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt: receipt.clone(),
            core_result: core_result.clone(),
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };
        // With super_proof present, the broken super_inclusion must fail proofs_valid.
        assert!(!result_with_super.proof_verdict().proofs_valid());

        receipt.super_proof = None;
        let result_without_super = SingleVerificationResult {
            source_path: std::path::PathBuf::from("test.pdf"),
            receipt_path: std::path::PathBuf::from("test.pdf.atl"),
            file_hash: [0xab; 32],
            file_hash_valid: true,
            receipt,
            core_result,
            anchor_results: vec![],
            policy: AnchorPolicy::AllAnchors,
        };
        // With no super_proof, the (irrelevant) broken super fields are ignored.
        assert!(result_without_super.proof_verdict().proofs_valid());
    }
}
