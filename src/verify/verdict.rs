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
//! [`Status::Invalid`] means at least one fact about the evidence was
//! CHECKED and is FALSE: `message_imprint` is `Mismatch` or `Malformed`,
//! `cms_signature == Refuted`, `timestamping_eku` names a *checked* EKU
//! failure (`Absent`/`Malformed`/`NotCritical`/`NotExclusive` — but never
//! `NotChecked`), a certificate path that was found and failed validation,
//! `target_hash != proof.root_hash`, a broken inclusion or Super-Tree proof,
//! or a source file whose hash does not match the receipt.
//!
//! Note that `timestamping_eku_ok == false` is NOT sufficient: that boolean
//! is also `false` for `TimestampingEku::NotChecked`, where the check never
//! ran. Branch on the enum, not the boolean.
//!
//! [`Status::Untrusted`] means **nothing was refuted** and this verifier
//! could not finish the check. Note the wording: it does *not* mean every
//! fact holds — a fact may have been impossible to evaluate at all. Several
//! distinct situations land here, and only the first two are about missing
//! trust material:
//!
//! - `TerminalAnchor::Assumed` — a self-issued terminal nobody vouched for;
//! - `PathStatus::Incomplete` — an issuer certificate is simply missing;
//! - `PathStatus::Indeterminate` — the chain could not be *evaluated* at all
//!   (a signature algorithm, public-key algorithm or curve `atl-core` does
//!   not implement — a SHA-1-self-signed root is the common case — or the
//!   path-exploration depth limit);
//! - `CmsSignature::Indeterminate` — the token's own CMS signature could not
//!   be evaluated, for the same class of reason (P-521 and RSA-PSS are not
//!   implemented);
//! - `MessageImprint::Indeterminate` — the token's `messageImprint` names a
//!   hash algorithm `atl-core` does not implement, so it was never compared
//!   with the receipt's root at all;
//! - `TimestampingEku::NotChecked` — no signer certificate could be
//!   established, so its EKU was never examined;
//! - a `bitcoin_ots` anchor whose block header was not fetched
//!   (`BitcoinBlockNotChecked`) or could not be fetched
//!   (`BitcoinBlockUnavailable`).
//!
//! The `Indeterminate` cases are why `untrusted` may not be described to the
//! user as "trust material is missing" and nothing more: there the missing
//! thing may be an algorithm implementation, and telling the user to go find
//! an intermediate certificate would send them after something that does not
//! exist. What unites every case is that nothing was refuted.
//!
//! A receipt with **no anchors at all** (Receipt-Lite) is
//! [`Status::Untrusted`] with reason [`ReasonCode::ReceiptUnanchored`].
//! ATL v2.0 §5.5 is explicit: "At least one anchor MUST be verified to
//! establish trust in the receipt", and "A receipt without any verified
//! anchors SHOULD be treated as untrustworthy". A receipt carrying no
//! anchors has zero verified anchors by definition, so it cannot be a
//! successful terminal outcome of `verify`. It used to exit 0 under the word
//! `pending`, which accepted precisely what §5.5 says to treat as
//! untrustworthy.
//!
//! "Pending" survives as a *description* of the receipt's state — it is
//! genuinely not yet anchored, and the prose and the `anchor_status` field
//! still say so — but it is no longer a status and no longer exit 0.
//!
//! [`Status::Valid`] is acceptance. Acceptance is relative to the anchor
//! policy in force ([`crate::verify::policy::AnchorPolicy`]): under the
//! default every anchor the receipt presents must be verified; under
//! `--allow-single-anchor` one is enough. A `Valid` reached under the
//! relaxed policy while some anchor went unresolved is still `Valid`, and
//! every renderer is required to say on what terms — see
//! [`crate::verify::policy::TrustAssessment::accepted_with_gaps`].
//!
//! # `PathStatus::Incomplete` and `chain_valid_at_gen_time`
//!
//! `atl-core` reports `chain_valid_at_gen_time == false` whenever the path
//! is `Incomplete` or `Indeterminate`, because no complete path was
//! validated. That flag being `false` is therefore NOT by itself evidence
//! that anything is wrong — it is only a refutation when a candidate path
//! was found and rejected, which `atl-core` reports distinctly as
//! `PathStatus::Invalid`. The classifier that applies this rule is
//! [`crate::verify::anchor::AnchorDetails::rfc3161_verdict`], not anything
//! in this file: it gathers every refutation before forming a verdict, and
//! reads `chain_valid_at_gen_time` only for a `Complete` path, where a
//! `false` really would be a contradiction.

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
    /// The CMS `SignerInfo` signature was checked and did not verify, or a
    /// required signed attribute is missing, duplicated, malformed or
    /// mismatched.
    CmsSignatureInvalid,
    /// The signer certificate lacks the exclusive critical
    /// `id-kp-timeStamping` EKU: the extension is absent, malformed,
    /// non-critical, or names other purposes. All four were *checked*.
    TsaTimestampingEkuInvalid,
    /// The token's `messageImprint` is structurally broken — its hash length
    /// contradicts the algorithm it names. A refutation, but deliberately
    /// not `tsa_imprint_mismatch`: no comparison could be attempted, so
    /// calling it a mismatch would explain a proven defect with a cause that
    /// is not true of it.
    TsaImprintMalformed,
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
    /// The OTS proof's computed Merkle root does not match the one that two
    /// or more of the configured block-explorer APIs report for that block.
    BitcoinMerkleRootMismatch,

    // --- Nothing refuted, check not finished (Untrusted) ---
    //
    // Two shapes live here: material genuinely missing on this side, and
    // facts that could not be evaluated at all. Only the former can be
    // fixed by supplying something.
    /// Every fact holds, but the chain terminates in a certificate no
    /// caller-supplied trust store names.
    TsaRootNotTrusted,
    /// Every fact holds, but chain construction ran out of certificates
    /// before reaching any terminal — an issuer certificate is missing.
    TsaChainIncomplete,
    /// The signer certificate's timestamping EKU was never examined,
    /// because no signer certificate could be established in the first
    /// place. Distinct from `tsa_timestamping_eku_invalid`, which reports a
    /// check that ran and failed: an unexamined fact may be neither passed
    /// nor failed.
    TsaTimestampingEkuNotChecked,
    /// The token's `messageImprint` could not be *compared* with the
    /// receipt's root hash: it names a hash algorithm `atl-core` does not
    /// implement, so no comparison took place. ATL mandates a *minimum* of
    /// algorithm support, not a prohibition on the rest, so this is the
    /// verifier's limitation rather than the token's defect — never a
    /// refutation.
    TsaImprintIndeterminate,
    /// The CMS `SignerInfo` signature could not be *evaluated*: it uses a
    /// signature, digest or public-key algorithm (or an ESS binding hash)
    /// `atl-core` does not implement — P-521 and RSA-PSS are the concrete
    /// cases today. Nothing about the signature is asserted, so this is
    /// never a refutation; it fails closed like any other `untrusted`.
    CmsSignatureIndeterminate,
    /// Nothing was refuted and nothing is missing from the token: the
    /// certificate path could not be *evaluated*. Either a signature on it
    /// uses cryptography `atl-core` does not implement (an unsupported
    /// signature algorithm, public-key algorithm or curve — a
    /// SHA-1-self-signed root is the case that motivated this code), or
    /// path exploration hit its depth limit. Supplying more certificates
    /// does not necessarily help; see the anchor's `error` text for what
    /// actually stopped the check.
    TsaChainIndeterminate,
    /// The OTS proof is structurally sound but no block header was fetched,
    /// so its Merkle root was never compared against one.
    BitcoinBlockNotChecked,
    /// A Bitcoin block lookup was attempted and failed (network/API error),
    /// so the anchor could not be confirmed either way.
    BitcoinBlockUnavailable,
    /// The block-explorer APIs queried for this block **contradicted each
    /// other** about its header.
    ///
    /// Emphatically not a refutation. Nothing about the receipt was shown to
    /// be false: the sources this verifier depends on disagree, so there is
    /// no established header to compare the OTS proof against. Refuting
    /// evidence on the strength of a source conflict would let a single
    /// wrong or compromised API turn sound evidence into an accusation.
    ///
    /// It is nonetheless an event the user must see — it can mean a chain
    /// fork, a stale index, or a compromised endpoint — so the conflicting
    /// reports are published per source rather than summarised away.
    BitcoinProvidersDisagree,
    /// Only one block-explorer API answered, so its report of the block
    /// header is uncorroborated.
    ///
    /// A single source decides nothing here, in either direction. It cannot
    /// make the anchor `verified`, because one endpoint's word is not proof
    /// of what Bitcoin contains; and it cannot make the receipt `invalid`
    /// either, for exactly the same reason — a fact that is not established
    /// cannot be established as false.
    BitcoinSingleSourceOnly,

    // --- Receipt-level aggregates ---
    /// The receipt carries no anchors at all (Receipt-Lite), so it has zero
    /// **verified anchors** and ATL v2.0 §5.5's floor is not met.
    ///
    /// Maps to [`Status::Untrusted`] and exit code 3. It is not a
    /// refutation: the receipt's proofs may be entirely sound, and nothing
    /// about it has been shown false. What is absent is any external
    /// attestation that the entry existed at a point in time — which is the
    /// whole claim an ATL receipt is for. §5.5: "A receipt without any
    /// verified anchors SHOULD be treated as untrustworthy."
    ReceiptUnanchored,
    /// At least one batch item was refuted.
    BatchItemsInvalid,
    /// At least one batch item could not be processed at all — an unreadable
    /// source file, or a receipt that would not parse.
    ///
    /// Maps to [`Status::Error`] and exit code 2, the same outcome
    /// single-file mode produces for the same input. It used to map to
    /// `Invalid`, which asserted that the *evidence was refuted* when the
    /// tool had merely failed to read a file — and made the exit code depend
    /// on whether the caller passed a file or a directory.
    ///
    /// The bucket deliberately does not distinguish "could not open" from
    /// "would not parse": single-file mode does not either, and matching it
    /// is the whole point.
    BatchItemsErrored,
    /// No batch item was refuted, but at least one could not be verified to
    /// completion — a missing trust root, or a check that could not be
    /// performed. See that item's own reason code for which.
    BatchItemsUntrusted,
    /// At least one batch item carries no anchors at all (Receipt-Lite), so
    /// the batch as a whole contains a receipt with zero verified anchors.
    ///
    /// [`Status::Untrusted`], exit code 3 — the same answer single-file mode
    /// gives for the same receipt, for the same ATL v2.0 §5.5 reason. It was
    /// `pending` and exit 0 on both paths until that was recognised as
    /// accepting what §5.5 says to treat as untrustworthy.
    BatchItemsUnanchored,
    /// At least one path the caller named was never verified at all: a
    /// source file with no matching receipt, or a receipt with no matching
    /// source file.
    ///
    /// This is not cosmetic bookkeeping. The caller pointed at those files
    /// and asked about them; answering `valid` while silently skipping them
    /// would report success for work that was never done. Nothing about them
    /// is refuted — they were simply not checked — so this is `Untrusted`,
    /// but it must reach the aggregate verdict and the exit code, not just a
    /// summary line.
    BatchItemsUnmatched,
    /// A non-empty batch in which **no** file was verified. A backstop: with
    /// the buckets above routed correctly this should be unreachable, and it
    /// exists so that a future change to the counts cannot resurrect a
    /// `valid` verdict backed by zero verifications.
    BatchNothingVerified,
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
            Self::TsaImprintMalformed => "tsa_imprint_malformed",
            Self::TsaTimestampingEkuNotChecked => "tsa_timestamping_eku_not_checked",
            Self::SuperProofMissing => "super_proof_missing",
            Self::BitcoinOtsProofInvalid => "bitcoin_ots_proof_invalid",
            Self::BitcoinMerkleRootMismatch => "bitcoin_merkle_root_mismatch",
            Self::TsaRootNotTrusted => "tsa_root_not_trusted",
            Self::TsaChainIncomplete => "tsa_chain_incomplete",
            Self::TsaImprintIndeterminate => "tsa_imprint_indeterminate",
            Self::CmsSignatureIndeterminate => "cms_signature_indeterminate",
            Self::TsaChainIndeterminate => "tsa_chain_indeterminate",
            Self::BitcoinBlockNotChecked => "bitcoin_block_not_checked",
            Self::BitcoinBlockUnavailable => "bitcoin_block_unavailable",
            Self::BitcoinProvidersDisagree => "bitcoin_providers_disagree",
            Self::BitcoinSingleSourceOnly => "bitcoin_single_source_only",
            Self::ReceiptUnanchored => "receipt_unanchored",
            Self::BatchItemsInvalid => "batch_items_invalid",
            Self::BatchItemsUntrusted => "batch_items_untrusted",
            Self::BatchItemsUnanchored => "batch_items_unanchored",
            Self::BatchItemsUnmatched => "batch_items_unmatched",
            Self::BatchNothingVerified => "batch_nothing_verified",
            Self::BatchItemsErrored => "batch_items_errored",
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
/// Ordered by severity so aggregation over a batch is a `max`: a refutation
/// outranks a runtime failure, which outranks an unfinished check, which
/// outranks acceptance.
///
/// `Error` is deliberately *below* `Invalid`. A neighbouring file that could
/// not be opened must never conceal a receipt that was checked and refuted —
/// the same refutations-before-inabilities rule that governs every other
/// aggregate in this crate.
///
/// There is no `Pending`. A receipt with no anchors is `Untrusted`, for the
/// ATL v2.0 §5.5 reason given in the module docs; keeping a separate
/// exit-0 word for it was how this tool accepted receipts the specification
/// says to treat as untrustworthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// Accepted: every fact holds and the anchor policy in force is
    /// satisfied. Under the default policy that means every anchor the
    /// receipt presents reached a caller-supplied trust root; under
    /// `--allow-single-anchor` it means at least one did.
    Valid,
    /// Not refuted, not accepted. Three shapes reach here: the receipt
    /// presents no anchors at all (§5.5's floor cannot be met); material is
    /// missing on the verifier's side (an untrusted terminal root, an
    /// incomplete certificate path, an unfetched Bitcoin block); or a fact
    /// could not be evaluated at all (an imprint, CMS signature or
    /// certificate signature using cryptography this verifier does not
    /// implement). The reason code says which; what unites them is that
    /// nothing was refuted.
    Untrusted,
    /// Could not be processed: a file that would not open, or a receipt that
    /// would not parse. Not a statement about the evidence at all — the tool
    /// never got far enough to make one.
    ///
    /// Exists so that batch mode can report the same thing single-file mode
    /// does for the same input. Single mode returns a `CliError` (exit 2)
    /// and never reaches a `Status`; batch mode must still describe the run,
    /// and calling an unreadable file "refuted" made the contract depend on
    /// how the tool was invoked.
    Error,
    /// Refuted: at least one checkable fact is false.
    Invalid,
}

impl Status {
    /// The stable wire string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Untrusted => "untrusted",
            Self::Error => "error",
            Self::Invalid => "invalid",
        }
    }

    /// The process exit code for this status.
    ///
    /// `Untrusted` gets its own code (3) precisely so a script can tell
    /// "this evidence is broken" (1) from "I could not finish checking it"
    /// (3) without parsing JSON. Code 3 covers missing trust material, a
    /// check that could not be performed at all, **and** a receipt with no
    /// anchors — read the reason code before telling a user to go and supply
    /// something. `Error` is the operational code (2): the tool failed to
    /// process an input, which says nothing about the evidence.
    ///
    /// Exactly one status exits 0. That is the point: a caller who tests
    /// `if atl-cli verify ...` is asking "was this evidence accepted", and
    /// only `Valid` answers yes.
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        match self {
            Self::Valid => ExitCode::Valid,
            Self::Untrusted => ExitCode::Untrusted,
            // Exit 2, exactly as single-file mode returns for the same
            // input. A retry system reading 1 as "the evidence is bad" and 2
            // as "something went wrong on this run" must not be told
            // different stories by the two modes.
            Self::Error => ExitCode::Error,
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

    /// The verdict for a receipt carrying no anchors at all (Receipt-Lite).
    ///
    /// [`Status::Untrusted`], exit 3, reason `receipt_unanchored`. Named
    /// separately from [`Self::untrusted`] so the call site reads as the
    /// ATL v2.0 §5.5 rule it implements, and so nothing can quietly turn it
    /// back into a success.
    #[must_use]
    pub const fn unanchored() -> Self {
        Self {
            status: Status::Untrusted,
            reason_code: Some(ReasonCode::ReceiptUnanchored),
        }
    }

    /// A verdict with an explicit status and reason, for aggregates that
    /// need a state the convenience constructors above do not cover.
    #[must_use]
    pub const fn new(status: Status, reason: ReasonCode) -> Self {
        Self {
            status,
            reason_code: Some(reason),
        }
    }

    /// `true` only for [`Status::Valid`]. Nothing else — in particular not
    /// [`Status::Untrusted`], which now covers the unanchored receipt too —
    /// may ever be presented as a verified receipt.
    #[must_use]
    #[allow(dead_code)] // exercised by unit tests; the runtime path reads
                        // `status` directly
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

    /// ATL v2.0 §5.5: "A receipt without any verified anchors SHOULD be
    /// treated as untrustworthy." A Receipt-Lite has none, so it must not
    /// be a successful outcome of `verify`.
    #[test]
    fn an_unanchored_receipt_is_untrusted_and_never_exits_zero() {
        let verdict = ReceiptVerdict::unanchored();
        assert_eq!(verdict.status, Status::Untrusted);
        assert_eq!(verdict.status.as_str(), "untrusted");
        assert_eq!(verdict.reason_code, Some(ReasonCode::ReceiptUnanchored));
        assert!(!verdict.is_valid());
        assert_eq!(verdict.exit_code(), ExitCode::Untrusted);
        assert_eq!(verdict.exit_code().code(), 3);
    }

    /// Exactly one status may exit 0.
    #[test]
    fn only_valid_exits_zero() {
        for status in [Status::Untrusted, Status::Error, Status::Invalid] {
            assert_ne!(status.exit_code().code(), 0, "{status} must not exit 0");
        }
        assert_eq!(Status::Valid.exit_code().code(), 0);
    }

    #[test]
    fn exit_codes_are_the_documented_ones() {
        assert_eq!(ReceiptVerdict::VALID.exit_code().code(), 0);
        assert_eq!(ReceiptVerdict::unanchored().exit_code().code(), 3);
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
        assert!(Status::Invalid > Status::Error);
        assert!(Status::Error > Status::Untrusted);
        assert!(Status::Untrusted > Status::Valid);
    }

    /// A runtime failure exits 2 in every mode, and never claims the
    /// evidence was refuted.
    #[test]
    fn error_status_is_operational_not_a_refutation() {
        let verdict = ReceiptVerdict::new(Status::Error, ReasonCode::BatchItemsErrored);
        assert_eq!(verdict.exit_code(), ExitCode::Error);
        assert_eq!(verdict.exit_code().code(), 2);
        assert!(!verdict.is_valid());
        assert_eq!(verdict.status.as_str(), "error");
        // And it must not be mistaken for the refutation code.
        assert_ne!(verdict.exit_code(), ExitCode::Invalid);
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
            ReasonCode::TsaImprintMalformed,
            ReasonCode::TsaTimestampingEkuNotChecked,
            ReasonCode::TsaImprintIndeterminate,
            ReasonCode::CmsSignatureIndeterminate,
            ReasonCode::TsaChainIndeterminate,
            ReasonCode::BitcoinBlockNotChecked,
            ReasonCode::BitcoinBlockUnavailable,
            ReasonCode::BitcoinProvidersDisagree,
            ReasonCode::BitcoinSingleSourceOnly,
            ReasonCode::ReceiptUnanchored,
            ReasonCode::BatchItemsInvalid,
            ReasonCode::BatchItemsErrored,
            ReasonCode::BatchItemsUnanchored,
            ReasonCode::BatchItemsUnmatched,
            ReasonCode::BatchNothingVerified,
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
