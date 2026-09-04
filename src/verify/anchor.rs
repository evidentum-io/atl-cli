//! The per-anchor verdict every renderer reads, projected from the facts
//! `atl-core` establishes.
//!
//! # What this module is not
//!
//! It is **not** an implementation of ATL v2.0 §5.5. That is
//! [`verify_receipt_anchors`], and this crate calls it: binding each anchor
//! to the receipt's own root, decoding the payload, running the steps the
//! specification names and deciding which facts refute and which merely fail
//! to confirm is *protocol orchestration*, and a second implementation of a
//! mandatory rule drifts from the first. This crate carried one, and every
//! defect fixed on one side stayed open on the other until it did not.
//!
//! What lives here is everything downstream of the facts:
//!
//! * [`AnchorVerdict`] and [`AnchorState`] — this CLI's three-valued
//!   classification, and the granularity a user can act on;
//! * [`reason_for_finding`] — the stable `snake_case` reason codes, which are
//!   this CLI's contract and deliberately not `atl-core`'s vocabulary;
//! * [`AnchorDetails`] — the fact set as the renderers publish it;
//! * [`BlockSourceReport`] and [`PreparedOts`] — the Bitcoin half, which
//!   `atl-core` cannot finish because it performs no I/O.
//!
//! RFC 3161 verification is **pure computation**: decoding the token,
//! checking the CMS signature, and walking the certificate chain need no
//! network access whatsoever. It therefore reaches a final answer on every
//! verification, offline and online alike. Only `bitcoin_ots` anchors need
//! the network, and only to ask block-explorer APIs for the header whose
//! Merkle root the OTS proof is compared against
//! ([`crate::verify::online`]). Nothing here observes the Bitcoin network.
//!
//! Per the ATL trust model (`docs-md/atl-trust-model-decisions.md`, decision
//! Р1) nothing in this module knows any identity: no root, no fingerprint,
//! no TSA name. All trust material arrives as a caller-supplied
//! [`TrustStore`], built from `--tsa-trust-store` / `--tsa-intermediates`.
//!
//! # A refuted anchor is not a refuted receipt
//!
//! Nothing signs or hashes a receipt's `anchors` array, so every refutation
//! this module can report is one anybody who relayed the receipt could have
//! manufactured. It is always shown — an appended anchor is a sign of
//! interference — and it never decides the receipt's status. See
//! [`crate::verify::single::SingleVerificationResult::verdict`].

use atl_core::ots::BitcoinAttestation;
use atl_core::{
    verify_receipt_anchors, AnchorEvidence, AnchorFacts, CmsSignature, MessageImprint, PathStatus,
    ReceiptAnchor, Revocation, Rfc3161AnchorFacts, SelfSignature, TerminalAnchor, TimestampingEku,
    TrustStore, VerificationError, VerifyOptions,
};
use subtle::ConstantTimeEq;

use crate::verify::verdict::ReasonCode;

/// One block-explorer API's report of a block header.
///
/// A *report*, not a fact: it is what an HTTP endpoint returned. Two of
/// these agreeing is the strongest statement this tool makes about Bitcoin,
/// and it is still only "two separately operated endpoints said the same
/// thing" — their independence from each other is not established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSourceReport {
    /// The endpoint's name, e.g. `"blockstream.info"`.
    pub source: String,
    /// Block hash as reported (hex, no prefix).
    pub block_hash: String,
    /// Merkle root as reported (hex, no prefix).
    pub merkle_root: String,
    /// Block time as reported, in seconds since the epoch.
    pub block_timestamp_secs: u64,
}

impl BlockSourceReport {
    /// Two sources describe the same block header.
    ///
    /// **The single definition of agreement in this crate.** The classifier
    /// that decides `bitcoin_providers_disagree` and both renderers that
    /// show a disagreement call this one function, so what counts as a
    /// conflict cannot differ between deciding and displaying.
    ///
    /// It could, and did. The classifier compared the block hash, the Merkle
    /// root *and* the time, while the human renderer compared only the first
    /// two — so a disagreement about nothing but the time produced
    /// `bitcoin_providers_disagree` with no `SOURCES DISAGREE` block, no
    /// conflicting rows, and nothing telling the reader why. The event these
    /// checks exist to surface was silently invisible.
    ///
    /// All three fields are compared because all three are block-header
    /// facts — two correct providers describing the same block cannot differ
    /// on any of them — and all three are published downstream, so a
    /// conflict on any one would mean publishing a value this tool's own
    /// sources contradict.
    #[must_use]
    pub fn agrees_with(&self, other: &Self) -> bool {
        fn same_hex(a: &str, b: &str) -> bool {
            match (hex::decode(a), hex::decode(b)) {
                (Ok(a), Ok(b)) if a.len() == b.len() => a.ct_eq(&b).into(),
                // Unparsable or differently sized: not equal. Both are
                // rejected upstream by the 64-hex-char check, so this is a
                // guard rather than a path.
                _ => false,
            }
        }
        self.block_timestamp_secs == other.block_timestamp_secs
            && same_hex(&self.block_hash, &other.block_hash)
            && same_hex(&self.merkle_root, &other.merkle_root)
    }
}

/// Every source in `sources` describes the same block header.
///
/// `true` for an empty or single-element slice: there is nothing to
/// contradict. See [`BlockSourceReport::agrees_with`] for why this is the
/// only place the question is answered.
#[must_use]
pub fn sources_agree(sources: &[BlockSourceReport]) -> bool {
    let Some(first) = sources.first() else {
        return true;
    };
    sources.iter().all(|s| s.agrees_with(first))
}

/// Verdict for a single anchor.
///
/// The three states mirror [`crate::verify::verdict::Status`] minus
/// the unanchored case (an anchor that exists is never "unanchored"):
/// `Invalid` means
/// a fact about the anchor was checked and is false; `Untrusted` means
/// **nothing was refuted** and the check could not be finished.
///
/// Note the precise wording of `Untrusted`. It does *not* mean "every fact
/// holds": a fact may have been impossible to evaluate at all — an imprint
/// hash algorithm, a CMS signature algorithm or a certificate signature this
/// verifier does not implement. What unites the state is the absence of any
/// refutation, not the presence of every confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// Every fact holds and the anchor reached a configured trust root.
    Valid,
    /// Nothing was refuted, and the check could not be finished: either
    /// trust material is missing on the verifier's side, or a fact could not
    /// be evaluated at all. See the [`ReasonCode`] for which.
    Untrusted(ReasonCode),
    /// At least one fact about the anchor was checked and is false.
    ///
    /// **About the anchor, and about nothing else.** A receipt's `anchors`
    /// array is covered by neither the leaf hash nor the checkpoint blob, so
    /// anybody who relays a receipt can append an entry to it with no key —
    /// which means every refutation this crate can report about an anchor is
    /// one a stranger could have produced. It is always shown, and it never
    /// makes the receipt [`crate::verify::verdict::Status::Invalid`]. See
    /// [`crate::verify::single::SingleVerificationResult::verdict`].
    Invalid(ReasonCode),
}

impl AnchorVerdict {
    /// `true` only for [`Self::Valid`] — that is, only for a **verified
    /// anchor** in the sense [`AnchorState::Verified`] defines.
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

    /// The anchor's state, at the granularity a caller can act on.
    ///
    /// [`Self::Untrusted`] is one verdict covering several genuinely
    /// different situations; this projects it onto the distinctions that
    /// call for different reactions. The verdict remains the authority — the
    /// state is derived from it and never the other way round.
    #[must_use]
    pub const fn state(self) -> AnchorState {
        match self {
            Self::Valid => AnchorState::Verified,
            Self::Invalid(_) => AnchorState::Refuted,
            Self::Untrusted(reason) => AnchorState::from_reason(reason),
        }
    }
}

/// What became of one anchor, at the granularity that determines what — if
/// anything — a caller should do about it.
///
/// # `Verified` is a load-bearing word
///
/// ATL v2.0 §5.5 requires "at least one anchor MUST be verified to establish
/// trust in the receipt". This crate answers that question with exactly one
/// state, [`Self::Verified`], defined as: **the cryptographic facts were
/// checked AND the certificate path reached a trust anchor supplied by the
/// verifier's own trust store.**
///
/// Both halves are required. A token whose CMS signature and certificate
/// chain are flawless but whose terminal certificate no trust store names
/// proves only that some key signed it; which key, and whether anyone should
/// care, is exactly what was not established. That state has its own name
/// here — [`Self::CryptographicallyConsistent`] — and it is never counted as
/// a verified anchor, in the §5.5 tally or anywhere else.
///
/// # A gap in the specification, recorded here
///
/// §5.5's five steps for an RFC 3161 anchor say "verify the cryptographic
/// signature of the Time Stamping Authority" and stop. They never mention
/// building a certificate path, nor where a verifier obtains the trust
/// anchors that path must reach. Read literally, a self-signed certificate
/// generated by an attacker satisfies step 4. This implementation therefore
/// applies a stricter rule than the text states, and the gap is written up
/// in the CHANGELOG and README rather than left as a comment — the
/// specification is what needs fixing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorState {
    /// Cryptographic facts checked **and** a caller-supplied trust root
    /// reached. The only state that counts towards ATL v2.0 §5.5.
    Verified,
    /// Every checkable fact holds, and the path terminates in a certificate
    /// no trust store names. Nothing is refuted and nothing is missing from
    /// the token: what is missing is a reason to believe the terminal.
    ///
    /// Deliberately not called "verified": see the type-level docs.
    CryptographicallyConsistent,
    /// Path construction ran out of certificates before reaching any
    /// terminal — an issuer certificate is simply absent. The one state a
    /// caller fixes by supplying `--tsa-intermediates`.
    Incomplete,
    /// The check was not performed, because the selected mode does not
    /// perform it: an offline run does not fetch the Bitcoin block that
    /// would confirm an OTS proof.
    NotChecked,
    /// The check was attempted and did not complete — the Bitcoin block
    /// lookup failed. Distinct from [`Self::NotChecked`]: here the tool
    /// tried, so a retry is meaningful.
    Unavailable,
    /// A block-explorer API answered, but only one did, so nothing
    /// corroborates it. One endpoint's word is not proof of what Bitcoin
    /// contains — in either direction. A retry with better connectivity is
    /// the remedy.
    Uncorroborated,
    /// The block-explorer APIs answered and **contradicted each other**
    /// about the block header. Nothing about the receipt is refuted; the
    /// sources this verifier depends on do not agree, so there is no
    /// established header to compare against.
    ///
    /// Its own state because the reaction differs from every neighbour: a
    /// retry will most likely reproduce it, no certificate helps, and the
    /// conflict itself is a finding — a fork, a stale index, or a
    /// compromised endpoint.
    Contested,
    /// The check cannot be performed at all by this build: a hash,
    /// signature, public-key algorithm or curve `atl-core` does not
    /// implement, or a fact that depends on one that could not be
    /// established. No certificate and no network access changes this.
    Unevaluable,
    /// At least one checkable fact about the anchor is false.
    Refuted,
    /// Not resolved, for a reason none of the above names.
    ///
    /// No reason code reaches this arm today. It exists so that adding one
    /// to [`ReasonCode`] cannot silently be reported as a stronger state
    /// than it is: the weakest honest claim is "not resolved — read the
    /// reason code".
    Unresolved,
}

impl AnchorState {
    /// Project an [`AnchorVerdict::Untrusted`] reason code onto the state it
    /// describes.
    ///
    /// The match is **exhaustive on purpose**. It used to end in a wildcard,
    /// which meant a newly added [`ReasonCode`] would quietly come out as
    /// the vague `Unresolved` with nothing to warn anyone: the compiler
    /// cannot object to an arm that already covers everything. Listing every
    /// variant makes adding a reason code a build failure here, and forces
    /// whoever adds it to decide what a caller can actually do about it.
    #[must_use]
    pub const fn from_reason(reason: ReasonCode) -> Self {
        match reason {
            ReasonCode::TsaRootNotTrusted => Self::CryptographicallyConsistent,
            ReasonCode::TsaChainIncomplete => Self::Incomplete,
            ReasonCode::BitcoinBlockNotChecked => Self::NotChecked,
            ReasonCode::BitcoinBlockUnavailable => Self::Unavailable,
            ReasonCode::BitcoinSingleSourceOnly => Self::Uncorroborated,
            ReasonCode::BitcoinProvidersDisagree => Self::Contested,
            // Four shapes of "this build cannot evaluate it": an
            // unimplemented hash for the imprint, an unimplemented signature
            // or key algorithm for the CMS signature or for a certificate on
            // the path, and the EKU check that never ran because no signer
            // could be established for it to run against.
            ReasonCode::TsaImprintIndeterminate
            | ReasonCode::CmsSignatureIndeterminate
            | ReasonCode::TsaChainIndeterminate
            | ReasonCode::TsaTimestampingEkuNotChecked
            // A fifth shape of the same thing: the receipt's own
            // `bitcoin_block_time` is a string this build's parser cannot
            // read, so the comparison §5.5.2 step 5 asks for never ran. No
            // certificate and no network access changes it.
            | ReasonCode::BitcoinClaimedTimeUnreadable
            // A sixth: the Cargo feature that implements this anchor type is
            // compiled out, so nothing about the anchor was examined at all.
            | ReasonCode::AnchorTypeUnsupported => Self::Unevaluable,

            // Everything below is either a refutation or a receipt-/batch-
            // level aggregate, and none of them reaches this function: a
            // refuted anchor gets `Refuted` straight from
            // [`AnchorVerdict::state`], and the aggregates never appear on an
            // anchor at all. They are enumerated rather than swept up by a
            // wildcard so the exhaustiveness above is real.
            //
            // The answer for them is the weakest honest one -- "not
            // resolved, read the reason code" -- because inferring a
            // refutation from an `Untrusted` verdict would assert on this
            // side of the code exactly the thing the verdict declined to
            // assert on the other.
            ReasonCode::FileHashMismatch
            | ReasonCode::InclusionProofInvalid
            | ReasonCode::SuperInclusionProofInvalid
            | ReasonCode::SuperConsistencyProofInvalid
            | ReasonCode::CheckpointRootHashMismatch
            | ReasonCode::CheckpointTreeSizeMismatch
            | ReasonCode::CheckpointSignatureInvalid
            | ReasonCode::MetadataHashMismatch
            | ReasonCode::ReceiptMalformed
            | ReasonCode::ReceiptVerificationFailed
            | ReasonCode::AnchorTargetInvalid
            | ReasonCode::AnchorHashMalformed
            | ReasonCode::AnchorTargetHashMismatch
            | ReasonCode::TsaTokenUnparsable
            | ReasonCode::TsaImprintMismatch
            | ReasonCode::TsaImprintMalformed
            | ReasonCode::CmsSignatureInvalid
            | ReasonCode::TsaTimestampingEkuInvalid
            | ReasonCode::TsaChainInvalidAtGenTime
            | ReasonCode::SuperProofMissing
            | ReasonCode::BitcoinOtsProofInvalid
            | ReasonCode::BitcoinMerkleRootMismatch
            | ReasonCode::BitcoinClaimedHeightContradictsProof
            | ReasonCode::BitcoinClaimedTimeContradictsBlock
            | ReasonCode::ReceiptCheckIncomplete
            | ReasonCode::ReceiptUnanchored
            | ReasonCode::AnchorQuorumUnmet
            | ReasonCode::BatchItemsInvalid
            | ReasonCode::BatchItemsErrored
            | ReasonCode::BatchItemsUntrusted
            | ReasonCode::BatchItemsUnmatched
            | ReasonCode::BatchNothingVerified
            | ReasonCode::LogConsistencyFailed => Self::Unresolved,
        }
    }

    /// The stable wire string for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::CryptographicallyConsistent => "cryptographically_consistent",
            Self::Incomplete => "incomplete",
            Self::NotChecked => "not_checked",
            Self::Unavailable => "unavailable",
            Self::Uncorroborated => "uncorroborated",
            Self::Contested => "contested",
            Self::Unevaluable => "unevaluable",
            Self::Refuted => "refuted",
            Self::Unresolved => "unresolved",
        }
    }
}

impl std::fmt::Display for AnchorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of verifying one anchor.
#[derive(Debug, Clone)]
pub struct AnchorVerificationResult {
    /// `"rfc3161"` or `"bitcoin_ots"`.
    pub anchor_type: String,
    /// The single classification every consumer derives from.
    pub verdict: AnchorVerdict,
    /// Anchor-**asserted** time, in nanoseconds since the epoch.
    ///
    /// What the anchor claims, not what this verifier established. For an
    /// RFC 3161 anchor it is the token's own `genTime` (or, failing that,
    /// the receipt's `timestamp` field), populated whenever the token got
    /// far enough to be parsed — certificate validity has to be evaluated
    /// against some instant. It is `None` for an anchor rejected before that
    /// point (a wrong `target`, a malformed hash, a `target_hash` that does
    /// not pin to this receipt), because such an anchor was never read as a
    /// token at all.
    ///
    /// Only treat it as an established time when [`Self::verdict`] is
    /// [`AnchorVerdict::Valid`]; the renderers emit it under a `claimed_*`
    /// name otherwise. For a `bitcoin_ots` anchor it is the time of the
    /// header the sources agreed on, and is left `None` unless a
    /// corroborated header was obtained and matched.
    pub timestamp_nanos: Option<u64>,
    /// Human-readable elaboration. Never load-bearing: branch on
    /// [`Self::verdict`], not on this text.
    pub error: Option<String>,
    /// The full fact set, carried through rather than collapsed.
    pub details: AnchorDetails,
}

impl AnchorVerificationResult {
    /// `true` only when this anchor is a **verified anchor** in the ATL v2.0
    /// §5.5 sense: cryptographic facts checked *and* a caller-supplied trust
    /// root reached. See [`AnchorState::Verified`].
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verdict.is_valid()
    }

    /// This anchor's state, derived from its verdict.
    #[must_use]
    pub const fn state(&self) -> AnchorState {
        self.verdict.state()
    }

    /// Stable JSON/prose label for an RFC 3161 anchor's trust state, or
    /// `None` for any other anchor type.
    ///
    /// Derived from [`Self::verdict`] — the one classification every
    /// consumer reads — so the label can never disagree with the verdict,
    /// the receipt status, or the exit code. It lived on
    /// [`AnchorDetails`] while the CLI formed the verdict from those same
    /// fields; now that `atl-core` establishes the facts and the verdict
    /// follows from its findings, the fact set is no longer a place a
    /// verdict can be recomputed from.
    #[must_use]
    pub const fn rfc3161_trust_state(&self) -> Option<&'static str> {
        if !matches!(self.details, AnchorDetails::Rfc3161 { .. }) {
            return None;
        }
        Some(match self.verdict {
            AnchorVerdict::Valid => "trusted",
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted) => "assumed",
            AnchorVerdict::Untrusted(
                ReasonCode::TsaChainIndeterminate
                | ReasonCode::CmsSignatureIndeterminate
                | ReasonCode::TsaImprintIndeterminate
                | ReasonCode::TsaTimestampingEkuNotChecked,
            ) => "indeterminate",
            AnchorVerdict::Untrusted(_) => "incomplete",
            AnchorVerdict::Invalid(_) => "failed",
        })
    }
}

/// What became of the *time* half of ATL v2.0 §5.5.2 step 5: the receipt's
/// `bitcoin_block_time` against the time of the block header.
///
/// Four-valued rather than a boolean, for the reason every fact type in this
/// crate is: "compared and different" and "never compared" are different
/// findings, and only the first is a refutation. The block time appears
/// nowhere in an OTS proof — it exists only in the block header — so offline
/// there is nothing to compare against, and the honest report of that is
/// [`Self::NotCompared`], never a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimedTimeCheck {
    /// Compared against the time of a header two or more configured sources
    /// agreed on, and equal.
    Matches,
    /// Compared against such a header, and different. A refutation.
    Contradicted,
    /// Not compared, because no corroborated header was obtained: an
    /// offline run, a failed lookup, a single uncorroborated source, or
    /// sources that contradicted each other. An inability.
    NotCompared,
    /// Not compared, because the receipt's own `bitcoin_block_time` is a
    /// string this build's parser cannot read. Also an inability — see
    /// [`ReasonCode::BitcoinClaimedTimeUnreadable`].
    Unreadable,
}

impl ClaimedTimeCheck {
    /// The stable wire string for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matches => "matches",
            Self::Contradicted => "contradicted",
            Self::NotCompared => "not_compared",
            Self::Unreadable => "unreadable",
        }
    }
}

impl std::fmt::Display for ClaimedTimeCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
        /// Whether the token's `MessageImprint` matched the receipt's root
        /// hash, contradicted it, or could not be compared at all.
        /// Three-valued because an unimplemented hash algorithm means no
        /// comparison happened — reporting that as a mismatch would assert
        /// the outcome of a check that never ran.
        message_imprint: MessageImprint,
        /// Whether the CMS `SignerInfo` signature verified, was refuted, or
        /// could not be evaluated at all. Three-valued because an algorithm
        /// `atl-core` does not implement must not be published as a broken
        /// signature — see [`reason_for_finding`].
        cms_signature: CmsSignature,
        /// Every link on the constructed path was valid at `genTime`.
        ///
        /// `atl-core` reports this as `false` whenever no complete path was
        /// built, so it is only a *refutation* when `path_status` is
        /// [`PathStatus::Invalid`] — a rule `atl-core` applies inside the
        /// finding it reports, never re-derived here.
        chain_valid_at_gen_time: bool,
        /// What stopped the chain from completing, in prose, when
        /// `atl-core` had something to say. Never load-bearing.
        chain_diagnostic: Option<String>,
        /// The signer certificate carries the exclusive critical
        /// `id-kp-timeStamping` EKU.
        timestamping_eku_ok: bool,
        /// *Which* RFC 3161 2.3 condition the EKU check came out on —
        /// absent, malformed, non-critical, non-exclusive, or never checked.
        /// A single boolean cannot tell a caller which, and they call for
        /// different reactions.
        timestamping_eku: TimestampingEku,
        /// How chain construction terminated.
        path_status: PathStatus,
        /// The certificate the chain terminated at, if any.
        terminal_anchor: Option<TerminalAnchor>,
        /// Revocation status (always `NotChecked` today).
        revocation: Revocation,
    },
    /// Bitcoin OpenTimestamps anchor facts.
    ///
    /// # What "the block" means here, exactly
    ///
    /// This tool does not observe the Bitcoin network. It queries
    /// block-explorer HTTP APIs and reads a block header out of their JSON.
    /// It validates no proof of work, follows no chain of headers, and has
    /// no independent way to know that what an endpoint returned is what
    /// Bitcoin contains. Every field below is therefore *what named sources
    /// reported*, and [`Self::Bitcoin::block_sources`] names them.
    ///
    /// Saying more than that — "observed on-chain", "confirmed against the
    /// blockchain" — was a claim about work this tool has never done, and
    /// the wording throughout this crate was corrected accordingly.
    Bitcoin {
        /// Block height carried by the earliest Bitcoin attestation **in
        /// the OTS proof**.
        ///
        /// The proof's number, not the receipt's — the two are separate
        /// assertions and are now compared with each other (§5.5.2 step 5);
        /// see `receipt_block_height`. This field used to be published as
        /// `claimed_block_height` with prose calling it "the receipt's own
        /// assertion", which named the wrong claimant: the receipt's own
        /// height field was not read anywhere in this crate.
        ///
        /// `None` when no attestation matches the receipt's claim (the
        /// height refutation) or when the proof never decoded: there is then
        /// no single attestation this run worked with, and inventing one —
        /// the lowest, say — would be picking a number the protocol never
        /// asked for. `proof_block_heights` carries the full set either way.
        ///
        /// Not an established fact until a block at that height has actually
        /// been fetched and its Merkle root matched (`merkle_match ==
        /// Some(true)`). Until then the renderers publish it under the
        /// `proof_` name — the same rule the RFC 3161 `genTime` follows.
        proof_block_height: Option<u64>,
        /// Every block height the OTS proof attests to, in proof order.
        ///
        /// Empty only when the proof never decoded. This is the evidence for
        /// a height refutation: a reader told the receipt's claim matches
        /// nothing must be able to see what the proof does attest to.
        proof_block_heights: Vec<u64>,
        /// Block height **the receipt states** for this anchor, in its
        /// `bitcoin_block_height` field.
        ///
        /// The receipt's own assertion about where in the chain this anchor
        /// lands, published verbatim and never as an established fact. It is
        /// checked against `proof_block_height` before anything else is
        /// reported about the anchor, so a fact set that reaches a reader
        /// with the two disagreeing cannot also carry a `Valid` verdict.
        receipt_block_height: u64,
        /// Block time **the receipt states**, in its `bitcoin_block_time`
        /// field, verbatim and unparsed.
        ///
        /// Kept as the receipt wrote it rather than normalised: what a
        /// reader needs to see beside `claimed_time_check: "unreadable"` is
        /// the exact string that could not be read.
        receipt_block_time: String,
        /// What became of the receipt's `bitcoin_block_time` — compared and
        /// equal, compared and different, or not compared at all.
        claimed_time_check: ClaimedTimeCheck,
        /// Block time in seconds, or `None` when no block was fetched.
        ///
        /// `Option`, not a `0` sentinel. As a `u64` it defaulted to `0` for
        /// an unfetched block and was rendered as
        /// `block_timestamp: "1970-01-01T00:00:00Z"` — a machine-parsable
        /// value that looks like a real timestamp, published for a check
        /// that never ran. That is worse than no field at all.
        block_timestamp_secs: Option<u64>,
        /// The anchor's `target_hash`, as written in the receipt.
        target_hash: String,
        /// Number of hash operations in the selected attestation's Merkle
        /// path, or `None` when no attestation was selected.
        operation_count: Option<usize>,
        /// Merkle root computed from the OTS proof (`sha256:` prefixed), or
        /// `None` when the proof did not decode or no attestation matched.
        computed_root: Option<String>,
        /// The Merkle root the sources report for that block, or `None` when
        /// no single agreed header was obtained.
        block_merkle_root: Option<String>,
        /// Whether the two roots match, or `None` if no single agreed header
        /// was obtained (no source answered, or the sources contradicted
        /// each other).
        merkle_match: Option<bool>,
        /// Every block-explorer API that answered, and what each reported.
        ///
        /// Always published, never summarised away. When the sources agree
        /// the entries are identical and the list is simply an attribution —
        /// *these* endpoints said so. When they disagree the list is the
        /// finding itself, and the only place a user can see it.
        block_sources: Vec<BlockSourceReport>,
    },
    /// The anchor was rejected before any fact set could be established.
    Unknown,
}

impl AnchorDetails {
    /// The SHA-256 fingerprint (hex, no prefix) of the certificate a caller
    /// would have to add to `--tsa-trust-store` to turn an
    /// `Untrusted`/`Assumed` outcome into `Valid`. `None` when the chain
    /// never reached a terminal (nothing specific to name).
    #[must_use]
    pub fn untrusted_root_fingerprint(&self) -> Option<String> {
        match self {
            Self::Rfc3161 {
                terminal_anchor:
                    Some(TerminalAnchor::Assumed {
                        sha256_fingerprint, ..
                    }),
                ..
            } => Some(hex::encode(sha256_fingerprint)),
            _ => None,
        }
    }
}

/// Render a compact explanation of why an RFC 3161 anchor did not reach
/// `Valid`.
///
/// Prose only: every fact it reads was already established by `atl-core`,
/// and the verdict was already decided by [`verdict_from_facts`] from the
/// findings `atl-core` reported. This function re-derives nothing.
fn summarize_rfc3161(facts: &Rfc3161AnchorFacts) -> String {
    let mut reasons = Vec::new();
    match facts.message_imprint {
        MessageImprint::Verified => {}
        MessageImprint::Mismatch => {
            reasons.push("messageImprint does not match the receipt's Data Tree root".to_string());
        }
        // Refuted too, but not a mismatch: no comparison could be attempted.
        MessageImprint::Malformed => {
            reasons.push(
                "messageImprint is malformed: its hash length contradicts the hash algorithm it \
                 names"
                    .to_string(),
            );
        }
        // No comparison happened, so nothing about the root is claimed, and
        // no certificate the caller could supply changes that.
        MessageImprint::Indeterminate => {
            reasons.push(
                "messageImprint could not be compared with the receipt's Data Tree root \
                 (nothing was refuted): it names a hash algorithm this verifier does not \
                 implement"
                    .to_string(),
            );
        }
    }
    match facts.cms_signature {
        CmsSignature::Verified => {}
        CmsSignature::Refuted => {
            reasons.push(match &facts.diagnostic {
                Some(detail) => format!("CMS signature invalid: {detail}"),
                None => "CMS signature invalid".to_string(),
            });
        }
        // Names the real cause, and does not suggest a remedy: no
        // certificate the caller could supply makes an unimplemented
        // algorithm implementable.
        CmsSignature::Indeterminate => {
            reasons.push(match &facts.diagnostic {
                Some(detail) => {
                    format!("CMS signature could not be checked (nothing was refuted): {detail}")
                }
                None => "CMS signature could not be checked (nothing was refuted)".to_string(),
            });
        }
    }
    if let Some(reason) = facts.timestamping_eku.reason() {
        reasons.push(format!(
            "signer certificate's id-kp-timeStamping EKU is not usable: {reason}"
        ));
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
        // Deliberately NOT the "supply an intermediate or a root" advice.
        // The chain could not be *evaluated* — most often because the
        // certificate is signed with cryptography atl-core does not
        // implement — and sending the user off to find a certificate they
        // may already have would waste their time and misdescribe the
        // problem. Name what actually stopped the check instead.
        PathStatus::Indeterminate => {
            reasons.push(match &facts.chain_diagnostic {
                Some(detail) => format!(
                    "certificate chain could not be evaluated (nothing was refuted): {detail}"
                ),
                None => {
                    "certificate chain could not be evaluated (nothing was refuted)".to_string()
                }
            });
        }
        PathStatus::Complete => {}
    }
    match &facts.terminal_anchor {
        Some(TerminalAnchor::Assumed {
            sha256_fingerprint,
            self_signature,
        }) => {
            let fingerprint = hex::encode(sha256_fingerprint);
            reasons.push(match self_signature {
                SelfSignature::Verified => format!(
                    "chain terminates in a certificate no trust store names (sha256:{fingerprint}) \
                     -- supply it with --tsa-trust-store"
                ),
                // Naming it as a trust anchor still resolves this — a
                // pinned anchor is an external input and is not re-checked
                // — but the reason it is unresolved right now is the
                // unverifiable self-signature, not a missing file.
                SelfSignature::Unverifiable => format!(
                    "chain terminates in a self-issued certificate (sha256:{fingerprint}) whose \
                     own signature this verifier cannot check; nothing is refuted -- name it with \
                     --tsa-trust-store if you trust it from an external source"
                ),
            });
        }
        None | Some(TerminalAnchor::Trusted { .. }) => {}
    }
    if reasons.is_empty() {
        "verification did not reach aggregate success".to_string()
    } else {
        reasons.join("; ")
    }
}

/// The stable CLI reason code for one finding `atl-core` reported about an
/// anchor.
///
/// This is a **translation**, not a classification: whether a finding is a
/// refutation or an inability is decided by
/// [`VerificationError::is_refutation`] in `atl-core`, and this function is
/// never asked. It only names, in this CLI's own stable vocabulary, what the
/// core already established — so a reason code cannot claim a strength the
/// finding behind it does not have.
///
/// # Exhaustive on purpose
///
/// No wildcard arm. A finding `atl-core` adds later must be given a reason
/// code deliberately; a catch-all would silently publish it under whatever
/// code happened to be nearest, and this crate's whole contract is that the
/// code names what was actually found.
fn reason_for_finding(finding: &VerificationError) -> ReasonCode {
    match finding {
        // ---- ATL v2.0 §5.5.1 / §5.5.2 steps 1-2: binding the anchor ----
        VerificationError::AnchorTargetInvalid { .. } => ReasonCode::AnchorTargetInvalid,
        VerificationError::AnchorTargetHashMismatch { .. } => ReasonCode::AnchorTargetHashMismatch,
        // Every hash `atl-core` reports unreadable while binding an anchor:
        // the anchor's own `target_hash`, and the receipt root it must pin
        // to (`proof.root_hash` / `super_proof.super_root`).
        VerificationError::InvalidHash { .. } => ReasonCode::AnchorHashMalformed,
        VerificationError::MissingSuperProof => ReasonCode::SuperProofMissing,

        // ---- Step 3: the payload ----
        VerificationError::AnchorPayloadUndecodable { anchor_type, .. } => {
            if anchor_type == "bitcoin_ots" {
                ReasonCode::BitcoinOtsProofInvalid
            } else {
                ReasonCode::TsaTokenUnparsable
            }
        }
        VerificationError::AnchorTypeUnsupported { .. } => ReasonCode::AnchorTypeUnsupported,

        // ---- §5.5.2 steps 4-5: Bitcoin ----
        VerificationError::BitcoinHeightContradictsProof { .. } => {
            ReasonCode::BitcoinClaimedHeightContradictsProof
        }
        // `atl-core` performs no I/O, so it never obtains a block header.
        // Offline that is the honest end of the road; online it is replaced
        // wholesale by [`crate::verify::online`], which does fetch one.
        VerificationError::BitcoinBlockNotObtained => ReasonCode::BitcoinBlockNotChecked,

        // ---- §5.5.1 steps 4-5 plus chain construction: RFC 3161 ----
        //
        // Each of these carries the fact itself, so the refuted/indeterminate
        // split is read off the payload and never guessed from the variant.
        VerificationError::Rfc3161MessageImprint(imprint) => match imprint {
            MessageImprint::Mismatch => ReasonCode::TsaImprintMismatch,
            // Refuted too, but calling it a mismatch would explain a proven
            // defect with the wrong cause: no comparison was attempted.
            MessageImprint::Malformed => ReasonCode::TsaImprintMalformed,
            MessageImprint::Verified | MessageImprint::Indeterminate => {
                ReasonCode::TsaImprintIndeterminate
            }
        },
        VerificationError::Rfc3161CmsSignature(signature) => match signature {
            CmsSignature::Refuted => ReasonCode::CmsSignatureInvalid,
            CmsSignature::Verified | CmsSignature::Indeterminate => {
                ReasonCode::CmsSignatureIndeterminate
            }
        },
        VerificationError::Rfc3161TimestampingEku(eku) => match eku {
            // All four were *checked* and fail RFC 3161 2.3.
            TimestampingEku::Absent
            | TimestampingEku::Malformed
            | TimestampingEku::NotCritical
            | TimestampingEku::NotExclusive => ReasonCode::TsaTimestampingEkuInvalid,
            // Never examined: no signer certificate was settled on.
            TimestampingEku::Ok | TimestampingEku::NotChecked => {
                ReasonCode::TsaTimestampingEkuNotChecked
            }
        },
        VerificationError::Rfc3161CertificatePath {
            status,
            valid_at_gen_time,
        } => match status {
            // A candidate link was found and rejected; and a path that
            // completed yet is invalid at genTime is a contradiction.
            PathStatus::Invalid => ReasonCode::TsaChainInvalidAtGenTime,
            PathStatus::Complete if !valid_at_gen_time => ReasonCode::TsaChainInvalidAtGenTime,
            // Ran out of certificates: a missing issuer, not a broken one.
            PathStatus::Incomplete => ReasonCode::TsaChainIncomplete,
            // The path could not be *evaluated*. Deliberately not
            // `tsa_chain_incomplete`, which would send the reader hunting
            // for a certificate that would not help.
            PathStatus::Indeterminate | PathStatus::Complete => ReasonCode::TsaChainIndeterminate,
        },
        // Nothing is refuted by the absence of a reason to believe a
        // certificate. `None` means the chain named no terminal at all,
        // which is missing material rather than an untrusted one.
        VerificationError::Rfc3161TerminalNotTrusted { terminal } => match terminal {
            Some(TerminalAnchor::Assumed { .. }) => ReasonCode::TsaRootNotTrusted,
            Some(TerminalAnchor::Trusted { .. }) | None => ReasonCode::TsaChainIncomplete,
        },

        // ---- Not findings about an anchor ----
        //
        // `verify_receipt_anchors` produces none of these. They are the
        // receipt-level errors, which travel through
        // [`crate::verify::single`] instead. Reaching this arm would mean a
        // receipt-level fact had been attributed to an anchor, so the
        // weakest honest code is the right answer.
        VerificationError::InvalidReceipt(_)
        | VerificationError::SignatureFailed
        | VerificationError::InclusionProofFailed { .. }
        | VerificationError::ConsistencyProofFailed { .. }
        | VerificationError::RootHashMismatch
        | VerificationError::TreeSizeMismatch
        | VerificationError::SuperInclusionFailed { .. }
        | VerificationError::SuperConsistencyFailed { .. }
        | VerificationError::SuperDataMismatch { .. }
        | VerificationError::UnsupportedVersion(_)
        | VerificationError::MetadataHashMismatch { .. }
        | VerificationError::MetadataNotCanonicalizable { .. }
        | VerificationError::SourceTextNotChecked
        | VerificationError::NoTrustAnchor { .. }
        | VerificationError::AnchorFinding { .. } => ReasonCode::ReceiptVerificationFailed,
    }
}

/// Reduce one anchor's fact set to this CLI's three-valued verdict.
///
/// The three outcomes are `atl-core`'s own — [`AnchorFacts::is_verified`],
/// [`AnchorFacts::is_refuted`], [`AnchorFacts::is_indeterminate`] — and they
/// partition, so nothing here collapses them into two. **Any refutation
/// outranks every inability**, which is why the refutations are consulted
/// first: `atl-core` gathers every finding before any is weighed, and this
/// reads them in that order.
fn verdict_from_facts(facts: &AnchorFacts) -> AnchorVerdict {
    if let Some(refutation) = facts.refutations().next() {
        return AnchorVerdict::Invalid(reason_for_finding(refutation));
    }
    if let Some(inability) = facts.inabilities().next() {
        return AnchorVerdict::Untrusted(reason_for_finding(inability));
    }
    AnchorVerdict::Valid
}

/// Prose for one finding, for a reader rather than for a branch.
///
/// Never load-bearing: every consumer branches on
/// [`AnchorVerificationResult::verdict`]. The evidence each message quotes
/// comes out of the finding itself, so a message cannot describe a check
/// that was not the one performed.
fn describe_finding(finding: &VerificationError) -> String {
    match finding {
        VerificationError::AnchorTargetInvalid {
            expected, actual, ..
        } => {
            format!("Invalid target '{actual}', expected '{expected}'")
        }
        VerificationError::AnchorTargetHashMismatch { anchor_type, .. } => {
            if anchor_type == "bitcoin_ots" {
                "target_hash does not match super_root".to_string()
            } else {
                "target_hash does not match proof.root_hash".to_string()
            }
        }
        // The anchor's own `target_hash` is named by the message alone; a
        // receipt root that would not parse is named by its field, because
        // the reader must be told which of the two hashes is unreadable.
        VerificationError::InvalidHash { field, message } => {
            if field == "anchor.target_hash" {
                message.clone()
            } else {
                format!("invalid {field}: {message}")
            }
        }
        VerificationError::MissingSuperProof => "Receipt has no super_proof".to_string(),
        VerificationError::AnchorPayloadUndecodable {
            anchor_type,
            reason,
        } => {
            if anchor_type == "bitcoin_ots" {
                format!("OTS verification failed: {reason}")
            } else {
                reason.clone()
            }
        }
        VerificationError::AnchorTypeUnsupported {
            anchor_type,
            required_feature,
        } => format!(
            "this build cannot verify {anchor_type} anchors: it was compiled without the \
             {required_feature} feature -- nothing about the anchor was examined"
        ),
        VerificationError::BitcoinHeightContradictsProof { claimed, attested } => {
            let heights = attested
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "the receipt states bitcoin_block_height {claimed}, but its own OTS proof \
                 attests to no such block (attested: [{heights}])"
            )
        }
        VerificationError::BitcoinBlockNotObtained => "Bitcoin block not fetched: the OTS \
             proof's merkle root was not compared against any block header, and neither was \
             the block time the receipt states (re-run with network access)"
            .to_string(),
        // The RFC 3161 findings are summarised together by
        // [`summarize_rfc3161`], which reads the whole fact set and can say
        // that several things went wrong at once.
        _ => finding_fallback(finding),
    }
}

/// The last resort for a finding [`describe_finding`] has no wording for.
///
/// Kept separate so the common path stays readable, and deliberately says
/// only what is known rather than inventing a cause.
fn finding_fallback(finding: &VerificationError) -> String {
    format!("{finding:?}")
}

/// The message an anchor carries beside its verdict.
///
/// `None` exactly when the anchor is [`AnchorVerdict::Valid`]: there is
/// nothing to explain.
fn error_for_facts(facts: &AnchorFacts) -> Option<String> {
    if facts.is_verified() {
        return None;
    }
    // An RFC 3161 token that decoded has a whole fact set to report on, and
    // several of its facts can fail at once. Summarising them together is
    // more use than quoting whichever one happens to decide the verdict.
    if let AnchorEvidence::Rfc3161(rfc3161) = facts.evidence() {
        return Some(summarize_rfc3161(rfc3161));
    }
    // Otherwise the finding that decided the verdict is the message: a
    // refutation if there is one, and only then an inability.
    facts
        .refutations()
        .next()
        .or_else(|| facts.inabilities().next())
        .map(describe_finding)
}

/// The Bitcoin fact set as this CLI publishes it, built from whatever
/// `atl-core` was able to establish.
///
/// Produced for **every** `bitcoin_ots` anchor, including one rejected
/// before its proof was ever decoded: the receipt's own two claims
/// (`bitcoin_block_height`, `bitcoin_block_time`) and the `target_hash` come
/// from the anchor itself, and they are what a reader most wants to see
/// beside a damaged anchor.
#[allow(clippy::option_if_let_else)] // the `if let` here reads better than `map_or_else`
fn bitcoin_details(
    target_hash: &str,
    receipt_block_height: u64,
    receipt_block_time: &str,
    evidence: &AnchorEvidence,
) -> AnchorDetails {
    let (proof_block_height, proof_block_heights, operation_count, computed_root) =
        if let AnchorEvidence::BitcoinOts(bitcoin) = evidence {
            (
                bitcoin.attestation.as_ref().map(|a| a.block_height),
                bitcoin.attested_block_heights.clone(),
                bitcoin.attestation.as_ref().map(|a| a.merkle_path.len()),
                bitcoin.computed_block_merkle_root.clone(),
            )
        } else {
            (None, Vec::new(), None, None)
        };

    AnchorDetails::Bitcoin {
        proof_block_height,
        proof_block_heights,
        receipt_block_height,
        receipt_block_time: receipt_block_time.to_string(),
        // `atl-core` obtains no block header, so §5.5.2 step 5's time half
        // was not carried out. Reporting that as anything but "not compared"
        // would be the overclaim this whole taxonomy exists to prevent. The
        // online pass replaces the whole result when it does obtain one.
        claimed_time_check: ClaimedTimeCheck::NotCompared,
        block_timestamp_secs: None,
        target_hash: target_hash.to_string(),
        operation_count,
        computed_root,
        block_merkle_root: None,
        merkle_match: None,
        block_sources: Vec::new(),
    }
}

/// Turn one anchor's `atl-core` fact set into the result every renderer,
/// the policy and the exit code read.
///
/// `anchor` is the entry the facts were established for — index-aligned with
/// the `Vec` [`establish_anchor_facts`] returns — and supplies the fields
/// that are the receipt's own assertions rather than findings about them.
fn result_from_facts(anchor: &ReceiptAnchor, facts: &AnchorFacts) -> AnchorVerificationResult {
    let (details, timestamp_nanos) = match anchor {
        ReceiptAnchor::Rfc3161 { .. } => {
            let details = match facts.evidence() {
                AnchorEvidence::Rfc3161(rfc3161) => AnchorDetails::Rfc3161 {
                    message_imprint: rfc3161.message_imprint,
                    cms_signature: rfc3161.cms_signature,
                    chain_valid_at_gen_time: rfc3161.chain_valid_at_gen_time,
                    chain_diagnostic: rfc3161.chain_diagnostic.clone(),
                    timestamping_eku_ok: rfc3161.timestamping_eku_ok,
                    timestamping_eku: rfc3161.timestamping_eku,
                    path_status: rfc3161.path_status,
                    terminal_anchor: rfc3161.terminal_anchor,
                    revocation: rfc3161.revocation,
                },
                // Rejected before the token was read, so there is no fact
                // set: a wrong `target`, an unreadable hash, a `target_hash`
                // that pins to some other root, or a token that would not
                // decode.
                _ => AnchorDetails::Unknown,
            };
            // The token's own `genTime`, or the anchor's `timestamp` field
            // when the token would not decode. A claim, never an
            // established time -- the renderers publish it under a
            // `claimed_*` name until the verdict is `Valid`.
            (details, facts.claimed_timestamp())
        }
        ReceiptAnchor::BitcoinOts {
            target_hash,
            bitcoin_block_height,
            bitcoin_block_time,
            ..
        } => (
            bitcoin_details(
                target_hash,
                *bitcoin_block_height,
                bitcoin_block_time,
                facts.evidence(),
            ),
            // Left empty offline on purpose. For a `bitcoin_ots` anchor this
            // field carries the time of the block header the sources agreed
            // on -- an established fact -- and no header exists here. The
            // anchor's own `timestamp` claim is not put in its place: the
            // renderers would publish it as `claimed_timestamp`, a field
            // this anchor type has never had.
            None,
        ),
    };

    AnchorVerificationResult {
        anchor_type: anchor.anchor_type().to_string(),
        verdict: verdict_from_facts(facts),
        timestamp_nanos,
        error: error_for_facts(facts),
        details,
    }
}

/// Everything a Bitcoin OTS anchor's network-free pass established, in the
/// shape the online pass needs.
pub struct PreparedOts {
    /// The attestation the receipt's own claimed height selected.
    pub attestation: BitcoinAttestation,
    /// Merkle root computed from the OTS proof, `sha256:` prefixed.
    pub computed_root: String,
    /// Number of hash operations in the selected attestation's Merkle path.
    pub operation_count: usize,
    /// Every block height the proof attests to, in proof order. Published
    /// alongside the selected one so a reader can see the whole set.
    pub attested_block_heights: Vec<u64>,
    /// The height the receipt states, carried forward so every outcome can
    /// publish it beside the proof's own. Equal to
    /// `attestation.block_height` by the time this struct exists — the
    /// attestation was *selected by* this claim, and a claim matching no
    /// attestation is a refutation from which no `PreparedOts` is built.
    pub receipt_block_height: u64,
    /// The block time the receipt states, verbatim. Nothing offline can
    /// check it; the online pass compares it with the header it obtained.
    pub receipt_block_time: String,
}

impl PreparedOts {
    /// What the network still has to settle for this anchor, or `None` when
    /// there is nothing left for it to settle.
    ///
    /// `None` covers three cases, and none of them may be turned into a
    /// block lookup:
    ///
    /// * the anchor is not a `bitcoin_ots` anchor at all;
    /// * it was **refuted** — a wrong `target`, a `target_hash` naming
    ///   another root, an undecodable proof, a stated height its own proof
    ///   contradicts. A refutation stands whatever a block explorer says,
    ///   and fetching a block for it would invite the header to overwrite
    ///   the finding;
    /// * no attestation or no computed Merkle root was established, so there
    ///   is nothing to compare a header against and no height to ask for.
    #[must_use]
    pub fn from_facts(facts: &AnchorFacts) -> Option<Self> {
        if facts.is_refuted() {
            return None;
        }
        let AnchorEvidence::BitcoinOts(bitcoin) = facts.evidence() else {
            return None;
        };
        let attestation = bitcoin.attestation.clone()?;
        let computed_root = bitcoin.computed_block_merkle_root.clone()?;
        Some(Self {
            operation_count: attestation.merkle_path.len(),
            attestation,
            computed_root,
            attested_block_heights: bitcoin.attested_block_heights.clone(),
            receipt_block_height: bitcoin.receipt_block_height,
            receipt_block_time: bitcoin.receipt_block_time.clone(),
        })
    }
}

/// Establish ATL v2.0 §5.5 for every anchor the receipt presents, by asking
/// `atl-core`.
///
/// # Why this is one call and not an implementation
///
/// Binding each anchor to the receipt's own root, decoding its payload,
/// running the steps the specification names and reporting which facts hold
/// is *protocol orchestration*, and `atl-core` publishes it as
/// [`verify_receipt_anchors`]. This crate used to carry a second copy: two
/// implementations of a mandatory rule drift, and a defect fixed on one side
/// stays open on the other — which is exactly what happened, repeatedly.
///
/// What stays here is everything the core cannot do: the network
/// ([`crate::verify::online`]), the acceptance policy
/// ([`crate::verify::policy`]), and the status, reason codes and exit codes
/// that are this CLI's own contract ([`crate::verify::verdict`]).
///
/// `trust_store` is threaded straight from `--tsa-trust-store` /
/// `--tsa-intermediates` and from nowhere else: a certificate found inside
/// the token being verified is never promoted to a trust anchor.
#[must_use]
pub fn establish_anchor_facts(
    receipt: &atl_core::Receipt,
    trust_store: Option<&TrustStore>,
) -> Vec<AnchorFacts> {
    let options = VerifyOptions {
        rfc3161_trust_store: trust_store.cloned(),
        ..VerifyOptions::default()
    };
    verify_receipt_anchors(receipt, &options)
}

/// Project each anchor's fact set onto the result this CLI reports.
///
/// `facts` must be what [`establish_anchor_facts`] returned for `receipt`,
/// so entry *i* describes `receipt.anchors()[i]`. A shorter slice leaves the
/// remaining anchors unreported rather than mis-attributing facts to them.
///
/// `bitcoin_ots` anchors carry their network-free outcome here; the online
/// pass replaces them in place.
#[must_use]
pub fn offline_results(
    receipt: &atl_core::Receipt,
    facts: &[AnchorFacts],
) -> Vec<AnchorVerificationResult> {
    receipt
        .anchors()
        .iter()
        .zip(facts)
        .map(|(anchor, facts)| result_from_facts(anchor, facts))
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    use atl_core::{
        CheckpointJson, Receipt, ReceiptBuilder, ReceiptEntry, ReceiptProof, SourceTextCheck,
        SuperProof,
    };

    const TEST_ROOT_HASH: &str =
        "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const SUPER_ROOT_HASH: &str =
        "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER_HASH: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // ================================================================
    // Fixtures
    // ================================================================

    /// A receipt whose `proof.root_hash` is [`TEST_ROOT_HASH`] and whose
    /// `super_proof.super_root` is [`SUPER_ROOT_HASH`], carrying `anchors`.
    ///
    /// Only the anchor step is under test here, so nothing else about the
    /// receipt has to hold: `verify_receipt_anchors` covers ATL v2.0 §5.5
    /// and nothing else, and the two roots are the only fields it reads.
    fn receipt_with(anchors: Vec<ReceiptAnchor>, super_proof: bool) -> Receipt {
        let entry = ReceiptEntry {
            id: "550e8400-e29b-41d4-a716-446655440000"
                .parse()
                .expect("fixture UUID"),
            payload_hash: TEST_ROOT_HASH.to_string(),
            metadata_hash: OTHER_HASH.to_string(),
            metadata: serde_json::json!({}),
        };
        let proof = ReceiptProof {
            tree_size: 1,
            root_hash: TEST_ROOT_HASH.to_string(),
            inclusion_path: vec![],
            leaf_index: 0,
            checkpoint: CheckpointJson {
                origin: OTHER_HASH.to_string(),
                tree_size: 1,
                root_hash: TEST_ROOT_HASH.to_string(),
                timestamp: 1_704_067_200_000_000_000,
                signature: "base64:AAAA".to_string(),
                key_id: OTHER_HASH.to_string(),
            },
            consistency_proof: None,
        };
        ReceiptBuilder::new("2.0.0".to_string(), entry, proof)
            .super_proof_option(super_proof.then(|| SuperProof {
                genesis_super_root: OTHER_HASH.to_string(),
                data_tree_index: 0,
                super_tree_size: 1,
                super_root: SUPER_ROOT_HASH.to_string(),
                inclusion: vec![],
                consistency_to_origin: vec![],
            }))
            .anchors(anchors)
            .build(SourceTextCheck::assume_duplicate_property_names_already_rejected())
    }

    fn rfc3161_anchor(target: &str, target_hash: &str, token_der: &str) -> ReceiptAnchor {
        ReceiptAnchor::Rfc3161 {
            target: target.to_string(),
            target_hash: target_hash.to_string(),
            tsa_url: "https://example.invalid/tsa".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: token_der.to_string(),
        }
    }

    fn bitcoin_anchor(
        target: &str,
        target_hash: &str,
        ots_proof: &str,
        height: u64,
    ) -> ReceiptAnchor {
        ReceiptAnchor::BitcoinOts {
            target: target.to_string(),
            target_hash: target_hash.to_string(),
            timestamp: "2026-01-19T07:01:20Z".to_string(),
            bitcoin_block_height: height,
            bitcoin_block_time: "2026-01-19T07:01:20+00:00".to_string(),
            ots_proof: ots_proof.to_string(),
        }
    }

    /// The single anchor's result, as the offline pass reports it.
    fn only_result(anchor: ReceiptAnchor, super_proof: bool) -> AnchorVerificationResult {
        let receipt = receipt_with(vec![anchor], super_proof);
        let facts = establish_anchor_facts(&receipt, None);
        let mut results = offline_results(&receipt, &facts);
        assert_eq!(results.len(), 1, "one anchor in, one result out");
        results.remove(0)
    }

    /// The single anchor's fact set, as `atl-core` established it.
    fn only_facts(anchor: ReceiptAnchor, super_proof: bool) -> AnchorFacts {
        let receipt = receipt_with(vec![anchor], super_proof);
        let mut facts = establish_anchor_facts(&receipt, None);
        assert_eq!(facts.len(), 1, "one anchor in, one fact set out");
        facts.remove(0)
    }

    // ================================================================
    // The translation table: `reason_for_finding`
    // ================================================================

    /// Every finding shape, with the code it must be named by.
    ///
    /// This is the whole classifier now: `atl-core` decides *what was found*
    /// and whether it refutes, and this crate only names it. The table is
    /// therefore the place the three-valued facts must not be flattened, and
    /// each pair below that differs only in its payload is one of those
    /// places.
    fn finding_table() -> Vec<(VerificationError, ReasonCode)> {
        vec![
            (
                VerificationError::AnchorTargetInvalid {
                    anchor_type: "rfc3161".to_string(),
                    expected: "data_tree_root".to_string(),
                    actual: "nonsense".to_string(),
                },
                ReasonCode::AnchorTargetInvalid,
            ),
            (
                VerificationError::AnchorTargetHashMismatch {
                    anchor_type: "rfc3161".to_string(),
                    expected: TEST_ROOT_HASH.to_string(),
                    actual: OTHER_HASH.to_string(),
                },
                ReasonCode::AnchorTargetHashMismatch,
            ),
            (
                VerificationError::InvalidHash {
                    field: "anchor.target_hash".to_string(),
                    message: "missing sha256: prefix".to_string(),
                },
                ReasonCode::AnchorHashMalformed,
            ),
            (
                VerificationError::MissingSuperProof,
                ReasonCode::SuperProofMissing,
            ),
            (
                VerificationError::AnchorPayloadUndecodable {
                    anchor_type: "rfc3161".to_string(),
                    reason: "not CMS SignedData".to_string(),
                },
                ReasonCode::TsaTokenUnparsable,
            ),
            (
                VerificationError::AnchorPayloadUndecodable {
                    anchor_type: "bitcoin_ots".to_string(),
                    reason: "not an OTS proof".to_string(),
                },
                ReasonCode::BitcoinOtsProofInvalid,
            ),
            (
                VerificationError::AnchorTypeUnsupported {
                    anchor_type: "bitcoin_ots".to_string(),
                    required_feature: "bitcoin-ots".to_string(),
                },
                ReasonCode::AnchorTypeUnsupported,
            ),
            (
                VerificationError::BitcoinHeightContradictsProof {
                    claimed: 900_000,
                    attested: vec![932_897],
                },
                ReasonCode::BitcoinClaimedHeightContradictsProof,
            ),
            (
                VerificationError::BitcoinBlockNotObtained,
                ReasonCode::BitcoinBlockNotChecked,
            ),
            // --- messageImprint: refuted twice, and by two different causes ---
            (
                VerificationError::Rfc3161MessageImprint(MessageImprint::Mismatch),
                ReasonCode::TsaImprintMismatch,
            ),
            (
                VerificationError::Rfc3161MessageImprint(MessageImprint::Malformed),
                ReasonCode::TsaImprintMalformed,
            ),
            (
                VerificationError::Rfc3161MessageImprint(MessageImprint::Indeterminate),
                ReasonCode::TsaImprintIndeterminate,
            ),
            // --- CMS signature ---
            (
                VerificationError::Rfc3161CmsSignature(CmsSignature::Refuted),
                ReasonCode::CmsSignatureInvalid,
            ),
            (
                VerificationError::Rfc3161CmsSignature(CmsSignature::Indeterminate),
                ReasonCode::CmsSignatureIndeterminate,
            ),
            // --- timestamping EKU: four checked failures, one unexamined ---
            (
                VerificationError::Rfc3161TimestampingEku(TimestampingEku::Absent),
                ReasonCode::TsaTimestampingEkuInvalid,
            ),
            (
                VerificationError::Rfc3161TimestampingEku(TimestampingEku::Malformed),
                ReasonCode::TsaTimestampingEkuInvalid,
            ),
            (
                VerificationError::Rfc3161TimestampingEku(TimestampingEku::NotCritical),
                ReasonCode::TsaTimestampingEkuInvalid,
            ),
            (
                VerificationError::Rfc3161TimestampingEku(TimestampingEku::NotExclusive),
                ReasonCode::TsaTimestampingEkuInvalid,
            ),
            (
                VerificationError::Rfc3161TimestampingEku(TimestampingEku::NotChecked),
                ReasonCode::TsaTimestampingEkuNotChecked,
            ),
            // --- certificate path: one refutation, two inabilities, and the
            //     complete-but-invalid contradiction ---
            (
                VerificationError::Rfc3161CertificatePath {
                    status: PathStatus::Invalid,
                    valid_at_gen_time: false,
                },
                ReasonCode::TsaChainInvalidAtGenTime,
            ),
            (
                VerificationError::Rfc3161CertificatePath {
                    status: PathStatus::Complete,
                    valid_at_gen_time: false,
                },
                ReasonCode::TsaChainInvalidAtGenTime,
            ),
            (
                VerificationError::Rfc3161CertificatePath {
                    status: PathStatus::Incomplete,
                    valid_at_gen_time: false,
                },
                ReasonCode::TsaChainIncomplete,
            ),
            (
                VerificationError::Rfc3161CertificatePath {
                    status: PathStatus::Indeterminate,
                    valid_at_gen_time: false,
                },
                ReasonCode::TsaChainIndeterminate,
            ),
            // --- terminal anchor ---
            (
                VerificationError::Rfc3161TerminalNotTrusted {
                    terminal: Some(TerminalAnchor::Assumed {
                        sha256_fingerprint: [7u8; 32],
                        self_signature: SelfSignature::Verified,
                    }),
                },
                ReasonCode::TsaRootNotTrusted,
            ),
            (
                VerificationError::Rfc3161TerminalNotTrusted { terminal: None },
                ReasonCode::TsaChainIncomplete,
            ),
        ]
    }

    #[test]
    fn every_finding_is_named_by_its_own_reason_code() {
        for (finding, expected) in finding_table() {
            assert_eq!(
                reason_for_finding(&finding),
                expected,
                "wrong reason code for {finding:?}"
            );
        }
    }

    /// **The classification may not drift from `atl-core`'s.**
    ///
    /// The refuted/indeterminate split is `VerificationError::is_refutation`
    /// and nothing else; this crate only gives each finding a name. The two
    /// must agree, so every code this table produces for a refutation has to
    /// be one this CLI treats as a refutation, and every code produced for
    /// an inability has to be one it treats as an inability.
    ///
    /// The check is by construction: [`AnchorState::from_reason`] is defined
    /// only for the inability codes and answers `Unresolved` for every
    /// refutation code, so an inability whose code is a refutation's would be
    /// reported with a state that names nothing.
    #[test]
    fn refutation_and_inability_codes_do_not_cross() {
        for (finding, code) in finding_table() {
            if finding.is_refutation() {
                assert_eq!(
                    AnchorState::from_reason(code),
                    AnchorState::Unresolved,
                    "{code} names a refutation, so it must not double as an inability state"
                );
            } else {
                assert_ne!(
                    AnchorState::from_reason(code),
                    AnchorState::Unresolved,
                    "{code} names an inability, so it must project onto a real state"
                );
            }
        }
    }

    // ================================================================
    // `rfc3161_trust_state`, derived from the verdict
    // ================================================================

    fn rfc3161_result(verdict: AnchorVerdict) -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            verdict,
            timestamp_nanos: None,
            error: None,
            details: AnchorDetails::Rfc3161 {
                message_imprint: MessageImprint::Verified,
                cms_signature: CmsSignature::Verified,
                chain_valid_at_gen_time: true,
                chain_diagnostic: None,
                timestamping_eku_ok: true,
                timestamping_eku: TimestampingEku::Ok,
                path_status: PathStatus::Complete,
                terminal_anchor: None,
                revocation: Revocation::NotChecked,
            },
        }
    }

    #[test]
    fn trust_state_follows_the_verdict() {
        assert_eq!(
            rfc3161_result(AnchorVerdict::Valid).rfc3161_trust_state(),
            Some("trusted")
        );
        assert_eq!(
            rfc3161_result(AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted))
                .rfc3161_trust_state(),
            Some("assumed")
        );
        assert_eq!(
            rfc3161_result(AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete))
                .rfc3161_trust_state(),
            Some("incomplete")
        );
        for indeterminate in [
            ReasonCode::TsaChainIndeterminate,
            ReasonCode::CmsSignatureIndeterminate,
            ReasonCode::TsaImprintIndeterminate,
            ReasonCode::TsaTimestampingEkuNotChecked,
        ] {
            assert_eq!(
                rfc3161_result(AnchorVerdict::Untrusted(indeterminate)).rfc3161_trust_state(),
                Some("indeterminate"),
                "{indeterminate}"
            );
        }
        assert_eq!(
            rfc3161_result(AnchorVerdict::Invalid(ReasonCode::TsaImprintMismatch))
                .rfc3161_trust_state(),
            Some("failed")
        );
    }

    #[test]
    fn a_non_rfc3161_anchor_has_no_trust_state() {
        let mut result = rfc3161_result(AnchorVerdict::Valid);
        result.details = AnchorDetails::Unknown;
        assert_eq!(result.rfc3161_trust_state(), None);
        // A `bitcoin_ots` anchor never has one either: `trust_state`
        // describes an RFC 3161 certificate path and nothing else.
        assert_eq!(
            only_result(
                bitcoin_anchor("super_root", SUPER_ROOT_HASH, "base64:proof", 800_000),
                true
            )
            .rfc3161_trust_state(),
            None
        );
    }

    // ================================================================
    // Binding the anchor to the receipt (§5.5.1 / §5.5.2 steps 1-2)
    // ================================================================

    #[test]
    fn wrong_target_is_refuted() {
        let result = only_result(
            rfc3161_anchor("super_root", TEST_ROOT_HASH, "base64:x"),
            true,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetInvalid)
        );
        // Rejected before the token was read, so no fact set exists.
        assert!(matches!(result.details, AnchorDetails::Unknown));
        let error = result.error.expect("a refutation must say what it refuted");
        assert!(error.contains("data_tree_root"), "{error}");
    }

    #[test]
    fn target_hash_that_pins_to_another_root_is_refuted() {
        let result = only_result(
            rfc3161_anchor("data_tree_root", OTHER_HASH, "base64:x"),
            true,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch)
        );
    }

    #[test]
    fn a_malformed_target_hash_is_refuted() {
        let result = only_result(
            rfc3161_anchor("data_tree_root", "not-a-hash", "base64:x"),
            true,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::AnchorHashMalformed)
        );
    }

    #[test]
    fn a_bitcoin_anchor_without_a_super_proof_is_refuted() {
        let result = only_result(
            bitcoin_anchor("super_root", SUPER_ROOT_HASH, "base64:proof", 800_000),
            false,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::SuperProofMissing)
        );
        assert_eq!(
            result.error.as_deref(),
            Some("Receipt has no super_proof"),
            "the reader must be told which half of the pinning is missing"
        );
    }

    /// **A damaged Bitcoin anchor still publishes the receipt's own claims.**
    ///
    /// The `bitcoin_block_height`, `bitcoin_block_time` and `target_hash` a
    /// reader most wants to see are the receipt's assertions, not findings
    /// about them, so they survive a rejection that happened before the
    /// proof was ever decoded.
    #[test]
    fn a_rejected_bitcoin_anchor_still_carries_the_receipts_claims() {
        for (anchor, expected) in [
            (
                bitcoin_anchor("data_tree_root", SUPER_ROOT_HASH, "base64:proof", 800_000),
                ReasonCode::AnchorTargetInvalid,
            ),
            (
                bitcoin_anchor("super_root", OTHER_HASH, "base64:proof", 800_000),
                ReasonCode::AnchorTargetHashMismatch,
            ),
            (
                bitcoin_anchor("super_root", "not-a-hash", "base64:proof", 800_000),
                ReasonCode::AnchorHashMalformed,
            ),
            (
                bitcoin_anchor("super_root", SUPER_ROOT_HASH, "base64:rubbish", 800_000),
                ReasonCode::BitcoinOtsProofInvalid,
            ),
        ] {
            let result = only_result(anchor, true);
            assert_eq!(result.verdict, AnchorVerdict::Invalid(expected));
            let AnchorDetails::Bitcoin {
                receipt_block_height,
                receipt_block_time,
                target_hash,
                claimed_time_check,
                ..
            } = &result.details
            else {
                panic!("{expected}: a bitcoin_ots anchor must carry a Bitcoin fact set");
            };
            assert_eq!(*receipt_block_height, 800_000);
            assert_eq!(receipt_block_time, "2026-01-19T07:01:20+00:00");
            assert!(!target_hash.is_empty());
            // Nothing offline compared it, and saying otherwise would be the
            // overclaim the four-valued type exists to prevent.
            assert_eq!(*claimed_time_check, ClaimedTimeCheck::NotCompared);
        }
    }

    #[test]
    fn garbage_token_is_unparsable_not_untrusted() {
        let result = only_result(
            rfc3161_anchor("data_tree_root", TEST_ROOT_HASH, "base64:bm90YXRva2Vu"),
            true,
        );
        assert_eq!(
            result.verdict,
            AnchorVerdict::Invalid(ReasonCode::TsaTokenUnparsable)
        );
        assert_eq!(result.rfc3161_trust_state(), None);
        // The anchor's own `timestamp` field is the only time on offer once
        // the token will not decode, and it is a claim, never established.
        assert_eq!(
            result.timestamp_nanos,
            Some(1_704_067_200_000_000_000),
            "a token that would not decode still leaves the anchor's claim"
        );
    }

    // ================================================================
    // ATL v2.0 §5.5.2: OpenTimestamps
    // ================================================================

    /// Build a real, serializable OTS proof whose single fork carries a
    /// Bitcoin attestation at each of `heights`, all under `start_digest`.
    ///
    /// Synthetic, but not a stub: it goes out as bytes and comes back
    /// through `atl-core`'s own parser and extractor, so what the test
    /// exercises is the production path and not a hand-made attestation
    /// list. Real Evidentum proofs carry exactly one attestation, which is
    /// why the multi-attestation case needs constructing at all.
    fn multi_attestation_proof(start_digest: [u8; 32], heights: &[u64]) -> String {
        use atl_core::core::ots::{
            Attestation, DetachedTimestampFile, DigestType, Op, Step, StepData, Timestamp,
        };
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let branch = |height: u64, marker: u8| Step {
            // One hash op per branch, so each attestation has a non-empty
            // merkle path.
            data: StepData::Op(Op::Sha256),
            output: vec![marker; 32],
            next: vec![Step {
                data: StepData::Attestation(Attestation::Bitcoin { height }),
                output: vec![marker; 32],
                next: vec![],
            }],
        };

        let file = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp: Timestamp {
                start_digest: start_digest.to_vec(),
                first_step: Step {
                    data: StepData::Fork,
                    output: start_digest.to_vec(),
                    next: heights
                        .iter()
                        .enumerate()
                        .map(|(i, h)| {
                            branch(
                                *h,
                                u8::try_from(i).expect("few branches").wrapping_add(0xa0),
                            )
                        })
                        .collect(),
                },
            },
        };
        format!(
            "base64:{}",
            STANDARD.encode(file.to_bytes().expect("fixture serializes"))
        )
    }

    /// A receipt whose `super_root` is `digest`, so an OTS proof built over
    /// `digest` pins to it.
    fn ots_receipt(digest: [u8; 32], heights: &[u64], claimed: u64) -> Receipt {
        let super_root = format!("sha256:{}", hex::encode(digest));
        let proof = multi_attestation_proof(digest, heights);
        let anchor = ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: super_root.clone(),
            timestamp: "2026-01-19T07:01:20Z".to_string(),
            bitcoin_block_height: claimed,
            bitcoin_block_time: "2026-01-19T07:01:20+00:00".to_string(),
            ots_proof: proof,
        };
        let mut receipt = receipt_with(vec![anchor], true);
        // The fixture receipt's `super_root` has to be the digest the proof
        // starts from, or the anchor never gets past pinning.
        receipt = rebuild_with_super_root(&receipt, &super_root);
        receipt
    }

    /// Rebuild `receipt` with a different `super_proof.super_root`.
    ///
    /// `Receipt` exposes no setters, so a changed field means a new receipt.
    fn rebuild_with_super_root(receipt: &Receipt, super_root: &str) -> Receipt {
        let mut super_proof = receipt.super_proof().cloned().expect("fixture has one");
        super_proof.super_root = super_root.to_string();
        ReceiptBuilder::new(
            receipt.spec_version().to_string(),
            receipt.entry().clone(),
            receipt.proof().clone(),
        )
        .super_proof(super_proof)
        .anchors(receipt.anchors().to_vec())
        .build(SourceTextCheck::assume_duplicate_property_names_already_rejected())
    }

    /// **A claim matching any attestation holds (ATL v2.0 §5.5.2 step 5).**
    ///
    /// A proof may carry several Bitcoin attestations. The specification
    /// says "match the proof" and never singles one out — the word
    /// *attestation* does not appear in it at all — so a receipt naming a
    /// block its own proof genuinely attests to must not be refuted.
    #[test]
    fn any_attested_height_satisfies_the_receipt_claim() {
        let digest = [0x11; 32];
        for claimed in [932_897, 932_910, 1_000_000] {
            let receipt = ots_receipt(digest, &[932_897, 932_910, 1_000_000], claimed);
            let facts = establish_anchor_facts(&receipt, None);
            let prepared = PreparedOts::from_facts(&facts[0])
                .unwrap_or_else(|| panic!("height {claimed} is attested by the proof"));

            // The attestation SELECTED is the one the receipt named, not the
            // lowest: everything downstream -- the computed root and the
            // block the online pass looks up -- must describe that block.
            assert_eq!(prepared.attestation.block_height, claimed);
            assert_eq!(prepared.receipt_block_height, claimed);
            assert_eq!(
                prepared.attested_block_heights,
                vec![932_897, 932_910, 1_000_000]
            );
        }
    }

    /// Only a height attested by **none** of them is refuted — including one
    /// that merely sits between two attested heights, which is what makes
    /// this different from a range check.
    #[test]
    fn a_height_no_attestation_carries_is_refuted_with_the_whole_set() {
        let digest = [0x11; 32];
        for claimed in [900_000u64, 932_900, 2_097_151] {
            let receipt = ots_receipt(digest, &[932_897, 932_910], claimed);
            let facts = establish_anchor_facts(&receipt, None);
            let result = offline_results(&receipt, &facts).remove(0);

            assert_eq!(
                result.verdict,
                AnchorVerdict::Invalid(ReasonCode::BitcoinClaimedHeightContradictsProof),
                "height {claimed} is attested by nothing"
            );
            assert_eq!(result.state(), AnchorState::Refuted);
            // No block lookup may be attempted for it: a refutation stands
            // whatever a block explorer reports.
            assert!(PreparedOts::from_facts(&facts[0]).is_none());

            let AnchorDetails::Bitcoin {
                proof_block_height,
                proof_block_heights,
                receipt_block_height,
                ..
            } = &result.details
            else {
                panic!("a refuted Bitcoin anchor must still carry a Bitcoin fact set");
            };
            assert_eq!(*receipt_block_height, claimed);
            // No attestation was selected, so none is named as "the" proof's
            // height; the set is the evidence.
            assert_eq!(*proof_block_height, None);
            assert_eq!(proof_block_heights, &vec![932_897, 932_910]);
            let error = result.error.expect("a refutation must say what it refuted");
            assert!(
                error.contains("932897") && error.contains("932910"),
                "{error}"
            );
        }
    }

    /// **Any refutation outranks every inability.**
    ///
    /// A `bitcoin_ots` anchor whose stated height its own proof contradicts
    /// carries both kinds of finding at once: the height refutation, and the
    /// block header `atl-core` never fetched. The refutation must decide,
    /// and the inability must not be silently dropped from the fact set.
    #[test]
    fn a_refutation_beside_an_inability_decides_the_anchor() {
        let receipt = ots_receipt([0x11; 32], &[932_897], 900_000);
        let facts = establish_anchor_facts(&receipt, None);

        assert!(facts[0].is_refuted());
        assert!(!facts[0].is_indeterminate());
        assert!(!facts[0].is_verified());
        // Both findings are present; the ranking is the rule, not a filter.
        assert_eq!(facts[0].refutations().count(), 1);
        assert_eq!(facts[0].inabilities().count(), 1);
        assert_eq!(
            offline_results(&receipt, &facts)[0].verdict,
            AnchorVerdict::Invalid(ReasonCode::BitcoinClaimedHeightContradictsProof)
        );
    }

    /// A structurally sound OTS proof is `untrusted` offline, never
    /// accepted: nothing has compared its Merkle root against a block.
    #[test]
    fn a_sound_ots_proof_is_untrusted_until_a_block_is_seen() {
        let receipt = ots_receipt([0x11; 32], &[932_897], 932_897);
        let facts = establish_anchor_facts(&receipt, None);
        let result = offline_results(&receipt, &facts).remove(0);

        assert_eq!(
            result.verdict,
            AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockNotChecked)
        );
        assert_eq!(result.state(), AnchorState::NotChecked);
        assert!(!result.verified());
        // It is the one case the network can still settle.
        let prepared = PreparedOts::from_facts(&facts[0]).expect("the block is still to be seen");
        assert_eq!(prepared.attestation.block_height, 932_897);
        assert!(prepared.computed_root.starts_with("sha256:"));
        assert_eq!(
            prepared.operation_count,
            prepared.attestation.merkle_path.len()
        );

        let AnchorDetails::Bitcoin {
            computed_root,
            block_merkle_root,
            merkle_match,
            block_timestamp_secs,
            block_sources,
            ..
        } = &result.details
        else {
            panic!("bitcoin fact set");
        };
        assert_eq!(
            computed_root.as_deref(),
            Some(prepared.computed_root.as_str())
        );
        // No header was obtained, so nothing may be published as one.
        assert_eq!(*block_merkle_root, None);
        assert_eq!(*merkle_match, None);
        assert_eq!(*block_timestamp_secs, None);
        assert!(block_sources.is_empty());
    }

    /// A `bitcoin_ots` anchor publishes no `timestamp_nanos` offline.
    ///
    /// For this anchor type the field carries the time of the block header
    /// the sources agreed on — an established fact — and offline there is no
    /// header. Putting the anchor's own `timestamp` claim there instead
    /// would publish it as `claimed_timestamp`, a field this anchor type has
    /// never had.
    #[test]
    fn a_bitcoin_anchor_publishes_no_time_offline() {
        let receipt = ots_receipt([0x11; 32], &[932_897], 932_897);
        let facts = establish_anchor_facts(&receipt, None);
        assert_eq!(offline_results(&receipt, &facts)[0].timestamp_nanos, None);
    }

    // ================================================================
    // Plumbing
    // ================================================================

    /// **`token_der` must carry the `base64:` prefix ATL v2.0 §4.2 writes.**
    ///
    /// This crate used to prepend the prefix when a receipt omitted it, so a
    /// bare base64 token verified here and nowhere else — `atl-core`'s
    /// decoder requires it, as does every producer. A verifier that accepts
    /// a wider set of inputs than the library it verifies with is two parts
    /// of one system disagreeing about what a receipt is, which is how
    /// "could not check" turns into "checked and false" (the `spec_version`
    /// gate was the same shape). The set accepted is now exactly
    /// `atl-core`'s.
    #[test]
    fn a_token_without_the_base64_prefix_is_not_decoded() {
        let prefixed = only_result(
            rfc3161_anchor("data_tree_root", TEST_ROOT_HASH, "base64:bm90YXRva2Vu"),
            true,
        );
        let bare = only_result(
            rfc3161_anchor("data_tree_root", TEST_ROOT_HASH, "bm90YXRva2Vu"),
            true,
        );
        assert_eq!(
            prefixed.verdict,
            AnchorVerdict::Invalid(ReasonCode::TsaTokenUnparsable)
        );
        assert_eq!(
            bare.verdict,
            AnchorVerdict::Invalid(ReasonCode::TsaTokenUnparsable)
        );
        let error = bare.error.expect("the decoder says what it wanted");
        assert!(error.contains("base64:"), "{error}");
    }

    #[test]
    fn prepared_ots_is_never_built_for_an_rfc3161_anchor() {
        let facts = only_facts(
            rfc3161_anchor("data_tree_root", TEST_ROOT_HASH, "base64:bm90YXRva2Vu"),
            true,
        );
        assert!(PreparedOts::from_facts(&facts).is_none());
    }

    /// **Only an anchor the network can still settle asks for the network.**
    ///
    /// `PreparedOts::from_facts` is the whole predicate — "is a Bitcoin
    /// anchor present" is not, because a receipt's `anchors` array is
    /// authenticated by nothing and appending one used to be enough to make
    /// this tool go online. An appended Bitcoin anchor that cannot bind to
    /// the receipt is refuted offline and asks for nothing.
    #[test]
    fn only_an_unsettled_bitcoin_anchor_asks_for_the_network() {
        // An RFC 3161 anchor never does: its verification is pure
        // computation.
        assert!(PreparedOts::from_facts(&only_facts(
            rfc3161_anchor("data_tree_root", TEST_ROOT_HASH, "base64:bm90YXRva2Vu"),
            true
        ))
        .is_none());

        // Nor does a Bitcoin anchor pinned to a root this receipt does not
        // have -- the cheapest thing a relay can append.
        assert!(PreparedOts::from_facts(&only_facts(
            bitcoin_anchor("super_root", SUPER_ROOT_HASH, "base64:proof", 800_000),
            false
        ))
        .is_none());
        assert!(PreparedOts::from_facts(&only_facts(
            bitcoin_anchor("super_root", OTHER_HASH, "base64:proof", 800_000),
            true
        ))
        .is_none());

        // A sound one does, and that is the case the network exists for.
        let receipt = ots_receipt([0x11; 32], &[932_897], 932_897);
        let facts = establish_anchor_facts(&receipt, None);
        assert!(PreparedOts::from_facts(&facts[0]).is_some());
    }

    /// Facts and anchors are index-aligned, and a short fact slice reports
    /// fewer anchors rather than mis-attributing facts to the wrong one.
    #[test]
    fn results_are_index_aligned_with_the_receipts_anchors() {
        let receipt = receipt_with(
            vec![
                rfc3161_anchor("data_tree_root", TEST_ROOT_HASH, "base64:bm90YXRva2Vu"),
                bitcoin_anchor("super_root", SUPER_ROOT_HASH, "base64:rubbish", 800_000),
            ],
            true,
        );
        let facts = establish_anchor_facts(&receipt, None);
        let results = offline_results(&receipt, &facts);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].anchor_type, "rfc3161");
        assert_eq!(results[1].anchor_type, "bitcoin_ots");
        assert_eq!(offline_results(&receipt, &facts[..1]).len(), 1);
    }

    #[test]
    fn sources_agree_is_the_only_definition_of_agreement() {
        let report = |source: &str, time: u64| BlockSourceReport {
            source: source.to_string(),
            block_hash: "aa".repeat(32),
            merkle_root: "bb".repeat(32),
            block_timestamp_secs: time,
        };
        assert!(sources_agree(&[]));
        assert!(sources_agree(&[report("one", 1)]));
        assert!(sources_agree(&[report("one", 1), report("two", 1)]));
        // A conflict about nothing but the time is still a conflict.
        assert!(!sources_agree(&[report("one", 1), report("two", 2)]));
    }
}
