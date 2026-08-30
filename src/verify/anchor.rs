//! Anchor verification and the per-anchor verdict every renderer reads.
//!
//! RFC 3161 verification is **pure computation**: decoding the token,
//! checking the CMS signature, and walking the certificate chain need no
//! network access whatsoever. It therefore runs on every verification,
//! offline and online alike, and lives here rather than in
//! [`crate::verify::online`]. Only `bitcoin_ots` anchors need the network,
//! and only to ask block-explorer APIs for the header whose Merkle root the
//! OTS proof is compared against. Nothing here observes the Bitcoin network.
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
    CmsSignature, MessageImprint, PathStatus, ReceiptAnchor, Revocation, Rfc3161AnchorFacts,
    SelfSignature, TerminalAnchor, TimestampingEku, TrustStore, ANCHOR_TARGET_DATA_TREE_ROOT,
    ANCHOR_TARGET_SUPER_ROOT,
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
            | ReasonCode::TsaTimestampingEkuNotChecked => Self::Unevaluable,

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
            | ReasonCode::ReceiptUnanchored
            | ReasonCode::BatchItemsInvalid
            | ReasonCode::BatchItemsErrored
            | ReasonCode::BatchItemsUntrusted
            | ReasonCode::BatchItemsUnanchored
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
        /// signature — see [`AnchorDetails::rfc3161_verdict`].
        cms_signature: CmsSignature,
        /// Every link on the constructed path was valid at `genTime`.
        ///
        /// `atl-core` reports this as `false` whenever no complete path was
        /// built, so it is only a *refutation* when `path_status` is
        /// [`PathStatus::Invalid`] — see [`AnchorDetails::rfc3161_verdict`].
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
        /// Block height **claimed** by the earliest attestation in the OTS
        /// proof, as read out of the receipt.
        ///
        /// Not an established fact until a block at that height has actually
        /// been fetched and its Merkle root matched (`merkle_match ==
        /// Some(true)`). Until then it is the receipt's own assertion about
        /// where in the chain this anchor lands, and the renderers publish
        /// it under a `claimed_` name — the same rule the RFC 3161 `genTime`
        /// follows.
        block_height: u64,
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
        /// Number of hash operations in the OTS Merkle path.
        operation_count: usize,
        /// Merkle root computed from the OTS proof (`sha256:` prefixed).
        computed_root: String,
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
    /// Classify an RFC 3161 anchor's facts. Returns `None` for any other
    /// anchor type.
    ///
    /// This is the ONLY place the RFC 3161 trust decision is made; the
    /// per-anchor verdict, the receipt status, both renderers and the exit
    /// code are all derived from it.
    ///
    /// # Aggregation, not early returns
    ///
    /// Every fact is collected before any verdict is formed. An earlier
    /// version returned as soon as it met a non-`Verified` fact, which meant
    /// an *inability* encountered first silently suppressed a *refutation*
    /// found later: `message_imprint: Indeterminate` together with
    /// `cms_signature: Refuted` came out `untrusted`, even though
    /// `untrusted` is defined as "nothing was refuted". Having spent this
    /// whole rework stopping the CLI from accusing without grounds, that
    /// produced the mirror-image defect — concealing what had actually been
    /// proved.
    ///
    /// So: gather every refutation first; if any exists, the anchor is
    /// `Invalid`. Only when there is none may an inability be reported, and
    /// only then can the outcome be `Untrusted`. Any refuted fact outranks
    /// every indeterminate fact, whichever order they appear in.
    #[must_use]
    pub fn rfc3161_verdict(&self) -> Option<AnchorVerdict> {
        let Self::Rfc3161 {
            message_imprint,
            cms_signature,
            chain_valid_at_gen_time,
            timestamping_eku,
            path_status,
            terminal_anchor,
            ..
        } = self
        else {
            return None;
        };

        // ---- Phase 1: every refutation, gathered before judging ----
        //
        // Ordered by how directly each bears on "does this token attest to
        // THIS receipt", so the reported code is the most informative one
        // when several hold at once. Which is reported never changes the
        // verdict: any entry at all means `Invalid`.
        let mut refutations: Vec<ReasonCode> = Vec::new();

        match message_imprint {
            MessageImprint::Mismatch => refutations.push(ReasonCode::TsaImprintMismatch),
            // A structurally broken imprint is refuted too, but calling it a
            // mismatch would explain a proven defect with the wrong cause.
            MessageImprint::Malformed => refutations.push(ReasonCode::TsaImprintMalformed),
            MessageImprint::Verified | MessageImprint::Indeterminate => {}
        }
        if matches!(cms_signature, CmsSignature::Refuted) {
            refutations.push(ReasonCode::CmsSignatureInvalid);
        }
        match timestamping_eku {
            // Checked, and the certificate does not satisfy RFC 3161 2.3.
            TimestampingEku::Absent
            | TimestampingEku::Malformed
            | TimestampingEku::NotCritical
            | TimestampingEku::NotExclusive => {
                refutations.push(ReasonCode::TsaTimestampingEkuInvalid);
            }
            // Never examined (no signer was established) — an inability, and
            // reporting it as an EKU failure would refute on an unchecked
            // fact. Handled in phase 2.
            TimestampingEku::Ok | TimestampingEku::NotChecked => {}
        }
        match path_status {
            // A candidate link was found and failed validation.
            PathStatus::Invalid => refutations.push(ReasonCode::TsaChainInvalidAtGenTime),
            // A path that completed must also have been valid at genTime;
            // `atl-core` cannot produce the contrary, but if it ever did,
            // that is a refutation and not a success.
            PathStatus::Complete if !*chain_valid_at_gen_time => {
                refutations.push(ReasonCode::TsaChainInvalidAtGenTime);
            }
            PathStatus::Complete | PathStatus::Incomplete | PathStatus::Indeterminate => {}
        }

        if let Some(reason) = refutations.first() {
            return Some(AnchorVerdict::Invalid(*reason));
        }

        // ---- Phase 2: nothing was refuted; report the first inability ----
        if matches!(message_imprint, MessageImprint::Indeterminate) {
            return Some(AnchorVerdict::Untrusted(
                ReasonCode::TsaImprintIndeterminate,
            ));
        }
        if matches!(cms_signature, CmsSignature::Indeterminate) {
            return Some(AnchorVerdict::Untrusted(
                ReasonCode::CmsSignatureIndeterminate,
            ));
        }
        if matches!(timestamping_eku, TimestampingEku::NotChecked) {
            return Some(AnchorVerdict::Untrusted(
                ReasonCode::TsaTimestampingEkuNotChecked,
            ));
        }

        Some(match path_status {
            // Ran out of certificates before any terminal: a missing issuer,
            // not a broken one.
            PathStatus::Incomplete => AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete),
            // The path could not be *evaluated* — unsupported cryptography
            // or the depth limit. Fail closed, but never a refutation. This
            // is inspected before `terminal_anchor`, because an
            // `Indeterminate` path can still carry an `Assumed` terminal
            // whose self-signature is precisely what could not be checked,
            // and reporting that as `tsa_root_not_trusted` would name the
            // wrong problem.
            PathStatus::Indeterminate => {
                AnchorVerdict::Untrusted(ReasonCode::TsaChainIndeterminate)
            }
            PathStatus::Complete => match terminal_anchor {
                Some(TerminalAnchor::Trusted { .. }) => AnchorVerdict::Valid,
                Some(TerminalAnchor::Assumed { .. }) => {
                    AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted)
                }
                // `Complete` always carries a terminal in atl-core; treat
                // the impossible case as missing material rather than as a
                // refutation.
                None => AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete),
            },
            // Handled in phase 1; unreachable here.
            PathStatus::Invalid => AnchorVerdict::Invalid(ReasonCode::TsaChainInvalidAtGenTime),
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
                message_imprint: facts.message_imprint,
                cms_signature: facts.cms_signature,
                chain_valid_at_gen_time: facts.chain_valid_at_gen_time,
                chain_diagnostic: facts.chain_diagnostic.clone(),
                timestamping_eku_ok: facts.timestamping_eku_ok,
                timestamping_eku: facts.timestamping_eku,
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
/// root has not been compared against any block header, so nothing external
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
            "Bitcoin block not fetched: the OTS proof's merkle root was not compared against \
             any block header (re-run with network access)"
                .to_string(),
        ),
        details: AnchorDetails::Bitcoin {
            block_height: prepared.attestation.block_height,
            block_timestamp_secs: None,
            target_hash: target_hash.to_string(),
            operation_count: prepared.operation_count,
            computed_root: prepared.computed_root,
            block_merkle_root: None,
            merkle_match: None,
            block_sources: Vec::new(),
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
        imprint: MessageImprint,
        cms: CmsSignature,
        chain: bool,
        eku: bool,
        path_status: PathStatus,
        terminal_anchor: Option<TerminalAnchor>,
    ) -> AnchorDetails {
        rfc3161_details_full(
            imprint,
            cms,
            chain,
            if eku {
                TimestampingEku::Ok
            } else {
                TimestampingEku::Absent
            },
            path_status,
            terminal_anchor,
        )
    }

    /// The same, with the EKU state given explicitly — needed to exercise
    /// `NotChecked`, which no boolean can express.
    fn rfc3161_details_full(
        imprint: MessageImprint,
        cms: CmsSignature,
        chain: bool,
        eku: TimestampingEku,
        path_status: PathStatus,
        terminal_anchor: Option<TerminalAnchor>,
    ) -> AnchorDetails {
        AnchorDetails::Rfc3161 {
            message_imprint: imprint,
            cms_signature: cms,
            chain_valid_at_gen_time: chain,
            chain_diagnostic: None,
            timestamping_eku_ok: eku.is_ok(),
            timestamping_eku: eku,
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
            MessageImprint::Verified,
            CmsSignature::Verified,
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
            MessageImprint::Verified,
            CmsSignature::Verified,
            true,
            true,
            PathStatus::Complete,
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [7u8; 32],
                self_signature: SelfSignature::Verified,
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
        let details = rfc3161_details(
            MessageImprint::Verified,
            CmsSignature::Verified,
            false,
            true,
            PathStatus::Incomplete,
            None,
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Untrusted(ReasonCode::TsaChainIncomplete))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("incomplete"));
        assert_eq!(details.untrusted_root_fingerprint(), None);
    }

    /// `Indeterminate` is routed explicitly, fails closed, and is NOT a
    /// refutation. Its reason code must be the one that names the real
    /// problem, not `tsa_chain_incomplete` (which would send the user
    /// hunting for a certificate) and not `tsa_root_not_trusted`.
    #[test]
    fn indeterminate_path_is_untrusted_not_invalid() {
        let details = rfc3161_details(
            MessageImprint::Verified,
            CmsSignature::Verified,
            false,
            true,
            PathStatus::Indeterminate,
            None,
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Untrusted(ReasonCode::TsaChainIndeterminate))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("indeterminate"));
    }

    /// An `Indeterminate` path carrying an `Assumed`/`Unverifiable`
    /// terminal — the SHA-1 self-signed root case — is still reported as
    /// indeterminate. Reading the terminal first would call it
    /// `tsa_root_not_trusted`, which names the wrong problem: the root is
    /// not merely un-vouched-for, its self-signature was never checked.
    #[test]
    fn an_unverifiable_self_signature_is_reported_as_indeterminate() {
        let details = rfc3161_details(
            MessageImprint::Verified,
            CmsSignature::Verified,
            false,
            true,
            PathStatus::Indeterminate,
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [3u8; 32],
                self_signature: SelfSignature::Unverifiable,
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Untrusted(ReasonCode::TsaChainIndeterminate))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("indeterminate"));
    }

    /// Neither `Incomplete` nor `Indeterminate` may ever produce a valid
    /// anchor, under ANY combination of the other facts and terminal
    /// anchors — including a `Trusted` terminal, which cannot occur
    /// alongside them but must not be a way in if it ever did.
    #[test]
    fn incomplete_and_indeterminate_never_reach_success() {
        let terminals = [
            None,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [1u8; 32],
            }),
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [1u8; 32],
                self_signature: SelfSignature::Verified,
            }),
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: [1u8; 32],
                self_signature: SelfSignature::Unverifiable,
            }),
        ];

        for status in [PathStatus::Incomplete, PathStatus::Indeterminate] {
            for terminal in terminals {
                for chain_valid in [true, false] {
                    let details = rfc3161_details(
                        MessageImprint::Verified,
                        CmsSignature::Verified,
                        chain_valid,
                        true,
                        status,
                        terminal,
                    );
                    let verdict = details.rfc3161_verdict().expect("rfc3161 details");
                    assert!(
                        !verdict.is_valid(),
                        "{status:?} with terminal {terminal:?} and chain_valid={chain_valid} \
                         must never be valid, got {verdict:?}"
                    );
                    assert!(
                        matches!(verdict, AnchorVerdict::Untrusted(_)),
                        "{status:?} must be Untrusted, never a refutation: {verdict:?}"
                    );
                    assert_ne!(details.rfc3161_trust_state(), Some("trusted"));
                }
            }
        }
    }

    /// **Blocker regression.** A `messageImprint` naming a hash algorithm
    /// this verifier does not implement was never *compared* with the
    /// receipt's root, so it must not be reported as a mismatch. ATL
    /// mandates a minimum of algorithm support, not a prohibition on the
    /// rest, so this is the verifier's limitation, not the token's defect.
    #[test]
    fn an_uncomparable_imprint_is_untrusted_not_a_mismatch() {
        let details = rfc3161_details(
            MessageImprint::Indeterminate,
            CmsSignature::Verified,
            true,
            true,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [1u8; 32],
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Untrusted(
                ReasonCode::TsaImprintIndeterminate
            ))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("indeterminate"));
    }

    /// An imprint that WAS compared and differs stays a refutation.
    #[test]
    fn a_refuted_imprint_is_still_a_refutation() {
        let details = rfc3161_details(
            MessageImprint::Mismatch,
            CmsSignature::Verified,
            true,
            true,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [1u8; 32],
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::TsaImprintMismatch))
        );
    }

    /// Neither indeterminate fact may ever reach success, in any
    /// combination with the others.
    #[test]
    fn indeterminate_facts_never_reach_success() {
        let trusted = Some(TerminalAnchor::Trusted {
            sha256_fingerprint: [1u8; 32],
        });
        for (imprint, cms) in [
            (MessageImprint::Indeterminate, CmsSignature::Verified),
            (MessageImprint::Verified, CmsSignature::Indeterminate),
            (MessageImprint::Indeterminate, CmsSignature::Indeterminate),
        ] {
            let details = rfc3161_details(imprint, cms, true, true, PathStatus::Complete, trusted);
            let verdict = details.rfc3161_verdict().expect("rfc3161 details");
            assert!(
                !verdict.is_valid(),
                "{imprint:?}/{cms:?} must never be valid"
            );
            assert!(
                matches!(verdict, AnchorVerdict::Untrusted(_)),
                "{imprint:?}/{cms:?} must be Untrusted, never a refutation: {verdict:?}"
            );
        }
    }

    /// **The blocker regression.** Any refuted fact must outrank every
    /// indeterminate fact, in every pairing, whichever order they are
    /// inspected in.
    ///
    /// The case that motivated it: `MessageImprint::Indeterminate` with
    /// `CmsSignature::Refuted` used to return at the first non-verified fact
    /// and come out `untrusted` — concealing a proven refutation behind
    /// "nothing was refuted". Having spent this rework stopping the CLI
    /// accusing without grounds, that was the mirror-image defect.
    #[test]
    fn any_refutation_outranks_every_indeterminate() {
        let inconclusive_imprints = [MessageImprint::Verified, MessageImprint::Indeterminate];
        let refuted_imprints = [MessageImprint::Mismatch, MessageImprint::Malformed];
        let inconclusive_cms = [CmsSignature::Verified, CmsSignature::Indeterminate];
        let inconclusive_ekus = [TimestampingEku::Ok, TimestampingEku::NotChecked];
        let inconclusive_paths = [
            PathStatus::Complete,
            PathStatus::Incomplete,
            PathStatus::Indeterminate,
        ];

        // A refuted imprint, against every combination of inabilities.
        for imprint in refuted_imprints {
            for cms in inconclusive_cms {
                for eku in inconclusive_ekus {
                    for path in inconclusive_paths {
                        let details = rfc3161_details_full(imprint, cms, true, eku, path, None);
                        let verdict = details.rfc3161_verdict().expect("rfc3161 details");
                        assert!(
                            matches!(verdict, AnchorVerdict::Invalid(_)),
                            "{imprint:?}+{cms:?}+{eku:?}+{path:?} must be Invalid, got {verdict:?}"
                        );
                    }
                }
            }
        }

        // A refuted CMS signature, against every combination of inabilities.
        for imprint in inconclusive_imprints {
            for eku in inconclusive_ekus {
                for path in inconclusive_paths {
                    let details =
                        rfc3161_details_full(imprint, CmsSignature::Refuted, true, eku, path, None);
                    assert_eq!(
                        details.rfc3161_verdict(),
                        Some(AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid)),
                        "{imprint:?}+Refuted+{eku:?}+{path:?} must be Invalid"
                    );
                }
            }
        }

        // A refuted EKU, and a refuted path, likewise.
        for imprint in inconclusive_imprints {
            for cms in inconclusive_cms {
                let refuted_eku = rfc3161_details_full(
                    imprint,
                    cms,
                    true,
                    TimestampingEku::Absent,
                    PathStatus::Indeterminate,
                    None,
                );
                assert!(
                    matches!(
                        refuted_eku.rfc3161_verdict(),
                        Some(AnchorVerdict::Invalid(_))
                    ),
                    "a checked EKU failure must outrank {imprint:?}+{cms:?}"
                );

                let refuted_path = rfc3161_details_full(
                    imprint,
                    cms,
                    false,
                    TimestampingEku::NotChecked,
                    PathStatus::Invalid,
                    None,
                );
                assert_eq!(
                    refuted_path.rfc3161_verdict(),
                    Some(AnchorVerdict::Invalid(ReasonCode::TsaChainInvalidAtGenTime)),
                    "a refuted path must outrank {imprint:?}+{cms:?}"
                );
            }
        }
    }

    /// The exact counterexample from the review, spelled out on its own so a
    /// regression names itself.
    #[test]
    fn an_indeterminate_imprint_never_conceals_a_refuted_signature() {
        let details = rfc3161_details_full(
            MessageImprint::Indeterminate,
            CmsSignature::Refuted,
            true,
            TimestampingEku::Ok,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [1u8; 32],
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid)),
            "untrusted means nothing was refuted; a refuted signature must not hide behind an \
             uncomparable imprint"
        );
        assert_eq!(details.rfc3161_trust_state(), Some("failed"));
    }

    /// A malformed imprint is refuted, but must not be explained as a
    /// mismatch: no comparison could be attempted at all.
    #[test]
    fn a_malformed_imprint_has_its_own_reason_code() {
        let details = rfc3161_details_full(
            MessageImprint::Malformed,
            CmsSignature::Verified,
            true,
            TimestampingEku::Ok,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [1u8; 32],
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::TsaImprintMalformed))
        );
    }

    /// An EKU that was never *examined* must not be reported as an EKU
    /// failure. Before aggregation this was masked by the CMS check
    /// returning first, but the boolean it read was `false` — one reordering
    /// away from refuting on an unchecked fact.
    #[test]
    fn an_unexamined_eku_is_not_an_eku_failure() {
        let details = rfc3161_details_full(
            MessageImprint::Verified,
            CmsSignature::Verified,
            false,
            TimestampingEku::NotChecked,
            PathStatus::Indeterminate,
            None,
        );
        let verdict = details.rfc3161_verdict().expect("rfc3161 details");
        assert!(
            !matches!(
                verdict,
                AnchorVerdict::Invalid(ReasonCode::TsaTimestampingEkuInvalid)
            ),
            "an unexamined EKU must never be reported as a checked failure: {verdict:?}"
        );
        assert!(matches!(verdict, AnchorVerdict::Untrusted(_)));
    }

    /// Every *checked* EKU failure stays a refutation — the fix must not
    /// soften real failures into "cannot tell".
    #[test]
    fn checked_eku_failures_remain_refutations() {
        for eku in [
            TimestampingEku::Absent,
            TimestampingEku::Malformed,
            TimestampingEku::NotCritical,
            TimestampingEku::NotExclusive,
        ] {
            let details = rfc3161_details_full(
                MessageImprint::Verified,
                CmsSignature::Verified,
                true,
                eku,
                PathStatus::Complete,
                Some(TerminalAnchor::Trusted {
                    sha256_fingerprint: [1u8; 32],
                }),
            );
            assert_eq!(
                details.rfc3161_verdict(),
                Some(AnchorVerdict::Invalid(
                    ReasonCode::TsaTimestampingEkuInvalid
                )),
                "{eku:?} was checked and failed; it must stay a refutation"
            );
        }
    }

    /// **Blocker regression.** A CMS signature this verifier cannot evaluate
    /// must fail closed as `untrusted`, never as `invalid`. `atl-core`
    /// explicitly does not implement P-521 or RSA-PSS, so this is a token a
    /// real TSA can mint today -- and under the previous `is_ok()` collapse
    /// its holder was told the evidence had been disproved.
    #[test]
    fn an_unevaluatable_cms_signature_is_untrusted_not_invalid() {
        let details = rfc3161_details(
            MessageImprint::Verified,
            CmsSignature::Indeterminate,
            true,
            true,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [1u8; 32],
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Untrusted(
                ReasonCode::CmsSignatureIndeterminate
            ))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("indeterminate"));
    }

    /// A CMS signature that WAS checked and failed stays a refutation — the
    /// fix must not soften real failures into "cannot tell".
    #[test]
    fn a_refuted_cms_signature_is_still_a_refutation() {
        let details = rfc3161_details(
            MessageImprint::Verified,
            CmsSignature::Refuted,
            true,
            true,
            PathStatus::Complete,
            Some(TerminalAnchor::Trusted {
                sha256_fingerprint: [1u8; 32],
            }),
        );
        assert_eq!(
            details.rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid))
        );
        assert_eq!(details.rfc3161_trust_state(), Some("failed"));
    }

    /// An unevaluatable CMS signature never reaches success, whatever else
    /// holds — including a fully trusted certificate path.
    #[test]
    fn an_unevaluatable_cms_signature_never_reaches_success() {
        for status in [
            PathStatus::Complete,
            PathStatus::Incomplete,
            PathStatus::Indeterminate,
            PathStatus::Invalid,
        ] {
            for terminal in [
                None,
                Some(TerminalAnchor::Trusted {
                    sha256_fingerprint: [1u8; 32],
                }),
            ] {
                let details = rfc3161_details(
                    MessageImprint::Verified,
                    CmsSignature::Indeterminate,
                    true,
                    true,
                    status,
                    terminal,
                );
                let verdict = details.rfc3161_verdict().expect("rfc3161 details");
                assert!(
                    !verdict.is_valid(),
                    "{status:?}/{terminal:?} must never be valid"
                );
                if matches!(status, PathStatus::Invalid) {
                    // A refuted path is a proven defect and must not be
                    // concealed behind an unevaluatable signature.
                    assert!(
                        matches!(verdict, AnchorVerdict::Invalid(_)),
                        "a refuted path must outrank an indeterminate signature: {verdict:?}"
                    );
                } else {
                    assert!(
                        matches!(verdict, AnchorVerdict::Untrusted(_)),
                        "{status:?}/{terminal:?} must be Untrusted, never a refutation"
                    );
                }
            }
        }
    }

    #[test]
    fn invalid_path_is_a_refutation() {
        let details = rfc3161_details(
            MessageImprint::Verified,
            CmsSignature::Verified,
            false,
            true,
            PathStatus::Invalid,
            None,
        );
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
            rfc3161_details(
                MessageImprint::Mismatch,
                CmsSignature::Verified,
                true,
                true,
                PathStatus::Complete,
                trusted
            )
            .rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::TsaImprintMismatch))
        );
        assert_eq!(
            rfc3161_details(
                MessageImprint::Verified,
                CmsSignature::Refuted,
                true,
                true,
                PathStatus::Complete,
                trusted
            )
            .rfc3161_verdict(),
            Some(AnchorVerdict::Invalid(ReasonCode::CmsSignatureInvalid))
        );
        assert_eq!(
            rfc3161_details(
                MessageImprint::Verified,
                CmsSignature::Verified,
                true,
                false,
                PathStatus::Complete,
                trusted
            )
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
