//! The anchor policy the caller selected, and the three independent axes a
//! receipt's anchors are reported on.
//!
//! # Why three axes and not one word
//!
//! A single verdict word had to carry three questions of different natures
//! at once, and answered all of them with the same "untrusted":
//!
//! - **evidence** — is trust established at all? ATL v2.0 §5.5: "At least
//!   one anchor MUST be verified to establish trust in the receipt."
//! - **policy** — is the anchor quorum the caller asked for satisfied? The
//!   default requires every anchor the receipt presents; the §5.5 floor —
//!   one verified anchor — is opted into with `--allow-single-anchor`.
//! - **coverage** — did every anchor the receipt presents reach a result at
//!   all? An anchor that was never checked is not the same as one that was
//!   checked and found wanting.
//!
//! They are genuinely independent. A Receipt-Full verified offline has
//! evidence established (its TSA anchor reached a trusted root), incomplete
//! coverage (the Bitcoin block was never fetched) and — under the default
//! policy — an unsatisfied quorum. Collapsing that into one word threw away
//! two of the three answers.
//!
//! # What "verified anchor" means here
//!
//! Exactly one thing, everywhere in this crate (see
//! [`crate::verify::anchor::AnchorState::Verified`]): the anchor's
//! cryptographic facts were checked AND the certificate path reached a trust
//! anchor from the store the **caller** supplied. A cryptographically
//! flawless token whose terminal certificate nobody vouches for proves that
//! some key signed it and nothing more; it is
//! [`crate::verify::anchor::AnchorState::CryptographicallyConsistent`], and
//! it is never counted in [`TrustAssessment::verified_anchors`].

use std::fmt;

use crate::verify::anchor::{AnchorState, AnchorVerdict, AnchorVerificationResult};
use crate::verify::verdict::ReasonCode;

/// The anchor quorum a receipt must reach to be accepted.
///
/// Never inferred from the receipt: it is the verifier's own policy, chosen
/// by the caller, and it is reported alongside every verdict so a reader can
/// see which question was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnchorPolicy {
    /// The default: **every** anchor the receipt presents must be a verified
    /// anchor.
    ///
    /// Note precisely what this does and does not require. It is a rule
    /// about the anchors *this receipt offers*: a Receipt-TSA satisfies it
    /// with its single TSA anchor and no Bitcoin anchor anywhere. It is
    /// therefore **not** ATL v2.0 §5.6, which is about requiring both anchor
    /// *types* — §5.6 is reported separately as
    /// [`TrustAssessment::max_trust_profile`] and is never this profile's
    /// test. Describing the default as "§5.6 maximum trust" asserted two
    /// different requirements at once, only one of which is enforced here.
    ///
    /// Why it is strict all the same: a receipt that offers a Bitcoin anchor
    /// and then cannot have it confirmed has not delivered what it offered,
    /// and this is a *reference* verifier whose default will become the
    /// de-facto norm. A consequence worth naming: a Receipt-Full verified
    /// offline comes out *worse* than a Receipt-TSA with the same trusted
    /// root, because the Receipt-TSA never claimed a Bitcoin anchor in the
    /// first place. That is an honest report about a promise not kept, not
    /// an unfairness to be smoothed away.
    #[default]
    AllAnchors,

    /// `--allow-single-anchor`: the ATL v2.0 §5.5 floor — **one** verified
    /// anchor is enough.
    ///
    /// This is a quorum, not a licence to ignore array elements. Anchors
    /// that did not reach a result are still reported, individually and with
    /// their reasons, and the coverage axis still says the run was
    /// incomplete. What changes is only the threshold for acceptance.
    ///
    /// It never counts a refuted anchor towards the one it asks for — a
    /// refuted anchor is no more verified than an unresolved one — and never
    /// rescues a receipt with no anchors at all: no quorum of one can be met
    /// by zero.
    ///
    /// Note what this means when both are present. A receipt with one
    /// verified anchor is accepted here, and stays accepted when somebody
    /// appends an anchor that fails verification beside it: under this
    /// profile the quorum was already met, and an appended anchor may not
    /// withdraw what a genuine one established. Under
    /// [`Self::AllAnchors`] the same append does unmeet the quorum, because
    /// that profile asks for every anchor presented — a property of the
    /// profile, not a finding about the receipt.
    SingleAnchor,
}

impl AnchorPolicy {
    /// Build the policy from the `--allow-single-anchor` flag.
    #[must_use]
    pub const fn from_allow_single_anchor(allow_single_anchor: bool) -> Self {
        if allow_single_anchor {
            Self::SingleAnchor
        } else {
            Self::AllAnchors
        }
    }

    /// The stable wire name of this profile.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllAnchors => "all-anchors",
            Self::SingleAnchor => "single-anchor",
        }
    }

    /// One line of prose naming the requirement, with its spec citation.
    #[must_use]
    pub const fn requirement(self) -> &'static str {
        match self {
            // Deliberately cites no section. This profile is a rule about
            // the anchors THIS receipt offers, which is not what any single
            // section of the specification states; §5.6 belongs to
            // `max_trust_profile` and nowhere else.
            Self::AllAnchors => "every anchor the receipt presents must be verified (default)",
            Self::SingleAnchor => {
                "at least one anchor must be verified (--allow-single-anchor; ATL v2.0 \
                 \u{a7}5.5 floor)"
            }
        }
    }
}

impl std::fmt::Display for AnchorPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One anchor that did not come through as a verified anchor, with why.
///
/// Used for both halves of the coverage axis — [`TrustAssessment::unresolved`]
/// (no result at all) and [`TrustAssessment::refuted`] (a result, and it is
/// false). The two are kept in separate lists because they call for opposite
/// reactions: one may be fixable by supplying something, the other never is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedAnchor {
    /// `"rfc3161"` or `"bitcoin_ots"`.
    pub anchor_type: String,
    /// Which kind of not-verified this is.
    pub state: AnchorState,
    /// The stable reason code, identical to the one the anchor reports.
    pub reason: ReasonCode,
}

/// The three axes, computed once from a receipt's per-anchor verdicts.
///
/// Nothing here re-derives an anchor's outcome; every field is a tally over
/// [`AnchorVerificationResult::verdict`], which remains the single
/// per-anchor classification authority.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustAssessment {
    /// The quorum the caller asked for.
    pub policy: AnchorPolicy,
    /// How many anchors the receipt presents.
    pub total_anchors: usize,
    /// How many of them are **verified anchors** — cryptographic facts
    /// checked *and* a caller-supplied trust root reached. Nothing weaker is
    /// counted here.
    pub verified_anchors: usize,
    /// Every anchor that reached no result at all, in receipt order.
    pub unresolved: Vec<UnresolvedAnchor>,
    /// Every anchor that was checked and found false, in receipt order.
    ///
    /// Listed rather than merely counted. A refuted anchor used to vanish
    /// from the coverage axis entirely — it was neither `verified` nor
    /// `unresolved` — so `coverage.complete` came out `true` beside a
    /// `status: "invalid"` verdict, quietly reporting the refuted anchor as
    /// settled business.
    pub refuted: Vec<UnresolvedAnchor>,
    /// What refuted the receipt itself, if anything — a source file whose
    /// hash does not match, a structural failure, a broken inclusion or
    /// Super-Tree proof.
    ///
    /// Nothing to do with the anchors, and precisely why it is here. The
    /// axes are supposed to agree with the **verdict**, and a verdict of
    /// `invalid` has causes that never touch an anchor. Without this, a
    /// receipt verified against the wrong source file reported
    /// `evidence.established: true` beside `status: "invalid"`.
    pub receipt_refutation: Option<ReasonCode>,
    /// Both anchor types verified, before the refutation rule in
    /// [`Self::max_trust_profile`] is applied. Never read this directly.
    ///
    /// Private, and excluded from the hand-written [`fmt::Debug`] below.
    /// The derived `Debug` printed it, which meant the un-poisoned value
    /// could reach a log or an error message without ever passing through
    /// the accessor that applies the refutation rule — a guarantee enforced
    /// by convention rather than by the type.
    both_anchor_types_verified: bool,
}

/// Prints the axes as they are *reported*, never the raw tally behind them.
///
/// Hand-written for one reason: `both_anchor_types_verified` must not be
/// observable anywhere without [`TrustAssessment::max_trust_profile`]'s
/// refutation rule applied to it, and a derived `Debug` published it
/// verbatim. What a reader of a debug dump wants is the answers anyway, so
/// this prints those.
impl fmt::Debug for TrustAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustAssessment")
            .field("policy", &self.policy)
            .field("total_anchors", &self.total_anchors)
            .field("verified_anchors", &self.verified_anchors)
            .field("unresolved", &self.unresolved)
            .field("refuted", &self.refuted)
            .field("receipt_refutation", &self.receipt_refutation)
            .field("evidence_established", &self.evidence_established())
            .field("policy_satisfied", &self.policy_satisfied())
            .field("coverage_complete", &self.coverage_complete())
            .field("max_trust_profile", &self.max_trust_profile())
            .finish()
    }
}

impl TrustAssessment {
    /// Tally the axes from a receipt's anchor results.
    ///
    /// `receipt_refutation` is whatever refuted the receipt *without*
    /// reference to its anchors (see
    /// [`crate::verify::single::SingleVerificationResult::receipt_refutation`]).
    /// It is required, not optional plumbing: the axes must agree with the
    /// verdict, and a verdict of `invalid` has causes an anchor tally cannot
    /// see.
    #[must_use]
    pub fn compute(
        anchors: &[AnchorVerificationResult],
        policy: AnchorPolicy,
        receipt_refutation: Option<ReasonCode>,
    ) -> Self {
        let mut verified_anchors = 0;
        let mut unresolved = Vec::new();
        let mut refuted = Vec::new();
        // Booleans, not counts: the protocol does not forbid a receipt from
        // carrying two anchors of the same type, and §5.6 asks whether both
        // *types* are verified, not how many anchors there are. Two verified
        // RFC 3161 anchors and no Bitcoin one must not add up to "both".
        let mut rfc3161_verified = false;
        let mut bitcoin_verified = false;

        for anchor in anchors {
            match anchor.verdict {
                AnchorVerdict::Valid => {
                    verified_anchors += 1;
                    match anchor.anchor_type.as_str() {
                        "rfc3161" => rfc3161_verified = true,
                        "bitcoin_ots" => bitcoin_verified = true,
                        _ => {}
                    }
                }
                AnchorVerdict::Invalid(reason) => refuted.push(UnresolvedAnchor {
                    anchor_type: anchor.anchor_type.clone(),
                    state: AnchorState::Refuted,
                    reason,
                }),
                AnchorVerdict::Untrusted(reason) => unresolved.push(UnresolvedAnchor {
                    anchor_type: anchor.anchor_type.clone(),
                    state: AnchorState::from_reason(reason),
                    reason,
                }),
            }
        }

        Self {
            policy,
            total_anchors: anchors.len(),
            verified_anchors,
            unresolved,
            refuted,
            receipt_refutation,
            both_anchor_types_verified: rfc3161_verified && bitcoin_verified,
        }
    }

    /// At least one anchor was checked and found false.
    ///
    /// The gate on every other statement this type makes. A refutation is
    /// not one bad anchor among several good ones: the receipt as a whole is
    /// refuted, and no tally of trusted neighbours survives that.
    #[must_use]
    pub const fn refuted_anchors(&self) -> usize {
        self.refuted.len()
    }

    /// `true` when the **receipt itself** was refuted.
    ///
    /// The gate on every trust-bearing statement this type makes — and
    /// deliberately not [`Self::has_refutation`].
    ///
    /// A receipt does not authenticate its own `anchors` array: it is
    /// covered by neither the leaf hash nor the checkpoint blob, so anybody
    /// who relays a receipt can append an entry to it without a key. While
    /// the axes answered to `has_refutation`, a stranger could append one
    /// malformed token and take `evidence.established`, `policy.satisfied`
    /// and `max_trust_profile` from a receipt holding a flawless independent
    /// anchor — a denial of verification available for free to every relay.
    ///
    /// The asymmetry is the whole shape of the guarantee. Appending an
    /// anchor that fails verification costs nothing and may change nothing.
    /// Producing one that *passes* needs a timestamp token over this
    /// receipt's own root chaining to a caller-supplied trust root, which is
    /// exactly what a stranger cannot do — so a verified anchor does raise
    /// [`Self::verified_anchors`] and can satisfy the quorum. Anchors would
    /// be pointless otherwise.
    ///
    /// A refuted anchor is still counted, listed and shown: it never becomes
    /// a verified anchor, it keeps [`Self::coverage_complete`] false, and it
    /// stays in [`Self::refuted`] where both renderers print it.
    #[must_use]
    pub const fn receipt_refuted(&self) -> bool {
        self.receipt_refutation.is_some()
    }

    /// What refuted **the receipt**, or `None` if nothing did.
    ///
    /// Always equal to the top-level `reason_code` when it is `Some`, and
    /// `None` in every other case — including a receipt carrying an anchor
    /// that was checked and found false.
    ///
    /// # Why a refuted anchor does not appear here
    ///
    /// It used to fall back to the first refuted anchor's reason, which made
    /// this field a function of the `anchors` array. Nothing signs or hashes
    /// that array, so anybody who relays a receipt can rewrite it — and
    /// against a clean Receipt-Lite the fallback turned `refuted_by: null`
    /// into `refuted_by: "anchor_target_hash_mismatch"`, letting a stranger
    /// put a refutation's name on a receipt nothing had refuted.
    ///
    /// The anchor findings are not hidden by this: [`Self::refuted`] lists
    /// every one of them with its own reason code, and
    /// [`Self::refuted_anchors`] counts them.
    #[must_use]
    pub const fn refuted_by(&self) -> Option<ReasonCode> {
        self.receipt_refutation
    }

    /// **ATL v2.0 §5.6.** Both an RFC 3161 and a Bitcoin OTS anchor are
    /// verified, and the receipt itself was not refuted.
    ///
    /// Reported on every run whatever the policy, because §5.6 describes the
    /// maximum-trust *tier* rather than this tool's acceptance threshold: an
    /// accepted Receipt-TSA is `valid` with this `false`.
    ///
    /// # Why a refutation forces `false`
    ///
    /// It used to be computed from the verified anchors alone, so a receipt
    /// with a verified TSA anchor, a verified Bitcoin anchor **and** a third
    /// refuted one reported `status: "invalid"` with "maximum trust profile
    /// attained" printed beside it. That is the defect this whole rework
    /// exists to remove, relocated into a supporting field: the verdict said
    /// the evidence was disproved while the next line said the highest trust
    /// tier had been reached.
    ///
    /// A receipt this run has disproved is not at any trust tier, whatever
    /// its anchors say: they commit to `proof.root_hash`, and a receipt
    /// refuted at that level is not the thing they timestamped.
    ///
    /// A refuted *anchor* does not force `false` here, and must not: it is a
    /// statement about that anchor, appendable by anyone (see
    /// [`Self::receipt_refuted`]), and §5.6 asks whether both anchor types
    /// are verified — a question a third, unverified entry does not answer.
    /// It cannot be `true` on the strength of one either, since only a
    /// verified anchor is counted.
    #[must_use]
    pub const fn max_trust_profile(&self) -> bool {
        self.both_anchor_types_verified && !self.receipt_refuted()
    }

    /// **Evidence axis.** ATL v2.0 §5.5: at least one anchor is verified, so
    /// trust in the receipt is established — and the receipt itself was not
    /// refuted.
    ///
    /// Independent of the *policy*: a Receipt-Full whose Bitcoin anchor was
    /// never confirmed still has its trust established by the TSA anchor,
    /// even though the default quorum does not accept it. That is the whole
    /// point of publishing this axis separately.
    ///
    /// It is **not** independent of a refutation *of the receipt*. Trust
    /// cannot be "established" in a receipt a check has disproved, however
    /// many of its anchors reached a trusted root; reporting
    /// `evidence.established: true` beside `status: "invalid"` would hand a
    /// reader the opposite of what the run concluded.
    ///
    /// A refuted *anchor* is a different matter and does not clear this
    /// axis. §5.5 sets a threshold — "at least one anchor MUST be verified"
    /// — and has no term for the anchors that do not meet it; a rule
    /// otherwise would let anybody who relays a receipt withdraw the trust a
    /// genuine anchor established, by appending rubbish beside it. See
    /// [`Self::receipt_refuted`].
    #[must_use]
    pub const fn evidence_established(&self) -> bool {
        self.verified_anchors > 0 && !self.receipt_refuted()
    }

    /// **Coverage axis.** Every anchor the receipt presents was carried
    /// through to a sound result.
    ///
    /// Two things make this `false`, and they are reported in separate lists
    /// because they call for opposite reactions:
    ///
    /// - [`Self::unresolved`] — no result at all. Supply trust material, go
    ///   online, or accept that this build cannot evaluate it.
    /// - [`Self::refuted`] — a result, and it is false. Nothing supplied to
    ///   this tool fixes it; the anchor is evidence of interference. It does
    ///   not make the receipt invalid — see [`Self::receipt_refuted`] — but
    ///   it is exactly why coverage must account for it here.
    ///
    /// A refuted anchor did reach *a* result, and an earlier version of this
    /// method took that as enough — leaving `complete: true` printed beside
    /// `status: "invalid"`, with the refuted anchor named in neither list.
    /// Coverage exists to account for every anchor presented, and an anchor
    /// that proves the receipt wrong is the last one that may go unlisted.
    ///
    /// A refutation of the *receipt* also makes this `false`, even when
    /// every anchor came through cleanly. Coverage asks whether the anchors
    /// account for **this** evidence, and they do not: they commit to
    /// `proof.root_hash`, and a source file whose hash does not match the
    /// receipt, or an inclusion proof that does not lead to that root, is
    /// not the thing those anchors timestamped.
    #[must_use]
    pub const fn coverage_complete(&self) -> bool {
        self.unresolved.is_empty() && self.refuted.is_empty() && self.receipt_refutation.is_none()
    }

    /// **Policy axis.** The selected quorum is met.
    ///
    /// Both arms require that the *receipt* was not refuted. That is
    /// belt-and-braces — callers consult this only after
    /// [`crate::verify::single::SingleVerificationResult::verdict`] has
    /// already forced `invalid` — but a "policy satisfied" that could be
    /// true of a refuted receipt would be a trap for the next reader.
    ///
    /// A refuted **anchor** does not clear it. Under
    /// [`AnchorPolicy::SingleAnchor`] a receipt with one verified anchor
    /// stays accepted when a refuted one is appended beside it, which is the
    /// invariant: appending an anchor that fails verification changes no
    /// status. Under [`AnchorPolicy::AllAnchors`] the quorum is unmet
    /// because the refuted anchor is not verified and the profile demands
    /// that every anchor presented is — a property of that profile, which is
    /// equally unmet by an anchor that is merely unresolved.
    #[must_use]
    pub const fn policy_satisfied(&self) -> bool {
        if self.receipt_refuted() || self.total_anchors == 0 {
            return false;
        }
        match self.policy {
            AnchorPolicy::AllAnchors => self.verified_anchors == self.total_anchors,
            AnchorPolicy::SingleAnchor => self.verified_anchors > 0,
        }
    }

    /// `true` when the run was accepted **because** the policy was relaxed:
    /// the quorum is met, but some anchor never reached a result.
    ///
    /// Under [`AnchorPolicy::AllAnchors`] this is unreachable by
    /// construction, which is the point: only a deliberately lowered
    /// threshold can produce a success that does not cover everything the
    /// receipt offered. Every renderer must qualify its success line when
    /// this holds — an unqualified "VALID" here would be exactly the
    /// overclaim this crate exists to prevent.
    #[must_use]
    pub const fn accepted_with_gaps(&self) -> bool {
        self.policy_satisfied() && !self.coverage_complete()
    }

    /// The reason code to report when the quorum is not satisfied.
    ///
    /// Two answers, and both are computed from [`Self::verified_anchors`]
    /// alone:
    ///
    /// * [`ReasonCode::ReceiptUnanchored`] — no anchor verified at all, so
    ///   ATL v2.0 §5.5's floor is unmet;
    /// * [`ReasonCode::AnchorQuorumUnmet`] — §5.5's floor is met and the
    ///   caller's stricter profile is not.
    ///
    /// # Why it names no anchor
    ///
    /// It used to return the first unresolved anchor's reason, falling back
    /// to the first refuted one, so that the advice stayed actionable —
    /// `tsa_root_not_trusted` tells a caller what to supply and a
    /// policy-level code does not. But that made the receipt's own reported
    /// reason a function of the `anchors` array, which is authenticated by
    /// nothing: **anybody who relays a receipt can append, prepend or
    /// reorder it**, and so choose which of those reasons the tool printed.
    /// Since a reader reads one line, that handed a stranger the choice of
    /// what the reader was told.
    ///
    /// `verified_anchors` is the one quantity a relay cannot move
    /// downwards: it counts anchors bearing a timestamp over this receipt's
    /// own root that chain to a trust root the *caller* supplied. Appending
    /// rubbish cannot lower it, and producing something that raises it is
    /// exactly what a stranger cannot do.
    ///
    /// The advice is not lost, only relocated to where per-anchor advice
    /// belongs: every anchor that did not count is listed with its own
    /// reason in [`Self::unresolved`] and [`Self::refuted`], both published
    /// in the JSON and printed by the human renderer, which follows them
    /// with the concrete remedy for each.
    #[must_use]
    pub const fn unsatisfied_reason(&self) -> Option<ReasonCode> {
        if self.total_anchors == 0 || self.verified_anchors == 0 {
            Some(ReasonCode::ReceiptUnanchored)
        } else {
            Some(ReasonCode::AnchorQuorumUnmet)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::anchor::AnchorDetails;

    fn anchor(anchor_type: &str, verdict: AnchorVerdict) -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: anchor_type.to_string(),
            verdict,
            timestamp_nanos: None,
            error: None,
            details: AnchorDetails::Unknown,
        }
    }

    #[test]
    fn all_anchors_policy_requires_every_anchor() {
        let anchors = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor(
                "bitcoin_ots",
                AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockNotChecked),
            ),
        ];
        let assessment = TrustAssessment::compute(&anchors, AnchorPolicy::AllAnchors, None);

        assert!(assessment.evidence_established(), "the TSA anchor verified");
        assert!(!assessment.coverage_complete());
        assert!(!assessment.policy_satisfied());
        assert!(!assessment.accepted_with_gaps());
        assert!(!assessment.max_trust_profile());
        // §5.5's floor IS met -- the TSA anchor verified -- so the reason
        // names the caller's own stricter profile, not the Bitcoin anchor.
        assert_eq!(
            assessment.unsatisfied_reason(),
            Some(ReasonCode::AnchorQuorumUnmet)
        );
    }

    #[test]
    fn single_anchor_policy_accepts_the_same_receipt_but_reports_the_gap() {
        let anchors = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor(
                "bitcoin_ots",
                AnchorVerdict::Untrusted(ReasonCode::BitcoinBlockNotChecked),
            ),
        ];
        let assessment = TrustAssessment::compute(&anchors, AnchorPolicy::SingleAnchor, None);

        assert!(assessment.policy_satisfied());
        assert!(!assessment.coverage_complete());
        assert!(
            assessment.accepted_with_gaps(),
            "a success reached by lowering the threshold must be flagged as such"
        );
        assert_eq!(assessment.unresolved.len(), 1);
        assert_eq!(assessment.unresolved[0].state, AnchorState::NotChecked);
    }

    /// The §5.5 floor is one *verified* anchor. Zero anchors cannot meet a
    /// quorum of one, so relaxing the policy must not accept a Receipt-Lite.
    #[test]
    fn no_anchors_satisfies_no_policy() {
        for policy in [AnchorPolicy::AllAnchors, AnchorPolicy::SingleAnchor] {
            let assessment = TrustAssessment::compute(&[], policy, None);
            assert!(!assessment.policy_satisfied(), "{policy}");
            assert!(!assessment.evidence_established(), "{policy}");
            // Nothing was presented, so nothing is outstanding: the failure
            // is the empty quorum, not an unfinished check.
            assert!(assessment.coverage_complete(), "{policy}");
        }
    }

    /// A cryptographically flawless token whose root nobody vouches for is
    /// not a verified anchor, under any policy.
    #[test]
    fn cryptographic_consistency_is_not_verification() {
        let anchors = vec![anchor(
            "rfc3161",
            AnchorVerdict::Untrusted(ReasonCode::TsaRootNotTrusted),
        )];
        for policy in [AnchorPolicy::AllAnchors, AnchorPolicy::SingleAnchor] {
            let assessment = TrustAssessment::compute(&anchors, policy, None);
            assert_eq!(assessment.verified_anchors, 0, "{policy}");
            assert!(!assessment.evidence_established(), "{policy}");
            assert!(!assessment.policy_satisfied(), "{policy}");
            assert_eq!(
                assessment.unresolved[0].state,
                AnchorState::CryptographicallyConsistent
            );
        }
    }

    /// A refutation of the **receipt** — a mismatched source file, a broken
    /// proof — poisons the axes exactly as a refuted anchor does, even
    /// though no anchor is at fault and every one of them verified.
    ///
    /// The assessment saw only `anchor_results` until this was threaded in,
    /// so a receipt verified against the wrong file reported
    /// `evidence.established: true` beside `status: "invalid"`.
    #[test]
    fn a_receipt_level_refutation_poisons_every_axis() {
        let anchors = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor("bitcoin_ots", AnchorVerdict::Valid),
        ];

        // Same anchors, no receipt-level refutation: fully accepted.
        let clean = TrustAssessment::compute(&anchors, AnchorPolicy::AllAnchors, None);
        assert!(clean.evidence_established());
        assert!(clean.policy_satisfied());
        assert!(clean.coverage_complete());
        assert!(clean.max_trust_profile());

        for reason in [
            ReasonCode::FileHashMismatch,
            ReasonCode::InclusionProofInvalid,
            ReasonCode::SuperInclusionProofInvalid,
            ReasonCode::SuperConsistencyProofInvalid,
            ReasonCode::MetadataHashMismatch,
        ] {
            let assessment =
                TrustAssessment::compute(&anchors, AnchorPolicy::AllAnchors, Some(reason));

            assert!(assessment.receipt_refuted(), "{reason}");
            assert_eq!(assessment.refuted_by(), Some(reason));
            // The anchor tally is untouched and stays honest ...
            assert_eq!(assessment.verified_anchors, 2, "{reason}");
            assert_eq!(assessment.refuted_anchors(), 0, "{reason}");
            // ... and every trust-bearing statement still refuses.
            assert!(!assessment.evidence_established(), "{reason}");
            assert!(!assessment.policy_satisfied(), "{reason}");
            assert!(!assessment.coverage_complete(), "{reason}");
            assert!(!assessment.max_trust_profile(), "{reason}");
            assert!(!assessment.accepted_with_gaps(), "{reason}");
        }
    }

    /// The hand-written `Debug` prints the reported axes, never the raw
    /// `both_anchor_types_verified` behind `max_trust_profile`. A derived
    /// `Debug` published it, so the un-poisoned value could reach a log
    /// without passing the refutation rule.
    #[test]
    fn debug_never_exposes_the_unpoisoned_tally() {
        let anchors = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor("bitcoin_ots", AnchorVerdict::Valid),
        ];
        let assessment = TrustAssessment::compute(
            &anchors,
            AnchorPolicy::AllAnchors,
            Some(ReasonCode::FileHashMismatch),
        );
        let rendered = format!("{assessment:?}");

        assert!(
            !rendered.contains("both_anchor_types_verified"),
            "{rendered}"
        );
        assert!(rendered.contains("max_trust_profile: false"), "{rendered}");
        assert!(
            rendered.contains("evidence_established: false"),
            "{rendered}"
        );
        assert!(rendered.contains("coverage_complete: false"), "{rendered}");
    }

    /// **A refuted anchor is counted, listed and shown — and takes no trust
    /// away.**
    ///
    /// The receipt does not authenticate its `anchors` array, so anybody who
    /// relays it can append an entry. A refuted anchor is therefore a
    /// statement about that anchor and about nothing else: it is never a
    /// verified anchor, it keeps the coverage axis honest, and it may not
    /// withdraw what a genuine anchor established.
    #[test]
    fn a_refuted_anchor_is_reported_and_takes_no_trust_away() {
        let anchors = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor(
                "bitcoin_ots",
                AnchorVerdict::Invalid(ReasonCode::BitcoinMerkleRootMismatch),
            ),
        ];
        for policy in [AnchorPolicy::AllAnchors, AnchorPolicy::SingleAnchor] {
            let assessment = TrustAssessment::compute(&anchors, policy, None);

            // Reported, in full, in its own list.
            assert_eq!(assessment.refuted_anchors(), 1, "{policy}");
            // `refuted_by` speaks for the RECEIPT, and nothing refuted it.
            // Naming the anchor here would let a relay put a refutation's
            // name on a receipt nothing had refuted.
            assert_eq!(assessment.refuted_by(), None, "{policy}");
            assert_eq!(
                assessment.refuted[0].reason,
                ReasonCode::BitcoinMerkleRootMismatch,
                "the anchor keeps its own reason in the coverage list: {policy}"
            );
            assert_eq!(assessment.refuted[0].anchor_type, "bitcoin_ots");
            assert_eq!(assessment.refuted[0].state, AnchorState::Refuted);
            assert_eq!(
                assessment.refuted[0].reason,
                ReasonCode::BitcoinMerkleRootMismatch
            );
            assert!(assessment.unresolved.is_empty(), "{policy}");
            assert!(
                !assessment.coverage_complete(),
                "the refuted anchor must be accounted for, not silently \
                 counted as settled: {policy}"
            );

            // And it is not a statement about the receipt.
            assert!(!assessment.receipt_refuted(), "{policy}");
            assert!(
                assessment.evidence_established(),
                "one anchor really did reach a trusted root, and an entry \
                 anybody could have appended may not withdraw that: {policy}"
            );
        }

        // The quorum still answers its own question. `--allow-single-anchor`
        // is met -- one verified anchor -- so appending the refuted one
        // changed no status at all. The default profile is unmet, because it
        // demands every anchor presented be verified, and a refuted one is
        // no more verified than an unresolved one.
        assert!(
            TrustAssessment::compute(&anchors, AnchorPolicy::SingleAnchor, None).policy_satisfied()
        );
        assert!(
            !TrustAssessment::compute(&anchors, AnchorPolicy::AllAnchors, None).policy_satisfied()
        );
    }

    /// **A refutation of the RECEIPT poisons every trust-bearing axis.**
    ///
    /// The other half of the rule above, and the one that has to keep
    /// holding: a source file whose hash does not match, a broken inclusion
    /// proof, a checkpoint that contradicts the proof. Those are statements
    /// about the receipt, they are what `status: "invalid"` reports, and no
    /// supporting field may announce achieved trust beside one.
    #[test]
    fn a_receipt_refutation_poisons_every_axis() {
        let anchors = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor("bitcoin_ots", AnchorVerdict::Valid),
        ];
        for policy in [AnchorPolicy::AllAnchors, AnchorPolicy::SingleAnchor] {
            let assessment =
                TrustAssessment::compute(&anchors, policy, Some(ReasonCode::FileHashMismatch));
            assert!(assessment.receipt_refuted(), "{policy}");
            assert!(
                !assessment.max_trust_profile(),
                "§5.6 cannot be attained by a receipt a check has disproved: {policy}"
            );
            assert!(
                !assessment.evidence_established(),
                "trust is not established in refuted evidence, however many \
                 anchors reached a trusted root: {policy}"
            );
            assert!(!assessment.coverage_complete(), "{policy}");
            assert!(!assessment.policy_satisfied(), "{policy}");
            assert!(!assessment.accepted_with_gaps(), "{policy}");
            assert_eq!(
                assessment.refuted_by(),
                Some(ReasonCode::FileHashMismatch),
                "{policy}"
            );
        }
    }

    /// **§5.6 asks about the two anchor types, and an appended entry does
    /// not answer it either way.**
    ///
    /// Both types verified is both types verified, whatever else is in the
    /// list: a third entry that failed verification is something anybody
    /// could have added, so letting it withdraw the profile would hand every
    /// relay a downgrade. What it cannot do is *create* the profile, since
    /// only a verified anchor is counted.
    #[test]
    fn an_appended_failed_anchor_neither_grants_nor_withdraws_the_max_trust_profile() {
        let both = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor("bitcoin_ots", AnchorVerdict::Valid),
        ];
        let mut with_appended = both.clone();
        with_appended.push(anchor(
            "rfc3161",
            AnchorVerdict::Invalid(ReasonCode::TsaImprintMismatch),
        ));

        for policy in [AnchorPolicy::AllAnchors, AnchorPolicy::SingleAnchor] {
            let clean = TrustAssessment::compute(&both, policy, None);
            let appended = TrustAssessment::compute(&with_appended, policy, None);

            assert!(clean.max_trust_profile(), "{policy}");
            assert_eq!(
                appended.max_trust_profile(),
                clean.max_trust_profile(),
                "an appended failed anchor must not withdraw §5.6: {policy}"
            );
            assert_eq!(appended.verified_anchors, 2, "{policy}");
            assert_eq!(appended.total_anchors, 3, "{policy}");
            assert_eq!(appended.refuted_anchors(), 1, "{policy}");
            // Still reported, and still keeping coverage honest.
            assert!(!appended.coverage_complete(), "{policy}");
            assert_eq!(
                appended.refuted[0].reason,
                ReasonCode::TsaImprintMismatch,
                "{policy}"
            );
        }

        // The quorum is the one thing it does move, and only under the
        // profile that demands every anchor presented be verified.
        assert!(
            TrustAssessment::compute(&with_appended, AnchorPolicy::SingleAnchor, None)
                .policy_satisfied()
        );
        assert!(
            !TrustAssessment::compute(&with_appended, AnchorPolicy::AllAnchors, None)
                .policy_satisfied()
        );
    }

    /// The protocol does not forbid two anchors of the same type. §5.6 asks
    /// whether both *types* are verified, so two verified RFC 3161 anchors
    /// must not add up to "both" — and the per-anchor counts must still be
    /// per anchor.
    #[test]
    fn duplicate_anchor_types_do_not_forge_the_max_trust_profile() {
        let two_tsa = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor("rfc3161", AnchorVerdict::Valid),
        ];
        let assessment = TrustAssessment::compute(&two_tsa, AnchorPolicy::AllAnchors, None);
        assert_eq!(assessment.verified_anchors, 2);
        assert!(
            !assessment.max_trust_profile(),
            "two TSA anchors are not an RFC 3161 anchor plus a Bitcoin one"
        );
        // The quorum is still met: every anchor presented is verified.
        assert!(assessment.policy_satisfied());
        assert!(assessment.evidence_established());
        assert!(assessment.coverage_complete());

        // Duplicates of both types: the counts still count anchors rather
        // than types, and a fourth entry that failed verification is listed
        // without taking the profile away.
        let mixed = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor("bitcoin_ots", AnchorVerdict::Valid),
            anchor("bitcoin_ots", AnchorVerdict::Valid),
            anchor(
                "rfc3161",
                AnchorVerdict::Invalid(ReasonCode::AnchorTargetHashMismatch),
            ),
        ];
        let assessment = TrustAssessment::compute(&mixed, AnchorPolicy::AllAnchors, None);
        assert_eq!(assessment.verified_anchors, 3);
        assert_eq!(assessment.total_anchors, 4);
        assert_eq!(assessment.refuted_anchors(), 1);
        assert!(assessment.max_trust_profile());
        assert!(assessment.evidence_established());
        assert!(!assessment.coverage_complete());
    }

    #[test]
    fn max_trust_profile_needs_both_anchor_types_verified() {
        let anchors = vec![
            anchor("rfc3161", AnchorVerdict::Valid),
            anchor("bitcoin_ots", AnchorVerdict::Valid),
        ];
        let assessment = TrustAssessment::compute(&anchors, AnchorPolicy::AllAnchors, None);
        assert!(assessment.max_trust_profile());
        assert!(assessment.policy_satisfied());
        assert!(assessment.coverage_complete());
        assert!(!assessment.accepted_with_gaps());
    }

    #[test]
    fn profile_names_are_stable() {
        assert_eq!(AnchorPolicy::AllAnchors.as_str(), "all-anchors");
        assert_eq!(AnchorPolicy::SingleAnchor.as_str(), "single-anchor");
        assert_eq!(AnchorPolicy::default(), AnchorPolicy::AllAnchors);
        assert_eq!(
            AnchorPolicy::from_allow_single_anchor(true),
            AnchorPolicy::SingleAnchor
        );
        assert_eq!(
            AnchorPolicy::from_allow_single_anchor(false),
            AnchorPolicy::AllAnchors
        );
    }
}
