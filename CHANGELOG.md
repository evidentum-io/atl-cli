# Changelog

All notable changes to `atl-cli` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Section references are to the ATL Protocol v2.0 specification.

## [Unreleased]

### Changed — BREAKING

#### An unanchored receipt is no longer a successful outcome

**A receipt carrying no anchors (Receipt-Lite) now reports `untrusted` and
exits 3.** It previously reported `pending` and exited 0. The reason code is
`receipt_unanchored`, unchanged.

§5.5 is unambiguous:

> At least one anchor MUST be verified to establish trust in the receipt.
> Anchors provide independent, third-party proof that a specific hash existed
> at a specific time. Without a verified anchor, the receipt proves only
> internal consistency, not temporal existence.
>
> A receipt without any **verified anchors** SHOULD be treated as
> untrustworthy.

A Receipt-Lite has no anchors at all, therefore zero verified anchors,
therefore it is exactly the case §5.5 names. Reporting exit 0 for it accepted
— under a softer word — precisely what the specification says to treat as
untrustworthy, and any caller testing `if atl-cli verify …` was told yes
about a receipt carrying no external attestation of any kind.

Nothing about such a receipt is refuted: its Merkle proofs may be entirely
sound, and the output still reports them as such
(`verification.proofs_valid: true` alongside `status: "untrusted"`). The word
"pending" survives as a *description* of the receipt's state —
`anchor_status: "unanchored"` in JSON, the Receipt-Lite note in the human
output, and the batch `summary.unanchored` bucket — but it is no longer a
status and no longer exit 0.

`--allow-single-anchor` does not restore the old behaviour and is not
intended to: it lowers the anchor quorum to one *verified* anchor, and no
quorum of one can be met by none. The remedy is an anchored receipt.

Consequences across the surface:

- `Status::Pending` is removed. Exactly one status (`valid`) exits 0.
- Batch: `summary.pending` → `summary.unanchored`; reason code
  `batch_items_pending` → `batch_items_unanchored`; an unanchored item's own
  row now reads `status: "untrusted"`, `reason_code: "receipt_unanchored"`.
  The batch status for such a mixture is `untrusted`, exit 3.
- The `unanchored` bucket is kept separate from `untrusted` only so the
  report can say which kind of untrusted it is — no trust material a caller
  could supply changes it.

### Added

#### `--allow-single-anchor`: the §5.5 floor, opted into explicitly

The default anchor policy is unchanged and remains strict: **every anchor a
receipt presents must be verified.** The profile is named `all-anchors`, and
it is a rule about the anchors *this receipt offers* — a Receipt-TSA
satisfies it with its single TSA anchor and no Bitcoin anchor anywhere.

It is therefore **not** §5.6, which is about requiring both anchor *types*;
§5.6 is reported separately as `max_trust_profile` and is never this
profile's test. The profile's own `requirement` string cites no section,
because no single section states it.

Why it is strict all the same: a receipt that offers a Bitcoin anchor and
then cannot have it confirmed did not deliver what it offered, and this is a
reference verifier whose default becomes a de-facto norm.

A consequence stated rather than hidden: a Receipt-Full verified offline
comes out *worse* than a Receipt-TSA with the same trusted root, because the
Receipt-TSA never claimed a Bitcoin anchor. That is an honest report about a
promise not kept, not a defect.

`--allow-single-anchor` lowers the quorum to §5.5's floor: one verified
anchor suffices. It never rescues a refuted anchor (a refutation is
policy-independent and always `invalid`, exit 1), never accepts a receipt
with no anchors, and never hides an unresolved one. When it is what produced
the acceptance, `assessment.coverage.accepted_with_gaps` is `true` and the
human status line reads `VALID under policy 'single-anchor' (1 of 2 anchors
verified; 1 unresolved)` — never a bare `VALID`.

#### Three axes reported separately: evidence, policy, coverage

A single verdict word had to answer three questions of different natures, and
answered all of them "untrusted". The JSON gains an `assessment` object and
the human output a **Trust Assessment** block:

- `assessment.evidence` — is trust established at all (§5.5: at least one
  verified anchor, and nothing refuted)? Carries `verified_anchors`,
  `refuted_anchors`, `total_anchors`.
- `assessment.policy` — is the selected quorum met? Carries `profile`
  (`"all-anchors"` / `"single-anchor"`), `requirement`, `satisfied`, and
  `max_trust_profile`.
- `assessment.coverage` — was every anchor presented carried to a sound
  result? Carries `complete`, `accepted_with_gaps`, `unresolved[]` and
  `refuted[]`, each entry with its anchor type, state and reason code.

They disagree often, and the disagreement is the information: a Receipt-Full
verified offline has evidence **established**, policy **unsatisfied** and
coverage **incomplete** at the same time.

**A refutation poisons every axis, from any cause.** Whenever anything is
refuted, `evidence.established`, `policy.satisfied`, `coverage.complete` and
`max_trust_profile` are all `false`, and refuted anchors are listed in
`coverage.refuted[]` rather than counted as settled. No field beside a
`status: "invalid"` verdict may report achieved trust.

Two shapes of the same defect were closed. First, a receipt with two verified
anchors and a third refuted one printed `max_trust_profile: true` and
"Receipt-Full profile … ATTAINED" beside `status: "invalid"`. Second — and
worse, because the machine contract has no accident to save it — the axes
were tallied from `anchor_results` alone while `verdict()` also declares
`invalid` for reasons that never touch an anchor: a mismatched source file, a
broken inclusion proof, a broken Super-Tree proof. Verifying the wrong file
against a receipt with a trusted TSA anchor reported
`evidence.established: true`, `policy.satisfied: true` and
`coverage.complete: true` next to `reason_code: "file_hash_mismatch"`. The
human renderer hid it only by returning early on a hash mismatch, which was
a coincidence rather than a defence.

`evidence.refuted_by` was added: the reason code that disqualifies the
receipt, from either source, always equal to the top-level `reason_code`. It
is what makes `established: false` beside `verified_anchors: 1` legible
rather than contradictory. The human §5.6 line now answers `YES` / `NO`
(`NO — this receipt was refuted`) rather than with the attainment wording, so
no form of that word can appear beside a refuted receipt.

`assessment.policy.max_trust_profile` reports §5.6 independently of the
acceptance threshold. An accepted Receipt-TSA is `valid` with
`max_trust_profile: false`. The field is absent as a whole for a receipt with
no anchors — there is no quorum to report on.

Batch output gains `policy_profile` at the top level and an `assessment`
object per verified item.

#### Per-anchor `state`

Each anchor result carries a `state` alongside `verified` and `reason_code`,
uniform across anchor types: `verified`, `cryptographically_consistent`,
`incomplete`, `not_checked`, `unavailable`, `unevaluable`, `refuted`. This
separates situations the single word `untrusted` had merged — an anchor not
checked because the run was offline, one whose lookup failed, one whose
cryptography this build cannot evaluate, and one whose chain is sound but
whose root nobody vouches for.

The RFC 3161-only `trust_state` field is unchanged and still emitted.

#### An unverified Bitcoin anchor publishes nothing as established

`block_timestamp` was rendered from a `0` sentinel meaning "no block was
fetched", so an unconfirmed anchor emitted
`block_timestamp: "1970-01-01T00:00:00Z"` — a parsable, real-looking value
published for a check that never ran, which is worse than an absent field.
`block_height` was published under its plain name although it is read out of
the receipt and establishes nothing until a block at that height has been
fetched and its Merkle root matched.

Both now follow the rule already applied to the RFC 3161 `genTime`: a plain
name is reserved for a fact this run established **about this receipt**.
`block_height` / `block_timestamp` / `block_merkle_root` / `merkle_match`
appear only for a verified anchor. The underlying time is `Option<u64>`
rather than a `0` sentinel, so the stub no longer exists to be rendered.

The two numbers are renamed differently, because they are different kinds of
not-established:

| when | height | time |
|---|---|---|
| verified | `block_height` | `block_timestamp` |
| no block fetched | `claimed_block_height` | *absent* |
| header corroborated, Merkle root did not match | `claimed_block_height` | `reported_block_timestamp` |

The height is the receipt's own assertion, read out of the OTS proof, hence
`claimed_`. The time in the third row is what named sources reported, hence
`reported_` — calling it "claimed" would be a second falsehood, since nobody
claimed it, and calling it "observed" (its first name, corrected below)
overstated it in the other direction.

That third row was a live defect of its own: the online path fetches the
block *before* comparing Merkle roots, and `block_timestamp` was serialized
unconditionally, so a receipt refuted by `bitcoin_merkle_root_mismatch`
published a genuinely reported block time under the plain name beside
`merkle_match: false` — a date offered for evidence the same object refutes.
Human output now reads `Block #932898 @ … (as reported by the sources below;
this block does NOT date this receipt)`.

`computed_root`, `block_merkle_root` and `merkle_match` deliberately keep
their plain names on a refuted anchor: each is either a deterministic local
computation or the evidence *of* the mismatch, none is presented as a fact
about the receipt, and renaming them would hide the fields a reader needs in
order to see what went wrong.

#### Fixed: a failure detail taken from an unrelated cause

The human failure line attached the first refuted anchor's prose whatever the
top-level reason was. A receipt refuted by a broken Super-Tree proof, one of
whose anchors separately failed to parse, printed
`super_inclusion_proof_invalid: RFC 3161 parse error: CMS ContentInfo parse
failed`. Both halves were true and unrelated; welded together they assert a
causal claim nobody checked. An anchor's prose is now used only when that
anchor's own reason code is the verdict's reason code — the rule the JSON
renderer already applied.

### Changed — BREAKING

#### Bitcoin anchors: two providers must agree, and we stop saying "on-chain"

This tool does not observe the Bitcoin network. It queries public
block-explorer HTTP APIs and reads a block header out of their JSON: no proof
of work is validated, no chain of headers is followed, no peer is contacted.
Two long-standing overstatements followed from ignoring that.

**One endpoint decided the verdict.** The lookup returned the first answer it
got, and that unverified Merkle root alone decided `merkle_match` — so a
single wrong or compromised API could make an anchor `verified`. Every
provider is now queried on each lookup, and a header is usable only when
**two or more separately operated providers report the same one**. Separately
*operated* is the whole claim: the word "independent" has been removed from
the acceptance condition, the code and the docs, because it asserted a
property this tool cannot check — and stood, in one comment, ten lines above
its own denial.

Compared between providers: **block hash**, **Merkle root** and **block
time**. All three are header fields (two correct providers cannot differ on
any of them) and all three are published downstream, so a disagreement on any
one would mean publishing a value our own sources contradict. The height is
checked separately and against a stronger reference — each provider's
reported height against the height that was *requested* — rather than between
providers. Agreement is **unanimity among those who answered**, never a
majority: a majority would let two wrong endpoints outvote a correct one and
would hide the disagreement.

| sources | outcome | exit |
|---|---|---|
| two or more, agreeing | compared → `valid`, or `invalid` on a mismatch | 0 / 1 |
| two or more, disagreeing | `untrusted` / `bitcoin_providers_disagree` | 3 |
| exactly one | `untrusted` / `bitcoin_single_source_only` | 3 |
| none | `untrusted` / `bitcoin_block_unavailable` | 3 |

Only a corroborated header can refute. **A mismatch from a single
uncorroborated endpoint is not a refutation**: if one source is not enough to
accept evidence it is not enough to accuse it either, and the alternative
lets one API turn sound evidence into `invalid`. A provider disagreement is
likewise never a finding about the receipt — it is a conflict among the
sources, and every conflicting report is published (`SOURCES DISAGREE` in the
human output, `block_sources` in the JSON) with the words *nothing about this
receipt is refuted by this*.

New reason codes `bitcoin_providers_disagree` and
`bitcoin_single_source_only`; new anchor states `contested` and
`uncorroborated`. Both reasons carry their own headline and their own advice
in every renderer — they previously fell through to "trust root unavailable"
and "missing trust material", telling a user to go and find certificates when
two APIs had contradicted each other, or when only one had answered.

**Agreement has one definition.** `BlockSourceReport::agrees_with` is the
single predicate, used by the classifier that decides
`bitcoin_providers_disagree` and by both renderers that display it. It was
duplicated, and the copies differed: the classifier compared the block hash,
the Merkle root *and* the time, while the human renderer compared only the
first two — so a conflict about nothing but the time was classified as a
disagreement and then rendered as though nothing had happened.

**Responses are bound to the block that was requested.** `height` was copied
in from the function argument, so a well-formed response describing a
*different* block was accepted as an answer about this one; the reported
height is now checked against the request, and in a two-step lookup the
detail response's `id` is checked against the hash the first step returned.

**Block-time validation fails closed.** An unreadable system clock fell back
to `u64::MAX`, which made the upper-bound comparison unsatisfiable, so every
future time passed — fail-open, beneath a comment claiming the opposite.
Without a clock the upper bound cannot be evaluated, and a check that cannot
be performed is not a check that passed.

**Only corroborated headers are cached.** `Unavailable`, `Uncorroborated` and
`Disagreement` were cached with no TTL, so one timeout became a permanent
wrong answer for that height for the rest of the process, and falsified the
claim that every provider is queried on each lookup. The three transient
outcomes are now retried in full.

The remaining cache carries a **ten-minute TTL** — one expected Bitcoin block
interval, a reasoned figure rather than a picked one. An earlier revision had
no TTL, justified by "the process lives seconds"; that premise was false,
because batch mode walks a whole directory in one process with no bound on
how long it takes, so the second receipt at a given height would be answered
from a corroboration obtained at the start of the run. The TTL does not make
a cached header fresh and prevents no reorganisation; it bounds staleness,
which without it grew with the size of the batch.

What corroboration establishes is now written out exactly —
that at the moment of the query two or more APIs reported the same header,
and **not** that the block is deeply confirmed, that a reorganisation has not
since occurred, or that the sources are independent of each other at all —
they are separately operated endpoints, and shared hosting, a shared upstream
index or a common failure are not ruled out. It had been described as "a stable fact", which nothing in the code
checks.

**The wording no longer claims what is not done.** `observed on-chain` in the
human output is gone, along with "confirmed against the blockchain" in the
docs and prose. The output names the sources instead — `Reported by:
blockstream.info, mempool.space (2 sources)` — and the JSON carries
`block_sources` with each endpoint's name and what it reported. The
unverified-anchor time field is renamed `observed_block_timestamp` →
`reported_block_timestamp`: nobody claimed it, we asked and were told, and
`observed` overstated it in the other direction.

**Block times are validated at intake.** A value earlier than Bitcoin's
genesis block (2009-01-03) or more than two hours in the future — Bitcoin's
own consensus limit on header time — is not a block time, and such a response
is now discarded rather than published. This closes the other half of the `0`
→ `"1970-01-01T00:00:00Z"` problem: the tool's own sentinel was removed
earlier, but a zero handed to us by an API would have rendered exactly the
same way.

### Documentation

#### A gap in the specification, recorded for amendment

§5.5's five steps for an RFC 3161 anchor end at "verify the cryptographic
signature of the Time Stamping Authority". They never mention constructing a
certificate path, and never say where a verifier obtains the trust anchors
that path must reach. **Read literally, a self-signed certificate generated
by an attacker satisfies step 4.**

This implementation applies a stricter rule than the text states, and defines
a **verified anchor** as: the cryptographic facts were checked **and** the
certificate path reached a trust anchor supplied by the verifier's own trust
store. Both halves are required, and only this state counts towards §5.5.

A token whose CMS signature and chain are flawless but whose terminal
certificate nobody vouches for proves that *some key* signed it, and nothing
more; it is reported as `cryptographically_consistent` and is never counted
as verified. The word "verified" is reserved for the strong sense throughout.

This is recorded here, and in the README, rather than left as a code comment:
the specification text is what needs amending. It is the same gap already
noted as decision Р6 in `docs-md/atl-trust-model-decisions.md` — mechanisms
for *discovering* trust material are not the same as grounds for *trusting*
it, and §5.5 should require both a path to a trust anchor and an external
channel for obtaining that anchor.

## 0.9.0

Earlier releases are recorded in the git history; this file starts with the
work above.
