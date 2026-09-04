# Changelog

All notable changes to `atl-cli` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Section references are to the ATL Protocol v2.0 specification.

## [Unreleased]

### Fixed — the reason the tool gives was a relay's to choose

A receipt's `anchors` array is covered by neither the leaf hash nor the
checkpoint blob, so **anybody who relays a receipt can rewrite it** — append,
prepend, reorder — with no key. The previous release stopped an appended
anchor from changing the receipt's *status*. It did not stop it changing what
the tool called the *reason*:

```
                       reason_code                     anchor_status
clean Receipt-Lite     receipt_unanchored              unanchored
+ one junk anchor      anchor_target_hash_mismatch     anchored
```

Both runs exit 3 and both report `untrusted`, and nothing was concealed — the
anchor appeared in full. What moved was the headline. "There is no anchor
here" became "one anchor did not match", which reads as a local mishap and
hides the more fundamental fact that no trust was established at all. A
reader who reads one line — and a reader reads one line — was handed a choice
made by somebody else. It is the defect this project spent six rounds
removing from `atl-core`, one storey up, in the field a user actually sees.

**Every field that speaks for the receipt is now computed from facts a relay
cannot move.** The quantity that carries this is the count of *verified*
anchors: anchors bearing a timestamp over this receipt's own root that chain
to a trust root the **caller** supplied. Appending rubbish cannot lower it,
and producing something that raises it is exactly what a stranger cannot do.

Found by running a clean receipt and five tampered variants of it — append
and prepend, RFC 3161 and Bitcoin, and a wrong `target` — through the CLI
across five fixtures and four flag settings, and diffing the **entire**
top-level output rather than the fields anybody had thought to check. Seven
fields moved. Each is listed below with what it does now.

#### `reason_code`, and `errors[0]`

The top-level reason was `unresolved.first()` falling back to
`refuted.first()` — a function of the anchor array. It is now one of two
codes computed from the verified count alone:

* **`receipt_unanchored`** — no anchor was verified. ATL v2.0 §5.5's own
  words are "a receipt without any **verified anchors** SHOULD be treated as
  untrustworthy", and that is now exactly what the code means. It covers a
  receipt presenting no anchors, one whose anchors were all left unresolved,
  and one whose anchors were all refuted, **without distinguishing them** —
  which is not a loss of precision but the honest position: the second and
  third are what the first looks like after somebody appends to it, and this
  tool cannot tell which happened.
* **`anchor_quorum_unmet`** (new) — §5.5's floor *is* met and the caller's
  stricter profile is not. A statement about the caller's own profile,
  naming no anchor.

`errors[]` now always leads with the receipt's own statement, and lists
*every* anchor that did not verify after it. It used to filter the `_detail`
entries to anchors whose code equalled the top-level reason — so when that
reason was itself an anchor's code, the array a machine consumer reads was
chosen by whoever last handled the receipt, and against a Receipt-Lite the
receipt-level statement did not merely lose its place, it was gone. A relay
can now only ever *add* to this array, which is unavoidable and correct: an
appended anchor must be visible.

**The per-anchor codes are not lost, they are relocated** to where per-anchor
advice belongs: `anchor_verification.results[].reason_code`,
`assessment.coverage.unresolved[]` / `.refuted[]`, the `errors[]` entries
after the first, and the human renderer's advice block, which still prints
the concrete remedy for each (`--tsa-trust-store` with the fingerprint to
supply, `--tsa-intermediates`, "re-run with network access", and so on).

#### `anchor_status` is now two numbers

`anchor_status` was the string `"anchored"` / `"unanchored"`, computed from
`receipt.anchors().is_empty()`. One appended anchor flipped it, so a receipt
that had never been anchored stopped looking unanchored — on the word of
somebody who supplied no key.

It is now an object, because these are two different facts and one string
cannot carry both:

```json
"anchor_status": { "state": "none_verified", "verified": 0, "presented": 1 }
```

`verified` and `state` are computed from the verified count and are
unmovable. `presented` describes the document that arrived and is published
as the relay-controlled number it is — `presented: 0` does mean this tool saw
a Receipt-Lite, but it does not prove the log issued one, and a non-zero
value proves nothing about the log at all.

The human output's `Anchor Status: UNANCHORED` line becomes
`Anchors: NONE VERIFIED (0 presented)` / `Anchors: 1 of 2 verified`, and the
headline reads `NOT VERIFIED: no anchor was verified` rather than
`NOT VERIFIED: the receipt carries no anchors (Receipt-Lite)`. The
Receipt-Lite tier is still explained in full, now worded "as it reached this
tool" wherever it is a statement about the document that arrived.

#### `mode`: a relay could make somebody else's verifier emit traffic

`receipt_requires_network` asked "is any anchor a `bitcoin_ots` anchor". So
appending one to a Receipt-Lite made this tool build a Tokio runtime, probe
connectivity and report `mode: "online"` — outbound requests a stranger with
no key had caused, for a receipt whose every check had already finished
locally, and a run that then said it had gone online.

The question is now "is there an anchor a block header would still settle",
which is `PreparedOts::from_facts` — the same predicate the online pass uses
to build its work list, so the decision to go online and the decision to look
anything up can no longer disagree. An anchor that does not bind to this
receipt is refuted offline and asks for nothing. `requires_network`, the
old per-anchor predicate, is deleted rather than left to be reused.

#### `assessment.evidence.refuted_by`

Fell back to the first refuted anchor's reason, so against a clean
Receipt-Lite it turned `null` into `"anchor_target_hash_mismatch"` — a
refutation's name on a receipt nothing had refuted. It now reports the
receipt's own refutation and nothing else, and is `null` whenever the receipt
was not refuted. The anchor findings stay in `coverage.refuted[]`, counted by
`evidence.refuted_anchors`.

#### `assessment` is always present

It was omitted when no anchors were presented, which made the object's very
*presence* a function of the `anchors` array: appending one made
`evidence.established`, `evidence.verified_anchors`, `evidence.refuted_by`
and `policy.max_trust_profile` — four fields a relay cannot otherwise move —
appear where a consumer had been reading nothing. All four are answerable for
a receipt with no anchors, and answering them costs nothing.

#### The batch reason no longer depends on one item's anchor array

`batch_items_unanchored` was reported ahead of `batch_items_untrusted`
whenever any item presented no anchors. Bucket membership is decided by that
item's `anchors` array — so appending one rubbish anchor to one Receipt-Lite
in a directory changed the whole **batch's** reported reason. The two
aggregate into `batch_items_untrusted`; `batch_items_unanchored` is removed.
The `unanchored` summary count and the per-item bucket survive, because they
describe what arrived, and they feed no aggregate reason.

#### What a relay can still move, stated plainly

Under the **default** profile — every anchor the receipt presents must be
verified — appending an anchor takes an accepted receipt from `valid` (exit
0) to `untrusted` (exit 3). That is inherent, not an oversight: the profile
is defined over the presented set, and the presented set is a relay's to
change. Removing it would mean not asking the question the profile exists to
ask.

The shape of what a relay gets is what matters, and it is bounded:

* never an accusation — `untrusted`, never `invalid`, and nothing reports the
  receipt as refuted;
* never a reason of their choosing — `anchor_quorum_unmet` names the caller's
  own profile and no anchor;
* never under **`--allow-single-anchor`**, which asks §5.5's own question and
  cannot be moved by appending, since appending cannot lower a count.

Both the human output and the README say so where it happens, so a caller who
needs an outcome a relay cannot touch knows which flag to pass. Pinned by
`the_default_profile_is_relay_sensitive_and_the_relaxed_one_is_not`.

#### The guard compares the whole reported tuple

`an_appended_failed_anchor_changes_no_status` compared the status. That is
how this leaked: in `atl-core` we compared `is_valid` while
`is_indeterminate` moved, then the error set; here the status held while
`reason_code` and `anchor_status` moved. The guard now compares every
top-level field — status, exit code, reason code, `anchor_status.state` and
`.verified`, `mode`, the file-hash block, the proof flags, the three unmovable
assessment fields and `errors[0]` — against both settings of
`--allow-single-anchor`, with the per-anchor enumerations exempted by name
and with a reason given for each exemption.
`an_appended_anchor_cannot_make_a_receipt_lite_stop_looking_unanchored` runs
the same comparison over four kinds of appended junk, and
`the_receipt_level_tuple_is_not_constant` checks the comparison can fail at
all, so a bug in the helper cannot make every invariance assertion pass for
free.

#### Measured

Against the whole 271-case corpus, versus the last released behaviour:
**no exit code and no status changed.** Twenty reason codes did, all three
of the intended kinds:

| before | after | cases |
|---|---|---|
| `tsa_chain_incomplete` | `receipt_unanchored` | 12 |
| `tsa_root_not_trusted` | `receipt_unanchored` | 6 |
| `bitcoin_block_not_checked` | `anchor_quorum_unmet` | 2 |

Re-running the tamper experiment afterwards, the only top-level fields that
still move are `anchor_status.presented`, the per-anchor enumerations, and —
under the default profile only — the acceptance itself, as described above.


### Changed — §5.5 is asked of `atl-core`, and a refuted anchor no longer refutes the receipt

`atl-cli` verified the receipt with `VerifyOptions { skip_anchors: true }` and
then implemented ATL v2.0 §5.5 itself. That was never duplicated
*cryptography* — `verify_rfc3161_token` and `verify_ots_anchor_impl` were
always public — it was duplicated **protocol orchestration**: pinning each
anchor to the receipt's own root, decoding the payload, deciding which facts
refute and which merely fail to confirm, and reducing them to an outcome.
Two implementations of a mandatory rule drift, and every defect fixed on one
side stays open on the other.

`atl-core` 0.29 publishes that orchestration as
`verify_receipt_anchors(&receipt, &options) -> Vec<AnchorFacts>`, with three
outcomes that partition (`is_verified` / `is_refuted` / `is_indeterminate`)
and no verdict formed. This release deletes the copy and calls it.

**Removed from this crate, and what replaced each:**

| removed | now |
|---|---|
| `verify_rfc3161_anchor` — target/`target_hash` pinning plus steps 3-5 | `atl_core::verify_receipt_anchors` |
| `prepare_bitcoin_ots` — `super_root` pinning, OTS decoding, attestation selection by claimed height, §5.5.2 step 5's height half, Merkle-root computation | same call |
| `verify_bitcoin_ots_offline` | `anchor::offline_results` over the facts |
| `verify_anchors_offline` | `anchor::establish_anchor_facts` + `anchor::offline_results` |
| `AnchorDetails::rfc3161_verdict` — the fact-to-outcome classifier | `anchor::verdict_from_facts`, which reads `AnchorFacts::refutations()` then `AnchorFacts::inabilities()` |
| `AnchorDetails::rfc3161_trust_state` | `AnchorVerificationResult::rfc3161_trust_state`, derived from the verdict |
| `decode_hash_hex`, `constant_time_eq` — the pinning helpers | `atl-core`'s, which are the same code |
| `map_core_error` | `single::classify_core_error`, three-valued |

What stays here, and stays deliberately: everything network (`online.rs`, the
block sources, source agreement, the `bitcoin_block_time` comparison, the
computed-root-versus-header check — `atl-core` performs no I/O, so a Bitcoin
anchor is *never* verified there); the acceptance policy (`AnchorPolicy`,
`--allow-single-anchor`, the three `TrustAssessment` axes, §5.6's
`max_trust_profile`); `Status` / `ReasonCode` / exit codes / both renderers,
which are this CLI's contract; the source file's hash against
`entry.payload_hash`; batches; PEM parsing for `--tsa-trust-store` /
`--tsa-intermediates`; and receipt loading.

#### A refuted anchor is reported, and changes no status

`verdict()` had a rule between "is the receipt itself refuted" and "does the
quorum hold": **any** refuted anchor made the receipt `invalid`, exit 1,
under every policy. It is gone.

An ATL receipt does not authenticate its own anchors. The leaf hash is
`SHA256(0x00 || payload_hash || metadata_hash)` and the checkpoint blob is 98
bytes of origin, tree size, timestamp and root hash — the `anchors` array
appears in neither, so nothing signs it and nothing hashes it. **Anybody who
relays a receipt can append an anchor to it, with no key**, and every anchor
refutation this tool can produce is reachable that way: a wrong `target`, a
`target_hash` naming another root, an undecodable payload, a genuine token
minted over other data, a stated Bitcoin height the proof contradicts. The
observation therefore never distinguishes "this receipt was altered" from
"somebody appended rubbish", and while it decided the status, any relay could
turn *trust could not be established* into *this evidence is disproved* — an
accusation manufactured for free, and a denial of verification available to
everyone who handles a receipt.

Nothing is lost. Altering a receipt so that a genuine anchor stops matching
means changing `proof.root_hash`, which the checkpoint comparison and the
inclusion proof catch at receipt level, and those still exit 1.

**The guarantee is one-sided, and only the one side is claimed.** An anchor
that *fails* verification changes no status. An anchor that *passes* raises
the verified count and can carry the receipt over the quorum — as it must,
since that is what anchors are for, and producing one needs a timestamp token
over this receipt's own root chaining to a trust root the caller supplied.
The test suite pins both directions, so "the invariant holds" cannot be
confused with "anchors do not matter".

**And it is never hidden.** The anchor keeps its own `refuted` state and its
own reason code, it is listed under `assessment.coverage.refuted`, and it
keeps `coverage.complete` false. A consumer that dropped it on the floor
because it does not gate the verdict would be concealing exactly the
tampering it exists to reveal, so the human output was changed in three
places:

* a new paragraph, printed **whatever the status** — `valid` included —
  naming every failed anchor, its reason code and its detail, and saying
  plainly that it does not disprove the receipt and what to do about it. It
  is not attached to a failure path: under `--allow-single-anchor` an
  accepted receipt can carry one, and that is precisely where the finding
  would otherwise be lost.
* the qualified success line counts both kinds of gap —
  `VALID under policy 'single-anchor' (1 of 3 anchors verified; 1 unresolved,
  1 REFUTED)`. It counted only the unresolved ones, so an accepted receipt
  with a failed anchor printed `0 unresolved` beside `1 of 3 anchors
  verified` and left the reader to work out where the other two went.
* `untrusted_headline` gained an arm for the anchor-refutation reason codes:
  `NOT VERIFIED: an anchor was checked and failed (the receipt itself is not
  disproved)`. They used to fall through to "trust root unavailable", which
  after this change would have sent the reader after a certificate that
  cannot help and hidden the one thing worth seeing.

The `untrusted` lead-in was reworded from "The evidence was NOT disproved.
This verifier could not finish checking it" to "The RECEIPT was NOT disproved.
This verifier could not establish trust in it" — the old wording is false
beside a refuted anchor, and "the evidence" was ambiguous between the two.

Measured against the whole of `test_data/receipts` and `real-data`, two
receipts change outcome, and only these two:

| fixture (against `real-data/testfile.txt`) | before | after |
|---|---|---|
| `invalid/bitcoin_height_contradicts_proof.atl` | `invalid`, exit 1, `bitcoin_claimed_height_contradicts_proof` | `untrusted`, exit 3, `receipt_unanchored` |
| `invalid/hostile_anchor_timestamp.atl` | `invalid`, exit 1, `tsa_token_unparsable` | `untrusted`, exit 3, `receipt_unanchored` |

In both, the anchor itself still reports `state: "refuted"` with the same
reason code it had before.

The `TrustAssessment` axes follow the same line: `evidence.established`,
`policy.satisfied` and `max_trust_profile` are gated on a refutation of the
**receipt**, not on `refuted_anchors`. While they were gated on both, a
stranger could take §5.6 and "trust established" away from a receipt holding
two verified anchors by appending a third that fails. `coverage.complete` is
unchanged and still `false` for a refuted anchor: coverage accounts for every
anchor presented, and that is where the finding belongs.

#### The four statuses are computed from `receipt_errors()`

`atl-core` 0.29 splits its error list into statements about the receipt and
findings about its anchors (`VerificationError::is_about_the_receipt`), and
`receipt_errors()` is the filter. `SingleVerificationResult::receipt_refutation`
reads that iterator rather than `errors()`, so the same forgery cannot arrive
by the other door — through an anchor finding `atl-core` reported at receipt
level. It is belt to the braces above: with `skip_anchors: true` no anchor
finding reaches that list today, and a guard that depends on an option
staying set is not a guard.

#### Receipt-level findings are classified three ways, and fail closed

`map_core_error` returned `Option<ReasonCode>`, which conflated "nothing was
disproved" with "nothing to report". `classify_core_error` returns
`Refutation` / `Inability` / `Deferred`, matches every `VerificationError`
variant by name with no wildcard, and routes the inabilities —
`metadata_not_canonicalizable`, `source_text_not_checked`, and a
`spec_version` this build has never implemented — to the new
`receipt_check_incomplete` (`untrusted`, exit 3). A wildcard's two possible
silent answers are "this evidence is disproved" and "nothing to see here";
both are wrong, and this is the third.

`NoTrustAnchor` stays `Deferred`: this crate answers the quorum question
itself, from the per-anchor verdicts and the caller's own policy. In 0.29 it
became `NoTrustAnchor { required, verified }` and the `AnchorFailed` aggregate
was removed; `From<VerificationError> for CliError` was updated accordingly,
and every anchor finding now converts to the generic `VerificationFailed`
rather than to `TsaVerificationFailed` / `OtsVerificationFailed`, neither of
which may be produced from a finding about an anchor.

#### Two new reason codes

* `receipt_check_incomplete` — a receipt-level check `atl-core` could not
  finish (see above). `untrusted`, exit 3.
* `anchor_type_unsupported` — the Cargo feature implementing that anchor type
  was compiled out, so nothing about the anchor was examined. `untrusted`,
  exit 3, state `unevaluable`. Unreachable in a released `atl-cli`, which
  always enables both of `atl-core`'s anchor features; it exists so a build
  that does not cannot report an unexamined anchor as unresolved for some
  other reason.

### Changed — receipts are parsed through `Receipt::from_json`

`load_receipt` used `serde_json::from_str`. RFC 8785 §3.1 forbids duplicate
property names, and that is a property of a byte stream: once JSON has been
parsed the duplicate is gone and no inspection recovers it. `serde_json` keeps
the last occurrence, so a receipt stating `root_hash` twice is a document two
conformant verifiers can reach opposite verdicts on, over identical bytes.

`Receipt::from_json` scans the text and refuses it, and it is the only parse
that records the check was made — a receipt without that record is one
`atl-core` declines to confirm, reporting `source_text_not_checked`. Such a
receipt is now rejected at load time with exit 2, the same as malformed JSON,
because it cannot be read as *a* receipt at all.

`from_json` also gates `spec_version`, so this crate's own gate is gone rather
than kept in step by hand: two parts of one system disagreeing about what they
accept is how "could not check" became "checked and false" the last time. The
message a caller sees is unchanged — the version this build implements is
still named, which `atl-core`'s own error does not do.

### Changed — `token_der` must carry the `base64:` prefix

This crate prepended `base64:` when a receipt's `token_der` omitted it, so a
bare base64 token verified here and nowhere else: `atl-core`'s decoder
requires the prefix, and so does every producer and every fixture. A verifier
that accepts a wider set of inputs than the library it verifies with is two
parts of one system disagreeing about what a receipt is — the same shape as
the `spec_version` gate above. The set accepted is now exactly `atl-core`'s,
and a bare token is `tsa_token_unparsable`.

No receipt in `test_data/` or `real-data/` is affected; every one of them
writes the prefix.


### Fixed — the receipt's claims about its own Bitcoin anchor were never checked

ATL v2.0 §5.5.2 lists five steps for a Bitcoin OpenTimestamps anchor. Step 5
reads:

> Verify that `bitcoin_block_height` and `bitcoin_block_time` match the
> proof.

Neither field appeared anywhere in this crate's production code. Both call
sites destructured `ReceiptAnchor::BitcoinOts` with `..` and dropped them. A
receipt could state block 900000 while carrying an OTS proof that attests to
932897, and nothing would notice: the tool printed the proof's block and left
the receipt's own assertion unread.

The two halves of step 5 are not symmetrical, and conflating them would
produce the exact defect this taxonomy exists to prevent.

**Height — refutable, offline included.** An OpenTimestamps Bitcoin
attestation encodes the height in its own bytes, so the comparison is pure
computation. An anchor whose stated height its own proof contradicts is now
`refuted`, reason `bitcoin_claimed_height_contradicts_proof`, in offline and
online runs alike, and before any block-explorer request is made. (The
*receipt* is `untrusted`, exit 3 — see the entry above on why an anchor
anybody could have appended does not disprove a document.)

A proof may carry several Bitcoin attestations, and the claim holds if it
matches **any** of them: §5.5.2 says "match the proof" and singles none out —
the word *attestation* does not appear in the specification at all. A first
version compared against the lowest, which would have refuted a receipt
naming a block genuinely present in its own proof, on a criterion nobody set.
The rule now lives once, in `atl_core::ots::attestation_for_claimed_height`,
and the attestation the receipt names is the one this run verifies against.

**Time — not refutable without a header.** No proof carries a block time. The
comparison is possible only against a header two or more configured sources
agree on, so:

| situation | `claimed_time_check` | outcome |
|---|---|---|
| corroborated header, times equal | `matches` | no effect |
| corroborated header, times differ | `contradicted` | the anchor is `refuted`, `bitcoin_claimed_time_contradicts_block`; the receipt is `untrusted`, exit 3 |
| no corroborated header (offline, failed lookup, single source, sources disagree) | `not_compared` | no effect — the anchor keeps the untrusted reason it already had |
| receipt's own string unparsable by this build | `unreadable` | `untrusted`, exit 3, `bitcoin_claimed_time_unreadable` |

Times are compared as **instants at nanosecond resolution**, using
`atl-core`'s parser rather than a second one kept here. A Bitcoin header
carries a whole-second time, so a receipt claiming `07:01:20.000000001`
names an instant the header does not contain, and the outcome is
`contradicted`. An explicit zero fraction (`.0`, `.000000000`) names the same
instant and matches. Precision finer than a nanosecond cannot be represented
exactly, so it is refused rather than truncated and arrives as `unreadable` —
truncating would put a different instant back into the `matches` branch.

A hostile timestamp is answered, not crashed on. `bitcoin_block_time` and an
anchor's `timestamp` are unvalidated strings from the receipt; a
`bitcoin_block_time` of `"\u{1F4A5}abc"` used to abort the process with
SIGABRT inside `atl-core`'s parser. Any such string is now `unreadable` —
exit 3, nothing refuted — and the property is pinned by an integration test
that rejects a signal-death as well as a panic.

**Two different instants may never be reported as equal.** A first version of
this check compared whole seconds only, so `07:01:20.000000001` against a
block stamped `07:01:20` came out `matches`, `valid`, exit 0 — the check
added to stop unverified claims being republished as verified was itself
republishing one.

An offline run does **not** refute a receipt whose block time is wrong, and
that is deliberate: the comparison did not happen, and an unperformed
comparison cannot fail. Equally, a timestamp string this build cannot parse
is a fact about the parser — ISO 8601 admits spellings it does not read — so
it is an inability, not a refutation. It still costs the anchor its
acceptance, because a required step did not happen. Times are compared as
instants, so `+00:00` and `Z` spellings of one moment match.

Where both a Merkle-root mismatch and a time contradiction hold, the anchor
is `refuted` either way and `bitcoin_merkle_root_mismatch` is reported as the
more informative cause; the time comparison's own result is still published.

### Changed — BREAKING

#### `claimed_block_height` is now `proof_block_height`, beside two new fields

The old name said that *something* claimed the height without saying what,
and the prose beside it attributed it to the receipt — which was simply
wrong, since the receipt's own `bitcoin_block_height` was read nowhere. Two
distinct assertions had one name between them, and the one an attacker could
move independently was invisible.

| field | whose claim | when emitted |
|---|---|---|
| `block_height` | established fact (header fetched and matched) | `verified: true` only |
| `proof_block_height` | the OTS proof's earliest Bitcoin attestation | `verified: false` only |
| `receipt_block_height` | the receipt's `bitcoin_block_height` | every `bitcoin_ots` anchor |
| `receipt_block_time` | the receipt's `bitcoin_block_time`, verbatim | every `bitcoin_ots` anchor |
| `claimed_time_check` | what became of that time | every `bitcoin_ots` anchor |
| `proof_block_heights` | every height the proof attests to | whenever any attestation was read |

`proof_block_height` is **absent** when no attestation matches the receipt's
claim: nothing was selected, and naming one — the lowest, say — would be
publishing a number the protocol never asked for. `proof_block_heights` is
the evidence for that refutation, and the reader needs it to check the
finding.

"every `bitcoin_ots` anchor" includes one rejected before its proof ever
decoded — a wrong `target`, a `target_hash` that does not pin to the receipt.
Those used to report `AnchorDetails::Unknown`, whose serialization drops
every Bitcoin field, so the receipt's claims were hidden precisely at the
damaged anchors where they are most worth seeing. Proof-derived fields
(`computed_root`, `operation_count`, `proof_block_heights`) are honestly
absent there rather than zeroed.

Scripts reading `claimed_block_height` must read `proof_block_height`, and
should consider whether they wanted `receipt_block_height` all along.

#### An unsupported `spec_version` is an error, not a refutation

The CLI's own gate admitted every `2.x`; `atl-core`'s admitted only `2.0.0`.
While the server emits `2.0.0` this was invisible, but a `2.0.1` receipt
would have passed the CLI's door and then been reported by the core verifier
as a **defective receipt** (`receipt_malformed`, exit 1) — "we do not
implement that revision" published as "your evidence is broken".

Both gates now ask one predicate, `atl_core::is_supported_spec_version`, and
it matches exactly. §4.2 defines `spec_version` and stops there: no
compatibility rule, no statement that a verifier must accept later revisions
within a major version. With nothing written down to rely on, accepting
`2.0.1` would assert a verification carried out under rules this build has
never seen. Such a receipt is refused as an unusable input — exit 2, the same
as an unreadable file — never exit 1.

Widening the accepted set is a specification change first; §4.2 has to state
the compatibility rule before an implementation can lean on one.

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
`anchor_status.presented: 0` in JSON, the Receipt-Lite note in the human
output, and the batch `summary.unanchored` bucket — but it is no longer a
status and no longer exit 0.

`--allow-single-anchor` does not restore the old behaviour and is not
intended to: it lowers the anchor quorum to one *verified* anchor, and no
quorum of one can be met by none. The remedy is an anchored receipt.

Consequences across the surface:

- `Status::Pending` is removed. Exactly one status (`valid`) exits 0.
- Batch: `summary.pending` → `summary.unanchored`; reason code
  `batch_items_pending` → `batch_items_untrusted`; an unanchored item's own
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
anchor suffices. It never counts a refuted anchor towards that one — a
refuted anchor is no more verified than an unresolved one — never accepts a
receipt with no anchors, and never hides either kind. When it is what
produced the acceptance, `assessment.coverage.accepted_with_gaps` is `true`
and the human status line reads `VALID under policy 'single-anchor' (1 of 2
anchors verified; 1 unresolved, 0 REFUTED)` — never a bare `VALID`.

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

**A refutation of the receipt poisons every axis, from any cause.** Whenever
the receipt is refuted, `evidence.established`, `policy.satisfied`,
`coverage.complete` and `max_trust_profile` are all `false`. No field beside
a `status: "invalid"` verdict may report achieved trust. A refuted *anchor*
clears only `coverage.complete`, and is listed in `coverage.refuted[]` rather
than counted as settled — see the entry at the top of this release for why an
anchor anybody could have appended may not move a trust-bearing axis.

Two shapes of the same defect were closed. First, a receipt with two verified
anchors and a third refuted one printed `max_trust_profile: true` and
"Receipt-Full profile … ATTAINED" beside `status: "invalid"`. (That receipt
is no longer `invalid` at all, but the pairing was the defect and the fix
stands: the axes and the verdict may not contradict each other.) Second — and
worse, because the machine contract has no accident to save it — the axes
were tallied from `anchor_results` alone while `verdict()` also declares
`invalid` for reasons that never touch an anchor: a mismatched source file, a
broken inclusion proof, a broken Super-Tree proof. Verifying the wrong file
against a receipt with a trusted TSA anchor reported
`evidence.established: true`, `policy.satisfied: true` and
`coverage.complete: true` next to `reason_code: "file_hash_mismatch"`. The
human renderer hid it only by returning early on a hash mismatch, which was
a coincidence rather than a defence.

`evidence.refuted_by` was added: what was refuted — the receipt's own
refutation first, then the first refuted anchor. It is what makes
`established: false` beside `verified_anchors: 1` legible rather than
contradictory. (The anchor fallback was removed later in this same release —
see "the reason the tool gives was a relay's to choose" above; the field now
reports a refutation of the receipt and nothing else.) The human §5.6 line now answers `YES` / `NO`
(`NO — this receipt was refuted`) rather than with the attainment wording, so
no form of that word can appear beside a refuted receipt.

`assessment.policy.max_trust_profile` reports §5.6 independently of the
acceptance threshold. An accepted Receipt-TSA is `valid` with
`max_trust_profile: false`. (`assessment` was omitted for a receipt with no
anchors at the time; it is now always present — see above for why its
presence may not depend on the `anchors` array.)

Batch output gains `policy_profile` at the top level and an `assessment`
object per verified item.

#### Per-anchor `state`

Each anchor result carries a `state` alongside `verified` and `reason_code`,
uniform across anchor types: `verified`, `cryptographically_consistent`,
`incomplete`, `not_checked`, `unavailable`, `uncorroborated`, `contested`,
`unevaluable`, `refuted`, `unresolved`. This
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
anchor's own reason code is the verdict's reason code. (Later in this same
release the top-level reason stopped being an anchor's code at all, so the
condition is unreachable and the detail is the bare reason code; the guard
stays as the rule.)

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
| two or more, agreeing | compared → the anchor is `verified`, or `refuted` on a mismatch | 0 / 3 |
| two or more, disagreeing | `untrusted` / `bitcoin_providers_disagree` | 3 |
| exactly one | `untrusted` / `bitcoin_single_source_only` | 3 |
| none | `untrusted` / `bitcoin_block_unavailable` | 3 |

Only a corroborated header can refute. **A mismatch from a single
uncorroborated endpoint is not a refutation**: if one source is not enough to
accept evidence it is not enough to accuse it either, and the alternative
lets one API publish `state: "refuted"` against a sound anchor. A provider disagreement is
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
