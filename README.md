# atl-cli

Command-line verification tool for ATL Protocol v2.0.

## Documentation

Full documentation is available at:

**https://atl-protocol.org/implementations/atl-cli**

## Breaking change: an unanchored receipt is no longer a success

**A receipt carrying no anchors (Receipt-Lite) now exits 3, not 0.** Its
status is `untrusted` and its reason code is `receipt_unanchored`.

ATL v2.0 §5.5 leaves no room:

> At least one anchor MUST be verified to establish trust in the receipt.
> […] A receipt without any **verified anchors** SHOULD be treated as
> untrustworthy.

A Receipt-Lite has no anchors, so it has zero verified anchors, so it is
precisely the case §5.5 names. This tool used to report it as `pending` and
exit 0 — accepting, under a softer word, exactly what the specification says
to treat as untrustworthy. A CI job asking `if atl-cli verify …` was told yes
about a receipt with no external attestation of any kind.

Nothing about such a receipt is *refuted*: its Merkle proofs may be entirely
sound, and the output still says so (`verification.proofs_valid` can be
`true` alongside `status: "untrusted"`). What is missing is any independent
evidence that the entry existed at a point in time — which is the whole claim
an ATL receipt exists to make.

"Pending" survives as a *description* of the state, not as a verdict: the
JSON keeps `anchor_status: "unanchored"`, the human output still explains the
Receipt-Lite tier, and the batch summary counts such items in their own
`unanchored` bucket. What it no longer is, is exit 0.

**If your pipeline depended on exit 0 here, the remedy is an anchored receipt
(Receipt-TSA or Receipt-Full), not a flag.** `--allow-single-anchor` does not
help: it lowers the quorum to one *verified* anchor, and no quorum of one can
be met by none.

## Verification outcomes

`atl-cli verify` reports one of four statuses. They are also the JSON
`status` field, and each maps to a fixed exit code so scripts never have to
parse the output:

| status | exit | meaning |
|---|---|---|
| `valid` | 0 | Every checkable fact holds and the anchor policy in force is satisfied. |
| `untrusted` | 3 | Nothing was refuted; the check could not be finished, or the receipt has no anchors at all. Material may be missing on this side (a trust root, an issuer certificate, network access for a Bitcoin anchor, a receipt that never paired with its source file), a fact may have been impossible to evaluate, or ATL v2.0 §5.5's floor may simply be unmet — see `reason_code`. |
| `invalid` | 1 | The evidence was refuted: some checkable fact is false. |
| `error` | 2 | The tool could not process an input (file not found, unparsable receipt, unreadable trust material). Says nothing about the evidence. Batch mode only — single-file mode exits before a status exists. |

Exactly one status exits 0. A caller who writes `if atl-cli verify …` is
asking "was this evidence accepted", and only `valid` answers yes.

`untrusted` and `invalid` are deliberately distinct. Telling a holder of
sound evidence that it is broken, when the real problem is an unconfigured
verifier, is a different and worse failure than either outcome on its own.

Note that `untrusted` does **not** always mean "bring me a certificate".
Four reason codes say the check could not be *performed* at all:
`cms_signature_indeterminate` (the token's own CMS signature uses an
algorithm this verifier does not implement — P-521 and RSA-PSS are the
concrete cases), `tsa_imprint_indeterminate` (the token's `messageImprint`
names a hash algorithm it does not implement, so it was never compared with
the receipt's root), and `tsa_chain_indeterminate` (the certificate path
could not be evaluated — most often because a certificate on it is signed
with cryptography `atl-core` does not implement), and
`tsa_timestamping_eku_not_checked` (no signer certificate could be
established, so its EKU was never examined). SHA-1-self-signed roots are the common case, and they are not
exotic: 31 of the 156 roots in macOS's system store sign themselves with
SHA-1, DigiCert Assured ID Root CA among them. Supplying more intermediates
will not help there; naming the terminal certificate with
`--tsa-trust-store` will, because a trust anchor is an external input whose
own signature is beside the point (RFC 5280 §6.1). The anchor's `error` text
names the actual cause in every case.

Alongside `status`, every non-`valid` result carries a stable machine-readable
`reason_code` (`snake_case`, safe to branch on):

- `file_hash_mismatch`, `inclusion_proof_invalid`,
  `super_inclusion_proof_invalid`, `super_consistency_proof_invalid`,
  `checkpoint_root_hash_mismatch`, `checkpoint_tree_size_mismatch`,
  `checkpoint_signature_invalid`, `metadata_hash_mismatch`,
  `receipt_malformed`, `receipt_verification_failed`
- `anchor_target_invalid`, `anchor_hash_malformed`,
  `anchor_target_hash_mismatch`, `tsa_token_unparsable`,
  `tsa_imprint_mismatch`, `cms_signature_invalid`,
  `tsa_timestamping_eku_invalid`, `tsa_imprint_malformed`,
  `tsa_chain_invalid_at_gen_time`,
  `super_proof_missing`, `bitcoin_ots_proof_invalid`,
  `bitcoin_merkle_root_mismatch`
- `tsa_root_not_trusted`, `tsa_chain_incomplete`, `tsa_chain_indeterminate`,
  `cms_signature_indeterminate`, `tsa_imprint_indeterminate`,
  `tsa_timestamping_eku_not_checked`, `bitcoin_block_not_checked`,
  `bitcoin_block_unavailable`, `bitcoin_providers_disagree`,
  `bitcoin_single_source_only` (the `untrusted` reasons)
- `receipt_unanchored` (no anchors at all — §5.5's floor unmet),
  `batch_items_invalid`, `batch_items_errored`, `batch_items_unanchored`,
  `batch_items_untrusted`, `batch_items_unmatched`,
  `batch_nothing_verified`, `log_consistency_failed`

## Three axes, reported separately

One verdict word cannot carry three different questions, so the JSON
`assessment` object (and the human-readable **Trust Assessment** block)
publishes them apart. They disagree often, and the disagreement is the
information:

| axis | question | JSON |
|---|---|---|
| **evidence** | Is trust established at all? ATL v2.0 §5.5: at least one anchor verified, and nothing refuted. | `assessment.evidence.established`, with `verified_anchors` / `refuted_anchors` / `total_anchors` / `refuted_by` |
| **policy** | Is the anchor quorum you asked for met? | `assessment.policy.profile` / `.satisfied` |
| **coverage** | Was every anchor the receipt presents carried to a sound result? | `assessment.coverage.complete`, with `unresolved[]` and `refuted[]` |

A Receipt-Full verified offline is the case that motivates the split:
evidence **established** (its TSA anchor reached a root you supplied),
policy **unsatisfied** (the default requires every anchor), coverage
**incomplete** (the Bitcoin block was never fetched). Collapsed into one
word, two of those three answers were lost.

`assessment.policy.max_trust_profile` reports ATL v2.0 §5.6 separately again:
`true` only when both an RFC 3161 and a Bitcoin OTS anchor are verified and
nothing was refuted. It is reported on every run whatever the profile,
because §5.6 describes the maximum-trust *tier* rather than this tool's
acceptance threshold — an accepted Receipt-TSA is `valid` with
`max_trust_profile: false`.

`assessment` is absent for a receipt with no anchors: there is no quorum to
report on, and `receipt_unanchored` already says everything there is to say.

### A refutation poisons every axis

**No field beside a `status: "invalid"` verdict may report achieved trust.**
Whenever anything is refuted, `evidence.established`, `policy.satisfied`,
`coverage.complete` and `policy.max_trust_profile` are all `false`, and the
human §5.6 line reads `NO — this receipt was refuted`.

This holds for **every** cause of `invalid`, not only an anchor-level one.
The axes agree with the verdict, and a verdict of `invalid` has causes that
never touch an anchor: a source file whose hash does not match the receipt, a
broken inclusion proof, a broken Super-Tree proof. Tallied from the anchors
alone, verifying the wrong source file against a receipt with a perfectly
trusted TSA anchor produced:

```
status: invalid | reason_code: file_hash_mismatch
evidence.established: true      policy.satisfied: true      coverage.complete: true
```

— the trust block announcing that trust was established in a file the same
run had just shown to be the wrong one.

The counts stay honest. `verified_anchors` may well be non-zero beside
`established: false`, because the counts describe anchors while the booleans
describe the receipt. `evidence.refuted_by` names the reason code that
disqualifies it — always equal to the top-level `reason_code` — so the pair
reads as a refutation outranking a sound anchor rather than as a
contradiction.

Refuted anchors are **listed**, not merely counted, in `coverage.refuted[]`,
kept apart from `coverage.unresolved[]` because the two call for opposite
reactions: an unresolved anchor may be fixable by supplying trust material or
going online, and a refuted one never is.

### Anchor states

Each anchor also carries a `state`, uniform across anchor types and finer
than the pass/fail its `verified` boolean can express:

| state | meaning | can you fix it? |
|---|---|---|
| `verified` | Cryptographic facts checked **and** a trust root you supplied was reached. | — |
| `cryptographically_consistent` | Every checkable fact holds; the chain terminates in a certificate no trust store names. | Yes — `--tsa-trust-store` |
| `incomplete` | Path construction ran out of certificates before any terminal. | Yes — `--tsa-intermediates` |
| `not_checked` | The selected mode does not perform this check (an offline run does not fetch the block header). | Yes — re-run online |
| `unavailable` | The check was attempted and did not complete (no block-explorer API answered). | Maybe — retry |
| `uncorroborated` | Only one block-explorer API answered, so its report is unconfirmed. | Maybe — retry |
| `contested` | The block-explorer APIs contradicted each other. Not a finding about the receipt. | No — investigate the sources |
| `unevaluable` | This build cannot perform the check at all (an algorithm it does not implement). | No |
| `refuted` | A checkable fact is false. | No — the evidence is broken |

### "Verified anchor" means one thing

Throughout this tool, an anchor is **verified** only when its cryptographic
facts were checked **and** its certificate path reached a trust anchor from
the store *you* supplied. Both halves are required, and only this state
counts towards §5.5.

A token whose CMS signature and certificate chain are flawless but whose
terminal certificate nobody vouches for proves that *some key* signed it —
which key, and whether anyone should care, is exactly what was not
established. That state is `cryptographically_consistent`, and it is never
counted as a verified anchor anywhere.

**A gap in the specification.** §5.5's five steps for an RFC 3161 anchor say
"verify the cryptographic signature of the Time Stamping Authority" and stop.
They never mention constructing a certificate path, nor where a verifier
obtains the trust anchors that path must reach. Read literally, a self-signed
certificate an attacker generated satisfies step 4. This implementation is
deliberately stricter than the text, and the gap is recorded here rather than
buried in a code comment: the specification is what needs amending.

## The anchor policy, and `--allow-single-anchor`

By default **every anchor a receipt presents must be verified**. The profile
is called `all-anchors`, and note exactly what it is a rule about: the
anchors *this receipt offers*. A Receipt-TSA satisfies it with its single TSA
anchor and no Bitcoin anchor anywhere.

It is therefore **not** ATL v2.0 §5.6, which is about requiring both anchor
*types*. §5.6 is reported separately as `assessment.policy.max_trust_profile`
and is never this profile's test — describing the default as "§5.6 maximum
trust" claimed two different requirements at once, only one of which is
enforced.

Why it is strict all the same: a receipt that offers a Bitcoin anchor and
then cannot have it confirmed did not deliver what it offered, and this is a
*reference* verifier whose default will become the de-facto norm.

A consequence worth naming rather than hiding: **a Receipt-Full verified
offline comes out worse than a Receipt-TSA with the same trusted root**,
because the Receipt-TSA never claimed a Bitcoin anchor in the first place.
That is an honest report about a promise not kept — not an unfairness to be
smoothed away by accepting less.

`--allow-single-anchor` lowers the quorum to the §5.5 floor: one verified
anchor is enough. The eight combinations, all with the same TSA root
supplied:

| receipt | mode | flag | exit | status | why |
|---|---|---|---|---|---|
| Receipt-TSA | offline | — | 0 | `valid` | its one anchor is verified; nothing is outstanding |
| Receipt-TSA | offline | `--allow-single-anchor` | 0 | `valid` | same; the quorum was already met |
| Receipt-TSA | online | — | 0 | `valid` | no Bitcoin anchor, so no network step exists (`mode: "offline"`) |
| Receipt-TSA | online | `--allow-single-anchor` | 0 | `valid` | same |
| Receipt-Full | offline | — | 3 | `untrusted` | `bitcoin_block_not_checked`: an anchor it presented was never resolved |
| Receipt-Full | offline | `--allow-single-anchor` | 0 | `valid` | one verified anchor meets the floor — reported **with** the gap |
| Receipt-Full | online | — | 0 | `valid` | both anchors verified; `max_trust_profile: true` (§5.6) |
| Receipt-Full | online | `--allow-single-anchor` | 0 | `valid` | same; the flag changed nothing |

What the flag does **not** do:

- It never rescues a refuted anchor. One disproved fact is `invalid` (exit 1)
  under every policy, whatever the other anchors say — and every trust axis
  reports `false` beside it, as above.
- It never accepts a receipt with no anchors: a quorum of one cannot be met
  by none.
- It never hides anything. Coverage still reports every unresolved anchor
  with its state and reason, `assessment.coverage.accepted_with_gaps` is
  `true`, and the human status line reads `VALID under policy
  'single-anchor' (1 of 2 anchors verified; 1 unresolved)` — never a bare
  `VALID`.

## Output changes in 0.9

The JSON gained an `assessment` object (see *Three axes*) and a per-anchor
`state` (see *Anchor states*). Three names changed in the batch report,
following the §5.5 change above:

| was | is now |
|---|---|
| `summary.pending` | `summary.unanchored` |
| `reason_code: "batch_items_pending"` | `reason_code: "batch_items_unanchored"` |
| item `status: "pending"` | item `status: "untrusted"`, `reason_code: "receipt_unanchored"` |

The RFC 3161-only `trust_state` field is unchanged and still emitted; prefer
the new `state`, which is uniform across anchor types and finer-grained.

Four fields in the per-anchor JSON changed shape. The first two were
booleans forcing "could not check" to be reported as "checked and false"; the
third withholds a time nobody established; the fourth adds a fact that was
previously implied and untrue:

| was | is now |
|---|---|
| `imprint_matches_root: true \| false` | `message_imprint: "verified" \| "mismatch" \| "malformed" \| "indeterminate"` |
| `cms_signature_valid: true \| false` | `cms_signature: "verified" \| "refuted" \| "indeterminate"` |
| `timestamp` / `timestamp_nanos` on every anchor | emitted **only** when `verified` is `true`; otherwise `claimed_timestamp` / `claimed_timestamp_nanos` |
| `terminal_anchor.kind: "assumed"` | same, plus `terminal_anchor.self_signature: "verified" \| "unverifiable"` |

The batch `consistency` object changed too. `cross_checks[].included` is now
`cross_checks[].same_log_instance` — the name ATL v2.0 §5.4.3 uses, and the
one `atl-core` already gives the field it comes from — and a `log_instances`
count was added. The old name said that one receipt's Super-Tree had been
shown to contain the other's; nothing checks that, and §5.4.2 proves only
that the genesis state is a prefix of each receipt's *own* current state.
What the check establishes is §5.4.3's own conclusion: both receipts carry
the same `genesis_super_root` and valid `consistency_to_origin` proofs, so
the log history between them was not modified. `status` gained
`"not_checked"` for a run where no two participants shared a log instance,
so no comparison existed to pass or fail.

`path_status` gained the value `"indeterminate"`, and a new
`timestamping_eku` field reports *which* RFC 3161 §2.3 condition the EKU
check landed on (`"ok"`, `"absent"`, `"malformed"`, `"not_critical"`,
`"not_exclusive"`, `"not_checked"`) alongside the unchanged
`timestamping_eku_ok` boolean.

Scripts branching on `status` and `reason_code` are unaffected apart from the
new `untrusted` reason codes listed above.

The same rule now governs the Bitcoin anchor's numbers: a plain name is
reserved for a fact this run established **about this receipt**.

| when | height | time |
|---|---|---|
| verified (block fetched, Merkle root matched) | `block_height` | `block_timestamp` |
| no block fetched (offline) | `proof_block_height` | *absent* |
| header corroborated, Merkle root **did not** match | `proof_block_height` | `reported_block_timestamp` |
| the receipt's claimed height matches no attestation | *absent* — see `proof_block_heights` | *absent* |

Beside these, and emitted for **every** `bitcoin_ots` anchor whatever the
outcome, are the receipt's own two assertions: `receipt_block_height` and
`receipt_block_time`. See "The receipt's own claims about its Bitcoin anchor"
below for why they are separate fields.

The two un-established names differ because they are different kinds of
not-established. The height is what the *OTS proof* attests to — hence
`proof_`. The time in the third row is what named sources *reported*; calling
it "claimed" would be a falsehood, since nobody claimed it, we asked and were
told. Nor "observed" — that was an earlier name and overstated it in the
other direction, since this tool reads HTTP APIs rather than watching the
chain.

That third row is the sharp case. The online path fetches the block **before**
deciding whether its Merkle root matches, so a receipt refuted by
`bitcoin_merkle_root_mismatch` used to publish a genuinely reported block
time under the plain `block_timestamp` — a date offered for evidence the same
object refutes, sitting next to `merkle_match: false`. "Named sources
reported this block" and "this block dates your evidence" are the distinction
the whole tool turns on.
Human output reads `Block #932898 @ 2026-01-19T07:22:22Z (as reported by the
sources below; this block does NOT date this receipt)`.

Earlier, the block time was a `0` sentinel rendered as
`"1970-01-01T00:00:00Z"` — a parsable, real-looking timestamp published for a
check that never ran. The underlying field is an `Option`, so that stub no
longer exists to be rendered.

Three neighbouring fields deliberately keep their plain names even on a
refuted anchor: `computed_root` (a deterministic local computation over the
receipt's own bytes, named for exactly that), `block_merkle_root` (a property
of the *block*, emitted only when one was fetched and never without
`merkle_match` beside it) and `merkle_match` (whose `false` **is** the
refutation). Each is either a local computation or the evidence *of* the
mismatch; renaming them would hide the fields a reader needs in order to see
what went wrong.

The timestamp split deserves a word, because it is the field most likely to
be read straight out and acted on. This tool sells proof of *when* something
existed, so emitting the token's own unchecked `genTime` under the name
`timestamp` for an anchor that established nothing was the sharpest possible
version of reporting an unverified fact as verified. The key is now **absent**
rather than annotated for a non-accepted anchor: a script reading `timestamp`
gets nothing and fails loudly, instead of silently trusting a number nobody
established. The claim itself is still available as `claimed_timestamp` —
useful for diagnostics and for saying what was claimed, never admissible as
when something existed. Human output labels it `Claimed genTime (not
established)`.

## The receipt's own claims about its Bitcoin anchor

ATL v2.0 §5.5.2 step 5 requires a verifier to "verify that
`bitcoin_block_height` and `bitcoin_block_time` match the proof". Until
this release neither field was read anywhere in the tool: a receipt could
announce block 900000 while carrying an OTS proof that attests to 932897, and
the output printed the proof's block without ever mentioning the
disagreement. A claim the receipt makes about its own evidence went
unexamined.

The two halves of step 5 are not symmetrical, and the tool now says which is
which.

**The height is checkable offline.** An OpenTimestamps Bitcoin attestation
carries the block height in its own bytes, so comparing it with the receipt's
`bitcoin_block_height` is pure computation. A disagreement is therefore a
fact that was checked and is false: `status: "invalid"`, exit 1, reason code
`bitcoin_claimed_height_contradicts_proof` — with or without network access.
The two numbers are published side by side as `receipt_block_height` and
`proof_block_height`, so the finding can be audited rather than taken on
trust.

A proof may carry several Bitcoin attestations, and the claim holds if it
matches **any** of them — §5.5.2 says "match the proof" and singles none out.
`proof_block_heights` publishes the whole attested set, which is what makes a
refutation auditable; `proof_block_height` names the attestation this run
verified against, and is absent when none matched.

**The time is not.** No OTS proof carries a block time; it exists only in the
block header, which means the comparison is possible only after two or more
configured sources have agreed on one. A new field, `claimed_time_check`,
reports what happened:

| value | meaning | effect |
|---|---|---|
| `matches` | compared with a corroborated header, and equal | none |
| `contradicted` | compared, and different | `invalid`, exit 1, `bitcoin_claimed_time_contradicts_block` |
| `not_compared` | no corroborated header was obtained (offline, lookup failed, one source only, or sources disagreed) | none — the anchor stays untrusted for the reason it already was |
| `unreadable` | this build could not parse the receipt's own timestamp string | `untrusted`, exit 3, `bitcoin_claimed_time_unreadable` |

`not_compared` is the row that matters. Offline the comparison does not
happen, and an unperformed comparison cannot fail: a receipt whose stated
block time is nonsense is **not** refuted by an offline run, because nothing
about it was checked. Saying otherwise would report "we could not check" as
"we checked and it failed", which is the one thing this tool must never do.

`unreadable` is the mirror-image caution. RFC 3339 admits spellings this
build does not parse, so a string it cannot read is evidence about the
parser, not about the receipt — never a refutation. It does still cost the
anchor its acceptance, because a step the specification requires did not
happen.

Comparison is between **instants at nanosecond resolution**, not strings, so
`2026-01-19T07:01:20+00:00` and `2026-01-19T07:01:20Z` are a match. A Bitcoin
header carries a whole-second time, so a receipt claiming
`07:01:20.000000001` names an instant the header does not contain and is
`contradicted`; an explicit `.000000000` names the same instant and matches;
and precision finer than a nanosecond is refused rather than truncated,
arriving as `unreadable`. Truncating it would report two different instants
as one.

Human output prints both claims under `Receipt states:`, saying in each case
whether the claim agreed, was contradicted, or was not compared at all.

## Batch mode says the same thing single-file mode does

The same input must mean the same thing however you invoke the tool. Batch
mode aggregates per-item outcomes; it never re-labels them on the way into
the summary.

| per-item outcome | batch summary bucket | batch status | exit |
|---|---|---|---|
| accepted | `valid` | `valid` (only if *every* item is) | 0 |
| unanchored (Receipt-Lite) | `unanchored` | `untrusted` | 3 |
| not refuted, check unfinished | `untrusted` | `untrusted` | 3 |
| never paired with a counterpart | `unmatched` | `untrusted` | 3 |
| could not be read or parsed | `errors` | `error` | 2 |
| refuted | `invalid` | `invalid` | 1 |

Two consequences worth stating, because both were once wrong:

- **A receipt that will not parse exits 2, not 1.** The tool failed to read
  an input; it never got far enough to say anything about the evidence.
  Reporting 1 there told a retry system that a substantive refutation had
  occurred — and only when the tool was invoked on a directory.
- **A batch containing an unanchored receipt is `untrusted`, exit 3.** Not
  `valid`, and no longer the old exit-0 `pending`: ATL v2.0 §5.5 again. The
  `unanchored` summary bucket is kept separate from `untrusted` only so the
  report can say which kind it is — no trust material a caller could supply
  would change it — but both are the same status word and the same exit code,
  matching single-file mode exactly.

Refutations are reported ahead of anything that merely could not be done, so
a neighbouring file that failed to open never conceals a receipt that was
checked and refuted. That ordering holds for the run as a whole and not only
for the item buckets: if the verification mode cannot be settled — `--online`
with no connectivity, say — the summary is still printed and the exit code
still comes from the verdict, because the offline checks had already
finished. It never turns into a success: a run whose requested check was not
completed exits non-zero even when nothing was refuted.

## Receipts from several log instances are reported, not refuted

Point batch mode at a directory holding receipts from two different ATL log
instances and it applies ATL v2.0 §5.4.3 within each one, reports
`consistency.log_instances`, and leaves the verdict to the receipts
themselves.

It used to exit 1 — `invalid`, *the evidence was disproved*. The reference
log was whichever receipt the directory walk yielded first, which made the
tool invent a log identity out of filesystem ordering. §3.3.2 says
`genesis_super_root` "serves as the immutable identifier for the log
instance", so that identity is a fact the receipt states about itself; and
§5.4.3 defines what to conclude when two identifiers agree while defining no
error for the case where they differ. Nothing about either receipt is false,
and a *tampered* genesis is caught per receipt as a broken §5.4.2 proof long
before any comparison runs.

What the comparison establishes is narrower than it sounds, and the output
now says so. §5.4.3 concludes that "the log history between them was not
modified", and that is the claim — no stronger. It is not a defence against
a Split-View (fork) attack: §7.3.2 names a verified external anchor as the
primary defence and scopes consistency proofs to within a single tree.

## Batch mode: unmatched files count

Batch mode pairs a source file `X` with a receipt `X.atl`. Files that do not
pair up are reported as `unmatched` — and they **block acceptance**. A batch
is `valid` only when every path you named was verified and accepted.

This is worth stating explicitly because the alternative is so much worse
than it looks. Point the tool at directories whose naming has drifted from
the convention and *every* file lands in `unmatched`: nothing is verified at
all. Reporting `valid` and exit 0 there would hand a CI job a green tick for
work that was never done. Zero files verified is never a success, and
`status: "valid"` with `summary.valid == 0` cannot occur.

Nothing about an unmatched file is *refuted* — it was never examined — so the
status is `untrusted` (exit 3) with reason `batch_items_unmatched`, and the
remedy is a naming fix, not trust material.

## Trust material

This tool ships **no** TSA roots, fingerprints, or operator keys. ATL is a
public protocol and Evidentum is one operator among others; baking any
identity into the reference verifier would make the protocol somebody's
brand. All trust material is supplied from outside:

- `--tsa-trust-store <path>` — certificates you have decided, through some
  external trusted channel, to treat as **trust anchors**. A chain that
  reaches one of them terminates successfully.
- `--tsa-intermediates <path>` — certificates used only to **bridge a gap**
  in a token's own certificate set. They confer no trust: a chain walking
  through one must still reach an anchor.

Both accept a PEM file (one or more concatenated certificates), a single DER
certificate, or a directory of either.

Keeping the roles apart matters. Some TSAs (Sectigo, DigiCert) issue tokens
whose topmost certificate is cross-signed by a legacy root the token does not
include; such a chain reports `untrusted` / `tsa_chain_incomplete`. Passing
the missing issuer to `--tsa-intermediates` completes it. Passing it to
`--tsa-trust-store` would *also* complete it, but by silently moving your
trust boundary out to a certificate you never chose to trust.

One asymmetry follows from RFC 5280 §6.1 and is worth knowing about: an
**intermediate or root** named by `--tsa-trust-store` is an *input* to path
validation, so its own signature, validity window and CA fields are not
re-examined — you said you trust it. The same certificate passed to
`--tsa-intermediates` is just another link on the path and is checked like
any other. A SHA-1 self-signed root therefore resolves a chain as an anchor
and yields `tsa_chain_indeterminate` as an intermediate. That is not a bug in
either direction: the difference is exactly the difference between what you
declared and what the token supplied.

**The signer certificate is the one exception.** Pinning it is allowed, but
it buys no exemption: its validity at `genTime`, its critical extensions and
its `KeyUsage` are checked first, and a signer that fails them is refuted
however you named it. A timestamp's entire claim is temporal, so reporting a
chain as sound at `genTime` for a signer that had already expired then would
assert something nobody checked.

## What "the Bitcoin anchor was checked" actually means

**This tool does not observe the Bitcoin network.** It queries public
block-explorer HTTP APIs — blockstream.info, mempool.space, blockchain.info —
and reads a block header out of their JSON. It validates no proof of work,
follows no chain of headers and contacts no peer. It has no way, on its own,
to know that what an endpoint returned is what Bitcoin contains.

Two things follow, and both are now enforced rather than assumed.

**The wording says so.** Nothing is described as observed on-chain or
confirmed against the blockchain, because none of that happens. The output
names the sources: `Reported by: blockstream.info, mempool.space (2
sources)`, and the JSON carries `block_sources` with each endpoint's name and
what it reported. The JSON field for an unverified anchor's block time is
`reported_block_timestamp` — it was `observed_block_timestamp`, which went
too far in the same direction.

**A single source decides nothing.** Every provider is queried, concurrently,
on every lookup not already served by the in-process cache, and a block
header is usable only when **two or more separately operated providers
report the same one**. Previously the first answer won outright, so one wrong or
compromised endpoint could make an anchor `verified`.

What is compared between providers: the **block hash**, the **Merkle root**
and the **block time**. All three are header fields, so two correct providers
describing the same block cannot differ on any of them, and all three are
published downstream — a disagreement on any one would mean publishing a
value this tool's own sources contradict. Agreement means **unanimity among
those who answered**, not a majority: a majority rule would let two wrong
endpoints outvote a correct one and, worse, would hide the disagreement.

The **height** is not part of that comparison, because it is checked
separately and against a stronger reference: each provider's reported height
is matched to the height that was *requested* (see below). It was once
described here as "identical by construction" — which was the false
assumption that the height check exists to remove.

| sources | outcome | exit | why |
|---|---|---|---|
| two or more, agreeing | compared: `valid`, or `invalid` on a Merkle-root mismatch | 0 / 1 | the header is corroborated |
| two or more, disagreeing | `untrusted` / `bitcoin_providers_disagree` | 3 | no established header exists to compare against |
| exactly one | `untrusted` / `bitcoin_single_source_only` | 3 | one endpoint's word settles nothing |
| none | `untrusted` / `bitcoin_block_unavailable` | 3 | nothing to compare against |

Only the first row can produce a refutation, and that is deliberate. **A
mismatch reported by a single uncorroborated endpoint is not a refutation.**
If one source is not enough to accept evidence, it is not enough to accuse it
either — otherwise a wrong or compromised API could turn sound evidence into
`invalid`, which is the worst failure this tool has.

**A provider disagreement is never a finding about your receipt.** It is a
conflict among the sources — a chain fork, a stale index, a compromised
endpoint — and it is reported as such, in full: every conflicting report is
listed under `SOURCES DISAGREE` in the human output and in `block_sources` in
the JSON, alongside the words *nothing about this receipt is refuted by this*.

**Every response is bound to the block that was asked about.** The height a
provider reports is checked against the height that was requested, and in a
two-step lookup the detail response's block id is checked against the hash
the first step returned — otherwise a well-formed answer about some other
block is accepted as an answer about this one.

**Block times are validated on arrival, and the check fails closed.** A value
earlier than Bitcoin's genesis block (2009-01-03) or more than two hours in
the future — Bitcoin's own consensus limit — is not a block time, and such a
response is discarded at intake rather than published. If the system clock
cannot be read, the upper bound cannot be evaluated and the value is
**rejected**, not admitted.

That validation closes the other half of the `0` → `"1970-01-01T00:00:00Z"`
problem: the tool's own sentinel was removed earlier, and a zero handed to us
by an API would have rendered exactly the same way.

**Only corroborated headers are cached, and only for ten minutes** — one
expected Bitcoin block interval. The other three outcomes are transient
conditions of the network and are retried in full rather than remembered, so
one timeout cannot become a permanent answer for that height.

The TTL is there because batch mode walks a whole directory in a single
process, item by item, with no bound on how long that takes. Without it, the
second receipt anchored at a given height would be answered from a
corroboration obtained at the start of the run — and "at the moment of the
query" would quietly have meant "at the moment of the *first* query of this
run". The TTL does not make a cached header fresh and prevents no
reorganisation; it bounds how stale the answer can be, which without it grew
with the size of the batch.

### What corroboration does not establish

Said plainly, because the code does not check it and an earlier version of
this section called a corroborated header "a stable fact":

- **Confirmation depth is not checked.** A header one block deep and one
  thousand blocks deep are treated identically, and a shallow block can be
  orphaned.
- **Chain reorganisation is not tracked.** Nothing re-asks the sources
  whether they still report the same header.
- **The sources are not shown to be independent of each other.** They are
  separately operated endpoints and nothing more is established: shared
  hosting, a shared upstream index or a common failure are not ruled out.
  This is why nothing above says "two independent sources" — earlier versions
  of this section and of the code did, in the same breath as this caveat, and
  a reader would have been entitled to conclude that collusion or a common
  outage was ruled out. It is not.

None of this is a property of the cache. A completely fresh lookup
establishes the same thing and no more: that at the moment of the query — or
of a query for that height made within the last ten minutes of the same run —
two or more of the configured block-explorer APIs reported the same header. That is a real and
useful statement — it is simply not a statement about what Bitcoin will still
contain tomorrow.

## Network use

Only `bitcoin_ots` anchors need the network, and only to ask block-explorer
APIs for the header whose Merkle root the OpenTimestamps proof is compared
against — not to observe the chain; see the section above. RFC 3161
verification — token
decoding, CMS signature, certificate chain, validity at `genTime` — is pure
computation. A receipt with no Bitcoin anchor is therefore verified without
any network access at all, and reports `mode: "offline"` even under
`--online`: there is nothing online to do, and saying otherwise would be an
overclaim.

## License

Apache-2.0
