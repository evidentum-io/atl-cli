# atl-cli

Command-line verification tool for ATL Protocol v2.0.

## Documentation

Full documentation is available at:

**https://atl-protocol.org/implementations/atl-cli**

## Verification outcomes

`atl-cli verify` reports one of four statuses. They are also the JSON
`status` field, and each maps to a fixed exit code so scripts never have to
parse the output:

| status | exit | meaning |
|---|---|---|
| `valid` | 0 | Every checkable fact holds and every anchor reached a trust root you configured. |
| `pending` | 0 | The receipt carries no anchors at all (Receipt-Lite). Its proofs may be sound; it simply makes no external-time claim. |
| `untrusted` | 3 | Nothing was refuted; the check could not be finished. Either material is missing on this side (a trust root, an issuer certificate, network access for a Bitcoin anchor, a receipt that never paired with its source file) **or** a fact could not be evaluated at all — see `reason_code`. |
| `invalid` | 1 | The evidence was refuted: some checkable fact is false. |
| `error` | 2 | The tool could not process an input (file not found, unparsable receipt, unreadable trust material). Says nothing about the evidence. Batch mode only — single-file mode exits before a status exists. |

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
  `bitcoin_block_unavailable` (the `untrusted` reasons)
- `receipt_unanchored`, `batch_items_invalid`, `batch_items_errored`,
  `batch_items_pending`, `batch_items_untrusted`, `batch_items_unmatched`,
  `batch_nothing_verified`, `log_consistency_failed`

## Output changes in 0.9

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

`path_status` gained the value `"indeterminate"`, and a new
`timestamping_eku` field reports *which* RFC 3161 §2.3 condition the EKU
check landed on (`"ok"`, `"absent"`, `"malformed"`, `"not_critical"`,
`"not_exclusive"`, `"not_checked"`) alongside the unchanged
`timestamping_eku_ok` boolean.

Scripts branching on `status` and `reason_code` are unaffected apart from the
new `untrusted` reason codes listed above.

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

## Batch mode says the same thing single-file mode does

The same input must mean the same thing however you invoke the tool. Batch
mode aggregates per-item outcomes; it never re-labels them on the way into
the summary.

| per-item outcome | batch summary bucket | batch status | exit |
|---|---|---|---|
| accepted | `valid` | `valid` (only if *every* item is) | 0 |
| unanchored (Receipt-Lite) | `pending` | `pending` | 0 |
| not refuted, check unfinished | `untrusted` | `untrusted` | 3 |
| never paired with a counterpart | `unmatched` | `untrusted` | 3 |
| could not be read or parsed | `errors` | `error` | 2 |
| refuted | `invalid` | `invalid` | 1 |

Two consequences worth stating, because both were once wrong:

- **A receipt that will not parse exits 2, not 1.** The tool failed to read
  an input; it never got far enough to say anything about the evidence.
  Reporting 1 there told a retry system that a substantive refutation had
  occurred — and only when the tool was invoked on a directory.
- **A batch of unanchored receipts is `pending`, not `valid`.** `valid`
  means every anchor reached a configured trust root; a Receipt-Lite has no
  anchors to reach one. A mixture of accepted and unanchored items is
  `pending` too. The exit code stays 0, matching single-file mode.

Refutations are reported ahead of anything that merely could not be done, so
a neighbouring file that failed to open never conceals a receipt that was
checked and refuted.

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

## Network use

Only `bitcoin_ots` anchors need the network, and only to fetch the block whose
Merkle root confirms the OpenTimestamps proof. RFC 3161 verification — token
decoding, CMS signature, certificate chain, validity at `genTime` — is pure
computation. A receipt with no Bitcoin anchor is therefore verified without
any network access at all, and reports `mode: "offline"` even under
`--online`: there is nothing online to do, and saying otherwise would be an
overclaim.

## License

Apache-2.0
