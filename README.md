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
| `untrusted` | 3 | Nothing was refuted. This verifier was not given the material to finish the check — a trust root, a missing issuer certificate, or network access for a Bitcoin anchor. |
| `invalid` | 1 | The evidence was refuted: some checkable fact is false. |
| — | 2 | Runtime error (file not found, unparsable receipt, unreadable trust material). |

`untrusted` and `invalid` are deliberately distinct. Telling a holder of
sound evidence that it is broken, when the real problem is an unconfigured
verifier, is a different and worse failure than either outcome on its own.

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
  `tsa_timestamping_eku_invalid`, `tsa_chain_invalid_at_gen_time`,
  `super_proof_missing`, `bitcoin_ots_proof_invalid`,
  `bitcoin_merkle_root_mismatch`
- `tsa_root_not_trusted`, `tsa_chain_incomplete`,
  `bitcoin_block_not_checked`, `bitcoin_block_unavailable` (the `untrusted`
  reasons)
- `receipt_unanchored`, `batch_items_invalid`, `batch_items_untrusted`,
  `log_consistency_failed`

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
