//! What the receipt says about itself, and what happens when it is wrong.
//!
//! Two checks the CLI did not perform, both about assertions the receipt
//! makes on its own behalf:
//!
//! 1. **ATL v2.0 §5.5.2 step 5** — "verify that `bitcoin_block_height` and
//!    `bitcoin_block_time` match the proof". Neither field was read anywhere
//!    in the production code; a receipt could announce block 900000 while
//!    carrying an OTS proof that attests to 932897, and the output would
//!    print the proof's block without ever mentioning the disagreement.
//! 2. **ATL v2.0 §4.2** — `spec_version`. The CLI's own gate admitted every
//!    `2.x` while `atl-core`'s admitted only `2.0.0`, so a `2.0.1` receipt
//!    got past the door and was then reported as a *defective receipt*
//!    rather than as a revision this build does not implement.
//!
//! The fixtures under `test_data/receipts/invalid/` are the real
//! `real-data/receipt-full.atl` with exactly one field edited each; the OTS
//! proof, the Merkle proofs and the TSA token are untouched, so what these
//! tests exercise is the disagreement and nothing else. Their source file is
//! `real-data/testfile.txt`, matched by `entry.payload_hash`.
//!
//! Everything here runs with no network access: the height half of step 5 is
//! pure computation, and that is precisely why a verifier has no excuse for
//! skipping it.

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn real_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data/receipts/invalid")
        .join(name)
}

/// Run single-file verification and return the exit code with the JSON.
fn verify_single(receipt: &Path, extra: &[&str]) -> (i32, serde_json::Value) {
    let source = real_data_path("testfile.txt");
    let mut args = vec![
        "verify",
        source.to_str().unwrap(),
        receipt.to_str().unwrap(),
        "--json",
        "--offline",
    ];
    args.extend_from_slice(extra);

    let assert = Command::cargo_bin("atl-cli").unwrap().args(&args).assert();
    let output = assert.get_output();
    let code = output.status.code().expect("the process exited normally");
    let json = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    (code, json)
}

/// The same receipt through batch mode, which must answer identically.
fn verify_batch(receipt: &Path, extra: &[&str]) -> (i32, serde_json::Value) {
    let dir = TempDir::new().unwrap();
    std::fs::copy(
        real_data_path("testfile.txt"),
        dir.path().join("testfile.txt"),
    )
    .unwrap();
    std::fs::copy(receipt, dir.path().join("testfile.txt.atl")).unwrap();

    let path = dir.path().to_str().unwrap().to_string();
    let mut args = vec![
        "verify",
        path.as_str(),
        path.as_str(),
        "--json",
        "--offline",
    ];
    args.extend_from_slice(extra);

    let assert = Command::cargo_bin("atl-cli").unwrap().args(&args).assert();
    let output = assert.get_output();
    let code = output.status.code().expect("the process exited normally");
    let json = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    (code, json)
}

fn bitcoin_anchor(json: &serde_json::Value) -> &serde_json::Value {
    json["anchor_verification"]["results"]
        .as_array()
        .expect("anchor results")
        .iter()
        .find(|a| a["type"] == "bitcoin_ots")
        .expect("the fixture carries a bitcoin_ots anchor")
}

/// **A height the receipt's own proof contradicts is a refutation, offline.**
///
/// Not `untrusted`: nothing here was left unchecked. An `OpenTimestamps`
/// Bitcoin attestation carries the block height in its own bytes, so the two
/// assertions were compared with no network access and one of them is false.
#[test]
fn a_contradicted_block_height_is_invalid_offline() {
    let (code, json) = verify_single(&fixture_path("bitcoin_height_contradicts_proof.atl"), &[]);

    assert_eq!(code, 1, "{json}");
    assert_eq!(json["status"], "invalid");
    assert_eq!(
        json["reason_code"],
        "bitcoin_claimed_height_contradicts_proof"
    );

    let anchor = bitcoin_anchor(&json);
    assert_eq!(anchor["state"], "refuted", "{anchor}");
    assert_eq!(
        anchor["reason_code"], "bitcoin_claimed_height_contradicts_proof",
        "{anchor}"
    );

    // Both claims, each under a name that says whose it is. Without this the
    // finding is unauditable: the reader sees one height and cannot tell
    // which of the two it is.
    assert_eq!(anchor["receipt_block_height"], 900_000, "{anchor}");
    // The proof's side of it is the full attested set, not a single number
    // chosen by a rule the protocol never states. Nothing was "selected", so
    // `proof_block_height` is absent and the set is what is published.
    assert!(anchor["proof_block_height"].is_null(), "{anchor}");
    assert_eq!(
        anchor["proof_block_heights"],
        serde_json::json!([932_897]),
        "{anchor}"
    );
}

/// **A refutation may never carry a trust-bearing axis beside it.**
///
/// `evidence.established`, `policy.satisfied` and `coverage.complete` all
/// have to be `false`, and the refutation has to be named in `refuted_by` —
/// a consumer reading only the axes must not be able to conclude anything
/// was achieved.
#[test]
fn the_axes_assert_no_trust_beside_a_contradicted_height() {
    let (_, json) = verify_single(&fixture_path("bitcoin_height_contradicts_proof.atl"), &[]);

    let assessment = &json["assessment"];
    assert_eq!(assessment["evidence"]["established"], false, "{assessment}");
    assert_eq!(
        assessment["evidence"]["verified_anchors"], 0,
        "{assessment}"
    );
    assert_eq!(assessment["evidence"]["refuted_anchors"], 1, "{assessment}");
    assert_eq!(
        assessment["evidence"]["refuted_by"], "bitcoin_claimed_height_contradicts_proof",
        "{assessment}"
    );
    assert_eq!(assessment["policy"]["satisfied"], false, "{assessment}");
    assert_eq!(
        assessment["policy"]["max_trust_profile"], false,
        "{assessment}"
    );
    assert_eq!(assessment["coverage"]["complete"], false, "{assessment}");
    assert_eq!(
        assessment["coverage"]["accepted_with_gaps"], false,
        "{assessment}"
    );
}

/// **`--allow-single-anchor` relaxes a quorum, never a refutation.**
///
/// The flag lets one verified anchor stand in for all of them. It cannot
/// make a disproved anchor go away, and the exit code must not move.
#[test]
fn allow_single_anchor_does_not_rescue_a_contradicted_height() {
    let (code, json) = verify_single(
        &fixture_path("bitcoin_height_contradicts_proof.atl"),
        &["--allow-single-anchor"],
    );

    assert_eq!(code, 1, "{json}");
    assert_eq!(json["status"], "invalid", "{json}");
    assert_eq!(
        json["reason_code"],
        "bitcoin_claimed_height_contradicts_proof"
    );
}

/// **Batch mode gives the same answer as single mode.**
///
/// The same receipt, the same source, the same refutation — the contract
/// must not depend on whether the caller passed a file or a directory.
#[test]
fn batch_mode_reports_the_same_refutation() {
    let (single_code, _) =
        verify_single(&fixture_path("bitcoin_height_contradicts_proof.atl"), &[]);
    let (batch_code, json) =
        verify_batch(&fixture_path("bitcoin_height_contradicts_proof.atl"), &[]);

    assert_eq!(batch_code, single_code, "{json}");
    assert_eq!(batch_code, 1, "{json}");
    assert_eq!(json["status"], "invalid", "{json}");
    assert_eq!(json["reason_code"], "batch_items_invalid", "{json}");

    let item = &json["items"].as_array().expect("batch items")[0];
    assert_eq!(item["status"], "invalid", "{item}");
    assert_eq!(
        item["reason_code"], "bitcoin_claimed_height_contradicts_proof",
        "{item}"
    );
    // The axes on the item itself must carry no trust either.
    assert_eq!(
        item["assessment"]["evidence"]["established"], false,
        "{item}"
    );
    assert_eq!(item["assessment"]["policy"]["satisfied"], false, "{item}");
    assert_eq!(item["assessment"]["coverage"]["complete"], false, "{item}");
}

/// **Offline, a claimed block time is not compared — and that is said, not
/// implied by silence.**
///
/// No OTS proof carries a block time; it exists only in a block header. This
/// fixture's time is an hour off the real block's, and offline that must
/// change nothing at all: an unperformed comparison cannot fail. The
/// receipt stays `untrusted` for the reason it already was.
#[test]
fn a_wrong_block_time_is_not_refuted_offline() {
    let (code, json) = verify_single(&fixture_path("bitcoin_time_contradicts_block.atl"), &[]);

    assert_eq!(code, 3, "{json}");
    assert_eq!(json["status"], "untrusted", "{json}");

    let anchor = bitcoin_anchor(&json);
    assert_eq!(anchor["state"], "not_checked", "{anchor}");
    assert_eq!(
        anchor["reason_code"], "bitcoin_block_not_checked",
        "{anchor}"
    );
    assert_eq!(anchor["claimed_time_check"], "not_compared", "{anchor}");
    assert_eq!(
        anchor["receipt_block_time"], "2026-01-19T08:01:20+00:00",
        "the receipt's own string must be published verbatim: {anchor}"
    );
}

/// The human output has to name both claimants too. A reader of the prose is
/// entitled to the same distinction a reader of the JSON gets.
#[test]
fn the_human_output_names_whose_claim_is_whose() {
    let source = real_data_path("testfile.txt");
    let receipt = fixture_path("bitcoin_height_contradicts_proof.atl");

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--offline",
            "--verbose",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();

    assert!(text.contains("Receipt states:"), "{text}");
    assert!(text.contains("block #900000"), "{text}");
    assert!(text.contains("CONTRADICTED"), "{text}");
    assert!(text.contains("932897"), "{text}");
}

/// **A revision this build does not implement is an inability, not a
/// refutation.**
///
/// ATL v2.0 §4.2 states the current `spec_version` and defines no
/// compatibility rule, so `2.0.1` is refused. It must be refused the way an
/// unusable input is refused — exit 2, the same as an unreadable file —
/// never exit 1, which asserts that the evidence was disproved. Before this,
/// the CLI's `2.x` gate let such a receipt through and `atl-core`'s stricter
/// gate then produced `receipt_malformed`: a receipt reported as defective
/// on the strength of a revision number nobody had looked at.
#[test]
fn a_later_minor_revision_is_an_error_not_a_refutation() {
    let source = real_data_path("testfile.txt");
    let receipt = fixture_path("later_minor_version.atl");

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--offline",
        ])
        .assert()
        .code(2)
        .get_output()
        .stderr
        .clone();
    let text = String::from_utf8(output).unwrap();

    assert!(
        text.contains("2.0.1"),
        "the refused version must be named: {text}"
    );
    assert!(text.contains("2.0.0"), "the accepted one too: {text}");
}

/// **A hostile timestamp must produce a verdict, not a signal.**
///
/// `bitcoin_block_time` and an anchor's `timestamp` are deserialized as
/// unvalidated `String`s straight out of the receipt — a document this tool
/// does not control — and both reach `atl-core`'s RFC 3339 parser. That
/// parser indexed a `&str` at a byte position derived from its length, and
/// `str` slicing panics when the position is not a UTF-8 character boundary:
/// a `bitcoin_block_time` of `"💥abc"` aborted the process with SIGABRT.
///
/// A verifier that dies on a signal answers neither "refuted" nor "could not
/// check". Any exit code in the taxonomy is acceptable here; 134 is not, and
/// neither is a panic message on stderr.
#[test]
fn a_hostile_timestamp_produces_a_verdict_not_a_signal() {
    for fixture in ["hostile_block_time.atl", "hostile_anchor_timestamp.atl"] {
        let source = real_data_path("testfile.txt");
        let receipt = fixture_path(fixture);

        for extra in [&["--offline"][..], &["--online"][..]] {
            let mut args = vec![
                "verify",
                source.to_str().unwrap(),
                receipt.to_str().unwrap(),
                "--json",
            ];
            args.extend_from_slice(extra);

            let assert = Command::cargo_bin("atl-cli").unwrap().args(&args).assert();
            let output = assert.get_output();
            let code = output.status.code();
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(
                !stderr.contains("panicked"),
                "{fixture} {extra:?}: the process panicked: {stderr}"
            );
            // `code()` is `None` when the process died on a signal, which is
            // the failure this test exists to catch.
            let code = code.unwrap_or_else(|| {
                panic!("{fixture} {extra:?}: killed by a signal instead of answering")
            });
            assert!(
                [0, 1, 2, 3].contains(&code),
                "{fixture} {extra:?}: exit {code} is outside the verdict taxonomy"
            );

            let json: serde_json::Value =
                serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
            assert!(
                json.get("status").is_some(),
                "{fixture} {extra:?}: no verdict was rendered: {json}"
            );
        }
    }
}
