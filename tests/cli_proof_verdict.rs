#![allow(deprecated)]
//! End-to-end regression tests for the canonical proof-verdict model.
//!
//! These pin down the exact bug this test file was added for: `verify`
//! reporting `inclusion_valid: false` for a perfectly valid but unanchored
//! receipt (too strict, offline JSON), and reporting `VALID` / `true` when a
//! Super-Tree proof is actually broken (too lenient, online human + JSON —
//! the online renderer used to check only the base inclusion proof).
//!
//! `broken_super_proof_with_anchor.atl` carries an RFC 3161 anchor with a
//! garbage token so `--online` mode is exercised without any network access
//! (RFC 3161 verification is pure crypto against the embedded token; only
//! Bitcoin OTS anchor checks need the network, and this fixture has none).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn test_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join(name)
}

/// Unanchored receipt with genuinely valid proofs must report
/// `inclusion_valid: true` and true super-tree flags in JSON (offline) —
/// not the aggregate `is_valid`, which is `false` for any unanchored receipt.
#[test]
fn offline_json_unanchored_valid_receipt_has_true_inclusion_flags() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            test_data_path("files/document.pdf").to_str().unwrap(),
            test_data_path("receipts/valid/document.pdf.atl")
                .to_str()
                .unwrap(),
            "--json",
            "--offline",
        ])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    // Untrusted (ATL v2.0 §5.5 -- no verified anchor), yet every proof flag
    // below is `true`. That is the whole point of this test: the proof
    // verdict is a statement about proofs, not about trust, and the two must
    // stay separately readable.
    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "receipt_unanchored");
    assert_eq!(json["verification"]["inclusion_valid"], true);
    assert_eq!(json["verification"]["super_inclusion_valid"], true);
    assert_eq!(json["verification"]["super_consistency_valid"], true);
    assert_eq!(json["verification"]["proofs_valid"], true);
}

/// Same receipt, human-readable offline output: must print "Inclusion
/// Proof: VALID" (not blocked on the missing trust anchor, which is
/// reported separately as "Anchor Status: UNANCHORED", and drives the
/// untrusted headline).
#[test]
fn offline_human_unanchored_valid_receipt_shows_valid_inclusion() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        test_data_path("files/document.pdf").to_str().unwrap(),
        test_data_path("receipts/valid/document.pdf.atl")
            .to_str()
            .unwrap(),
        "--no-color",
        "--offline",
    ])
    .assert()
    .code(3)
    .stdout(predicate::str::contains("Inclusion Proof: VALID"))
    .stdout(predicate::str::contains("Anchor Status: UNANCHORED"))
    .stdout(predicate::str::contains(
        "NOT VERIFIED: the receipt carries no anchors (Receipt-Lite)",
    ));
}

/// A receipt whose base inclusion proof is valid but whose Super-Tree
/// `super_root` does not match (i.e. a genuinely broken super-tree proof)
/// must be reported INVALID — in both JSON and human, offline.
#[test]
fn offline_broken_super_proof_is_invalid_in_json_and_human() {
    let receipt = test_data_path("receipts/invalid/broken_super_proof.atl");
    let source = test_data_path("files/document.pdf");

    // JSON
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--json",
            "--offline",
        ])
        .assert()
        .code(1) // INVALID
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "invalid");
    assert_eq!(
        json["verification"]["inclusion_valid"], true,
        "base inclusion proof was not tampered with and must still read true"
    );
    assert_eq!(json["verification"]["super_inclusion_valid"], false);
    assert_eq!(json["verification"]["proofs_valid"], false);

    // Human
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        source.to_str().unwrap(),
        receipt.to_str().unwrap(),
        "--no-color",
        "--offline",
    ])
    .assert()
    .code(1)
    .stdout(predicate::str::contains("Inclusion Proof: INVALID"));
}

/// `broken_super_proof.atl` corrupts `super_root`, which breaks both
/// `super_inclusion_valid` and `super_consistency_valid` simultaneously (see
/// its fixture comment). This test uses a second fixture,
/// `broken_super_consistency_only.atl`, where `super_root` is untouched
/// (super-tree inclusion genuinely passes) and only `genesis_super_root` is
/// corrupted (consistency-to-origin genuinely fails), to prove the renderer
/// catches a consistency-only failure and doesn't only special-case the
/// inclusion check.
#[test]
fn offline_broken_super_consistency_only_is_invalid_in_json_and_human() {
    let receipt = test_data_path("receipts/invalid/broken_super_consistency_only.atl");
    let source = test_data_path("files/document.pdf");

    // JSON
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--json",
            "--offline",
        ])
        .assert()
        .code(1) // INVALID
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "invalid");
    assert_eq!(
        json["verification"]["inclusion_valid"], true,
        "base inclusion proof was not tampered with and must still read true"
    );
    assert_eq!(
        json["verification"]["super_inclusion_valid"], true,
        "super_root was not tampered with, super-tree inclusion must still read true"
    );
    assert_eq!(
        json["verification"]["super_consistency_valid"], false,
        "genesis_super_root was tampered with, consistency-to-origin must read false"
    );
    assert_eq!(json["verification"]["proofs_valid"], false);

    // Human
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        source.to_str().unwrap(),
        receipt.to_str().unwrap(),
        "--no-color",
        "--offline",
    ])
    .assert()
    .code(1)
    .stdout(predicate::str::contains("Inclusion Proof: INVALID"));
}

/// Regression test for the online-mode "mildness" bug: `--online` on a
/// receipt with a broken Super-Tree proof (but a structurally-present,
/// network-free RFC 3161 anchor) must report the inclusion proof INVALID in
/// both JSON and human output, not silently VALID because only the base
/// inclusion proof was ever checked.
#[test]
fn online_broken_super_proof_is_invalid_in_json_and_human() {
    let receipt = test_data_path("receipts/invalid/broken_super_proof_with_anchor.atl");
    let source = test_data_path("files/document.pdf");

    // JSON
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--json",
            "--online",
        ])
        .assert()
        .code(1) // INVALID
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "invalid");
    assert_eq!(
        json["verification"]["inclusion_valid"], true,
        "base inclusion proof was not tampered with and must still read true"
    );
    assert_eq!(
        json["verification"]["super_inclusion_valid"], false,
        "online JSON must expose super-tree flags, not just base inclusion_valid"
    );
    assert_eq!(json["verification"]["proofs_valid"], false);

    // Human — this is the exact line that used to print VALID pre-fix
    // because `human::print_single_online_result` only checked
    // `core_result.inclusion_valid`, ignoring the broken super-tree proof.
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        source.to_str().unwrap(),
        receipt.to_str().unwrap(),
        "--no-color",
        "--online",
    ])
    .assert()
    .code(1)
    .stdout(predicate::str::contains("Inclusion Proof: INVALID"));
}
