//! Batch-mode tests for what `mode` means and what it costs.
//!
//! Two things are pinned here:
//!
//! 1. **`mode` must not overclaim.** `execute_batch` used to compute a mode,
//!    hand `mode: "online"` to the renderer, and never run a single online
//!    check -- so for a Bitcoin OTS anchor the block was never fetched and
//!    the Merkle root never compared, with nothing in the output saying so.
//! 2. **A verification that needs no network must not touch it.** RFC 3161
//!    verification is pure computation; a receipt anchored only by a TSA must
//!    be reported `mode: "offline"` even under `--online`, because no network
//!    call is made or needed.
//!
//! The fixtures are real Evidentum receipts from `real-data/`, matched to
//! their sources by `entry.payload_hash`.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn real_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// Build a one-item batch directory from a real source/receipt pair.
fn batch_dir(source: &str, receipt: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    let source_path = real_data_path(source);
    std::fs::copy(&source_path, dir.path().join(source)).unwrap();
    std::fs::copy(
        real_data_path(receipt),
        dir.path().join(format!("{source}.atl")),
    )
    .unwrap();
    dir
}

fn run_batch(dir: &TempDir, extra: &[&str]) -> serde_json::Value {
    let path = dir.path().to_str().unwrap().to_string();
    let mut args = vec!["verify", path.as_str(), path.as_str(), "--json"];
    args.extend_from_slice(extra);

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args(&args)
        .assert()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

/// A batch whose receipts are anchored only by RFC 3161 needs no network, so
/// `--online` must not make it claim it went online -- and must not probe
/// connectivity to decide that.
#[test]
fn rfc3161_only_batch_reports_offline_even_under_online_flag() {
    let dir = batch_dir("testfile.txt", "receipt-tsa.atl");
    let json = run_batch(&dir, &["--online"]);
    assert_eq!(
        json["mode"], "offline",
        "no network call is made for an RFC 3161-only batch, so the mode must not say online"
    );
}

/// The same holds for a single file: `--online` on a locally-verifiable
/// receipt is a no-op, not a connectivity requirement.
#[test]
fn rfc3161_only_single_reports_offline_even_under_online_flag() {
    let source = real_data_path("testfile.txt");
    let receipt = real_data_path("receipt-tsa.atl");

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--json",
            "--online",
        ])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["mode"], "offline");
    // The full RFC 3161 fact set is still produced -- going "offline" costs
    // nothing here, which is the whole point.
    assert_eq!(json["anchor_verification"]["results"][0]["type"], "rfc3161");
    assert_eq!(
        json["anchor_verification"]["results"][0]["cms_signature_valid"],
        true
    );
}

/// An unanchored receipt likewise never triggers a probe.
#[test]
fn unanchored_batch_reports_offline() {
    let dir = batch_dir("testfile.txt", "receipt-lite.atl");
    let json = run_batch(&dir, &["--online"]);
    assert_eq!(json["mode"], "offline");
    assert_eq!(json["items"][0]["status"], "pending");
}

/// A Bitcoin OTS anchor that was never confirmed against a block must be
/// reported as unconfirmed, not as accepted.
///
/// This is the other half of the `mode` fix: before, an unfetched block
/// simply did not show up anywhere in the batch output.
#[test]
fn offline_batch_does_not_accept_an_unconfirmed_bitcoin_anchor() {
    let dir = batch_dir("testfile.txt", "receipt-full.atl");
    let json = run_batch(&dir, &["--offline"]);

    assert_eq!(json["mode"], "offline");
    assert_eq!(json["status"], "untrusted");
    // The TSA anchor of this receipt has an incomplete chain, so it reports
    // first; what matters is that the batch is not accepted.
    assert_eq!(json["summary"]["valid"], 0);
    assert_eq!(json["summary"]["untrusted"], 1);
    assert_ne!(json["items"][0]["status"], "valid");
}
