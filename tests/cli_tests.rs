#![allow(deprecated)]
//! CLI integration tests

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_help() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "ATL Protocol receipt verification tool",
        ));
}

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_missing_arguments() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_verify_help() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["verify", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SOURCE"))
        .stdout(predicate::str::contains("RECEIPT"))
        .stdout(predicate::str::contains("--offline"))
        .stdout(predicate::str::contains("--online"));
}

#[test]
fn test_offline_online_mutual_exclusion() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        "test.pdf",
        "test.pdf.atl",
        "--offline",
        "--online",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("cannot be used with"));
}
