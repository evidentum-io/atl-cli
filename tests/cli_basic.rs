#![allow(deprecated)]
//! Basic CLI tests: help, version, no args, command structure

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
        ))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("inspect"));
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
fn test_no_args() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
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
fn test_inspect_help() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["inspect", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("RECEIPT"))
        .stdout(predicate::str::contains("Display receipt contents"));
}

#[test]
fn test_invalid_command() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("invalid-command")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized"));
}

#[test]
fn test_verify_missing_arguments() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_verify_missing_receipt_argument() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["verify", "test.pdf"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_inspect_missing_argument() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.arg("inspect")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_global_quiet_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["--quiet", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Suppress output"));
}

#[test]
fn test_global_json_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["--json", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Output as JSON"));
}

#[test]
fn test_global_no_color_flag() {
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args(["--no-color", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Disable colored output"));
}
