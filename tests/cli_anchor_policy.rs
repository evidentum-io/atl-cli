//! The anchor policy: what `--allow-single-anchor` does, and what it must
//! never do.
//!
//! ATL v2.0 §5.5 sets the floor -- "at least one anchor MUST be verified to
//! establish trust in the receipt" -- and §5.6 sets the ceiling: "for maximum
//! trust, Verifiers SHOULD require both RFC 3161 and Bitcoin OTS anchors
//! (Receipt-Full)". This CLI defaults to the strict reading (every anchor the
//! receipt presents must be verified) and lets a caller drop to the floor
//! explicitly. These tests pin both ends, and pin what the flag may not
//! reach: a refutation, and a receipt with no anchors at all.
//!
//! Everything here runs `--offline`, so the Bitcoin anchor of a Receipt-Full
//! is deliberately left unresolved. That is the one situation in which the
//! two policies disagree, which makes it the situation worth pinning.

use assert_cmd::Command;
use std::path::PathBuf;
use tempfile::TempDir;

fn real_data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// Write the caller-supplied trust material this receipt's Sectigo chain
/// needs: the Comodo root it terminates at, plus the cross-signed
/// intermediate the token itself omits.
fn trust_material(dir: &TempDir) -> (PathBuf, PathBuf) {
    let anchor = dir.path().join("anchor.pem");
    let intermediate = dir.path().join("inter.pem");
    std::fs::write(&anchor, AAA_ROOT_PEM).unwrap();
    std::fs::write(&intermediate, USERTRUST_CROSS_SIGNED_PEM).unwrap();
    (anchor, intermediate)
}

/// Verify `receipt` offline with the trust material supplied, and return the
/// exit code plus the parsed JSON.
fn verify(receipt: &str, extra: &[&str]) -> (i32, serde_json::Value) {
    let dir = TempDir::new().unwrap();
    let (anchor, intermediate) = trust_material(&dir);

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            real_data("testfile.txt").to_str().unwrap(),
            real_data(receipt).to_str().unwrap(),
            "--offline",
            "--json",
            "--tsa-trust-store",
            anchor.to_str().unwrap(),
            "--tsa-intermediates",
            intermediate.to_str().unwrap(),
        ])
        .args(extra)
        .assert()
        .get_output()
        .clone();

    let code = output.status.code().unwrap();
    let json = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    (code, json)
}

/// A Receipt-TSA whose single anchor is verified satisfies both policies:
/// there is nothing left unresolved for them to disagree about.
#[test]
fn a_fully_verified_receipt_tsa_is_accepted_under_both_policies() {
    for extra in [&[][..], &["--allow-single-anchor"][..]] {
        let (code, json) = verify("receipt-tsa.atl", extra);
        assert_eq!(code, 0, "{json}");
        assert_eq!(json["status"], "valid");
        assert_eq!(json["assessment"]["evidence"]["established"], true);
        assert_eq!(json["assessment"]["evidence"]["verified_anchors"], 1);
        assert_eq!(json["assessment"]["coverage"]["complete"], true);
        assert_eq!(
            json["assessment"]["coverage"]["accepted_with_gaps"], false,
            "nothing was skipped, so no qualifier is warranted"
        );
        // §5.6 is still reported honestly: this is Receipt-TSA, not
        // Receipt-Full, so the maximum-trust profile is not attained even
        // though the receipt is accepted.
        assert_eq!(json["assessment"]["policy"]["max_trust_profile"], false);
    }
}

/// **The default, and why it is strict.** A Receipt-Full verified offline
/// offered a Bitcoin anchor and could not have it confirmed. Under the
/// default quorum that is `untrusted` and exit 3 -- worse than the
/// Receipt-TSA above, which never made the claim. That is an honest report
/// that the fuller profile was not met, not an unfairness.
#[test]
fn a_receipt_full_with_an_unconfirmed_bitcoin_anchor_is_untrusted_by_default() {
    let (code, json) = verify("receipt-full.atl", &[]);

    assert_eq!(code, 3, "{json}");
    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "bitcoin_block_not_checked");
    // The three axes disagree with each other, which is the entire reason
    // they are published separately: trust IS established, the quorum is
    // NOT met, and coverage is NOT complete.
    assert_eq!(json["assessment"]["evidence"]["established"], true);
    assert_eq!(json["assessment"]["evidence"]["verified_anchors"], 1);
    assert_eq!(json["assessment"]["evidence"]["total_anchors"], 2);
    assert_eq!(json["assessment"]["policy"]["profile"], "all-anchors");
    assert_eq!(json["assessment"]["policy"]["satisfied"], false);
    assert_eq!(json["assessment"]["coverage"]["complete"], false);
    assert_eq!(
        json["assessment"]["coverage"]["unresolved"][0]["type"],
        "bitcoin_ots"
    );
    assert_eq!(
        json["assessment"]["coverage"]["unresolved"][0]["state"], "not_checked",
        "the block was not fetched because this run is offline -- not because \
         the check failed or is impossible"
    );
}

/// The same receipt under the §5.5 floor: accepted, and the gap still
/// reported. `accepted_with_gaps` is what a consumer branches on to know the
/// acceptance was relative to a lowered threshold.
#[test]
fn allow_single_anchor_accepts_it_and_still_reports_the_gap() {
    let (code, json) = verify("receipt-full.atl", &["--allow-single-anchor"]);

    assert_eq!(code, 0, "{json}");
    assert_eq!(json["status"], "valid");
    assert_eq!(json["assessment"]["policy"]["profile"], "single-anchor");
    assert_eq!(json["assessment"]["policy"]["satisfied"], true);
    assert_eq!(
        json["assessment"]["coverage"]["complete"], false,
        "a lowered quorum does not make the unchecked anchor checked"
    );
    assert_eq!(json["assessment"]["coverage"]["accepted_with_gaps"], true);
    assert_eq!(
        json["assessment"]["coverage"]["unresolved"][0]["reason_code"],
        "bitcoin_block_not_checked"
    );
    assert_eq!(json["assessment"]["policy"]["max_trust_profile"], false);
}

/// And the human-readable rendering of that acceptance must not read as an
/// unqualified VALID: it names the profile, the counts, and the anchor that
/// went unresolved.
#[test]
fn a_relaxed_acceptance_is_never_rendered_as_a_bare_valid() {
    let dir = TempDir::new().unwrap();
    let (anchor, intermediate) = trust_material(&dir);

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            real_data("testfile.txt").to_str().unwrap(),
            real_data("receipt-full.atl").to_str().unwrap(),
            "--offline",
            "--no-color",
            "--tsa-trust-store",
            anchor.to_str().unwrap(),
            "--tsa-intermediates",
            intermediate.to_str().unwrap(),
            "--allow-single-anchor",
        ])
        .assert()
        .code(0)
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        stdout.contains("Status: VALID under policy 'single-anchor'"),
        "the success must be qualified by the policy that produced it:\n{stdout}"
    );
    assert!(!stdout.contains("Status: VALID\n"), "{stdout}");
    assert!(stdout.contains("Coverage: INCOMPLETE"), "{stdout}");
    assert!(
        stdout.contains("bitcoin_block_not_checked"),
        "the unresolved anchor must be named with its reason:\n{stdout}"
    );
    assert!(
        stdout.contains("Receipt-Full profile"),
        "\u{a7}5.6 attainment is reported either way:\n{stdout}"
    );
}

/// The floor is one *verified* anchor. Zero anchors meet no quorum, so
/// relaxing the policy cannot accept a Receipt-Lite.
#[test]
fn allow_single_anchor_never_accepts_an_unanchored_receipt() {
    for extra in [&[][..], &["--allow-single-anchor"][..]] {
        let (code, json) = verify("receipt-lite.atl", extra);
        assert_eq!(code, 3, "{json}");
        assert_eq!(json["status"], "untrusted");
        assert_eq!(json["reason_code"], "receipt_unanchored");
        assert!(
            json["assessment"].is_null(),
            "there is no quorum to report on when no anchor was presented: {json}"
        );
    }
}

/// **A refutation must poison every supporting field.**
///
/// The fixture is a real Receipt-Full plus one extra RFC 3161 anchor pointed
/// at a hash that is not this receipt's Data Tree root, so exactly three
/// outcomes coexist: one verified anchor, one unresolved (its Bitcoin block
/// was never fetched, this being an offline run) and one refuted.
///
/// The verdict is `invalid`, and nothing printed beside it may claim
/// achieved trust. This is the defect the axes reintroduced when they were
/// added: they were tallied from the verified anchors alone, so
/// `evidence.established`, `coverage.complete` and `max_trust_profile` could
/// all report success next to a `status: "invalid"` verdict.
#[test]
fn a_refuted_anchor_leaves_no_axis_claiming_trust() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);
    let receipt_path = dir.path().join("mixed.atl");

    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-full.atl")).unwrap()).unwrap();
    let anchors = receipt["anchors"].as_array_mut().unwrap();
    let mut refuted = anchors
        .iter()
        .find(|a| a["type"] == "rfc3161")
        .expect("the fixture carries an RFC 3161 anchor")
        .clone();
    refuted["target_hash"] = serde_json::Value::String(format!("sha256:{}", "ab".repeat(32)));
    anchors.push(refuted);
    std::fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    for extra in [&[][..], &["--allow-single-anchor"][..]] {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        let output = cmd
            .args([
                "verify",
                real_data("testfile.txt").to_str().unwrap(),
                receipt_path.to_str().unwrap(),
                "--offline",
                "--json",
                "--tsa-trust-store",
                anchor_pem.to_str().unwrap(),
                "--tsa-intermediates",
                intermediate_pem.to_str().unwrap(),
            ])
            .args(extra)
            .assert()
            .code(1)
            .get_output()
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

        assert_eq!(json["status"], "invalid", "{json}");
        assert_eq!(json["reason_code"], "anchor_target_hash_mismatch");

        let a = &json["assessment"];
        // One anchor really did reach a trusted root, and the count says so.
        assert_eq!(a["evidence"]["verified_anchors"], 1, "{json}");
        assert_eq!(a["evidence"]["refuted_anchors"], 1, "{json}");
        assert_eq!(a["evidence"]["total_anchors"], 3, "{json}");
        // And yet nothing here may report achieved trust.
        assert_eq!(
            a["evidence"]["established"], false,
            "trust is not established in refuted evidence: {json}"
        );
        assert_eq!(a["policy"]["satisfied"], false, "{json}");
        assert_eq!(a["policy"]["max_trust_profile"], false, "{json}");
        assert_eq!(
            a["coverage"]["complete"], false,
            "the refuted anchor must be accounted for, not counted as settled: {json}"
        );
        assert_eq!(a["coverage"]["accepted_with_gaps"], false, "{json}");

        // The refuted anchor is named in the coverage axis, not merely
        // counted, and it is kept apart from the merely-unresolved one:
        // the two call for opposite reactions.
        assert_eq!(a["coverage"]["refuted"][0]["type"], "rfc3161", "{json}");
        assert_eq!(a["coverage"]["refuted"][0]["state"], "refuted");
        assert_eq!(
            a["coverage"]["refuted"][0]["reason_code"],
            "anchor_target_hash_mismatch"
        );
        assert_eq!(
            a["coverage"]["unresolved"][0]["type"], "bitcoin_ots",
            "{json}"
        );
        assert_eq!(a["coverage"]["unresolved"][0]["state"], "not_checked");
    }
}

/// The same fixture, human-readable: the §5.6 line must not carry the word
/// "ATTAINED" in any form beside a refuted verdict, and the refuted anchor
/// must appear in the Trust Assessment block.
#[test]
fn a_refuted_receipt_never_prints_an_attained_profile() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);
    let receipt_path = dir.path().join("mixed.atl");

    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-full.atl")).unwrap()).unwrap();
    let anchors = receipt["anchors"].as_array_mut().unwrap();
    let mut refuted = anchors
        .iter()
        .find(|a| a["type"] == "rfc3161")
        .unwrap()
        .clone();
    refuted["target_hash"] = serde_json::Value::String(format!("sha256:{}", "ab".repeat(32)));
    anchors.push(refuted);
    std::fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            real_data("testfile.txt").to_str().unwrap(),
            receipt_path.to_str().unwrap(),
            "--offline",
            "--no-color",
            "--tsa-trust-store",
            anchor_pem.to_str().unwrap(),
            "--tsa-intermediates",
            intermediate_pem.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(
        !stdout.contains("ATTAINED"),
        "no form of the attainment word may appear beside a refuted verdict:\n{stdout}"
    );
    assert!(stdout.contains("Status: INVALID"), "{stdout}");
    assert!(
        stdout.contains("Receipt-Full profile (§5.6, both anchor types verified): NO"),
        "{stdout}"
    );
    assert!(stdout.contains("Coverage: INCOMPLETE"), "{stdout}");
    assert!(
        stdout.contains("REFUTED: refuted (anchor_target_hash_mismatch)"),
        "the refuted anchor must be listed in the coverage axis:\n{stdout}"
    );
    assert!(!stdout.contains("Evidence: ESTABLISHED"), "{stdout}");
}

/// **Every `invalid` reason poisons the axes, not just an anchor-level one.**
///
/// `verdict()` declares `invalid` for reasons that never touch an anchor —
/// a source file whose hash does not match, a broken inclusion proof, a
/// broken Super-Tree proof. The assessment used to be tallied from the
/// anchors alone, so those receipts reported `evidence.established: true`,
/// `policy.satisfied: true` and `coverage.complete: true` beside
/// `status: "invalid"`. Hand the tool the wrong source file and the trust
/// block announced that trust in it was established.
///
/// The human renderer happened not to show it for a hash mismatch, because
/// it stops early there — an accident, not a defence, and no help at all to
/// the machine contract. Each case below carries a **verified** TSA anchor,
/// so `verified_anchors` is non-zero and only the refutation can be what
/// makes the axes refuse.
#[test]
fn every_invalid_reason_poisons_every_axis() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);

    // A receipt whose inclusion path no longer leads to `proof.root_hash`.
    // The anchors still pin to that root and still verify: the receipt is
    // refuted, its TSA anchor is not.
    let mut broken_inclusion: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-tsa.atl")).unwrap()).unwrap();
    broken_inclusion["proof"]["inclusion_path"] =
        serde_json::json!([format!("sha256:{}", "cd".repeat(32))]);
    let broken_inclusion_path = dir.path().join("broken-inclusion.atl");
    std::fs::write(
        &broken_inclusion_path,
        serde_json::to_vec(&broken_inclusion).unwrap(),
    )
    .unwrap();

    // A receipt whose consistency-to-origin proof no longer holds, for the
    // same reason: `super_root` is untouched, so the anchors still pin.
    let mut broken_super: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-full.atl")).unwrap()).unwrap();
    broken_super["super_proof"]["genesis_super_root"] =
        serde_json::json!(format!("sha256:{}", "ef".repeat(32)));
    let broken_super_path = dir.path().join("broken-super.atl");
    std::fs::write(
        &broken_super_path,
        serde_json::to_vec(&broken_super).unwrap(),
    )
    .unwrap();

    let cases: [(&str, PathBuf, PathBuf, &str); 3] = [
        (
            "file hash mismatch",
            real_data("testfile2.txt"),
            real_data("receipt-tsa.atl"),
            "file_hash_mismatch",
        ),
        (
            "broken inclusion proof",
            real_data("testfile.txt"),
            broken_inclusion_path,
            "inclusion_proof_invalid",
        ),
        (
            "broken super-tree proof",
            real_data("testfile.txt"),
            broken_super_path,
            "super_consistency_proof_invalid",
        ),
    ];

    for (label, source, receipt, expected_reason) in cases {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        let output = cmd
            .args([
                "verify",
                source.to_str().unwrap(),
                receipt.to_str().unwrap(),
                "--offline",
                "--json",
                "--tsa-trust-store",
                anchor_pem.to_str().unwrap(),
                "--tsa-intermediates",
                intermediate_pem.to_str().unwrap(),
            ])
            .assert()
            .code(1)
            .get_output()
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

        assert_eq!(json["status"], "invalid", "{label}: {json}");
        assert_eq!(json["reason_code"], expected_reason, "{label}: {json}");

        let a = &json["assessment"];
        // The TSA anchor really did reach a trusted root, and no anchor was
        // refuted. Only the receipt-level refutation can be what refuses.
        assert_eq!(a["evidence"]["verified_anchors"], 1, "{label}: {json}");
        assert_eq!(a["evidence"]["refuted_anchors"], 0, "{label}: {json}");
        assert!(
            a["coverage"]["refuted"].as_array().unwrap().is_empty(),
            "{label}: {json}"
        );

        assert_eq!(
            a["evidence"]["established"], false,
            "{label}: trust is not established in a receipt this run refuted: {json}"
        );
        assert_eq!(a["policy"]["satisfied"], false, "{label}: {json}");
        assert_eq!(a["policy"]["max_trust_profile"], false, "{label}: {json}");
        assert_eq!(a["coverage"]["complete"], false, "{label}: {json}");
        assert_eq!(
            a["coverage"]["accepted_with_gaps"], false,
            "{label}: {json}"
        );
        // And the field that keeps `established: false` beside
        // `verified_anchors: 1` legible rather than contradictory.
        assert_eq!(
            a["evidence"]["refuted_by"], expected_reason,
            "{label}: {json}"
        );
    }
}

/// The same three cases, human-readable: no line may assert achieved trust,
/// and the §5.6 line may not carry the attainment word in any form.
///
/// The hash-mismatch case returns early and prints no Trust Assessment at
/// all; that is fine, and deliberately not what this test relies on. What it
/// pins is that nothing affirmative is printed in any of the three.
#[test]
fn no_invalid_reason_prints_an_affirmative_trust_line() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);

    let mut broken_super: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-full.atl")).unwrap()).unwrap();
    broken_super["super_proof"]["genesis_super_root"] =
        serde_json::json!(format!("sha256:{}", "ef".repeat(32)));
    let broken_super_path = dir.path().join("broken-super.atl");
    std::fs::write(
        &broken_super_path,
        serde_json::to_vec(&broken_super).unwrap(),
    )
    .unwrap();

    let cases: [(&str, PathBuf, PathBuf); 2] = [
        (
            "file hash mismatch",
            real_data("testfile2.txt"),
            real_data("receipt-tsa.atl"),
        ),
        (
            "broken super-tree proof",
            real_data("testfile.txt"),
            broken_super_path,
        ),
    ];

    for (label, source, receipt) in cases {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        let output = cmd
            .args([
                "verify",
                source.to_str().unwrap(),
                receipt.to_str().unwrap(),
                "--offline",
                "--no-color",
                "--tsa-trust-store",
                anchor_pem.to_str().unwrap(),
                "--tsa-intermediates",
                intermediate_pem.to_str().unwrap(),
            ])
            .assert()
            .code(1)
            .get_output()
            .clone();
        let stdout = String::from_utf8(output.stdout).unwrap();

        assert!(stdout.contains("Status: INVALID"), "{label}:\n{stdout}");
        assert!(!stdout.contains("ATTAINED"), "{label}:\n{stdout}");
        assert!(
            !stdout.contains("Evidence: ESTABLISHED"),
            "{label}:\n{stdout}"
        );
        assert!(!stdout.contains("Coverage: COMPLETE"), "{label}:\n{stdout}");
    }
}

/// **An unverified Bitcoin anchor publishes no established-looking field.**
///
/// It used to emit `block_timestamp: "1970-01-01T00:00:00Z"` — the zero
/// sentinel for "no block was fetched", rendered as a real, parsable
/// timestamp — beside `block_height` taken straight out of the receipt. Both
/// now follow the rule already applied to the RFC 3161 `genTime`: an
/// unverified anchor's numbers live under `claimed_` names, and a value
/// nobody established is absent rather than annotated.
#[test]
fn an_unverified_bitcoin_anchor_publishes_nothing_as_established() {
    let (code, json) = verify("receipt-full.atl", &[]);
    assert_eq!(code, 3, "{json}");

    let bitcoin = json["anchor_verification"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["type"] == "bitcoin_ots")
        .expect("the fixture carries a bitcoin_ots anchor");

    assert_eq!(bitcoin["verified"], false, "{bitcoin}");
    assert_eq!(bitcoin["state"], "not_checked");

    for established in [
        "block_height",
        "block_timestamp",
        "block_merkle_root",
        "merkle_match",
        "timestamp",
        "timestamp_nanos",
    ] {
        assert!(
            bitcoin[established].is_null(),
            "`{established}` must be absent for an anchor nothing confirmed: {bitcoin}"
        );
    }
    // Nothing anywhere in the object may render as the Unix epoch.
    assert!(
        !bitcoin.to_string().contains("1970-"),
        "a zero sentinel rendered as a real-looking timestamp: {bitcoin}"
    );

    // Both claims are still available, each under a name that says whose it
    // is and neither of which can be mistaken for an established fact.
    assert_eq!(bitcoin["proof_block_height"], 932_897, "{bitcoin}");
    assert_eq!(bitcoin["receipt_block_height"], 932_897, "{bitcoin}");
    assert_eq!(
        bitcoin["receipt_block_time"], "2026-01-19T07:01:20+00:00",
        "{bitcoin}"
    );
    // Offline there is no block header, so the receipt's stated time was not
    // compared with anything -- and that must be said, not implied by
    // silence and not dressed up as agreement.
    assert_eq!(bitcoin["claimed_time_check"], "not_compared", "{bitcoin}");
}

/// **The elaboration must come from the verdict's own cause.**
///
/// This fixture is refuted by its Super-Tree inclusion proof and separately
/// carries an anchor whose token will not parse. The detail line used to
/// take the first refuted anchor's prose regardless, printing
/// `super_inclusion_proof_invalid: RFC 3161 parse error: …` — two true
/// statements welded into a false causal claim.
#[test]
fn the_failure_detail_comes_from_the_reason_that_produced_the_verdict() {
    let receipt = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test_data/receipts/invalid/broken_super_proof_with_anchor.atl");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test_data/files/document.pdf");

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--offline",
            "--no-color",
        ])
        .assert()
        .code(1)
        .get_output()
        .clone();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(stderr.contains("super_inclusion_proof_invalid"), "{stderr}");
    assert!(
        !stderr.contains("RFC 3161 parse error"),
        "an unrelated anchor's parse failure must not be offered as the cause \
         of a Super-Tree proof failure:\n{stderr}"
    );
    assert!(!stderr.contains("ContentInfo"), "{stderr}");
}

/// "AAA Certificate Services" — the Comodo root this receipt's chain leads
/// to, supplied as caller material exactly as a user would.
const AAA_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEb
MBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRow
GAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmlj
YXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezEL
MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQua
BtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe
3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4
YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZR
rOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cm
ez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQU
oBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
MAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20v
QUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29t
b2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUF
AAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1Q
GE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLz
Rt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2
G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsi
l2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3
smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==
-----END CERTIFICATE-----
";

/// "USERTrust RSA Certification Authority", cross-signed by the root above:
/// the intermediate that bridges the gap the token itself does not include.
const USERTRUST_CROSS_SIGNED_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIFgTCCBGmgAwIBAgIQOXJEOvkit1HX02wQ3TE1lTANBgkqhkiG9w0BAQwFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTE5MDMxMjAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5
MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJUUlVTVCBO
ZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRpb24gQXV0
aG9yaXR5MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBJlFzYOw9sI
s9CsVw127c0n00ytUINh4qogTQktZAnczomfzD2p7PbPwdzx07HWezcoEStH2jnG
vDoZtF+mvX2do2NCtnbyqTsrkfjib9DsFiCQCT7i6HTJGLSR1GJk23+jBvGIGGqQ
Ijy8/hPwhxR79uQfjtTkUcYRZ0YIUcuGFFQ/vDP+fmyc/xadGL1RjjWmp2bIcmfb
IWax1Jt4A8BQOujM8Ny8nkz+rwWWNR9XWrf/zvk9tyy29lTdyOcSOk2uTIq3XJq0
tyA9yn8iNK5+O2hmAUTnAU5GU5szYPeUvlM3kHND8zLDU+/bqv50TmnHa4xgk97E
xwzf4TKuzJM7UXiVZ4vuPVb+DNBpDxsP8yUmazNt925H+nND5X4OpWaxKXwyhGNV
icQNwZNUMBkTrNN9N6frXTpsNVzbQdcS2qlJC9/YgIoJk2KOtWbPJYjNhLixP6Q5
D9kCnusSTJV882sFqV4Wg8y4Z+LoE53MW4LTTLPtW//e5XOsIzstAL81VXQJSdhJ
WBp/kjbmUZIO8yZ9HE0XvMnsQybQv0FfQKlERPSZ51eHnlAfV1SoPv10Yy+xUGUJ
5lhCLkMaTLTwJUdZ+gQek9QmRkpQgbLevni3/GcV4clXhB4PY9bpYrrWX1Uu6lzG
KAgEJTm4Diup8kyXHAc/DVL17e8vgg8CAwEAAaOB8jCB7zAfBgNVHSMEGDAWgBSg
EQojPpbxB+zirynvgqV/0DCktDAdBgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rID
ZsswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAG
BgRVHSAAMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29t
L0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggr
BgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUA
A4IBAQAYh1HcdCE9nIrgJ7cz0C7M7PDmy14R3iJvm3WOnnL+5Nb+qh+cli3vA0p+
rvSNb3I8QzvAP+u431yqqcau8vzY7qN7Q/aGNnwU4M309z/+3ri0ivCRlv79Q2R+
/czSAaF9ffgZGclCKxO/WIu6pKJmBHaIkU4MiRTOok3JMrO66BQavHHxW/BBC5gA
CiIDEOUMsfnNkjcZ7Tvx5Dq2+UUTJnWvu6rvP3t3O9LEApE9GQDTF1w52z97GA1F
zZOFli9d31kWTz9RvdVFGD/tSo7oBmF0Ixa1DVBzJ0RHfxBdiSprhTEUxOipakyA
vGp4z7h/jnZymQyd/teRCBaho1+V
-----END CERTIFICATE-----
";
