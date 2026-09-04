//! The anchor policy: what `--allow-single-anchor` does, and what it must
//! never do.
//!
//! ATL v2.0 §5.5 sets the floor -- "at least one anchor MUST be verified to
//! establish trust in the receipt" -- and §5.6 sets the ceiling: "for maximum
//! trust, Verifiers SHOULD require both RFC 3161 and Bitcoin OTS anchors
//! (Receipt-Full)". This CLI defaults to the strict reading (every anchor the
//! receipt presents must be verified) and lets a caller drop to the floor
//! explicitly. These tests pin both ends, and pin what the flag may not
//! reach: a receipt with no anchors at all (no quorum of one is met by
//! zero), and a receipt this run disproved.
//!
//! They also pin the direction that has nothing to do with the flag: an
//! anchor that was checked and found false changes no status, under either
//! policy, because a receipt's `anchors` array is signed and hashed by
//! nothing and anybody who relays a receipt can append an entry to it. It is
//! reported in full all the same.
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
    // §5.5's floor IS met -- the TSA anchor verified -- so the receipt's own
    // reason names the caller's stricter profile and no anchor. The Bitcoin
    // anchor's own `bitcoin_block_not_checked` is on the anchor, in the
    // coverage axis, and in `errors[]`; the top-level code may not be a
    // function of an array anybody who relays the receipt can rewrite.
    assert_eq!(json["reason_code"], "anchor_quorum_unmet");
    assert_eq!(
        json["assessment"]["coverage"]["unresolved"][0]["reason_code"],
        "bitcoin_block_not_checked"
    );
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
        // The axes are answered for a Receipt-Lite too. Their *presence*
        // used to depend on the `anchors` array, which is authenticated by
        // nothing, so appending one anchor made four unmovable fields
        // appear out of nowhere.
        assert_eq!(
            json["assessment"]["evidence"]["established"], false,
            "{json}"
        );
        assert_eq!(
            json["assessment"]["evidence"]["verified_anchors"], 0,
            "{json}"
        );
        assert_eq!(json["assessment"]["evidence"]["total_anchors"], 0, "{json}");
        assert!(
            json["assessment"]["evidence"]["refuted_by"].is_null(),
            "{json}"
        );
        assert_eq!(
            json["assessment"]["policy"]["max_trust_profile"], false,
            "{json}"
        );
        assert_eq!(json["assessment"]["policy"]["satisfied"], false, "{json}");
    }
}

/// Everything the top level of the report says **about the receipt**, as one
/// comparable value.
///
/// A receipt's `anchors` array is covered by neither the leaf hash nor the
/// checkpoint blob, so a relay can rewrite it at will. Every field below is
/// therefore required to be a function of facts a relay cannot move —
/// chiefly the count of anchors that reached a trust root the *caller*
/// supplied, which nothing a stranger can do will raise.
///
/// # What is deliberately left out, and why
///
/// Three groups, each a per-anchor enumeration that **must** grow when an
/// anchor is appended, because concealing the appended anchor would be the
/// opposite defect:
///
/// * `anchor_verification.results[]` — the anchors themselves;
/// * `assessment.coverage.*` and `assessment.evidence.total_anchors` /
///   `refuted_anchors` — coverage accounts for every anchor *presented*, so
///   it is a statement about the presented set by definition;
/// * `assessment.policy.satisfied` under the default profile, which asks
///   that every anchor presented be verified and so is likewise defined over
///   the presented set. `--allow-single-anchor` is immune, and this test
///   runs both.
///
/// `anchor_status.presented` is left out for the same reason and reported as
/// the relay-controlled number it is; `anchor_status.verified` and
/// `.state` are compared, because those are the facts a relay cannot move.
fn receipt_level_tuple(code: i32, json: &serde_json::Value) -> String {
    let mut fields = vec![format!("exit={code}")];
    for key in [
        "status",
        "reason_code",
        "anchor_status.state",
        "anchor_status.verified",
        "mode",
        "file_hash.match",
        "file_hash.computed",
        "file_hash.expected",
        "verification.inclusion_valid",
        "verification.super_inclusion_valid",
        "verification.super_consistency_valid",
        "verification.proofs_valid",
        "verification.entry_id",
        "assessment.evidence.established",
        "assessment.evidence.verified_anchors",
        "assessment.evidence.refuted_by",
        "assessment.policy.max_trust_profile",
    ] {
        let mut node = json;
        for part in key.split('.') {
            node = &node[part];
        }
        fields.push(format!("{key}={node}"));
    }
    // The receipt's own statement in `errors[]`. Entry 0 is that statement;
    // the entries after it are the per-anchor findings and must be free to
    // grow.
    fields.push(format!("errors[0]={}", json["errors"][0]));
    fields.join("\n")
}

/// **A Receipt-Lite must not stop looking unanchored because a stranger
/// appended an anchor.**
///
/// The coordinator's experiment, pinned. A receipt with no anchors reports
/// `receipt_unanchored`: no trust was established and none ever was. Append
/// one rubbish anchor — which anybody who relays the receipt can do, with no
/// key — and the tool used to report `anchor_target_hash_mismatch` with
/// `anchor_status: "anchored"` instead. "There is no anchor here" became
/// "one anchor did not match", which sounds like a local mishap and hides
/// the larger fact; and a reader reads one line.
///
/// Every top-level field is compared, not just the status: this leaked once
/// through `reason_code` and `anchor_status` while the status held.
#[test]
fn an_appended_anchor_cannot_make_a_receipt_lite_stop_looking_unanchored() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);

    let clean: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-lite.atl")).unwrap()).unwrap();
    assert!(
        clean
            .get("anchors")
            .is_none_or(|a| a.as_array().unwrap().is_empty()),
        "the fixture must be a Receipt-Lite"
    );

    // Four things a relay can attach with no key at all.
    let junk = [
        serde_json::json!({
            "type": "rfc3161", "target": "data_tree_root",
            "target_hash": format!("sha256:{}", "ab".repeat(32)),
            "tsa_url": "https://example.invalid/tsa",
            "timestamp": "2024-01-01T00:00:00Z", "token_der": "base64:bm90YXRva2Vu"
        }),
        serde_json::json!({
            "type": "rfc3161", "target": "super_root",
            "target_hash": format!("sha256:{}", "cd".repeat(32)),
            "tsa_url": "https://example.invalid/tsa",
            "timestamp": "2024-01-01T00:00:00Z", "token_der": "base64:bm90YXRva2Vu"
        }),
        serde_json::json!({
            "type": "bitcoin_ots", "target": "super_root",
            "target_hash": format!("sha256:{}", "ef".repeat(32)),
            "timestamp": "2024-01-01T00:00:00Z",
            "bitcoin_block_height": 800_000,
            "bitcoin_block_time": "2024-01-01T00:00:00Z",
            "ots_proof": "base64:cnViYmlzaA=="
        }),
        serde_json::json!({
            "type": "rfc3161", "target": "data_tree_root",
            "target_hash": "not-a-hash",
            "tsa_url": "https://example.invalid/tsa",
            "timestamp": "2024-01-01T00:00:00Z", "token_der": "base64:bm90YXRva2Vu"
        }),
    ];

    let write = |name: &str, value: &serde_json::Value| {
        let path = dir.path().join(name);
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    };
    let clean_path = write("lite-clean.atl", &clean);

    let run = |receipt: &PathBuf, extra: &[&str]| {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        let output = cmd
            .args([
                "verify",
                real_data("testfile.txt").to_str().unwrap(),
                receipt.to_str().unwrap(),
                "--offline",
                "--json",
                "--tsa-trust-store",
                anchor_pem.to_str().unwrap(),
                "--tsa-intermediates",
                intermediate_pem.to_str().unwrap(),
            ])
            .args(extra)
            .assert()
            .get_output()
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.code().unwrap(), json)
    };

    // Both settings, not just the default: a guard that only ever runs under
    // one of them has not been shown to hold under the other.
    for extra in [&[][..], &["--allow-single-anchor"][..]] {
        let (clean_code, clean_json) = run(&clean_path, extra);
        assert_eq!(clean_code, 3, "{clean_json}");
        assert_eq!(clean_json["status"], "untrusted", "{clean_json}");
        assert_eq!(
            clean_json["reason_code"], "receipt_unanchored",
            "{clean_json}"
        );

        for (i, anchor) in junk.iter().enumerate() {
            let mut tampered = clean.clone();
            tampered["anchors"] = serde_json::json!([anchor]);
            let path = write(&format!("lite-tampered-{i}.atl"), &tampered);
            let (code, json) = run(&path, extra);

            assert_eq!(
                receipt_level_tuple(code, &json),
                receipt_level_tuple(clean_code, &clean_json),
                "junk anchor {i} moved what the receipt reports about itself \
                 ({extra:?})\nclean: {clean_json}\ntampered: {json}"
            );
            // Specifically, and because these are the two the experiment
            // caught: the reason a reader is given, and the anchor headline.
            assert_eq!(json["reason_code"], "receipt_unanchored", "{json}");
            assert_eq!(json["anchor_status"]["state"], "none_verified", "{json}");
            assert_eq!(json["anchor_status"]["verified"], 0, "{json}");

            // And the appended anchor is not concealed: `presented` counts
            // it, and it appears in full with its own finding.
            assert_eq!(json["anchor_status"]["presented"], 1, "{json}");
            assert_eq!(
                json["anchor_verification"]["results"]
                    .as_array()
                    .unwrap()
                    .len(),
                1,
                "{json}"
            );
        }
    }
}

/// **The one thing a relay can still move, pinned so it stays deliberate.**
///
/// The default profile asks that *every anchor the receipt presents* be
/// verified. That is a rule about the presented set, and the presented set
/// is a relay's to change — so appending one rubbish anchor to an accepted
/// receipt takes it from `valid` (exit 0) to `untrusted` (exit 3).
///
/// It is a denial of verification, and it is deliberately not fixed here,
/// because the only fix is to stop asking the question the profile exists to
/// ask. What matters is the shape of what a relay gets:
///
/// * never an accusation — the status is `untrusted`, never `invalid`, and
///   nothing reports the receipt as refuted;
/// * never a reason of their choosing — `anchor_quorum_unmet` names the
///   caller's own profile and no anchor;
/// * never `--allow-single-anchor`, which asks ATL v2.0 §5.5's own question
///   ("at least one verified anchor") and cannot be moved by appending,
///   since appending cannot lower a count.
///
/// A caller who does not want a relay able to do this should pass
/// `--allow-single-anchor` and read §5.5's answer.
#[test]
fn the_default_profile_is_relay_sensitive_and_the_relaxed_one_is_not() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);

    // `receipt-tsa.atl` presents exactly one anchor, and `trust_material`
    // is the material that verifies it -- so the clean receipt satisfies
    // even the default profile, which is the case this test needs.
    let clean: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-tsa.atl")).unwrap()).unwrap();
    let mut appended = clean.clone();
    appended["anchors"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "rfc3161", "target": "data_tree_root",
            "target_hash": format!("sha256:{}", "ab".repeat(32)),
            "tsa_url": "https://example.invalid/tsa",
            "timestamp": "2024-01-01T00:00:00Z", "token_der": "base64:bm90YXRva2Vu"
        }));

    let write = |name: &str, value: &serde_json::Value| {
        let path = dir.path().join(name);
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    };
    let clean_path = write("q-clean.atl", &clean);
    let appended_path = write("q-appended.atl", &appended);

    let run = |receipt: &PathBuf, extra: &[&str]| {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        let output = cmd
            .args([
                "verify",
                real_data("testfile.txt").to_str().unwrap(),
                receipt.to_str().unwrap(),
                "--offline",
                "--json",
                "--tsa-trust-store",
                anchor_pem.to_str().unwrap(),
                "--tsa-intermediates",
                intermediate_pem.to_str().unwrap(),
            ])
            .args(extra)
            .assert()
            .get_output()
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.code().unwrap(), json)
    };

    // --- The default profile: the relay CAN move acceptance ---
    let (clean_code, clean_json) = run(&clean_path, &[]);
    assert_eq!(clean_code, 0, "{clean_json}");
    assert_eq!(clean_json["status"], "valid", "{clean_json}");

    let (code, json) = run(&appended_path, &[]);
    assert_eq!(code, 3, "{json}");
    assert_eq!(json["status"], "untrusted", "{json}");
    // But only into `untrusted`, and only under a fixed code naming the
    // caller's own profile. Never `invalid`, and never a code the relay
    // picked by choosing which anchor to append.
    assert_ne!(json["status"], "invalid", "{json}");
    assert_eq!(json["reason_code"], "anchor_quorum_unmet", "{json}");
    assert!(
        json["assessment"]["evidence"]["refuted_by"].is_null(),
        "{json}"
    );
    // §5.5's floor is still met, and the report says so.
    assert_eq!(
        json["assessment"]["evidence"]["established"], true,
        "{json}"
    );
    assert_eq!(
        json["assessment"]["evidence"]["verified_anchors"], 1,
        "{json}"
    );
    assert_eq!(json["anchor_status"]["state"], "verified", "{json}");

    // --- `--allow-single-anchor`: the relay CANNOT ---
    let (clean_code, clean_json) = run(&clean_path, &["--allow-single-anchor"]);
    let (code, json) = run(&appended_path, &["--allow-single-anchor"]);
    assert_eq!(clean_code, 0, "{clean_json}");
    assert_eq!(
        receipt_level_tuple(code, &json),
        receipt_level_tuple(clean_code, &clean_json),
        "the §5.5 quorum must not be movable by appending\nclean: {clean_json}\nafter: {json}"
    );
    assert_eq!(json["status"], "valid", "{json}");
}

/// The guard above is only worth anything if the tuple it compares can
/// differ. Two receipts that genuinely differ must produce different tuples,
/// or a bug in `receipt_level_tuple` would make every invariance assertion
/// in this file pass for free.
#[test]
fn the_receipt_level_tuple_is_not_constant() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, _) = trust_material(&dir);

    let run = |source: &str, receipt: &str| {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        let output = cmd
            .args([
                "verify",
                real_data(source).to_str().unwrap(),
                real_data(receipt).to_str().unwrap(),
                "--offline",
                "--json",
                "--tsa-trust-store",
                anchor_pem.to_str().unwrap(),
            ])
            .assert()
            .get_output()
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        receipt_level_tuple(output.status.code().unwrap(), &json)
    };

    // A Receipt-Lite, an accepted Receipt-TSA and a receipt verified against
    // the wrong source file: three different outcomes, three different
    // tuples.
    let lite = run("testfile.txt", "receipt-lite.atl");
    let accepted = run("testfile2.txt", "receipt2-tsa.atl");
    let wrong_file = run("testfile.txt", "receipt2-tsa.atl");

    assert_ne!(lite, accepted);
    assert_ne!(lite, wrong_file);
    assert_ne!(accepted, wrong_file);
}

/// **An anchor anybody could have appended may not refute the receipt.**
///
/// A receipt authenticates neither the presence nor the contents of its
/// `anchors` array: the leaf hash covers `payload_hash` and `metadata_hash`,
/// the checkpoint blob covers origin, tree size, timestamp and root hash, and
/// the array appears in neither. **Anyone who relays a receipt can append an
/// anchor to it, with no key.**
///
/// The fixture is a real Receipt-Full plus one extra RFC 3161 anchor pointed
/// at a hash that is not this receipt's Data Tree root — the cheapest
/// possible forgery — so exactly three outcomes coexist: one verified anchor,
/// one unresolved (its Bitcoin block was never fetched, this being an offline
/// run) and one refuted.
///
/// The receipt was `untrusted` before the append and must stay `untrusted`
/// after it. It used to become `invalid`, exit 1: a stranger could turn
/// *trust could not be established* into *this evidence is disproved*, which
/// is a denial of verification available for free to every relay.
///
/// **Both halves are asserted**, because the first alone cannot tell "the
/// invariant holds" from "anchors do not matter":
///
/// 1. appending an anchor that fails verification changes no status;
/// 2. the anchor that **passes** is what carries the receipt — removing it
///    takes the acceptance away.
#[test]
fn an_appended_failed_anchor_changes_no_status() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);

    let genuine: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-full.atl")).unwrap()).unwrap();

    let mut appended = genuine.clone();
    {
        let anchors = appended["anchors"].as_array_mut().unwrap();
        let mut refuted = anchors
            .iter()
            .find(|a| a["type"] == "rfc3161")
            .expect("the fixture carries an RFC 3161 anchor")
            .clone();
        refuted["target_hash"] = serde_json::Value::String(format!("sha256:{}", "ab".repeat(32)));
        anchors.push(refuted);
    }

    // The same receipt with its one *verified* anchor removed: the control
    // for half 2.
    let mut without_tsa = genuine.clone();
    {
        let anchors = without_tsa["anchors"].as_array_mut().unwrap();
        anchors.retain(|a| a["type"] != "rfc3161");
    }

    let write = |name: &str, value: &serde_json::Value| {
        let path = dir.path().join(name);
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path
    };
    let genuine_path = write("genuine.atl", &genuine);
    let appended_path = write("appended.atl", &appended);
    let without_tsa_path = write("without-tsa.atl", &without_tsa);

    let run = |receipt: &PathBuf, extra: &[&str]| {
        let mut cmd = Command::cargo_bin("atl-cli").unwrap();
        let output = cmd
            .args([
                "verify",
                real_data("testfile.txt").to_str().unwrap(),
                receipt.to_str().unwrap(),
                "--offline",
                "--json",
                "--tsa-trust-store",
                anchor_pem.to_str().unwrap(),
                "--tsa-intermediates",
                intermediate_pem.to_str().unwrap(),
            ])
            .args(extra)
            .assert()
            .get_output()
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.code().unwrap(), json)
    };

    // ---- Half 1: appending moves nothing the receipt reports about itself ----
    for extra in [&[][..], &["--allow-single-anchor"][..]] {
        let (before_code, before) = run(&genuine_path, extra);
        let (after_code, after) = run(&appended_path, extra);

        // The WHOLE reported tuple, not just the status.
        //
        // Comparing one field is how this leaked twice already: `is_valid`
        // held while `is_indeterminate` moved, then the status held while
        // `reason_code` and `anchor_status` moved. Everything a reader of
        // the top level sees is compared here, and the per-anchor
        // enumerations -- which MUST grow, or the appended anchor would be
        // concealed -- are the only exemptions, named one by one.
        assert_eq!(
            receipt_level_tuple(before_code, &before),
            receipt_level_tuple(after_code, &after),
            "appending an anchor that fails verification moved something the \
             receipt reports about itself ({extra:?})\nbefore: {before}\nafter: {after}"
        );
        assert_ne!(
            after["status"], "invalid",
            "a stranger must never be able to make a receipt read as disproved: {after}"
        );

        // And it is never hidden. The refuted anchor keeps its own state and
        // reason code, is listed in the coverage axis, and keeps coverage
        // incomplete -- an appended anchor is evidence of interference, and
        // "does not decide the verdict" may not become "is not shown".
        let a = &after["assessment"];
        assert_eq!(a["evidence"]["refuted_anchors"], 1, "{after}");
        assert_eq!(a["evidence"]["total_anchors"], 3, "{after}");
        assert_eq!(a["evidence"]["verified_anchors"], 1, "{after}");
        assert_eq!(a["coverage"]["complete"], false, "{after}");
        assert_eq!(a["coverage"]["refuted"][0]["type"], "rfc3161", "{after}");
        assert_eq!(a["coverage"]["refuted"][0]["state"], "refuted", "{after}");
        assert_eq!(
            a["coverage"]["refuted"][0]["reason_code"], "anchor_target_hash_mismatch",
            "{after}"
        );
        // The merely-unresolved anchor stays in its own list: the two call
        // for opposite reactions and must not be run together.
        assert_eq!(
            a["coverage"]["unresolved"][0]["type"], "bitcoin_ots",
            "{after}"
        );
        assert_eq!(
            a["coverage"]["unresolved"][0]["state"], "not_checked",
            "{after}"
        );
        // Three outcomes, not two: verified, unresolved and refuted all
        // appear on the same receipt.
        let anchors = after["anchor_verification"]["results"].as_array().unwrap();
        let states: Vec<&str> = anchors
            .iter()
            .map(|a| a["state"].as_str().unwrap())
            .collect();
        assert_eq!(
            states,
            vec!["verified", "not_checked", "refuted"],
            "{after}"
        );
    }

    // ---- Half 2: the anchor that passes is what carries the receipt ----
    //
    // Under `--allow-single-anchor` the genuine receipt is accepted, and the
    // appended rubbish did not take that away. Remove the one *verified*
    // anchor and the acceptance goes with it -- so the test above is
    // measuring an invariant, not an inert flag.
    let (code, json) = run(&genuine_path, &["--allow-single-anchor"]);
    assert_eq!(code, 0, "a verified anchor meets the §5.5 floor: {json}");
    assert_eq!(json["status"], "valid", "{json}");

    let (code, json) = run(&appended_path, &["--allow-single-anchor"]);
    assert_eq!(code, 0, "appended rubbish may not withdraw it: {json}");
    assert_eq!(json["status"], "valid", "{json}");

    let (code, json) = run(&without_tsa_path, &["--allow-single-anchor"]);
    assert_eq!(
        code, 3,
        "with no verified anchor the receipt is unattested: {json}"
    );
    assert_eq!(json["status"], "untrusted", "{json}");
    assert_eq!(
        json["assessment"]["evidence"]["verified_anchors"], 0,
        "{json}"
    );
}

/// **An accepted receipt still shows the anchor that failed.**
///
/// Under `--allow-single-anchor` one verified anchor meets the quorum, so a
/// receipt can be accepted while carrying an anchor that was checked and
/// found false. That is the invariant working — an entry anybody could have
/// appended did not withdraw what a genuine anchor established — and it is
/// also the case where the finding is easiest to lose, because none of the
/// failure paths run. It must be visible in the status line, in the coverage
/// axis, and in prose that says what it means.
///
/// The status stays `valid`, exit 0: this test is the second half of
/// `an_appended_failed_anchor_changes_no_status`, and without it that one
/// cannot tell "the invariant holds" from "anchors do not matter".
#[test]
fn an_accepted_receipt_still_reports_a_failed_anchor() {
    let dir = TempDir::new().unwrap();
    let (anchor_pem, intermediate_pem) = trust_material(&dir);
    let receipt_path = dir.path().join("appended.atl");

    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(real_data("receipt-full.atl")).unwrap()).unwrap();
    {
        let anchors = receipt["anchors"].as_array_mut().unwrap();
        let mut failed = anchors
            .iter()
            .find(|a| a["type"] == "rfc3161")
            .expect("the fixture carries an RFC 3161 anchor")
            .clone();
        failed["target_hash"] = serde_json::Value::String(format!("sha256:{}", "ab".repeat(32)));
        anchors.push(failed);
    }
    std::fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            real_data("testfile.txt").to_str().unwrap(),
            receipt_path.to_str().unwrap(),
            "--offline",
            "--no-color",
            "--allow-single-anchor",
            "--tsa-trust-store",
            anchor_pem.to_str().unwrap(),
            "--tsa-intermediates",
            intermediate_pem.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Accepted -- and the success line says on what terms, counting BOTH
    // kinds of gap. Counting only the unresolved ones printed "0 unresolved"
    // beside "1 of 3 anchors verified" and left the reader to work out where
    // the other two went.
    assert!(
        stdout.contains("VALID under policy 'single-anchor'"),
        "{stdout}"
    );
    assert!(stdout.contains("1 unresolved, 1 REFUTED"), "{stdout}");
    // Named in the coverage axis...
    assert!(
        stdout.contains("REFUTED: refuted (anchor_target_hash_mismatch)"),
        "{stdout}"
    );
    // ...and explained, so a reader is told what an appended anchor means
    // rather than left to infer it from a reason code.
    assert!(
        stdout.contains("An anchor attached to this receipt was checked and FAILED:"),
        "an accepted receipt must still explain the failed anchor:\n{stdout}"
    );
    assert!(stdout.contains("does not disprove the receipt"), "{stdout}");
    // Nothing here may read as a refutation of the document.
    assert!(!stdout.contains("Status: INVALID"), "{stdout}");
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

    // Verified against the WRONG source file, so the receipt itself is
    // refuted -- which is the only kind of refutation that may reach the
    // verdict. The appended anchor rides along and must still be printed.
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            real_data("testfile2.txt").to_str().unwrap(),
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
    assert!(!stdout.contains("Evidence: ESTABLISHED"), "{stdout}");

    // And the same receipt against its OWN source file: nothing about the
    // receipt is refuted, so the verdict is not `invalid` -- but the anchor
    // somebody appended is still named, in full, in the coverage axis.
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
        .code(3)
        .get_output()
        .clone();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(!stdout.contains("Status: INVALID"), "{stdout}");
    assert!(stdout.contains("Coverage: INCOMPLETE"), "{stdout}");
    assert!(
        stdout.contains("REFUTED: refuted (anchor_target_hash_mismatch)"),
        "the appended anchor must be listed in the coverage axis:\n{stdout}"
    );
}

/// **Every `invalid` reason poisons the axes.**
///
/// Every reason for which `verdict()` declares `invalid` is one that never
/// touches an anchor — a source file whose hash does not match, a broken
/// inclusion proof, a broken Super-Tree proof — because an anchor cannot
/// produce `invalid` at all. The assessment used to be tallied from the
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
