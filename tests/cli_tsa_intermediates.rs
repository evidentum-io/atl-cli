//! Integration tests for `--tsa-intermediates` against REAL production data.
//!
//! `real-data/receipt-tsa.atl` is a genuine Evidentum-issued receipt anchored
//! by exactly one RFC 3161 anchor (Sectigo), matched to `real-data/testfile.txt`
//! by `entry.payload_hash` (not filename -- see
//! `docs-md/atl-trust-model-decisions.md`).
//!
//! Its token carries three certificates:
//!
//! ```text
//! Sectigo Public Time Stamping Signer R36
//!   <- Sectigo Public Time Stamping CA R36
//!        <- Sectigo Public Time Stamping Root R46
//!             <- USERTrust RSA Certification Authority   (NOT in the token)
//! ```
//!
//! The certificate Sectigo calls a "Root" is cross-signed by USERTrust RSA CA,
//! which the token does not include -- so chain construction runs out of
//! certificates and reports `PathStatus::Incomplete`. Nothing is refuted; a
//! link is simply missing on the verifier's side, which is exactly the
//! situation `--tsa-intermediates` exists for.
//!
//! These tests model a caller whose trust boundary is the older Comodo root,
//! "AAA Certificate Services". Reaching it needs USERTrust RSA CA's
//! AAA-cross-signed certificate as an INTERMEDIATE. Supplying that as an
//! anchor instead would move the trust boundary out to a certificate the
//! caller never chose to trust -- which is why the two flags are separate.
//!
//! Both certificates below were fetched from the CAs' own public repositories
//! (`http://crt.comodoca.com/AAACertificateServices.crt` and
//! `http://crt.usertrust.com/USERTrustRSAAAACA.crt`) and are embedded here
//! purely as material a caller would pass on the command line. Neither is
//! baked into `atl-cli` anywhere.
//!
//! This receipt has no `bitcoin_ots` anchor, so none of this touches the
//! network: RFC 3161 verification is pure computation.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// SHA-256 fingerprint of "AAA Certificate Services", the trust anchor these
/// tests configure. Asserted on so a different terminal certificate cannot
/// quietly pass as success.
const AAA_ROOT_SHA256: &str =
    "sha256:d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4";

/// "AAA Certificate Services" -- the self-signed Comodo root used here as the
/// caller's trust anchor.
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

/// "USERTrust RSA Certification Authority", as cross-signed by AAA
/// Certificate Services. This is the missing link: it is NOT a trust anchor
/// here, only the certificate that lets the chain continue from Sectigo's
/// Root R46 up to the caller's actual anchor.
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

fn real_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// Write the two certificates out, each to its own file, and return
/// `(anchor_path, intermediate_path)`.
fn trust_material(dir: &TempDir) -> (PathBuf, PathBuf) {
    let anchor = dir.path().join("aaa-certificate-services.pem");
    let intermediate = dir.path().join("usertrust-rsa-cross-signed.pem");
    std::fs::write(&anchor, AAA_ROOT_PEM).unwrap();
    std::fs::write(&intermediate, USERTRUST_CROSS_SIGNED_PEM).unwrap();
    (anchor, intermediate)
}

fn verify_json(args: &[&str], expected_code: i32) -> serde_json::Value {
    let source = real_data_path("testfile.txt");
    let receipt = real_data_path("receipt-tsa.atl");

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let mut full = vec![
        "verify",
        source.to_str().unwrap(),
        receipt.to_str().unwrap(),
        "--json",
    ];
    full.extend_from_slice(args);

    let output = cmd
        .args(&full)
        .assert()
        .code(expected_code)
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap()
}

/// With no trust material at all, an incomplete chain is `untrusted`, NOT
/// `invalid`.
///
/// This is the regression this test exists for: `PathStatus::Incomplete`
/// used to be folded into the same bucket as a broken signature, telling a
/// client their evidence was damaged when in fact the verifier was simply
/// missing a certificate.
#[test]
fn incomplete_chain_without_trust_material_is_untrusted_not_invalid() {
    let json = verify_json(&[], 3);

    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "tsa_chain_incomplete");

    let anchor = &json["anchor_verification"]["results"][0];
    assert_eq!(anchor["type"], "rfc3161");
    assert_eq!(anchor["verified"], false);
    assert_eq!(anchor["trust_state"], "incomplete");
    assert_eq!(anchor["path_status"], "incomplete");
    // Nothing about the token itself was refuted.
    assert_eq!(anchor["message_imprint"], "verified");
    assert_eq!(anchor["cms_signature"], "verified");
    assert_eq!(anchor["timestamping_eku_ok"], true);
    assert_eq!(json["anchor_verification"]["all_verified"], false);
}

/// The anchor alone is not enough: without the missing issuer certificate the
/// chain still cannot reach it, and the verdict stays `untrusted`.
#[test]
fn anchor_without_the_missing_issuer_is_still_untrusted() {
    let dir = TempDir::new().unwrap();
    let (anchor_path, _) = trust_material(&dir);

    let json = verify_json(&["--tsa-trust-store", anchor_path.to_str().unwrap()], 3);

    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "tsa_chain_incomplete");
    assert_eq!(
        json["anchor_verification"]["results"][0]["trust_state"],
        "incomplete"
    );
}

/// Anchor plus intermediate completes the chain: the SAME real receipt and
/// token now verify, terminating at the caller's chosen anchor.
#[test]
fn anchor_plus_intermediate_completes_a_real_cross_signed_chain() {
    let dir = TempDir::new().unwrap();
    let (anchor_path, intermediate_path) = trust_material(&dir);

    let json = verify_json(
        &[
            "--tsa-trust-store",
            anchor_path.to_str().unwrap(),
            "--tsa-intermediates",
            intermediate_path.to_str().unwrap(),
        ],
        0,
    );

    assert_eq!(json["status"], "valid");
    assert!(
        json.get("reason_code").is_none(),
        "a valid result has no reason code"
    );

    let anchor = &json["anchor_verification"]["results"][0];
    assert_eq!(anchor["verified"], true);
    assert_eq!(anchor["trust_state"], "trusted");
    assert_eq!(anchor["path_status"], "complete");
    assert_eq!(anchor["terminal_anchor"]["kind"], "trusted");
    assert_eq!(
        anchor["terminal_anchor"]["sha256_fingerprint"], AAA_ROOT_SHA256,
        "the chain must terminate at the anchor the caller configured, not somewhere else"
    );
    assert_eq!(json["anchor_verification"]["all_verified"], true);
}

/// The intermediate confers no trust of its own: handed ONLY the missing
/// issuer, with no anchor, the chain reaches a certificate nobody vouched
/// for and the verdict is still not `valid`.
#[test]
fn intermediate_alone_confers_no_trust() {
    let dir = TempDir::new().unwrap();
    let (_, intermediate_path) = trust_material(&dir);

    let json = verify_json(
        &["--tsa-intermediates", intermediate_path.to_str().unwrap()],
        3,
    );

    assert_eq!(json["status"], "untrusted");
    assert_ne!(
        json["anchor_verification"]["results"][0]["trust_state"],
        "trusted"
    );
    assert_eq!(json["anchor_verification"]["all_verified"], false);
}

/// A directory of intermediates works as well as a single file.
#[test]
fn intermediates_accept_a_directory() {
    let dir = TempDir::new().unwrap();
    let anchor_dir = TempDir::new().unwrap();
    std::fs::write(anchor_dir.path().join("root.pem"), AAA_ROOT_PEM).unwrap();
    std::fs::write(dir.path().join("cross.pem"), USERTRUST_CROSS_SIGNED_PEM).unwrap();

    let json = verify_json(
        &[
            "--tsa-trust-store",
            anchor_dir.path().to_str().unwrap(),
            "--tsa-intermediates",
            dir.path().to_str().unwrap(),
        ],
        0,
    );
    assert_eq!(json["status"], "valid");
}

/// An unreadable/absent `--tsa-intermediates` path is a runtime error
/// (exit 2), never a silently empty set of certificates.
#[test]
fn missing_intermediates_path_is_a_runtime_error() {
    let source = real_data_path("testfile.txt");
    let receipt = real_data_path("receipt-tsa.atl");

    Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--tsa-intermediates",
            "/nonexistent/intermediates.pem",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("/nonexistent/intermediates.pem"));
}

/// The human-readable output for an incomplete chain must point at the flag
/// that fixes it, and must not describe the evidence as broken.
#[test]
fn human_output_names_the_remedy_for_an_incomplete_chain() {
    let source = real_data_path("testfile.txt");
    let receipt = real_data_path("receipt-tsa.atl");

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--no-color",
        ])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let human = String::from_utf8(output).unwrap();
    assert!(
        human.contains("NOT VERIFIED: trust root unavailable"),
        "{human}"
    );
    assert!(human.contains("--tsa-intermediates"), "{human}");
    assert!(
        !human.contains("INVALID"),
        "a missing issuer certificate must never read as damaged evidence:\n{human}"
    );
}

// ---------------------------------------------------------------------
// `Indeterminate`: the chain could not be CHECKED, and that is not a
// refutation
// ---------------------------------------------------------------------
//
// "AAA Certificate Services" signs itself with `sha1WithRSAEncryption`, an
// algorithm `atl-core` deliberately does not implement. It is not an
// oddity: 31 of the 156 roots in macOS's system store are SHA-1
// self-signed, DigiCert Assured ID Root CA among them.
//
// Supplied as a trust ANCHOR (the tests above) it works, because a trust
// anchor is an external input and its own signature is beside the point.
// Supplied as an INTERMEDIATE it is just another certificate on the path,
// and the chain arrives at a self-issued certificate whose self-signature
// cannot be evaluated. That used to come out as `invalid` -- the CLI told
// the user their evidence had been disproved, on the strength of a
// signature nobody had checked.

/// **The regression this whole change exists for.** The same real receipt,
/// the same real certificates, but the SHA-1 self-signed root is handed in
/// as an intermediate rather than as an anchor: the result must be
/// `untrusted` (exit 3), never `invalid` (exit 1).
#[test]
fn sha1_self_signed_root_as_an_intermediate_is_indeterminate_not_invalid() {
    let dir = TempDir::new().unwrap();
    let both = dir.path().join("both.pem");
    std::fs::write(&both, format!("{USERTRUST_CROSS_SIGNED_PEM}{AAA_ROOT_PEM}")).unwrap();

    let json = verify_json(&["--tsa-intermediates", both.to_str().unwrap()], 3);

    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "tsa_chain_indeterminate");

    let anchor = &json["anchor_verification"]["results"][0];
    assert_eq!(anchor["path_status"], "indeterminate");
    assert_eq!(anchor["trust_state"], "indeterminate");
    assert_eq!(anchor["reason_code"], "tsa_chain_indeterminate");

    // The chain did reach the root -- it just could not confirm the root
    // signs itself.
    assert_eq!(anchor["terminal_anchor"]["kind"], "assumed");
    assert_eq!(anchor["terminal_anchor"]["self_signature"], "unverifiable");
    assert_eq!(
        anchor["terminal_anchor"]["sha256_fingerprint"], AAA_ROOT_SHA256,
        "the terminal must be the SHA-1 self-signed root itself"
    );

    // Nothing about the token was refuted. Every fact that WAS checked holds.
    assert_eq!(anchor["message_imprint"], "verified");
    assert_eq!(anchor["cms_signature"], "verified");
    assert_eq!(anchor["timestamping_eku_ok"], true);
}

/// **The output-layer blocker.** For an anchor that established no trust,
/// the token's `genTime` must not be emitted as `timestamp` — the key a
/// consumer reads as an established fact. This product sells proof of *when*
/// something existed; that number is the one thing that must never be handed
/// over unqualified.
///
/// The claim is not discarded: it moves to `claimed_timestamp`, so a script
/// reading `timestamp` gets nothing and fails loudly instead of silently
/// trusting a time nobody established.
#[test]
fn an_indeterminate_anchor_reports_a_claimed_time_not_an_established_one() {
    let dir = TempDir::new().unwrap();
    let both = dir.path().join("both.pem");
    std::fs::write(&both, format!("{USERTRUST_CROSS_SIGNED_PEM}{AAA_ROOT_PEM}")).unwrap();

    let json = verify_json(&["--tsa-intermediates", both.to_str().unwrap()], 3);
    let anchor = &json["anchor_verification"]["results"][0];

    assert_eq!(anchor["verified"], false);
    assert!(
        anchor.get("timestamp").is_none(),
        "an unverified anchor must not emit an established timestamp: {anchor}"
    );
    assert!(
        anchor.get("timestamp_nanos").is_none(),
        "nor the nanosecond form: {anchor}"
    );
    assert!(
        anchor.get("claimed_timestamp").is_some(),
        "the claim itself is still reported, under an unmistakable name: {anchor}"
    );
    assert!(anchor.get("claimed_timestamp_nanos").is_some());
}

/// The same for an anchor with no trust material at all (`Incomplete`) —
/// every non-`valid` verdict, not just the indeterminate one.
#[test]
fn an_untrusted_anchor_reports_a_claimed_time_not_an_established_one() {
    let json = verify_json(&[], 3);
    let anchor = &json["anchor_verification"]["results"][0];

    assert_eq!(anchor["verified"], false);
    assert!(anchor.get("timestamp").is_none());
    assert!(anchor.get("claimed_timestamp").is_some());
}

/// And the converse: an accepted anchor DOES establish a time, reported
/// under the plain name with no `claimed_*` alongside it.
#[test]
fn a_valid_anchor_reports_an_established_time() {
    let dir = TempDir::new().unwrap();
    let (anchor_path, intermediate_path) = trust_material(&dir);

    let json = verify_json(
        &[
            "--tsa-trust-store",
            anchor_path.to_str().unwrap(),
            "--tsa-intermediates",
            intermediate_path.to_str().unwrap(),
        ],
        0,
    );
    let anchor = &json["anchor_verification"]["results"][0];

    assert_eq!(anchor["verified"], true);
    assert!(
        anchor.get("timestamp").is_some(),
        "an accepted anchor establishes a time: {anchor}"
    );
    assert!(
        anchor.get("claimed_timestamp").is_none(),
        "and must not also carry the claim form: {anchor}"
    );
}

/// The human output must label it too. An unqualified `Timestamp:` line
/// under a NOT TRUSTED status reads as an established fact however the
/// status above it is worded.
#[test]
fn human_output_labels_an_unestablished_time_as_claimed() {
    let dir = TempDir::new().unwrap();
    let both = dir.path().join("both.pem");
    std::fs::write(&both, format!("{USERTRUST_CROSS_SIGNED_PEM}{AAA_ROOT_PEM}")).unwrap();

    let source = real_data_path("testfile.txt");
    let receipt = real_data_path("receipt-tsa.atl");

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--no-color",
            "--tsa-intermediates",
            both.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let human = String::from_utf8(output).unwrap();
    assert!(
        human.contains("Claimed genTime (not established)"),
        "an unestablished time must be labelled as claimed: {human}"
    );
    assert!(
        !human.contains("      Timestamp: "),
        "and must not appear under the plain established label: {human}"
    );
}

/// `Indeterminate` fails closed: it is never `valid`, never `verified`, and
/// never contributes to `all_verified`.
#[test]
fn an_indeterminate_chain_never_counts_as_success() {
    let dir = TempDir::new().unwrap();
    let both = dir.path().join("both.pem");
    std::fs::write(&both, format!("{USERTRUST_CROSS_SIGNED_PEM}{AAA_ROOT_PEM}")).unwrap();

    let json = verify_json(&["--tsa-intermediates", both.to_str().unwrap()], 3);

    assert_ne!(json["status"], "valid");
    assert_eq!(json["anchor_verification"]["results"][0]["verified"], false);
    assert_eq!(json["anchor_verification"]["all_verified"], false);
    assert_ne!(
        json["anchor_verification"]["results"][0]["trust_state"],
        "trusted"
    );
}

/// The very same certificate, named as a trust ANCHOR instead, still
/// resolves the chain -- proving the fix did not simply make SHA-1 roots
/// unusable, and that RFC 5280 6.1's "trust anchor is an input" reading is
/// what makes the difference.
#[test]
fn the_same_sha1_root_works_when_named_as_a_trust_anchor() {
    let dir = TempDir::new().unwrap();
    let (anchor_path, intermediate_path) = trust_material(&dir);

    let json = verify_json(
        &[
            "--tsa-trust-store",
            anchor_path.to_str().unwrap(),
            "--tsa-intermediates",
            intermediate_path.to_str().unwrap(),
        ],
        0,
    );

    assert_eq!(json["status"], "valid");
    assert_eq!(
        json["anchor_verification"]["results"][0]["terminal_anchor"]["sha256_fingerprint"],
        AAA_ROOT_SHA256
    );
}

/// The human-readable output for an `Indeterminate` chain must say what
/// actually stopped the check, and must NOT tell the reader to go find an
/// intermediate certificate or a root: neither would help, because what is
/// missing is an algorithm implementation.
#[test]
fn human_output_for_an_indeterminate_chain_does_not_ask_for_more_certificates() {
    let dir = TempDir::new().unwrap();
    let both = dir.path().join("both.pem");
    std::fs::write(&both, format!("{USERTRUST_CROSS_SIGNED_PEM}{AAA_ROOT_PEM}")).unwrap();

    let source = real_data_path("testfile.txt");
    let receipt = real_data_path("receipt-tsa.atl");

    let output = Command::cargo_bin("atl-cli")
        .unwrap()
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--no-color",
            "--tsa-intermediates",
            both.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .get_output()
        .stdout
        .clone();

    let human = String::from_utf8(output).unwrap();

    assert!(
        human.contains("could NOT be checked") || human.contains("could not be evaluated"),
        "the output must say the check could not be completed: {human}"
    );
    // "trust root unavailable" is false here: the root is present, the
    // check of it could not be performed. The headline must not claim
    // otherwise anywhere in the output, summary line included.
    assert!(
        !human.contains("trust root unavailable"),
        "an indeterminate chain must not be described as a missing trust root: {human}"
    );
    assert!(
        !human.contains("Supply it with --tsa-intermediates"),
        "an indeterminate chain must not be blamed on a missing intermediate: {human}"
    );
    assert!(
        !human.to_lowercase().contains("invalid"),
        "nothing was refuted, so the word must not appear: {human}"
    );
    // The real cause has to be nameable, not hidden behind a status word.
    assert!(
        human.contains("signature algorithm"),
        "the output must name what stopped the check: {human}"
    );
}
