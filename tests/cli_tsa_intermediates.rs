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
    assert_eq!(anchor["imprint_matches_root"], true);
    assert_eq!(anchor["cms_signature_valid"], true);
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
