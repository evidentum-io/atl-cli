//! Integration tests for `--tsa-trust-store` against REAL production data.
//!
//! `real-data/receipt2-tsa.atl` is a genuine Evidentum-issued Receipt-TSA
//! anchored by exactly one RFC 3161 anchor (GlobalSign), matched to
//! `real-data/testfile2.txt` by `entry.payload_hash` (not filename -- see
//! `docs-md/atl-trust-model-decisions.md`). Its token's certificate chain
//! terminates in "GlobalSign Root CA - R6", which genuinely IS self-signed,
//! so without a trust store this is real material for
//! `TerminalAnchor::Assumed` -- not a synthetic/adversarial fixture. That
//! root's own PEM (extracted once from the token with `openssl pkcs7
//! -print_certs`, used here purely as *a* certificate to pin, not because
//! it is specially trustworthy) is embedded below for `--tsa-trust-store`.
//!
//! This receipt carries no `bitcoin_ots` anchor, so nothing here needs the
//! network at all: RFC 3161 verification is pure computation. These tests
//! therefore pass no `--online` flag and make no connectivity probe -- and
//! that is itself part of what they pin down.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// The real GlobalSign root certificate this receipt's RFC 3161 token
/// chains to (self-signed: `CN=GlobalSign` under `OU=GlobalSign Root CA -
/// R6`). Not baked into `atl-cli` itself anywhere -- only used here, by the
/// test, exactly as a caller would pass it via `--tsa-trust-store`.
const GLOBALSIGN_ROOT_R6_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/RVEwDQYJKoZIhvcNAQEMBQAwTDEg
MB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2Jh
bFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTQxMjEwMDAwMDAwWhcNMzQx
MjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH6HPKZvnsFMp7PPcNCPG0RQssgrRI
xutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay/xTOURQh7ErdG1rG1ofuTToVBu1k
ZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025eShNUhqKGoC3GYEOfsSKvGRMIRxD
aNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qjuL++gmNQ0PAYid/kD3n16qIfKtJw
LnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0pPbzlUoSB239jLKJz9CgYXfIWHSw
1CM69106yqLbnQneXUQtkPGBzVeS+n68UARjNN9rkxi+azayOeSsJDa38O+2HBNX
k7besvjihbdzorg1qkXy4J02oW9UivFyVm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2
SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQCTXTAFO39OfuD8l4UoQSwC+n+7o/h
bguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdwgQqomnUdnjqGBQCe24DWJfncBZ4n
WUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQULHpYT9NLCEnFlWQaYw55PfWzjMpY
rZxCRXluDocZXFSxZba/jJvcE+kNb7gu3GduyYsRtYQUigAZcIN5kZeR1Bonvzce
MgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD
AQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzWx/B/yGdToDAfBgNVHSMEGDAWgBSu
bAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG9w0BAQwFAAOCAgEAgyXt6NH9lVLN
nsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8AorRbrcWc+ZfwFSY1XS+wc3iEZGt
Ixg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V33EByrKPrmzU+sQghoefEQzd5Mr61
55wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlNIC5waNrlU/yDXNOd8v9EDERm8tLj
vUYAGm0CuiVdjaExUd1URhxN25mW7xocBFymFe944Hn+Xds+qkxV/ZoVqW/hpvvf
cDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54NMMl+68KnyBr3TsTjxKM4kEaSHpz
oHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA/iU3/gKbaKxCXcPu9czc8FB10jZp
nOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HHTOwY3WzvUy2MmeFe8nI+z1TIvWfs
pA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsViVO6LAUP5MSeGbEYNNVMnbrt9x+v
JJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9x8jvOOJckvB595yEunQtYQEgfn7R
8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfLRVpOoERIyNiwmcUVhAn21klJwGW4
5hpxbqCo8YLoRT5s1gLXCmeDBVrJpBA=
-----END CERTIFICATE-----
";

fn real_data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("real-data")
        .join(name)
}

/// Without `--tsa-trust-store`, a real RFC 3161 anchor whose chain
/// terminates in a genuine self-signed (but un-pinned) root must NEVER be
/// reported valid -- in the exit code, the JSON `status`/`verified`/
/// `trust_state`, or the human-readable status line.
///
/// It must also not be reported as *broken*. Every cryptographic fact about
/// this token holds; the only thing missing is a root this verifier was
/// configured to trust. That is `untrusted` (exit 3), never `invalid`
/// (exit 1): a caller must be able to tell "your evidence is damaged" from
/// "bring me the trust root" without parsing the JSON.
#[test]
fn assumed_root_without_trust_store_never_reports_valid() {
    let source = real_data_path("testfile2.txt");
    let receipt = real_data_path("receipt2-tsa.atl");

    // JSON
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .code(3) // UNTRUSTED -- never 0, and never 1 either
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "untrusted");
    assert_eq!(json["reason_code"], "receipt_unanchored");
    assert_eq!(
        json["anchor_verification"]["results"][0]["reason_code"],
        "tsa_root_not_trusted"
    );
    let anchors = json["anchor_verification"]["results"]
        .as_array()
        .expect("must have anchor results");
    assert_eq!(anchors.len(), 1);
    let anchor = &anchors[0];
    assert_eq!(anchor["type"], "rfc3161");
    assert_eq!(
        anchor["verified"], false,
        "an Assumed terminal anchor must never report verified: true"
    );
    assert_eq!(
        anchor["trust_state"], "assumed",
        "this fixture's real chain terminates in a genuine self-signed, \
         un-pinned root -- it must classify as Assumed, not Trusted or Failed"
    );
    assert_eq!(anchor["terminal_anchor"]["kind"], "assumed");
    assert_eq!(json["anchor_verification"]["all_verified"], false);

    // Human -- same two facts must hold in prose, not just JSON.
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let human_output = cmd
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
    let human = String::from_utf8(human_output).unwrap();
    assert!(
        human.contains("NOT VERIFIED: no anchor was verified"),
        "human output must name the untrusted state explicitly:\n{human}"
    );
    // The anchor's own stable code is still in the output -- on the anchor
    // and in the advice block. It is no longer the receipt's headline,
    // because a code read off the `anchors` array is a relay's to choose.
    assert!(
        human.contains("tsa_root_not_trusted"),
        "human output must carry the stable reason code:\n{human}"
    );
    assert!(
        !human.contains("Status: VALID") && !human.contains("Status: TRUSTED"),
        "human output must not claim the anchor (or overall result) is valid/trusted:\n{human}"
    );
    assert!(
        !human.contains("INVALID"),
        "an unvouched-for root must never be presented as damaged evidence:\n{human}"
    );
    // The remedy must be actionable: name the certificate to supply.
    assert!(
        human.contains("--tsa-trust-store"),
        "human output must say what to supply:\n{human}"
    );
}

/// The SAME real receipt and token, verified again with `--tsa-trust-store`
/// pointing at the token's own real root: the chain now terminates
/// `Trusted`, and the anchor (and, since this receipt has no other proof
/// defects, the whole verification) reports valid.
#[test]
fn trusted_root_via_flag_reports_valid() {
    let source = real_data_path("testfile2.txt");
    let receipt = real_data_path("receipt2-tsa.atl");

    let dir = TempDir::new().unwrap();
    let trust_store_path = dir.path().join("globalsign-root-r6.pem");
    std::fs::write(&trust_store_path, GLOBALSIGN_ROOT_R6_PEM).unwrap();

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    let output = cmd
        .args([
            "verify",
            source.to_str().unwrap(),
            receipt.to_str().unwrap(),
            "--json",
            "--tsa-trust-store",
            trust_store_path.to_str().unwrap(),
        ])
        .assert()
        .code(0) // VALID
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(json["status"], "valid");
    let anchor = &json["anchor_verification"]["results"][0];
    assert_eq!(anchor["type"], "rfc3161");
    assert_eq!(anchor["verified"], true);
    assert_eq!(anchor["trust_state"], "trusted");
    assert_eq!(anchor["terminal_anchor"]["kind"], "trusted");
    assert_eq!(json["anchor_verification"]["all_verified"], true);

    // Human — must say TRUSTED, and the overall status must read VALID.
    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        source.to_str().unwrap(),
        receipt.to_str().unwrap(),
        "--no-color",
        "--tsa-trust-store",
        trust_store_path.to_str().unwrap(),
    ])
    .assert()
    .code(0)
    .stdout(predicate::str::contains("Status: VALID"))
    .stdout(predicate::str::contains("TRUSTED"));
}

/// `--tsa-trust-store` also accepts a *directory* of certificates, not just
/// a single file -- exercised here with the same real root, to catch a
/// regression in the directory-loading path specifically (not just the
/// single-file path already covered above).
#[test]
fn trusted_root_via_directory_trust_store_reports_valid() {
    let source = real_data_path("testfile2.txt");
    let receipt = real_data_path("receipt2-tsa.atl");

    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("root.pem"), GLOBALSIGN_ROOT_R6_PEM).unwrap();

    let mut cmd = Command::cargo_bin("atl-cli").unwrap();
    cmd.args([
        "verify",
        source.to_str().unwrap(),
        receipt.to_str().unwrap(),
        "--json",
        "--tsa-trust-store",
        dir.path().to_str().unwrap(),
    ])
    .assert()
    .code(0)
    .stdout(predicate::str::contains("\"trust_state\": \"trusted\""));
}
