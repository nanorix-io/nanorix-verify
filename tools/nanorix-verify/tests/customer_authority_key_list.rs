//! A customer's own key list, end to end against the real binary.
//!
//! A BYOC install signs with the customer's KMS key under the customer's
//! registered authority. The customer makes an identity key offline, signs a
//! key list naming that authority and key version, and publishes the identity
//! fingerprint where an assessor can reach it. The assessor pins that
//! fingerprint and runs `nanorix-verify --trust-chain`. Pinned on exit code and
//! verdict:
//!
//! 1. right pin, authority and key version in the list: exit 0, stage 8.
//! 2. wrong pin: exit 2, no proof is checked.
//! 3. proof key version not in the list: exit 1, stage 6,
//!    `signing_key_version_unknown`.
//! 4. a list signed by another identity, under the customer's pin: exit 2,
//!    whether it names that identity or claims the customer's.
//! 5. a proof naming an authority the list does not carry: exit 1, stage 6.
//!
//! The authorities file is the one the operator guide shows ("Anchoring proofs
//! to your own key list"), parsed into the same map the signing tool reads, so
//! the guide's format cannot drift from what verifies.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::trust_chain::{AuthorityRecord, TrustChainManifest};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");

const AUTHORITY: &str = "us-customer-kms-acme-v1";
const KEY_VERSION: &str = "1";

/// Stand-ins for the customer's KMS signing key, its offline identity key, and
/// an identity that is not the customer's.
const SIGNING_SEED: [u8; 32] = [0x41; 32];
const IDENTITY_SEED: [u8; 32] = [0x42; 32];
const OTHER_IDENTITY_SEED: [u8; 32] = [0x43; 32];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `sha256:<hex>` over raw Ed25519 public-key bytes, as the guide computes it.
fn fingerprint(pubkey: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(pubkey)))
}

/// The guide's authorities file with the customer's values filled in.
fn authorities_file() -> String {
    let signing_pub = SigningKey::from_bytes(&SIGNING_SEED)
        .verifying_key()
        .to_bytes();
    format!(
        r#"{{
  "{AUTHORITY}": {{
    "display_name": "Acme Health signing authority",
    "active_versions": [
      {{
        "signing_key_version": "{KEY_VERSION}",
        "public_key_b64": "{}",
        "public_key_fingerprint": "{}",
        "effective_from": "2026-11-01T00:00:00Z"
      }}
    ],
    "archived_versions": [],
    "revoked": false
  }}
}}"#,
        b64(&signing_pub),
        fingerprint(&signing_pub)
    )
}

fn key_list_signed_by(identity_seed: [u8; 32]) -> TrustChainManifest {
    let authorities: HashMap<String, AuthorityRecord> =
        serde_json::from_str(&authorities_file()).expect("guide authorities file parses");
    TrustChainManifest::build_and_sign(
        "1",
        "2026-11-01T00:00:00Z",
        authorities,
        &SigningKey::from_bytes(&identity_seed),
    )
}

fn customer_pin() -> String {
    fingerprint(
        &SigningKey::from_bytes(&IDENTITY_SEED)
            .verifying_key()
            .to_bytes(),
    )
}

/// A genuine 2.1 proof naming `authority` and `key_version`, signed with the
/// customer's key over its recomputed canonical hash. 2.1 signs both fields.
fn customer_proof(authority: &str, key_version: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json");
    let mut proof: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read fixture")).expect("parse");
    assert_eq!(proof["cdp_version"], "2.1");
    proof["authority_id"] = Value::String(authority.into());
    proof["signing_key_version"] = Value::String(key_version.into());
    let key = SigningKey::from_bytes(&SIGNING_SEED);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    proof["attestation"]["public_key"] =
        Value::String(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = Value::String(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

struct Files {
    _dir: tempfile::TempDir,
    proof: PathBuf,
    key_list: PathBuf,
}

fn write(proof: &Value, key_list: &TrustChainManifest) -> Files {
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_path = dir.path().join("audit-proof.json");
    let list_path = dir.path().join("trust-chain.json");
    std::fs::write(&proof_path, serde_json::to_vec_pretty(proof).unwrap()).unwrap();
    std::fs::write(&list_path, serde_json::to_vec_pretty(key_list).unwrap()).unwrap();
    Files {
        _dir: dir,
        proof: proof_path,
        key_list: list_path,
    }
}

fn verify(f: &Files, pin: &str, extra: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN_PATH)
        .arg(&f.proof)
        .arg("--trust-chain")
        .arg(&f.key_list)
        .arg("--identity-fingerprint")
        .arg(pin)
        .args(extra)
        .output()
        .expect("spawn nanorix-verify");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn verdict(stdout: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("json verdict ({e}): {stdout}"))
}

#[test]
fn right_pin_reaches_stage_8_under_the_customer_authority() {
    let f = write(
        &customer_proof(AUTHORITY, KEY_VERSION),
        &key_list_signed_by(IDENTITY_SEED),
    );

    let (code, stdout, stderr) = verify(&f, &customer_pin(), &["--json"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let v = verdict(&stdout);
    assert_eq!(v["valid"], true, "{stdout}");
    assert_eq!(v["stage_reached"], 8, "{stdout}");
    assert!(v["failure_reason"].is_null(), "{stdout}");

    let (code, stdout, stderr) = verify(
        &f,
        &customer_pin(),
        &["--required-authority-id", AUTHORITY, "--json"],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(verdict(&stdout)["stage_reached"], 8, "{stdout}");
}

#[test]
fn wrong_pin_refuses_the_key_list_before_any_proof() {
    let f = write(
        &customer_proof(AUTHORITY, KEY_VERSION),
        &key_list_signed_by(IDENTITY_SEED),
    );
    let wrong_pin = fingerprint(
        &SigningKey::from_bytes(&OTHER_IDENTITY_SEED)
            .verifying_key()
            .to_bytes(),
    );

    let (code, stdout, stderr) = verify(&f, &wrong_pin, &["--json"]);
    assert_eq!(code, 2, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("trust-chain manifest verification FAILED"),
        "{stderr}"
    );
    // The pin may be any authority's identity, so the refusal must not name Nanorix.
    assert!(
        stderr.contains("is not the pinned identity") && !stderr.contains("Nanorix"),
        "{stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "no proof verdict expected: {stdout}"
    );
}

#[test]
fn key_version_not_in_the_list_stops_at_stage_6() {
    let f = write(
        &customer_proof(AUTHORITY, "2"),
        &key_list_signed_by(IDENTITY_SEED),
    );

    let (code, stdout, stderr) = verify(&f, &customer_pin(), &["--json"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let v = verdict(&stdout);
    assert_eq!(v["valid"], false, "{stdout}");
    assert_eq!(v["stage_reached"], 6, "{stdout}");
    assert_eq!(
        v["failure_reason"]["type"], "signing_key_version_unknown",
        "{stdout}"
    );
    assert_eq!(v["failure_reason"]["version"], "2", "{stdout}");
}

#[test]
fn key_list_signed_by_another_identity_is_refused_under_the_customer_pin() {
    let proof = customer_proof(AUTHORITY, KEY_VERSION);

    let other = write(&proof, &key_list_signed_by(OTHER_IDENTITY_SEED));
    let (code, stdout, stderr) = verify(&other, &customer_pin(), &["--json"]);
    assert_eq!(code, 2, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("trust-chain manifest verification FAILED"),
        "{stderr}"
    );

    // Same list, relabelled with the customer's identity key and fingerprint
    // but still carrying the other identity's signature.
    let mut relabelled = key_list_signed_by(OTHER_IDENTITY_SEED);
    let genuine = key_list_signed_by(IDENTITY_SEED);
    relabelled.identity_fingerprint = genuine.identity_fingerprint.clone();
    relabelled.identity_public_key_b64 = genuine.identity_public_key_b64.clone();
    assert_ne!(relabelled.manifest_signature, genuine.manifest_signature);
    let forged = write(&proof, &relabelled);
    let (code, stdout, stderr) = verify(&forged, &customer_pin(), &["--json"]);
    assert_eq!(code, 2, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("trust-chain manifest verification FAILED"),
        "{stderr}"
    );
}

#[test]
fn proof_naming_an_authority_the_list_does_not_carry_stops_at_stage_6() {
    let f = write(
        &customer_proof("us-kms-nanorix-v1", KEY_VERSION),
        &key_list_signed_by(IDENTITY_SEED),
    );

    let (code, stdout, stderr) = verify(&f, &customer_pin(), &["--json"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let v = verdict(&stdout);
    assert_eq!(v["stage_reached"], 6, "{stdout}");
    assert_eq!(
        v["failure_reason"]["type"], "signing_key_version_unknown",
        "{stdout}"
    );
}
