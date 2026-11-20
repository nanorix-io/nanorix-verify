//! Batch and single-file mode report "verified" only for a proof whose signing
//! key chains to the key list given with `--trust-chain` (stage 8). A valid
//! signature that matches only the key the file carries (stage 7) is
//! "not_anchored"; anything lower, or invalid, is "not_verified". Exit 0 means
//! verified and nothing else. Pinned through the real binary:
//!
//! 1. genuine proof, `--trust-chain` and its pin: verified, exit 0.
//! 2. the same proof without `--trust-chain`: not_anchored, exit 4.
//! 3. a proof self-signed with a fresh key, under `--trust-chain`:
//!    not_verified, exit 1.
//! 4. the same self-signed proof without `--trust-chain`: not_anchored, exit
//!    4, which is why that status never counts as verified.
//! 5. an unsigned file: not_verified, exit 1, with or without `--trust-chain`
//!    (single-file mode exits 3 for it).
//! 6. the summary counts the three statuses apart, in text and JSON.

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
const SIGNING_SEED: [u8; 32] = [0x41; 32];
const IDENTITY_SEED: [u8; 32] = [0x42; 32];
const FRESH_SEED: [u8; 32] = [0x77; 32];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn fingerprint(pubkey: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(pubkey)))
}

fn build_key_list() -> TrustChainManifest {
    let signing_pub = SigningKey::from_bytes(&SIGNING_SEED)
        .verifying_key()
        .to_bytes();
    let authorities: HashMap<String, AuthorityRecord> = serde_json::from_str(&format!(
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
    ))
    .expect("authorities file parses");
    TrustChainManifest::build_and_sign(
        "1",
        "2026-11-01T00:00:00Z",
        authorities,
        &SigningKey::from_bytes(&IDENTITY_SEED),
    )
}

fn pin() -> String {
    fingerprint(
        &SigningKey::from_bytes(&IDENTITY_SEED)
            .verifying_key()
            .to_bytes(),
    )
}

/// A 2.1 proof naming the customer authority, signed with `seed` over its
/// recomputed canonical hash. The customer's own seed gives a genuine proof;
/// any other seed gives a proof signed with a key the key list does not hold.
fn proof_signed_with(seed: [u8; 32]) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json");
    let mut proof: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read fixture")).expect("parse");
    proof["authority_id"] = Value::String(AUTHORITY.into());
    proof["signing_key_version"] = Value::String(KEY_VERSION.into());
    let key = SigningKey::from_bytes(&seed);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    proof["attestation"]["public_key"] =
        Value::String(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = Value::String(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

/// The genuine proof with its signature removed: the chain still reproduces,
/// and nothing signs it.
fn unsigned_proof() -> Value {
    let mut proof = proof_signed_with(SIGNING_SEED);
    let attestation = proof["attestation"].as_object_mut().expect("attestation");
    attestation.remove("signature");
    attestation.remove("public_key");
    proof
}

struct Corpus {
    dir: tempfile::TempDir,
    key_list: PathBuf,
}

fn corpus(files: &[(&str, Value)]) -> Corpus {
    let dir = tempfile::tempdir().expect("tempdir");
    let proofs = dir.path().join("proofs");
    std::fs::create_dir(&proofs).unwrap();
    for (name, proof) in files {
        std::fs::write(proofs.join(name), serde_json::to_vec_pretty(proof).unwrap()).unwrap();
    }
    let key_list = dir.path().join("trust-chain.json");
    std::fs::write(
        &key_list,
        serde_json::to_vec_pretty(&build_key_list()).unwrap(),
    )
    .unwrap();
    Corpus { dir, key_list }
}

/// Runs `nanorix-verify [--trust-chain L --identity-fingerprint P] [--json] batch DIR`.
/// The global flags go before `batch`.
fn batch(c: &Corpus, anchored: bool, json: bool) -> (i32, String) {
    let mut cmd = Command::new(BIN_PATH);
    if anchored {
        cmd.arg("--trust-chain")
            .arg(&c.key_list)
            .arg("--identity-fingerprint")
            .arg(pin());
    }
    if json {
        cmd.arg("--json");
    }
    let out = cmd
        .arg("batch")
        .arg(c.dir.path().join("proofs"))
        .output()
        .expect("spawn nanorix-verify batch");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn json_run(c: &Corpus, anchored: bool) -> (i32, Value) {
    let (code, text) = batch(c, anchored, true);
    let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("json ({e}): {text}"));
    (code, v)
}

fn status_of(v: &Value, file: &str) -> String {
    v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with(file))
        .unwrap_or_else(|| panic!("{file} missing: {v}"))["status"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn genuine_proof_with_trust_chain_and_pin_is_verified() {
    let c = corpus(&[("genuine.json", proof_signed_with(SIGNING_SEED))]);
    let (code, v) = json_run(&c, true);
    assert_eq!(code, 0, "{v}");
    assert_eq!(status_of(&v, "genuine.json"), "verified", "{v}");
    assert_eq!(v["summary"]["verified"], 1, "{v}");
    assert_eq!(v["summary"]["not_anchored"], 0, "{v}");
    assert_eq!(v["summary"]["not_verified"], 0, "{v}");
    assert_eq!(v["files"][0]["stage_reached"], 8, "{v}");
}

#[test]
fn the_same_proof_without_trust_chain_is_not_anchored_and_exits_four() {
    let c = corpus(&[("genuine.json", proof_signed_with(SIGNING_SEED))]);
    let (code, v) = json_run(&c, false);
    assert_eq!(status_of(&v, "genuine.json"), "not_anchored", "{v}");
    assert_eq!(v["summary"]["verified"], 0, "{v}");
    assert_eq!(v["summary"]["not_anchored"], 1, "{v}");
    assert_eq!(v["summary"]["not_verified"], 0, "{v}");
    assert_eq!(v["summary"]["total"], 1, "{v}");
    assert_eq!(v["files"][0]["stage_reached"], 7, "{v}");
    // Not anchored is never exit 0; single-file mode exits 4 for it too.
    assert_eq!(code, 4, "{v}");

    let (code, text) = batch(&c, false, false);
    assert_eq!(code, 4, "{text}");
    assert!(
        text.lines().any(|l| l.starts_with("not anchored ")
            && l.contains("signature valid")
            && l.contains("key NOT anchored to a trust root")),
        "{text}"
    );
    assert!(text.contains("0 verified, 1 not anchored"), "{text}");
    assert!(!text.contains("1 / 1 verified"), "{text}");
}

#[test]
fn proof_self_signed_with_a_fresh_key_is_not_verified_under_trust_chain() {
    let c = corpus(&[("forged.json", proof_signed_with(FRESH_SEED))]);

    let (code, v) = json_run(&c, true);
    assert_eq!(code, 1, "{v}");
    assert_eq!(status_of(&v, "forged.json"), "not_verified", "{v}");
    assert_eq!(v["summary"]["verified"], 0, "{v}");
    assert_eq!(v["summary"]["not_anchored"], 0, "{v}");
    assert_eq!(v["summary"]["not_verified"], 1, "{v}");

    // Without the key list the same file reaches stage 7 on its own key, which
    // is why stage 7 can never be counted as verified.
    let (code, v) = json_run(&c, false);
    assert_eq!(status_of(&v, "forged.json"), "not_anchored", "{v}");
    assert_eq!(code, 4, "{v}");
}

#[test]
fn unsigned_file_is_not_verified_with_or_without_trust_chain() {
    let c = corpus(&[("unsigned.json", unsigned_proof())]);
    for anchored in [false, true] {
        let (code, v) = json_run(&c, anchored);
        assert_eq!(code, 1, "anchored={anchored}: {v}");
        assert_eq!(status_of(&v, "unsigned.json"), "not_verified", "{v}");
        assert_eq!(v["summary"]["not_verified"], 1, "{v}");
        assert_eq!(v["summary"]["verified"], 0, "{v}");
        assert_eq!(v["summary"]["not_anchored"], 0, "{v}");
    }
}

#[test]
fn summary_counts_the_three_statuses_apart() {
    let c = corpus(&[
        ("a_genuine.json", proof_signed_with(SIGNING_SEED)),
        ("b_forged.json", proof_signed_with(FRESH_SEED)),
        ("c_unsigned.json", unsigned_proof()),
    ]);
    let (code, v) = json_run(&c, true);
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["summary"]["verified"], 1, "{v}");
    assert_eq!(v["summary"]["not_anchored"], 0, "{v}");
    assert_eq!(v["summary"]["not_verified"], 2, "{v}");
    assert_eq!(v["summary"]["total"], 3, "{v}");

    let (code, text) = batch(&c, true, false);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("1 verified, 0 not anchored, 2 not verified (total 3)"),
        "{text}"
    );

    // No key list: the genuine and the forged file are both not anchored.
    let (code, v) = json_run(&c, false);
    assert_eq!(code, 1, "{v}");
    assert_eq!(v["summary"]["verified"], 0, "{v}");
    assert_eq!(v["summary"]["not_anchored"], 2, "{v}");
    assert_eq!(v["summary"]["not_verified"], 1, "{v}");
}

#[test]
fn empty_corpus_json_carries_the_not_anchored_key() {
    let c = corpus(&[]);
    let (code, v) = json_run(&c, false);
    assert_eq!(code, 2, "nothing was verified: {v}");
    assert_eq!(v["summary"]["not_anchored"], 0, "{v}");
    assert_eq!(v["summary"]["total"], 0, "{v}");
}

#[test]
fn batch_with_verified_and_not_anchored_files_exits_four() {
    // Without the key list both files are not anchored and none is not
    // verified, so the batch exits 4; only an all-verified batch exits 0.
    let c = corpus(&[
        ("a_genuine.json", proof_signed_with(SIGNING_SEED)),
        ("b_forged.json", proof_signed_with(FRESH_SEED)),
    ]);
    let (code, v) = json_run(&c, false);
    assert_eq!(v["summary"]["not_anchored"], 2, "{v}");
    assert_eq!(v["summary"]["not_verified"], 0, "{v}");
    assert_eq!(code, 4, "{v}");

    let only_genuine = corpus(&[("a_genuine.json", proof_signed_with(SIGNING_SEED))]);
    let (code, v) = json_run(&only_genuine, true);
    assert_eq!(v["summary"]["verified"], 1, "{v}");
    assert_eq!(code, 0, "{v}");
}

/// Runs `nanorix-verify [--trust-chain L --identity-fingerprint P] [--json] FILE`.
fn single(c: &Corpus, file: &str, anchored: bool, json: bool) -> (i32, String, String) {
    let mut cmd = Command::new(BIN_PATH);
    if anchored {
        cmd.arg("--trust-chain")
            .arg(&c.key_list)
            .arg("--identity-fingerprint")
            .arg(pin());
    }
    if json {
        cmd.arg("--json");
    }
    let out = cmd
        .arg(c.dir.path().join("proofs").join(file))
        .output()
        .expect("spawn nanorix-verify");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn single_json(c: &Corpus, file: &str, anchored: bool) -> (i32, Value) {
    let (code, stdout, stderr) = single(c, file, anchored, true);
    let v: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("json ({e}): {stdout}{stderr}"));
    (code, v)
}

#[test]
fn single_file_proof_self_signed_with_a_fresh_key_is_not_anchored_and_exits_four() {
    let c = corpus(&[("forged.json", proof_signed_with(FRESH_SEED))]);
    let (code, v) = single_json(&c, "forged.json", false);
    assert_eq!(v["status"], "not_anchored", "{v}");
    assert_eq!(v["valid"], true, "{v}");
    assert_eq!(v["stage_reached"], 7, "{v}");
    assert_eq!(code, 4, "{v}");

    let (code, stdout, stderr) = single(&c, "forged.json", false, false);
    assert_eq!(code, 4, "{stdout}{stderr}");
    assert!(stderr.contains("note: exiting 4"), "{stderr}");
    assert!(stdout.contains("key NOT anchored"), "{stdout}");

    // Under the key list the same file is not verified.
    let (code, v) = single_json(&c, "forged.json", true);
    assert_eq!(v["status"], "not_verified", "{v}");
    assert_eq!(code, 1, "{v}");
}

#[test]
fn single_file_proof_with_a_matching_trust_chain_is_verified_and_exits_zero() {
    let c = corpus(&[("genuine.json", proof_signed_with(SIGNING_SEED))]);
    let (code, v) = single_json(&c, "genuine.json", true);
    assert_eq!(v["status"], "verified", "{v}");
    assert_eq!(v["stage_reached"], 8, "{v}");
    assert_eq!(code, 0, "{v}");

    // The same file without the key list: not anchored, exit 4.
    let (code, v) = single_json(&c, "genuine.json", false);
    assert_eq!(v["status"], "not_anchored", "{v}");
    assert_eq!(code, 4, "{v}");
}

#[test]
fn single_file_unsigned_proof_is_not_verified_and_exits_three() {
    let c = corpus(&[("unsigned.json", unsigned_proof())]);
    for anchored in [false, true] {
        let (code, v) = single_json(&c, "unsigned.json", anchored);
        assert_eq!(v["status"], "not_verified", "anchored={anchored}: {v}");
        assert_eq!(code, 3, "anchored={anchored}: {v}");
    }
}
