//! `nanorix-verify --customer-activity <record>` end to end (ADR-056).
//!
//! The proof carries `customer_declared_activity_root`; the customer holds the
//! record. Four situations, each pinned against the real binary so the exit
//! code and the verdict wording — the two things an auditor's script and an
//! auditor's eyes read — cannot drift apart from the library:
//!
//! 1. record + root, matching → exit 0, checked.
//! 2. record + root, different → exit 1, `customer_declared_activity_root_mismatch`.
//! 3. record + proof without a root → exit 1, `required_field_missing`.
//! 4. root + no record → exit 0, disclosed as declared, not checked.
//!
//! And one usage rule: a record belongs to one proof, so batch mode refuses it.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");
const VECTORS: &str = include_str!("../fixtures/customer_declared_activity_root_vectors.json");

fn vector(name: &str) -> (Vec<u8>, String) {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap_or_else(|| panic!("vector {name}"));
    (
        v["input_utf8"].as_str().unwrap().as_bytes().to_vec(),
        v["root"].as_str().unwrap().to_string(),
    )
}

fn genuine_v2_1_fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json");
    serde_json::from_slice(&std::fs::read(&path).expect("read fixture")).expect("parse fixture")
}

/// A genuine 2.2 proof declaring `root`, signed over its recomputed canonical
/// hash the way the fixture generator signs.
fn signed_v2_2_with_root(root: &str) -> Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let key = SigningKey::from_bytes(&[0x56u8; 32]);
    let mut proof = genuine_v2_1_fixture();
    proof["cdp_version"] = Value::String("2.2".into());
    proof["customer_declared_activity_root"] = Value::String(root.to_string());
    let canonical = recompute_canonical_hash(&proof);
    let sig = key.sign(canonical.as_bytes());
    proof["attestation"]["public_key"] = Value::String(format!(
        "base64:{}",
        b64.encode(key.verifying_key().to_bytes())
    ));
    proof["attestation"]["signature"] =
        Value::String(format!("base64:{}", b64.encode(sig.to_bytes())));
    proof
}

struct Files {
    _dir: tempfile::TempDir,
    proof: PathBuf,
    record: PathBuf,
}

fn write(proof: &Value, record: &[u8]) -> Files {
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_path = dir.path().join("proof.json");
    let record_path = dir.path().join("activity_events.jsonl");
    std::fs::write(&proof_path, serde_json::to_vec_pretty(proof).unwrap()).unwrap();
    std::fs::write(&record_path, record).unwrap();
    Files {
        _dir: dir,
        proof: proof_path,
        record: record_path,
    }
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN_PATH).args(args).output().expect("spawn");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn record_and_matching_root_verify_with_exit_zero() {
    let (record, root) = vector("three");
    let f = write(&signed_v2_2_with_root(&root), &record);

    let (code, stdout, _) = run(&[
        f.proof.to_str().unwrap(),
        "--customer-activity",
        f.record.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("Signature valid"), "{stdout}");
    assert!(
        stdout.contains(&format!("Customer-declared activity root: {root}")),
        "{stdout}"
    );
    assert!(stdout.contains("matched"), "{stdout}");
    assert!(!stdout.contains("NOT checked"), "{stdout}");

    let (code, stdout, _) = run(&[
        f.proof.to_str().unwrap(),
        "--customer-activity",
        f.record.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("json verdict");
    assert_eq!(v["valid"], true);
    assert_eq!(v["stage_reached"], 7);
    assert_eq!(v["metadata"]["customer_declared_activity_root"], root);
    assert_eq!(v["metadata"]["customer_declared_activity_checked"], true);
}

#[test]
fn record_and_different_root_fail_with_mismatch_naming_both_roots() {
    let (_, root) = vector("three");
    let (other_record, other_root) = vector("single");
    let f = write(&signed_v2_2_with_root(&root), &other_record);

    let (code, stdout, _) = run(&[
        f.proof.to_str().unwrap(),
        "--customer-activity",
        f.record.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 1, "stdout:\n{stdout}");
    let v: Value = serde_json::from_str(&stdout).expect("json verdict");
    assert_eq!(v["valid"], false);
    assert_eq!(v["stage_reached"], 3);
    assert_eq!(
        v["failure_reason"],
        serde_json::json!({
            "type": "customer_declared_activity_root_mismatch",
            "claimed": root,
            "computed": other_root,
        })
    );

    let (code, stdout, _) = run(&[
        f.proof.to_str().unwrap(),
        "--customer-activity",
        f.record.to_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    assert!(stdout.contains("Verification FAILED"), "{stdout}");
    assert!(
        stdout.contains("customer_declared_activity_root_mismatch"),
        "{stdout}"
    );
}

#[test]
fn record_against_a_proof_without_a_root_fails_closed() {
    let (record, _) = vector("three");
    let f = write(&genuine_v2_1_fixture(), &record);

    let (code, stdout, _) = run(&[
        f.proof.to_str().unwrap(),
        "--customer-activity",
        f.record.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(code, 1, "stdout:\n{stdout}");
    let v: Value = serde_json::from_str(&stdout).expect("json verdict");
    assert_eq!(v["valid"], false);
    assert_eq!(
        v["failure_reason"],
        serde_json::json!({
            "type": "required_field_missing",
            "field": "customer_declared_activity_root",
        })
    );
    assert!(v["metadata"]
        .get("customer_declared_activity_root")
        .is_none());
}

#[test]
fn root_without_a_record_is_disclosed_not_failed() {
    let (record, root) = vector("three");
    let f = write(&signed_v2_2_with_root(&root), &record);

    let (code, stdout, _) = run(&[f.proof.to_str().unwrap()]);
    assert_eq!(code, 0, "stdout:\n{stdout}");
    assert!(stdout.contains("Signature valid"), "{stdout}");
    assert!(stdout.contains("declared, NOT checked"), "{stdout}");
    assert!(stdout.contains("--customer-activity"), "{stdout}");

    let (code, stdout, _) = run(&[f.proof.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("json verdict");
    assert_eq!(v["valid"], true);
    assert_eq!(v["failure_reason"], Value::Null);
    assert_eq!(v["metadata"]["customer_declared_activity_root"], root);
    assert_eq!(v["metadata"]["customer_declared_activity_checked"], false);
}

/// A proof that declares no root says nothing about one — neither key
/// appears in the verdict, so existing consumers see byte-identical output.
#[test]
fn a_proof_without_a_root_reports_nothing_about_one() {
    let (record, _) = vector("three");
    let f = write(&genuine_v2_1_fixture(), &record);
    let (code, stdout, _) = run(&[f.proof.to_str().unwrap(), "--json"]);
    assert_eq!(code, 0);
    let v: Value = serde_json::from_str(&stdout).expect("json verdict");
    assert!(v["metadata"]
        .get("customer_declared_activity_root")
        .is_none());
    assert!(v["metadata"]
        .get("customer_declared_activity_checked")
        .is_none());
}

#[test]
fn batch_mode_refuses_a_single_record() {
    let (record, root) = vector("three");
    let f = write(&signed_v2_2_with_root(&root), &record);
    let dir = f.proof.parent().unwrap().to_str().unwrap().to_string();
    let (code, _, stderr) = run(&[
        "--customer-activity",
        f.record.to_str().unwrap(),
        "batch",
        &dir,
    ]);
    assert_eq!(code, 2, "stderr:\n{stderr}");
    assert!(stderr.contains("exactly one proof"), "{stderr}");
}
