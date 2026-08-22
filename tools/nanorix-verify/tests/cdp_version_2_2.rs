//! `cdp_version: "2.2"` is verified exactly as `"2.1"`.
//!
//! CDP 2.2 (ADR-053 policy-denial summary + ADR-056 customer-declared activity
//! root) changes what a document may carry, not how it is canonicalised,
//! hashed or signed. The verifier therefore routes 2.2 through the 2.1 arm at
//! every version switch. These tests pin that from the outside, against a
//! committed corpus fixture, so a future "2.2-specific" branch that drifts from
//! the 2.1 recompute is caught here before it reaches a customer.
//!
//! The version string sits inside the canonical view, so a genuine 2.1 proof
//! that is merely re-labelled is NOT a genuine 2.2 proof — its signature no
//! longer verifies. Re-labelling and re-signing over the recomputed canonical
//! hash (the same operation the fixture generator's `sign_in_place` performs)
//! is what produces one.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::{verify_auditproof, FailureReason, SignatureFailureReason, VerifierPolicy};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("corpus")
}

fn read_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The first committed success fixture — a genuine, generator-signed 2.1 proof.
fn genuine_v2_1_fixture() -> Value {
    read_json(
        &corpus_root()
            .join("01_single_capsule_success")
            .join("0000_v2_1_signed.json"),
    )
}

/// Sign `proof` over its recomputed canonical hash and attach the attestation
/// block, exactly as `fixtures/generator.rs::sign_in_place` does. The key
/// differs from the corpus key; stage 7 verifies against the embedded key, so
/// the verdict does not depend on which key signed.
fn resign_in_place(proof: &mut Value, key: &SigningKey) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let canonical = recompute_canonical_hash(proof);
    let sig = key.sign(canonical.as_bytes());
    proof["attestation"]["public_key"] = Value::String(format!(
        "base64:{}",
        b64.encode(key.verifying_key().to_bytes())
    ));
    proof["attestation"]["signature"] =
        Value::String(format!("base64:{}", b64.encode(sig.to_bytes())));
}

#[test]
fn a_resigned_2_2_relabel_of_a_genuine_2_1_fixture_verifies_identically() {
    let original = genuine_v2_1_fixture();
    let baseline = verify_auditproof(&original, &[], &VerifierPolicy::default());
    assert!(baseline.valid, "corpus fixture must verify: {baseline:?}");
    assert_eq!(baseline.stage_reached, 7);

    let mut relabelled = original.clone();
    relabelled["cdp_version"] = Value::String("2.2".into());
    resign_in_place(&mut relabelled, &SigningKey::from_bytes(&[0x22u8; 32]));

    let result = verify_auditproof(&relabelled, &[], &VerifierPolicy::default());
    assert!(result.valid, "re-signed 2.2 must verify: {result:?}");
    assert_eq!(result.failure_reason, None);
    assert_eq!(result.stage_reached, baseline.stage_reached);

    // Everything the verdict reports is identical except the version it names.
    let mut expected_metadata = baseline.metadata.clone();
    expected_metadata.cdp_version = Some("2.2".into());
    assert_eq!(result.metadata, expected_metadata);
}

#[test]
fn the_version_string_is_canonical_bound_so_a_bare_relabel_fails_at_the_signature() {
    let mut relabelled = genuine_v2_1_fixture();
    relabelled["cdp_version"] = Value::String("2.2".into());

    let result = verify_auditproof(&relabelled, &[], &VerifierPolicy::default());
    assert!(!result.valid);
    assert_eq!(
        result.failure_reason,
        Some(FailureReason::SignatureMismatch {
            reason: SignatureFailureReason::DoesNotVerify
        }),
        "2.2 must pass the version gate and be rejected by the signature, \
         never reported as cdp_version_unsupported"
    );
    assert_eq!(result.stage_reached, 7);
}

#[test]
fn an_unverifiable_signing_mode_is_rejected_the_same_way_under_2_2() {
    let mut proof = genuine_v2_1_fixture();
    proof["cdp_version"] = Value::String("2.2".into());
    proof["signing_mode"] = Value::String("dual_signature".into());
    resign_in_place(&mut proof, &SigningKey::from_bytes(&[0x22u8; 32]));

    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert_eq!(
        result.failure_reason,
        Some(FailureReason::AlgorithmUnsupported {
            found: "signing_mode=dual_signature".into()
        })
    );
    assert_eq!(result.stage_reached, 4);
}

/// Corpus category 07 is the list of versions this verifier refuses. "2.2"
/// must never appear there: the category would then pin the opposite of what
/// the version gate does.
#[test]
fn corpus_category_07_does_not_list_2_2_as_unsupported() {
    let dir = corpus_root().join("07_failure_version_unsupported");
    let mut seen = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read category 07") {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".json") || name.ends_with(".expected.json") {
            continue;
        }
        let proof = read_json(&path);
        let version = proof["cdp_version"].as_str().unwrap_or("").to_string();
        assert_ne!(version, "2.2", "{name} pins 2.2 as unsupported");
        seen.push(version);
    }
    assert_eq!(seen.len(), 10, "category 07 should hold 10 fixtures");
}
