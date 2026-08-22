//! The stage-2 gate on `customer_declared_activity_root` (ADR-056), pinned
//! from the outside through `verify_auditproof`.
//!
//! Two things the gate must hold:
//!
//! 1. **The root is signed only on cdp_version 2.1 / 2.2.** In 1.0 the signed
//!    message is `final_hash`; in 2.0 it is the `document_hash` field. A root
//!    on either sits outside the signature, so anyone holding the document can
//!    write one and then present any bytes as "the record" it commits to. The
//!    verdict for such a document is `UnsignedFieldPopulated` at stage 2 — the
//!    same verdict the reserved attestation slots get — and
//!    `customer_declared_activity_checked` is never `true`.
//!
//! 2. **On 2.1 / 2.2 the root must be a `sha512:` + 128-lowercase-hex string**
//!    (bare 128-hex accepted). Any other shape is `FieldMalformed` at stage 2,
//!    before the chain walk and before any recompute consumes it, so the
//!    verdict blames the field rather than the signature or the record. The
//!    empty string is malformed, not absent.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::{
    compute_customer_declared_activity_root, strip_hash_prefix, verify_auditproof, FailureReason,
    VerifierPolicy,
};
use serde_json::{json, Value};
use std::path::Path;

const VECTORS: &str = include_str!("../fixtures/customer_declared_activity_root_vectors.json");

fn three_vector() -> (Vec<u8>, String) {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "three")
        .expect("three vector");
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

fn attach_signature(proof: &mut Value, key: &SigningKey, message: &str) {
    let b64 = base64::engine::general_purpose::STANDARD;
    let sig = key.sign(message.as_bytes());
    proof["attestation"] = json!({
        "public_key": format!("base64:{}", b64.encode(key.verifying_key().to_bytes())),
        "signature": format!("base64:{}", b64.encode(sig.to_bytes())),
    });
}

/// A genuine 1.0 proof: the fixture's chain and `final_hash`, signed over the
/// prefix-stripped `final_hash` — the 1.0 signed message.
fn genuine_v1_0() -> Value {
    let fixture = genuine_v2_1_fixture();
    let mut proof = json!({
        "cdp_version": "1.0",
        "capsule_id": fixture["capsule_id"],
        "destroyed_at": fixture["destroyed_at"],
        "chain": fixture["chain"],
        "final_hash": fixture["final_hash"],
    });
    let message = strip_hash_prefix(fixture["final_hash"].as_str().unwrap()).to_string();
    attach_signature(&mut proof, &SigningKey::from_bytes(&[0x10u8; 32]), &message);
    proof
}

/// A genuine 2.0 proof: the fixture's chain, signed over its `document_hash`
/// field — the 2.0 signed message, which is read, not recomputed.
fn genuine_v2_0() -> Value {
    let fixture = genuine_v2_1_fixture();
    let document_hash = format!("sha512:{}", "ab".repeat(64));
    let mut proof = json!({
        "cdp_version": "2.0",
        "capsule_id": fixture["capsule_id"],
        "destroyed_at": fixture["destroyed_at"],
        "chain": fixture["chain"],
        "final_hash": fixture["final_hash"],
        "document_hash": document_hash,
    });
    let message = strip_hash_prefix(&document_hash).to_string();
    attach_signature(&mut proof, &SigningKey::from_bytes(&[0x20u8; 32]), &message);
    proof
}

/// A genuine 2.2 proof carrying `root`, signed over its recomputed canonical
/// hash the way the fixture generator signs.
fn signed_v2_2_with_root(root: Value) -> Value {
    let mut proof = genuine_v2_1_fixture();
    proof["cdp_version"] = Value::String("2.2".into());
    proof["customer_declared_activity_root"] = root;
    let canonical = recompute_canonical_hash(&proof);
    attach_signature(
        &mut proof,
        &SigningKey::from_bytes(&[0x56u8; 32]),
        &canonical,
    );
    proof
}

fn with_record(record: &[u8]) -> VerifierPolicy {
    VerifierPolicy {
        customer_activity: Some(record.to_vec()),
        ..VerifierPolicy::default()
    }
}

fn unsigned_root() -> FailureReason {
    FailureReason::UnsignedFieldPopulated {
        field: "customer_declared_activity_root".into(),
    }
}

fn malformed(reason: &str) -> FailureReason {
    FailureReason::FieldMalformed {
        field: "customer_declared_activity_root".into(),
        reason: reason.into(),
    }
}

/// The attack the gate exists to stop: a genuine 1.0 proof, a root the
/// attacker computed over their own record, and that record supplied as the
/// sidecar. Without the gate the ladder reported "matched" and
/// `checked: true` — over a root nothing signed.
#[test]
fn an_injected_root_on_a_genuine_1_0_proof_is_unsigned_not_checked() {
    let baseline = verify_auditproof(&genuine_v1_0(), &[], &VerifierPolicy::default());
    assert!(
        baseline.valid,
        "the 1.0 construction must be genuine: {baseline:?}"
    );
    assert_eq!(baseline.stage_reached, 7);
    assert_eq!(baseline.metadata.customer_declared_activity_root, None);
    assert_eq!(baseline.metadata.customer_declared_activity_checked, None);

    let attacker_record = b"{\"event\":\"anything the attacker wants\"}\n";
    let attacker_root = compute_customer_declared_activity_root(attacker_record);
    let mut proof = genuine_v1_0();
    proof["customer_declared_activity_root"] = Value::String(attacker_root);

    for policy in [with_record(attacker_record), VerifierPolicy::default()] {
        let result = verify_auditproof(&proof, &[], &policy);
        assert!(!result.valid, "{result:?}");
        assert_eq!(result.failure_reason, Some(unsigned_root()));
        assert_eq!(result.stage_reached, 2);
        assert_ne!(
            result.metadata.customer_declared_activity_checked,
            Some(true),
            "a root no signature covers must never be reported as checked"
        );
    }
}

/// Same attack on 2.0, where the signed message is the `document_hash` field
/// and the root is equally outside it.
#[test]
fn an_injected_root_on_a_genuine_2_0_proof_is_unsigned_not_checked() {
    let baseline = verify_auditproof(&genuine_v2_0(), &[], &VerifierPolicy::default());
    assert!(
        baseline.valid,
        "the 2.0 construction must be genuine: {baseline:?}"
    );
    assert_eq!(baseline.stage_reached, 7);

    let (record, root) = three_vector();
    let mut proof = genuine_v2_0();
    proof["customer_declared_activity_root"] = Value::String(root);

    let result = verify_auditproof(&proof, &[], &with_record(&record));
    assert!(!result.valid);
    assert_eq!(result.failure_reason, Some(unsigned_root()));
    assert_eq!(result.stage_reached, 2);
    assert_ne!(
        result.metadata.customer_declared_activity_checked,
        Some(true)
    );
}

/// The version gate precedes the shape gate: a malformed root on 1.0 is
/// still reported as unsigned, because that is the more fundamental defect.
#[test]
fn on_an_unsigned_version_the_shape_is_not_consulted() {
    let mut proof = genuine_v1_0();
    proof["customer_declared_activity_root"] = json!(7);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert_eq!(result.failure_reason, Some(unsigned_root()));
    assert_eq!(result.stage_reached, 2);
}

/// `null` is absence on every version — the emitter writes the key with an
/// explicit `null` when the customer did not opt in.
#[test]
fn a_null_root_is_absence_on_every_version() {
    for mut proof in [genuine_v1_0(), genuine_v2_0()] {
        proof["customer_declared_activity_root"] = Value::Null;
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "{result:?}");
        assert_eq!(result.metadata.customer_declared_activity_root, None);
        assert_eq!(result.metadata.customer_declared_activity_checked, None);
    }
}

/// On 2.2 every shape no signer emits is `FieldMalformed` at stage 2, with
/// the pinned reason, whether or not a record is supplied. The proofs are
/// signed over the malformed value, so the signature would have verified —
/// which is exactly why the shape has to be rejected before it.
#[test]
fn a_malformed_root_on_2_2_is_field_malformed_at_stage_2() {
    let (record, root) = three_vector();
    let upper = format!("sha512:{}", strip_hash_prefix(&root).to_uppercase());
    let cases: Vec<(Value, &str)> = vec![
        (json!(""), "empty string"),
        (json!(7), "expected a JSON string"),
        (json!(false), "expected a JSON string"),
        (json!({ "sha512": root }), "expected a JSON string"),
        (json!([root]), "expected a JSON string"),
        (
            json!("abc"),
            "expected sha512: followed by 128 lowercase hex characters",
        ),
        (
            json!(upper),
            "expected sha512: followed by 128 lowercase hex characters",
        ),
        (
            json!(format!("sha256:{}", strip_hash_prefix(&root))),
            "expected sha512: followed by 128 lowercase hex characters",
        ),
    ];
    for (value, reason) in cases {
        let proof = signed_v2_2_with_root(value.clone());
        for policy in [with_record(&record), VerifierPolicy::default()] {
            let result = verify_auditproof(&proof, &[], &policy);
            assert!(!result.valid, "{value}: {result:?}");
            assert_eq!(result.failure_reason, Some(malformed(reason)), "{value}");
            assert_eq!(result.stage_reached, 2, "{value}");
            assert_ne!(
                result.metadata.customer_declared_activity_checked,
                Some(true)
            );
        }
    }
}

/// The accepted shapes still verify end to end, and the bare-hex form is
/// compared equal to the prefixed one.
#[test]
fn well_formed_roots_on_2_2_reach_the_sidecar_check() {
    let (record, root) = three_vector();
    let bare = strip_hash_prefix(&root).to_string();
    for value in [root.clone(), bare] {
        let proof = signed_v2_2_with_root(Value::String(value.clone()));
        let checked = verify_auditproof(&proof, &[], &with_record(&record));
        assert!(checked.valid, "{checked:?}");
        assert_eq!(checked.stage_reached, 7);
        assert_eq!(
            checked.metadata.customer_declared_activity_root.as_deref(),
            Some(value.as_str())
        );
        assert_eq!(
            checked.metadata.customer_declared_activity_checked,
            Some(true)
        );

        let declared = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(declared.valid);
        assert_eq!(
            declared.metadata.customer_declared_activity_checked,
            Some(false)
        );
    }
}
