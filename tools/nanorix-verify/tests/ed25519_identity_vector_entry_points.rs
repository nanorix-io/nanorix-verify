//! The public entry points must refuse the `identity_key_identity_R_S0` vector.
//!
//! Key = the identity point, signature = identity R and S = 0. Plain Ed25519
//! verification accepts that pair for every message, so each test first proves
//! the document is otherwise sound (a genuine signature is accepted) and then
//! swaps in the vector, which only the strict call site can refuse.

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nanorix_verify::{
    build_pubkey_bundle, verify_boundary_attestation, verify_pubkey_bundle, verify_receipt_bundle,
    verify_receipt_bundle_detailed, AuthorityRecord, BoundaryFailureReason, BundleError,
    PortableReceiptBundle, PubKeyEntry, PubkeyBundleError, SignatureFailureReason,
    TrustChainManifest, VerifierPolicy,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn identity_vector() -> ([u8; 32], [u8; 64]) {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/ed25519_strict_negative.json"
    ))
    .unwrap();
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "identity_key_identity_R_S0")
        .expect("vector present");
    let unhex = |s: &str| -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    };
    let pk: [u8; 32] = unhex(v["public_key_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let sig: [u8; 64] = unhex(v["signature_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    (pk, sig)
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn the_vector_verifies_under_plain_verify_for_every_message() {
    let (pk, sig) = identity_vector();
    let key = VerifyingKey::from_bytes(&pk).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    for m in [&b"a"[..], b"b", b"a different message", b""] {
        assert!(key.verify_strict(m, &sig).is_err());
        assert!(ed25519_dalek::Verifier::verify(&key, m, &sig).is_ok());
    }
}

fn bundle_fixture() -> PortableReceiptBundle {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/bundles/a_legacy_n1_idx0.prb.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn receipt_bundle_refuses_the_vector_and_accepts_the_genuine_fixture() {
    assert!(verify_receipt_bundle(&bundle_fixture()).is_ok());

    let (pk, sig) = identity_vector();
    let mut bundle = bundle_fixture();
    bundle.audit_proof_anchors.verification_key = b64(&pk);
    bundle.audit_proof_anchors.signature = b64(&sig);
    assert!(matches!(
        verify_receipt_bundle_detailed(&bundle),
        Err(BundleError::SignatureFailed)
    ));
    assert!(matches!(
        verify_receipt_bundle(&bundle),
        Err(BundleError::SignatureFailed)
    ));
}

fn entry(seed: u8) -> PubKeyEntry {
    PubKeyEntry {
        key_id: format!("k{seed}"),
        algorithm: "Ed25519".into(),
        public_key: format!(
            "base64:{}",
            b64(&SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes())
        ),
        valid_from: "2026-01-01T00:00:00Z".into(),
        valid_until: None,
        issued_by_org: "Nanorix".into(),
    }
}

#[test]
fn pubkey_bundle_refuses_the_vector_and_accepts_a_genuine_publisher() {
    let publisher = SigningKey::from_bytes(&[7u8; 32]);
    let genuine = build_pubkey_bundle(vec![entry(1)], &publisher, "pub", "Nanorix").unwrap();
    assert!(verify_pubkey_bundle(&genuine, &publisher.verifying_key()).is_ok());

    let (pk, sig) = identity_vector();
    let mut forged = genuine;
    forged.bundle_signature.signature = b64(&sig);
    let identity_key = VerifyingKey::from_bytes(&pk).unwrap();
    assert!(matches!(
        verify_pubkey_bundle(&forged, &identity_key),
        Err(PubkeyBundleError::BundleSignatureFailed)
    ));
}

fn fingerprint(pk: &[u8; 32]) -> String {
    let digest = Sha256::digest(pk);
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

#[test]
fn trust_chain_manifest_refuses_the_vector_and_accepts_a_genuine_identity() {
    let identity = SigningKey::from_bytes(&[11u8; 32]);
    let genuine = TrustChainManifest::build_and_sign(
        "1",
        "2026-10-01T00:00:00Z",
        HashMap::<String, AuthorityRecord>::new(),
        &identity,
    );
    let pinned = fingerprint(&identity.verifying_key().to_bytes());
    assert!(genuine.verify_signature(&pinned).is_ok());

    let (pk, sig) = identity_vector();
    let mut forged = genuine;
    forged.identity_public_key_b64 = b64(&pk);
    forged.identity_fingerprint = fingerprint(&pk);
    forged.manifest_signature = format!("base64:{}", b64(&sig));
    assert_eq!(
        forged.verify_signature(&fingerprint(&pk)),
        Err(nanorix_verify::trust_chain::ManifestError::SignatureInvalid)
    );
}

#[test]
fn boundary_attestation_refuses_the_vector_and_accepts_the_genuine_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/boundary/0001_single_signed.json"
    );
    let fixture: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let genuine = verify_boundary_attestation(&fixture, &VerifierPolicy::default());
    assert!(genuine.valid && genuine.signature_checked);

    let (pk, sig) = identity_vector();
    let mut forged = fixture;
    forged["attestation"]["public_key"] = format!("base64:{}", b64(&pk)).into();
    forged["attestation"]["signature"] = format!("base64:{}", b64(&sig)).into();
    let result = verify_boundary_attestation(&forged, &VerifierPolicy::default());
    assert!(!result.valid);
    assert_eq!(result.stage_reached, 3);
    assert!(matches!(
        result.failure_reason,
        Some(BoundaryFailureReason::SignatureMismatch {
            reason: SignatureFailureReason::DoesNotVerify
        })
    ));
}
