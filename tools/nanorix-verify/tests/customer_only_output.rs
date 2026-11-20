//! What the CLI prints about the signer, pinned byte for byte against the real
//! binary: a `customer_only` proof and the legacy customer shape (`nanorix_only`
//! under a customer authority), each at stage 7 (no key list) and stage 8 (the
//! customer's key list pinned), in human and JSON form; a v1.0 proof whose
//! labels the signature does not cover; a Nanorix proof whose stage-7 advice
//! still names nanorix.io; and the refusal of `customer_only` under a Nanorix
//! authority.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::trust_chain::{AuthorityRecord, KeyVersionRecord, TrustChainManifest};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");
const CUSTOMER: &str = "us-customer-kms-acme-v1";
const SIGNING_SEED: [u8; 32] = [0x51; 32];
const IDENTITY_SEED: [u8; 32] = [0x52; 32];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn fixture(relative: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus")
        .join(relative);
    serde_json::from_slice(&std::fs::read(&path).expect("read fixture")).expect("parse")
}

/// The corpus's first signed 2.1 proof, relabelled and re-signed with the
/// test customer key.
fn proof_with(mode: &str, authority: &str) -> Value {
    let mut proof = fixture("01_single_capsule_success/0000_v2_1_signed.json");
    proof["signing_mode"] = Value::String(mode.into());
    proof["authority_id"] = Value::String(authority.into());
    let key = SigningKey::from_bytes(&SIGNING_SEED);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    proof["attestation"]["public_key"] =
        Value::String(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = Value::String(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

fn key_list() -> TrustChainManifest {
    key_list_with_version("1")
}

fn key_list_with_version(version: &str) -> TrustChainManifest {
    let mut authorities = HashMap::new();
    authorities.insert(
        CUSTOMER.to_string(),
        AuthorityRecord {
            display_name: "Acme signing authority".to_string(),
            active_versions: vec![KeyVersionRecord {
                signing_key_version: version.to_string(),
                public_key_b64: b64(&SigningKey::from_bytes(&SIGNING_SEED)
                    .verifying_key()
                    .to_bytes()),
                public_key_fingerprint: "sha256:test".to_string(),
                effective_from: "2026-11-01T00:00:00Z".to_string(),
                archived_at: None,
                algorithm: None,
                pqc_partner_version: None,
            }],
            archived_versions: vec![],
            revoked: false,
            emits_population_heads: false,
        },
    );
    TrustChainManifest::build_and_sign(
        "1",
        "2026-11-02T00:00:00Z",
        authorities,
        &SigningKey::from_bytes(&IDENTITY_SEED),
    )
}

struct Run {
    code: i32,
    stdout: String,
}

fn run(proof: &Value, with_key_list: bool, json: bool) -> Run {
    run_with_list(proof, with_key_list.then(key_list), json)
}

fn run_with_list(proof: &Value, list: Option<TrustChainManifest>, json: bool) -> Run {
    let dir = tempfile::tempdir().expect("tempdir");
    let proof_path: PathBuf = dir.path().join("audit-proof.json");
    std::fs::write(&proof_path, serde_json::to_vec_pretty(proof).unwrap()).unwrap();
    let mut cmd = Command::new(BIN_PATH);
    cmd.env("NO_COLOR", "1").arg(&proof_path);
    if let Some(list) = list {
        let list_path = dir.path().join("key-list.json");
        std::fs::write(&list_path, serde_json::to_vec_pretty(&list).unwrap()).unwrap();
        cmd.arg("--trust-chain")
            .arg(&list_path)
            .arg("--identity-fingerprint")
            .arg(&list.identity_fingerprint);
    }
    if json {
        cmd.arg("--json");
    }
    let out = cmd.output().expect("run nanorix-verify");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8(out.stdout).expect("utf-8 stdout"),
    }
}

/// No line may say or imply who holds the signing key:
/// a signed label is not custody.
fn assert_no_custody_claim(stdout: &str) {
    assert!(!stdout.contains("does not hold"), "{stdout}");
    assert!(!stdout.contains("hold this key"), "{stdout}");
}

/// The corpus fixture key (`FIXTURE_SIGNING_SEED` in `fixtures/generator.rs`).
const FIXTURE_SIGNING_SEED: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
];

/// The corpus's first signed 2.1 proof with `field` removed (or set to
/// `value`), re-signed over its recompute with the fixture key.
fn fixture_resigned(field: &str, value: Option<Value>) -> Value {
    let mut proof = fixture("01_single_capsule_success/0000_v2_1_signed.json");
    match value {
        Some(v) => proof[field] = v,
        None => {
            proof.as_object_mut().unwrap().remove(field);
        }
    }
    let key = SigningKey::from_bytes(&FIXTURE_SIGNING_SEED);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    assert_eq!(
        proof["attestation"]["public_key"],
        format!("base64:{}", b64(&key.verifying_key().to_bytes())),
        "the fixture is signed with FIXTURE_SIGNING_SEED"
    );
    proof["attestation"]["signature"] = Value::String(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

fn identity_fingerprint() -> String {
    key_list().identity_fingerprint
}

const NOT_ESTABLISHED_BLOCK: &str = "  Not established by this check:
    It does not say who the legal person behind the fingerprint is.
    It does not say the key is non-exportable or HSM-held.
    It does not say Nanorix's software could not have requested the signature.
    It makes no regulatory statement.
";

#[test]
fn customer_only_stage_7_human_golden() {
    let r = run(&proof_with("customer_only", CUSTOMER), false, false);
    assert_eq!(r.code, 4, "not_anchored exits 4");
    assert_eq!(
        r.stdout,
        "⚠ Signature valid · key NOT anchored to a published key list · capsule cap_00000000000000000000000000000000 · region us-central1
  Integrity verified (no signed byte changed since signing; fields outside the signed view, such as metadata, are not checked). Authenticity pending: the signing key was read from the proof itself, not yet resolved against the signer's published key list.

  This proof's signed labels name a customer authority (us-customer-kms-acme-v1). To anchor its key, supply the key list and identity fingerprint published for that authority.
    nanorix-verify <proof.json> --trust-chain <key-list.json> --identity-fingerprint <sha256:... or hybrid1-sha256:...>
  Signer: authority us-customer-kms-acme-v1, key version 1 (covered by the signature)
  Signing mode: customer_only (covered by the signature)
  Signing key version: 1
  Algorithm: Ed25519
  Chain steps: 8 / 8
"
    );
    assert!(!r.stdout.contains("nanorix.io"));
    assert_no_custody_claim(&r.stdout);
}

#[test]
fn customer_only_stage_8_human_golden() {
    let r = run(&proof_with("customer_only", CUSTOMER), true, false);
    assert_eq!(r.code, 0);
    let expected = format!(
        "✓ Verified · capsule cap_00000000000000000000000000000000 · region us-central1
  Signer: authority us-customer-kms-acme-v1, key version 1 (covered by the signature)
  Signing mode: customer_only (covered by the signature)
  Key list: issued 2026-11-02T00:00:00Z, identity {} (the fingerprint you pinned)
  Signing key version: 1
  Algorithm: Ed25519
  Chain steps: 8 / 8
{NOT_ESTABLISHED_BLOCK}",
        identity_fingerprint()
    );
    assert_eq!(r.stdout, expected);
}

#[test]
fn customer_only_stage_8_json_golden() {
    let r = run(&proof_with("customer_only", CUSTOMER), true, true);
    assert_eq!(r.code, 0);
    let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
    assert_eq!(out["valid"], true);
    assert_eq!(out["stage_reached"], 8);
    assert_eq!(
        out["metadata"],
        serde_json::json!({
            "cdp_version": "2.1",
            "capsule_id": "cap_00000000000000000000000000000000",
            "region": "us-central1",
            "signing_key_version": "1",
            "algorithm": "Ed25519",
            "step_count": 8,
            "activity_event_count": null,
            "authority_id": CUSTOMER,
            "authority_signed": true,
            "signing_mode": "customer_only",
            "trust_chain_identity_fingerprint": identity_fingerprint(),
            "trust_chain_issued_at": "2026-11-02T00:00:00Z",
        })
    );
}

#[test]
fn customer_only_stage_7_json_golden() {
    let r = run(&proof_with("customer_only", CUSTOMER), false, true);
    assert_eq!(r.code, 4, "not_anchored exits 4");
    let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
    assert_eq!(out["stage_reached"], 7);
    assert_eq!(out["metadata"]["authority_id"], CUSTOMER);
    assert_eq!(out["metadata"]["authority_signed"], true);
    assert_eq!(out["metadata"]["signing_mode"], "customer_only");
    assert!(out["metadata"]
        .get("trust_chain_identity_fingerprint")
        .is_none());
    assert!(out["metadata"].get("trust_chain_issued_at").is_none());
}

#[test]
fn legacy_customer_proof_stage_7_human_golden() {
    let r = run(&proof_with("nanorix_only", CUSTOMER), false, false);
    assert_eq!(r.code, 4, "not_anchored exits 4");
    assert_eq!(
        r.stdout,
        "⚠ Signature valid · key NOT anchored to a published key list · capsule cap_00000000000000000000000000000000 · region us-central1
  Integrity verified (no signed byte changed since signing; fields outside the signed view, such as metadata, are not checked). Authenticity pending: the signing key was read from the proof itself, not yet resolved against the signer's published key list.

  This proof's signed labels name a customer authority (us-customer-kms-acme-v1). To anchor its key, supply the key list and identity fingerprint published for that authority.
    nanorix-verify <proof.json> --trust-chain <key-list.json> --identity-fingerprint <sha256:... or hybrid1-sha256:...>
  Signer: authority us-customer-kms-acme-v1, key version 1 (covered by the signature)
  Signing mode: nanorix_only (covered by the signature)
  signing_mode predates customer_only; this proof names a customer-classified authority, which only stage 8 (the customer's key list) anchors to the key that signed.
  Signing key version: 1
  Algorithm: Ed25519
  Chain steps: 8 / 8
"
    );
    assert_no_custody_claim(&r.stdout);
}

#[test]
fn legacy_customer_proof_stage_8_human_and_json_golden() {
    let r = run(&proof_with("nanorix_only", CUSTOMER), true, false);
    assert_eq!(r.code, 0);
    let expected = format!(
        "✓ Verified · capsule cap_00000000000000000000000000000000 · region us-central1
  Signer: authority us-customer-kms-acme-v1, key version 1 (covered by the signature)
  Signing mode: nanorix_only (covered by the signature)
  signing_mode predates customer_only; this proof names a customer-classified authority, and stage 8 resolved its key in the key list below, so the signer is the customer authority named above.
  Key list: issued 2026-11-02T00:00:00Z, identity {} (the fingerprint you pinned)
  Signing key version: 1
  Algorithm: Ed25519
  Chain steps: 8 / 8
{NOT_ESTABLISHED_BLOCK}",
        identity_fingerprint()
    );
    assert_eq!(r.stdout, expected);

    let r = run(&proof_with("nanorix_only", CUSTOMER), true, true);
    let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
    assert_eq!(out["stage_reached"], 8);
    assert_eq!(out["metadata"]["authority_id"], CUSTOMER);
    assert_eq!(out["metadata"]["authority_signed"], true);
    assert_eq!(out["metadata"]["signing_mode"], "nanorix_only");
}

/// v1.0 signs `final_hash` only: the labels print as not covered, and no
/// label there leads the reader to a key list, since none anchors a 1.0 proof.
#[test]
fn v1_0_labels_print_as_not_covered() {
    let mut proof =
        fixture("06_failure_authority_unknown/0014_v1_0_signed_default_authority_pin.json");
    let r = run(&proof, false, false);
    assert_eq!(r.code, 4, "not_anchored exits 4");
    assert!(
        r.stdout
            .contains("  Signer: authority us-kms-nanorix-v1 (default: absent from the proof; not covered by the signature), key version (none) (not covered by the signature)\n"),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("(covered by the signature)"),
        "{}",
        r.stdout
    );

    proof["authority_id"] = Value::String(CUSTOMER.into());
    let r = run(&proof, false, false);
    assert_eq!(r.code, 4, "not_anchored exits 4");
    assert!(
        r.stdout.contains("(not covered by the signature)"),
        "{}",
        r.stdout
    );
    // A 1.0 proof is never anchored, so no key list is offered, whichever
    // authority it names.
    assert!(
        r.stdout.contains("never anchored to a key list"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("--trust-chain"), "{}", r.stdout);
    assert!(
        !r.stdout.contains("signed labels name a customer authority"),
        "{}",
        r.stdout
    );
    assert_no_custody_claim(&r.stdout);
}

/// A Nanorix-signed proof keeps the nanorix.io advice and no customer lines.
#[test]
fn nanorix_proof_keeps_the_nanorix_advice() {
    let proof = fixture("01_single_capsule_success/0000_v2_1_signed.json");
    let r = run(&proof, false, false);
    assert_eq!(r.code, 4, "not_anchored exits 4");
    assert!(
        r.stdout.contains("nanorix.io/.well-known/trust-chain.json"),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("signed labels name a customer authority"),
        "{}",
        r.stdout
    );
    assert_no_custody_claim(&r.stdout);
    assert!(
        r.stdout.contains(
            "  Signer: authority us-kms-nanorix-v1, key version 1 (covered by the signature)\n  Signing mode: nanorix_only (covered by the signature)\n  Signing key version: 1\n"
        ),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("predates customer_only"), "{}", r.stdout);
}

#[test]
fn customer_only_under_the_nanorix_authority_is_refused() {
    let r = run(
        &proof_with("customer_only", "us-kms-nanorix-v1"),
        false,
        false,
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains(
            "  Failure: signing_mode_authority_mismatch (signing_mode: customer_only, claimed_authority_id: us-kms-nanorix-v1)\n  Stage reached: 4 / 8\n"
        ),
        "{}",
        r.stdout
    );
    // The gate runs at stage 4, before any signature check, and on unsigned
    // documents too: the hint never claims the labels were signed.
    assert!(
        r.stdout.contains("No signature was checked."),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("signed together"), "{}", r.stdout);
    let r = run(
        &proof_with("customer_only", "us-kms-nanorix-v1"),
        false,
        true,
    );
    let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
    assert_eq!(
        out["failure_reason"],
        serde_json::json!({
            "type": "signing_mode_authority_mismatch",
            "claimed_authority_id": "us-kms-nanorix-v1",
        })
    );
}

/// A null `claimed_authority_id` prints the phrase the Go, Python, TypeScript
/// and browser verifiers print for it.
#[test]
fn a_null_claimed_authority_is_named_with_the_shared_phrase() {
    for value in [None, Some(serde_json::json!(7))] {
        let mut proof = proof_with("customer_only", CUSTOMER);
        match value {
            Some(v) => proof["authority_id"] = v,
            None => {
                proof.as_object_mut().unwrap().remove("authority_id");
            }
        }
        let key = SigningKey::from_bytes(&SIGNING_SEED);
        let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
        proof["attestation"]["signature"] =
            Value::String(format!("base64:{}", b64(&sig.to_bytes())));
        let r = run(&proof, false, false);
        assert_eq!(r.code, 1, "{}", r.stdout);
        assert!(
            r.stdout.contains(
                "  Failure: signing_mode_authority_mismatch (signing_mode: customer_only, claimed_authority_id: absent or not a string, so the Nanorix default applies)\n"
            ),
            "{}",
            r.stdout
        );
    }
}

/// An absent `authority_id` on 2.1 is the issuer's default only on read; the
/// signature binds its absence, so the default is printed as a default.
#[test]
fn absent_authority_id_prints_the_default_as_a_default() {
    let proof = fixture_resigned("authority_id", None);
    let r = run(&proof, false, false);
    assert_eq!(r.code, 4, "not_anchored exits 4: {}", r.stdout);
    assert!(
        r.stdout.contains(
            "  Signer: authority us-kms-nanorix-v1 (default: absent from the proof; the signature covers its absence), key version 1 (covered by the signature)\n  Signing mode: nanorix_only (covered by the signature)\n"
        ),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout
            .contains("authority us-kms-nanorix-v1, key version"),
        "{}",
        r.stdout
    );

    let r = run(&proof, false, true);
    let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
    assert_eq!(out["stage_reached"], 7);
    assert!(
        out["metadata"].get("authority_id").is_none(),
        "{}",
        r.stdout
    );
    assert_eq!(out["metadata"]["authority_signed"], true);
    assert_eq!(out["metadata"]["signing_mode"], "nanorix_only");

    let proof = fixture_resigned("authority_id", Some(serde_json::json!(7)));
    let r = run(&proof, false, false);
    assert!(
        r.stdout.contains(
            "  Signer: authority us-kms-nanorix-v1 (default: not a string in the proof; the signature covers the value 7), key version 1 (covered by the signature)\n"
        ),
        "{}",
        r.stdout
    );
}

/// The same for an absent `signing_mode`.
#[test]
fn absent_signing_mode_prints_the_default_as_a_default() {
    let proof = fixture_resigned("signing_mode", None);
    let r = run(&proof, false, false);
    assert_eq!(r.code, 4, "not_anchored exits 4: {}", r.stdout);
    assert!(
        r.stdout.contains(
            "  Signer: authority us-kms-nanorix-v1, key version 1 (covered by the signature)\n  Signing mode: nanorix_only (default: absent from the proof; the signature covers its absence)\n"
        ),
        "{}",
        r.stdout
    );

    let r = run(&proof, false, true);
    let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
    assert_eq!(out["stage_reached"], 7);
    assert!(
        out["metadata"].get("signing_mode").is_none(),
        "{}",
        r.stdout
    );
    assert_eq!(out["metadata"]["authority_signed"], true);
    assert_eq!(out["metadata"]["authority_id"], "us-kms-nanorix-v1");
}

/// The key version prints as the integer the canonical view binds.
#[test]
fn key_version_prints_what_the_signature_binds() {
    let r = run(
        &fixture_resigned("signing_key_version", Some(serde_json::json!("abc"))),
        false,
        false,
    );
    assert!(
        r.stdout.contains(
            "  Signer: authority us-kms-nanorix-v1 (covered by the signature), key version abc (not a number; the signature covers 0)\n"
        ),
        "{}",
        r.stdout
    );
    let r = run(&fixture_resigned("signing_key_version", None), false, false);
    assert!(
        r.stdout.contains(
            "  Signer: authority us-kms-nanorix-v1 (covered by the signature), key version none (absent from the proof; the signature covers 0)\n"
        ),
        "{}",
        r.stdout
    );
}

/// A proof stopping before stage 7 reports no `authority_signed`, and its
/// labels print as unchecked.
#[test]
fn a_proof_without_a_checked_signature_has_no_authority_signed() {
    let mut proof = proof_with("customer_only", CUSTOMER);
    proof["attestation"]
        .as_object_mut()
        .unwrap()
        .remove("signature");
    let r = run(&proof, false, true);
    let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
    assert_eq!(out["stage_reached"], 4, "{}", r.stdout);
    assert!(
        out["metadata"].get("authority_signed").is_none(),
        "{}",
        r.stdout
    );
    assert_eq!(out["metadata"]["authority_id"], CUSTOMER);

    let r = run(&proof, false, false);
    assert!(
        r.stdout.contains(
            "  Signer: authority us-customer-kms-acme-v1, key version 1 (no signature was checked)\n  Signing mode: customer_only (no signature was checked)\n"
        ),
        "{}",
        r.stdout
    );
}

/// At stage 8 the key list resolved `attestation.signing_key_version`, which
/// the signature does not cover; the Signer line keeps the signed version.
#[test]
fn stage_8_names_a_resolved_key_version_that_differs_from_the_signed_one() {
    let mut proof = proof_with("customer_only", CUSTOMER);
    proof["attestation"]["signing_key_version"] = Value::String("2".into());
    let r = run_with_list(&proof, Some(key_list_with_version("2")), false);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.stdout.contains(
            "  Signer: authority us-customer-kms-acme-v1, key version 1 (covered by the signature)\n"
        ),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains(
            "  Key list resolved key version 2 (read from attestation.signing_key_version, which the signature does not cover)\n"
        ),
        "{}",
        r.stdout
    );
    // The metadata line prints the attestation's value, labelled as outside
    // the signature, beside the signed version on the Signer line.
    assert!(
        r.stdout
            .contains("  Signing key version (attestation, not covered by the signature): 2\n"),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("  Signing key version: "),
        "{}",
        r.stdout
    );

    let r = run(&proof_with("customer_only", CUSTOMER), true, false);
    assert!(
        !r.stdout.contains("Key list resolved key version"),
        "{}",
        r.stdout
    );
}

/// The `--json` metadata equals the Go verifier's for the same proofs:
/// TestSignerMetadataJSONMatchesTheRustVerifier in
/// tools/auditproof-verifier-go/signer_metadata_test.go holds the same literals.
#[test]
fn signer_metadata_json_matches_the_go_verifier() {
    let customer = fixture("13_customer_only/0000_v2_1_customer_only_signed.json");
    let mut absent_labels = fixture("01_single_capsule_success/0000_v2_1_signed.json");
    absent_labels
        .as_object_mut()
        .unwrap()
        .remove("authority_id");
    absent_labels
        .as_object_mut()
        .unwrap()
        .remove("signing_mode");
    let key = SigningKey::from_bytes(&FIXTURE_SIGNING_SEED);
    let sig = key.sign(recompute_canonical_hash(&absent_labels).as_bytes());
    absent_labels["attestation"]["signature"] =
        Value::String(format!("base64:{}", b64(&sig.to_bytes())));
    let mut unsigned = customer.clone();
    unsigned.as_object_mut().unwrap().remove("attestation");
    for (name, proof, stage, want) in [
        (
            "customer_only",
            customer.clone(),
            7,
            r#"{"activity_event_count":null,"algorithm":"Ed25519","authority_id":"us-customer-kms-acme-v1","authority_signed":true,"capsule_id":"cap_00000000000000000000000000000514","cdp_version":"2.1","region":"us-central1","signing_key_version":"1","signing_mode":"customer_only","step_count":8}"#,
        ),
        (
            "legacy pair",
            fixture("13_customer_only/0005_v2_1_legacy_nanorix_only_customer_authority.json"),
            7,
            r#"{"activity_event_count":null,"algorithm":"Ed25519","authority_id":"us-customer-kms-acme-v1","authority_signed":true,"capsule_id":"cap_00000000000000000000000000000519","cdp_version":"2.1","region":"us-central1","signing_key_version":"1","signing_mode":"nanorix_only","step_count":8}"#,
        ),
        (
            "1.0 signs final_hash only",
            fixture("06_failure_authority_unknown/0014_v1_0_signed_default_authority_pin.json"),
            7,
            r#"{"activity_event_count":null,"algorithm":"Ed25519","authority_signed":false,"capsule_id":null,"cdp_version":"1.0","region":null,"signing_key_version":null,"step_count":8}"#,
        ),
        (
            "absent labels are absent, not the default",
            absent_labels,
            7,
            r#"{"activity_event_count":null,"algorithm":"Ed25519","authority_signed":true,"capsule_id":"cap_00000000000000000000000000000000","cdp_version":"2.1","region":"us-central1","signing_key_version":"1","step_count":8}"#,
        ),
        (
            "no signature checked",
            unsigned,
            4,
            r#"{"activity_event_count":null,"algorithm":null,"authority_id":"us-customer-kms-acme-v1","capsule_id":"cap_00000000000000000000000000000514","cdp_version":"2.1","region":null,"signing_key_version":"1","signing_mode":"customer_only","step_count":8}"#,
        ),
    ] {
        let r = run(&proof, false, true);
        let out: Value = serde_json::from_str(&r.stdout).expect("JSON verdict");
        assert_eq!(out["stage_reached"], stage, "{name}: {}", r.stdout);
        let want: Value = serde_json::from_str(want).unwrap();
        assert_eq!(out["metadata"], want, "{name}");
    }
}

/// An authority id holding a right-to-left override and a control character
/// prints escaped in the Signer line, the stage-7 advice and the mismatch
/// line, with the text the Go CLI and the browser page show for the same id
/// (key_version_source_test.go and test_browser_reference_verifier.mjs).
#[test]
fn authority_id_controls_are_escaped_as_in_go_and_the_browser() {
    let r = run(
        &proof_with("customer_only", "us-customer-kms-\u{202e}acme\u{7}-v1"),
        false,
        false,
    );
    assert_eq!(r.code, 4, "{}", r.stdout);
    for want in [
        "  Signer: authority us-customer-kms-\\u{202e}acme\\u{7}-v1, key version 1 (covered by the signature)\n",
        "  This proof's signed labels name a customer authority (us-customer-kms-\\u{202e}acme\\u{7}-v1). To anchor its key, supply the key list and identity fingerprint published for that authority.\n",
    ] {
        assert!(r.stdout.contains(want), "{want}\n{}", r.stdout);
    }
    let r = run(
        &proof_with("customer_only", "us-kms-\u{202e}nanorix\u{7}-v1"),
        false,
        false,
    );
    assert_eq!(r.code, 1, "{}", r.stdout);
    assert!(
        r.stdout.contains(
            "  Failure: signing_mode_authority_mismatch (signing_mode: customer_only, claimed_authority_id: us-kms-\\u{202e}nanorix\\u{7}-v1)\n"
        ),
        "{}",
        r.stdout
    );
}

/// `verify_signature` reports no signature when the public key is missing,
/// even with a signature present; the note must not say the proof has none.
#[test]
fn a_signature_without_a_public_key_is_not_called_absent() {
    let mut proof = proof_with("customer_only", CUSTOMER);
    let attestation = proof["attestation"].as_object_mut().unwrap();
    attestation.remove("public_key");
    attestation.remove("verification_key");
    assert!(attestation.contains_key("signature"));
    let r = run(&proof, false, false);
    assert_eq!(r.code, 3, "{}", r.stdout);
    assert!(
        r.stdout.contains(
            "no signature was checked (the proof carries no signature or no public key)."
        ),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("carried no signature"), "{}", r.stdout);
}
