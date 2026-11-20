//! Row tests for `UNANCHORED_SURFACES.md`: every surface that returns
//! something a caller can read as success on a signed object, handed an
//! object correctly signed by a key nothing anchors. The rule: with no key
//! list, a key list given without a pin, or only the key the object carries,
//! the most a surface may return is `not_anchored`.
//!
//! A test for an open row asserts the wanted behaviour and is ignored, with
//! the item id in the ignore reason.

// The deprecated `valid` field is part of what a caller can read as success.
#![allow(deprecated)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use nanorix_verify::boundary::verify_boundary_attestation;
use nanorix_verify::bundle::{
    verify_receipt_bundle, verify_receipt_bundle_detailed, BundleVerification,
    PortableReceiptBundle,
};
use nanorix_verify::trust_chain::{AuthorityRecord, KeyVersionRecord, TrustChainManifest};
use nanorix_verify::{verify_auditproof, VerifierPolicy};
use serde_json::Value;

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");

/// The identity that signed the shared customer key lists.
const CUSTOMER_PIN: &str =
    "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("fixture JSON")
}

fn customer_proof() -> Value {
    json(&fixtures().join("trust_chain/proofs/customer_v1.json"))
}

fn customer_key_list() -> TrustChainManifest {
    serde_json::from_value(json(
        &fixtures().join("trust_chain/key_lists/customer_v1.json"),
    ))
    .expect("key list")
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(BIN_PATH)
        .env_remove("NANORIX_API_KEY")
        .args(args)
        .output()
        .expect("run nanorix-verify")
}

// ── verify_auditproof ──────────────────────────────────────────────────────

/// No key list: the signature checks against the key the proof carries, so
/// the result is `not_anchored`, never `ok()`.
#[test]
fn lib_auditproof_without_key_list_is_not_anchored() {
    let r = verify_auditproof(&customer_proof(), &[], &VerifierPolicy::default());
    assert_eq!(r.status(), "not_anchored", "{r:?}");
    assert!(!r.ok());
    assert_eq!(r.stage_reached, 7);
}

/// A key list handed to the library without a pin is the caller's say-so:
/// the proof resolves in it, but the result stops at `not_anchored`.
#[test]
fn lib_auditproof_key_list_without_pin_is_not_anchored() {
    let policy = VerifierPolicy {
        trust_chain: Some(customer_key_list()),
        ..Default::default()
    };
    let r = verify_auditproof(&customer_proof(), &[], &policy);
    assert_eq!(r.status(), "not_anchored", "{r:?}");
    assert!(!r.ok());
    assert_eq!(r.stage_reached, 7);
}

/// A list edited after it was signed, so that it names the key of a proof
/// signed by a stranger: without a pin nothing notices the edit, so the
/// proof must not come back `verified`.
#[test]
fn lib_auditproof_edited_key_list_without_pin_never_verifies() {
    let list: TrustChainManifest = serde_json::from_value(json(
        &fixtures().join("trust_chain/key_lists/customer_v1_key_swapped_after_signing.json"),
    ))
    .expect("key list");
    let proof =
        json(&fixtures().join("trust_chain/proofs/customer_v1_signed_by_stranger_key.json"));
    let r = verify_auditproof(
        &proof,
        &[],
        &VerifierPolicy {
            trust_chain: Some(list),
            ..Default::default()
        },
    );
    assert_ne!(r.status(), "verified", "{r:?}");
    assert!(!r.ok());
}

/// A manifest that went through `into_verified` and is then placed in the
/// policy without its pin is treated like any unpinned list: the policy field
/// cannot tell where the manifest came from. With the pin set it verifies.
#[test]
fn lib_auditproof_into_verified_manifest_without_pin_is_not_anchored() {
    let checked = customer_key_list()
        .into_verified(CUSTOMER_PIN)
        .expect("the pin signed this list");
    let unpinned = VerifierPolicy {
        trust_chain: Some(checked.manifest().clone()),
        ..Default::default()
    };
    let r = verify_auditproof(&customer_proof(), &[], &unpinned);
    assert_eq!(r.status(), "not_anchored", "{r:?}");
    assert!(!r.ok());

    let pinned = VerifierPolicy {
        trust_chain: Some(checked.manifest().clone()),
        pinned_identity_fingerprint: Some(CUSTOMER_PIN.to_string()),
        ..Default::default()
    };
    let r = verify_auditproof(&customer_proof(), &[], &pinned);
    assert_eq!(r.status(), "verified", "{r:?}");
    assert!(r.ok());
}

// ── nanorix-verify <proof> ─────────────────────────────────────────────────

/// No key list: exit 4 (`not_anchored`), never 0.
#[test]
fn cli_verify_without_key_list_exits_4() {
    let proof = fixtures().join("trust_chain/proofs/customer_v1.json");
    let out = run(&[proof.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A key list without a pin stops the run before any proof is read: exit 1
/// with an error naming `--identity-fingerprint`, and no verdict printed.
#[test]
fn cli_verify_key_list_without_pin_refuses() {
    let proof = fixtures().join("trust_chain/proofs/customer_v1.json");
    let list = fixtures().join("trust_chain/key_lists/customer_v1.json");
    let out = run(&[
        "--trust-chain",
        list.to_str().unwrap(),
        proof.to_str().unwrap(),
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("--identity-fingerprint"), "{stderr}");
    assert!(out.stdout.is_empty(), "no verdict may be printed");
}

/// `--json` without a key list says `not_anchored` and exits 4.
#[test]
fn cli_verify_json_without_key_list_says_not_anchored() {
    let proof = fixtures().join("trust_chain/proofs/customer_v1.json");
    let out = run(&["--json", proof.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4));
    let v: Value = serde_json::from_slice(&out.stdout).expect("JSON verdict");
    assert_eq!(v["status"], "not_anchored", "{v}");
}

// ── pubkey-bundle verify ───────────────────────────────────────────────────

/// Builds a signed pubkey bundle in `dir`; returns (bundle path, publisher key path).
fn pubkey_bundle(dir: &Path) -> (String, String) {
    use base64::Engine as _;
    let seed = [9u8; 32];
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let listed = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
    let seed_path = dir.join("seed.bin");
    std::fs::write(&seed_path, seed).unwrap();
    let pub_path = dir.join("publisher.bin");
    std::fs::write(&pub_path, signer.verifying_key().to_bytes()).unwrap();
    let keys_path = dir.join("keys.json");
    let keys = serde_json::json!({ "pubkeys": [{
        "key_id": "nrx-verify-test-1",
        "algorithm": "Ed25519",
        "public_key": base64::engine::general_purpose::STANDARD
            .encode(listed.verifying_key().to_bytes()),
        "valid_from": "2026-01-01T00:00:00Z",
        "issued_by_org": "vendor:example",
    }]});
    std::fs::write(&keys_path, keys.to_string()).unwrap();
    let bundle_path = dir.join("bundle.ppb.json");
    let built = run(&[
        "pubkey-bundle",
        "build",
        "--keys",
        keys_path.to_str().unwrap(),
        "--output",
        bundle_path.to_str().unwrap(),
        "--signer-seed",
        seed_path.to_str().unwrap(),
        "--signer-key-id",
        "nrx-bundle-publisher-test",
        "--issuer-org",
        "vendor:example",
    ]);
    assert_eq!(
        built.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    (
        bundle_path.to_str().unwrap().to_string(),
        pub_path.to_str().unwrap().to_string(),
    )
}

/// `pubkey-bundle verify` does not read a key list, so `--trust-chain` and
/// `--identity-fingerprint` are refused with exit 2 instead of being checked
/// and then dropped while the run exits 0.
#[test]
fn cli_pubkey_bundle_verify_refuses_key_list_and_pin_with_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let (bundle, publisher) = pubkey_bundle(dir.path());
    let list = fixtures().join("trust_chain/key_lists/customer_v1.json");
    let list = list.to_str().unwrap();
    let base = [
        "pubkey-bundle",
        "verify",
        bundle.as_str(),
        "--publisher-pubkey",
        publisher.as_str(),
    ];
    for extra in [
        vec![
            "--trust-chain",
            list,
            "--identity-fingerprint",
            CUSTOMER_PIN,
        ],
        vec!["--trust-chain", list],
        vec!["--identity-fingerprint", CUSTOMER_PIN],
    ] {
        let args: Vec<&str> = extra.iter().copied().chain(base).collect();
        let out = run(&args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty(), "{args:?}: no verdict may be printed");
    }
}

/// Exit 0 from `pubkey-bundle verify` says only that the publisher signature
/// holds under the key file given; the help says it anchors no listed key.
#[test]
fn cli_pubkey_bundle_verify_help_says_exit_0_anchors_no_key() {
    let out = run(&["pubkey-bundle", "verify", "--help"]);
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("anchors no key"), "{help}");
}

// ── receipt bundles ────────────────────────────────────────────────────────

fn legacy_bundle() -> PortableReceiptBundle {
    serde_json::from_value(json(&fixtures().join("bundles/a_legacy_n1_idx0.prb.json")))
        .expect("bundle")
}

/// The detailed result checks the bundle against the key it carries, so its
/// status says `not_anchored` even when the integrity checks all hold.
#[test]
fn receipt_bundle_detailed_on_carried_key_is_at_most_not_anchored() {
    let v = verify_receipt_bundle_detailed(&legacy_bundle()).expect("integrity holds");
    assert!(v.is_valid());
    assert_eq!(v.status(), "not_anchored");
}

/// `verify_receipt_bundle` returns `Ok(())` for integrity only: whenever it
/// is `Ok`, the detailed result for the same bundle says `not_anchored`.
#[test]
fn receipt_bundle_ok_on_carried_key_is_at_most_not_anchored() {
    let bundle = legacy_bundle();
    verify_receipt_bundle(&bundle).expect("integrity holds");
    assert_eq!(
        verify_receipt_bundle_detailed(&bundle).unwrap().status(),
        "not_anchored"
    );
}

/// A result whose integrity checks do not all hold says `not_verified`, as
/// one for a bundle signed over a document it does not carry does
/// (`receipt_bound` false).
#[test]
fn receipt_bundle_status_is_not_verified_when_integrity_fails() {
    let held = verify_receipt_bundle_detailed(&legacy_bundle()).expect("integrity holds");
    for v in [
        BundleVerification {
            receipt_bound: false,
            ..held.clone()
        },
        BundleVerification {
            signature_authentic: false,
            ..held
        },
    ] {
        assert!(!v.is_valid());
        assert_eq!(v.status(), "not_verified");
    }
}

/// `bundle verify` exits 0 on a bundle checked against the key it carries.
/// Wanted: exit 4, as a proof checked that way does.
#[test]
#[ignore = "open: bundle verify exits 0 on the carried key"]
fn cli_bundle_verify_on_carried_key_exits_4() {
    let bundle = fixtures().join("bundles/a_legacy_n1_idx0.prb.json");
    let out = run(&["bundle", "verify", bundle.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// ── boundary attestations ──────────────────────────────────────────────────

fn boundary_fixture() -> Value {
    json(&fixtures().join("boundary/0001_single_signed.json"))
}

/// A boundary attestation checked against the key it carries returns
/// `valid: true` with `trust_anchored: false`. Wanted: nothing a caller reads
/// alone says success for it.
#[test]
#[ignore = "open: boundary verification reads valid alone on the carried key"]
fn lib_boundary_on_carried_key_is_not_valid_alone() {
    let r = verify_boundary_attestation(&boundary_fixture(), &VerifierPolicy::default());
    assert!(r.signature_checked);
    assert!(
        !(r.valid && !r.trust_anchored),
        "valid alone reads as success: {r:?}"
    );
}

/// A key list without a pin anchors a boundary attestation today. Wanted:
/// `trust_anchored` stays false until the list is checked against a pin.
#[test]
#[ignore = "open: boundary verification trusts a key list given without a pin"]
fn lib_boundary_key_list_without_pin_is_not_anchored() {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let pubkey = signer.verifying_key().to_bytes();
    use base64::Engine as _;
    use sha2::Digest as _;
    let record = KeyVersionRecord {
        signing_key_version: "1".into(),
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(pubkey),
        public_key_fingerprint: format!("sha256:{}", hex::encode(sha2::Sha256::digest(pubkey))),
        effective_from: "2026-01-01T00:00:00Z".into(),
        archived_at: None,
        algorithm: None,
        pqc_partner_version: None,
    };
    let mut authorities = HashMap::new();
    authorities.insert(
        "us-kms-nanorix-v1".to_string(),
        AuthorityRecord {
            display_name: "anyone".into(),
            active_versions: vec![record],
            archived_versions: vec![],
            revoked: false,
            emits_population_heads: false,
        },
    );
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let list =
        TrustChainManifest::build_and_sign("1", "2026-01-01T00:00:00Z", authorities, &stranger);
    let r = verify_boundary_attestation(
        &boundary_fixture(),
        &VerifierPolicy {
            trust_chain: Some(list),
            ..Default::default()
        },
    );
    assert!(!r.trust_anchored, "{r:?}");
}

/// `boundary verify` exits 0 on an attestation checked against the key it
/// carries. Wanted: a status a gate cannot read as anchored.
#[test]
#[ignore = "open: boundary verify exits 0 on the carried key"]
fn cli_boundary_verify_on_carried_key_exits_4() {
    let file = fixtures().join("boundary/0001_single_signed.json");
    let out = run(&["boundary", "verify", file.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(4),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// ── signature checks ───────────────────────────────────────────────────────

/// `canonical_recompute::verify_signature` checks the proof against the key it
/// carries and answers `Verified`. Wanted: an answer that does not read as a
/// verified proof on its own.
#[test]
#[ignore = "open: canonical_recompute::verify_signature answers Verified on the key the proof carries"]
fn lib_verify_signature_on_carried_key_is_not_verified() {
    use nanorix_verify::canonical_recompute::{verify_signature, SignatureCheck};
    let proof = customer_proof();
    let version = proof["cdp_version"].as_str().unwrap().to_string();
    assert!(!matches!(
        verify_signature(&proof, &version),
        SignatureCheck::Verified
    ));
}

/// `canonical_recompute::verify_signature_against` checks only the key its
/// caller names: a proof signed by another key is refused, so the key the
/// proof carries never stands in for it.
#[test]
fn lib_verify_signature_against_another_key_is_refused() {
    use base64::Engine as _;
    use nanorix_verify::canonical_recompute::{verify_signature_against, SignatureCheck};
    let proof = customer_proof();
    let version = proof["cdp_version"].as_str().unwrap().to_string();
    let signer = proof["attestation"]["public_key"].as_str().unwrap();
    assert!(
        matches!(
            verify_signature_against(&proof, &version, signer),
            SignatureCheck::Verified
        ),
        "the signing key no longer verifies, so this case proves nothing"
    );
    let other = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let other_b64 =
        base64::engine::general_purpose::STANDARD.encode(other.verifying_key().to_bytes());
    assert!(!matches!(
        verify_signature_against(&proof, &version, &other_b64),
        SignatureCheck::Verified
    ));
}

/// A link that `verify_self` checks against the key its own proof carries, as
/// the adapters do.
struct CarriedKeyLink(Value);

impl nanorix_verify_types::chain::ChainNode for CarriedKeyLink {
    fn capsule_id(&self) -> &str {
        "cap_00000000000000000000000000000001"
    }
    fn org_id(&self) -> &str {
        "org_inventory"
    }
    fn parent_audit_proof_id(&self) -> Option<&str> {
        None
    }
    fn verify_self(
        &self,
    ) -> Result<
        nanorix_verify_types::chain::SingleVerification,
        nanorix_verify_types::chain::SingleVerificationFailure,
    > {
        use nanorix_verify::canonical_recompute::{verify_signature, SignatureCheck};
        let version = self.0["cdp_version"].as_str().unwrap_or_default();
        Ok(nanorix_verify_types::chain::SingleVerification {
            capsule_id: self.capsule_id().to_string(),
            org_id: self.org_id().to_string(),
            signature_verified: matches!(
                verify_signature(&self.0, version),
                SignatureCheck::Verified
            ),
            canonical_hash_verified: true,
            signing_key_version: String::new(),
        })
    }
}

/// `verify_chain` returns `Ok`, a verified chain, when every link checks on
/// the key it carries; nothing in the walk is anchored. Wanted: such a walk is
/// not returned as a verified chain.
#[test]
#[ignore = "open: verify_chain returns Ok when each link checks only on the key it carries"]
fn lib_verify_chain_on_carried_keys_is_not_verified() {
    use nanorix_verify_types::chain::{verify_chain, ChainNode, DEFAULT_MAX_CHAIN_DEPTH};
    let leaf = CarriedKeyLink(customer_proof());
    assert!(leaf.verify_self().unwrap().signature_verified);
    let walk = verify_chain(
        &leaf,
        |_| unreachable!("a genesis link has no parent"),
        DEFAULT_MAX_CHAIN_DEPTH,
    );
    assert!(
        walk.is_err(),
        "a walk on carried keys reads as verified: {walk:?}"
    );
}
