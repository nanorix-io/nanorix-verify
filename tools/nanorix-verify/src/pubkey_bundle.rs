//! Portable Pubkey Bundle (`.ppb.json`) — Wave B Item 8 surface.
//!
//! A JSON document carrying N cross-org Ed25519 verification pubkeys, used
//! when an receipt-batching specification cross-org chain references a parent AuditProof signed
//! under a different Nanorix customer account OR an offline/air-gap
//! environment where `/v1/keys/:id` lookup is unavailable.
//!
//! Per `feedback_narrowness_is_the_moat_resist_receipt_enrichment.md`: this
//! is a JSON convention + JSON Schema + SDK helper — NOT a new file format
//! with MIME registration / OS-level associations.
//!
//! Per `feedback_open_verifier_bounded_manifest.md`: the bundle algorithm is
//! open + portable; the trust root (publisher pubkey) is bounded out-of-band
//! by the verifier. Mirror of OpenPGP / X.509 / C2PA pattern: algorithm
//! openness + identity boundedness.
//!
//! ## Workflow
//!
//! 1. Bundle producer (Nanorix-managed publisher OR customer-signed)
//!    collects N pubkeys for cross-org parent verification.
//! 2. Producer calls `build_pubkey_bundle(...)` with the keys + a signing
//!    key + issuer org tag. Output: signed `.ppb.json`.
//! 3. Consumer (auditor / sovereign-EU customer / air-gap verifier) calls
//!    `verify_pubkey_bundle(bundle, &publisher_pubkey)` to confirm bundle
//!    publisher integrity.
//! 4. Consumer calls `resolve_parent_key(bundle, key_id, at_timestamp)` per
//!    parent_proof_link being verified to look up the parent's pubkey.
//!
//! ## Forever-Standard discipline
//!
//! Bundles are append-only — key rotation = new bundle generation, NEVER
//! mutation of an existing bundle. Old AuditProofs signed under rotated keys
//! must remain verifiable in perpetuity (healthcare 7-30 year retention).

use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::strip_base64_prefix;

/// Mandatory bundle disclaimer — factual language only, no compliance verdicts.
///
/// Vocabulary discipline per `regulatory_context` rules + CONVENTIONS.md:
/// forbidden words include `COMPLIANT`, `SATISFIED`, `PASSED`, `MEETS`.
pub const PORTABLE_PUBKEY_BUNDLE_DISCLAIMER: &str = "This Portable Pubkey Bundle is a key-discovery aid for cross-org chain verification. The bundle_signature confirms publisher integrity. The bundle issuer attests that the listed pubkeys were valid as of generated_at; subsequent key rotation or revocation MUST be verified out-of-band by the consuming party.";

/// Wave B Item 8 — Portable Pubkey Bundle wire shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortablePubkeyBundle {
    pub bundle_version: String,
    pub bundle_type: String,
    pub generated_at: String,
    pub issuer_organization: String,
    pub pubkeys: Vec<PubKeyEntry>,
    pub bundle_signature: BundleSignature,
    pub disclaimer: String,
}

/// A single pubkey entry within a Portable Pubkey Bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PubKeyEntry {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub valid_from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub issued_by_org: String,
}

/// Bundle self-signature carrying publisher integrity attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleSignature {
    pub algorithm: String,
    pub signed_by_key_id: String,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PubkeyBundleError {
    #[error("bundle_version unsupported: {0}")]
    UnsupportedVersion(String),
    #[error("bundle_type is not 'pubkey': {0}")]
    WrongBundleType(String),
    #[error("bundle_signature verification failed")]
    BundleSignatureFailed,
    #[error("publisher pubkey wrong size: got {0}, want 32")]
    InvalidPublisherKey(usize),
    #[error("bundle_signature wrong size: got {0}, want 64")]
    InvalidSignatureSize(usize),
    #[error("base64 decode error in field {field}: {reason}")]
    Base64Decode { field: &'static str, reason: String },
    #[error("canonical JCS serialization failed: {0}")]
    Canonicalization(String),
    #[error("pubkey entry {idx} invalid: {reason}")]
    InvalidEntry { idx: usize, reason: String },
    #[error("bundle has no pubkeys (must have at least one)")]
    EmptyBundle,
}

/// Build a Portable Pubkey Bundle from N pubkey entries + a signer key.
///
/// The bundle is self-signed using `signer_key`. The publishing party then
/// distributes the bundle out-of-band; consumers verify via
/// `verify_pubkey_bundle` using the publisher's pubkey (delivered through
/// trust-chain manifest / direct override / pre-shared OOB).
pub fn build_pubkey_bundle(
    keys: Vec<PubKeyEntry>,
    signer_key: &SigningKey,
    signer_key_id: &str,
    issuer_organization: &str,
) -> Result<PortablePubkeyBundle, PubkeyBundleError> {
    if keys.is_empty() {
        return Err(PubkeyBundleError::EmptyBundle);
    }
    for (idx, entry) in keys.iter().enumerate() {
        validate_entry(entry, idx)?;
    }

    let generated_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Build the bundle with an empty signature first; canonicalize; sign.
    let placeholder = PortablePubkeyBundle {
        bundle_version: "1.0".to_string(),
        bundle_type: "pubkey".to_string(),
        generated_at,
        issuer_organization: issuer_organization.to_string(),
        pubkeys: keys,
        bundle_signature: BundleSignature {
            algorithm: "Ed25519".to_string(),
            signed_by_key_id: signer_key_id.to_string(),
            signature: String::new(),
        },
        disclaimer: PORTABLE_PUBKEY_BUNDLE_DISCLAIMER.to_string(),
    };

    let canonical = canonical_bytes_for_signing(&placeholder)?;
    let signature: Signature = signer_key.sign(&canonical);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    let mut bundle = placeholder;
    bundle.bundle_signature.signature = sig_b64;
    Ok(bundle)
}

/// Verify a Portable Pubkey Bundle's publisher signature.
///
/// `publisher_pubkey` is the trust-anchor; it MUST be delivered out-of-band
/// (Nanorix trust-chain manifest / direct override / pre-shared with auditor).
/// The bundle's `bundle_signature.signed_by_key_id` MUST match the consumer's
/// expected publisher identity — verified at the application layer, not by
/// this function (separation of cryptographic verification from policy).
pub fn verify_pubkey_bundle(
    bundle: &PortablePubkeyBundle,
    publisher_pubkey: &VerifyingKey,
) -> Result<(), PubkeyBundleError> {
    if bundle.bundle_version != "1.0" {
        return Err(PubkeyBundleError::UnsupportedVersion(
            bundle.bundle_version.clone(),
        ));
    }
    if bundle.bundle_type != "pubkey" {
        return Err(PubkeyBundleError::WrongBundleType(
            bundle.bundle_type.clone(),
        ));
    }
    if bundle.pubkeys.is_empty() {
        return Err(PubkeyBundleError::EmptyBundle);
    }
    for (idx, entry) in bundle.pubkeys.iter().enumerate() {
        validate_entry(entry, idx)?;
    }

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(strip_base64_prefix(&bundle.bundle_signature.signature))
        .map_err(|e| PubkeyBundleError::Base64Decode {
            field: "bundle_signature.signature",
            reason: e.to_string(),
        })?;
    if sig_bytes.len() != 64 {
        return Err(PubkeyBundleError::InvalidSignatureSize(sig_bytes.len()));
    }
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PubkeyBundleError::BundleSignatureFailed)?;
    let signature = Signature::from_bytes(&sig_array);

    // Canonicalize the bundle with signature field cleared.
    let mut canonical_input = bundle.clone();
    canonical_input.bundle_signature.signature = String::new();
    let canonical = canonical_bytes_for_signing(&canonical_input)?;

    publisher_pubkey
        .verify(&canonical, &signature)
        .map_err(|_| PubkeyBundleError::BundleSignatureFailed)?;

    Ok(())
}

/// Resolve a parent AuditProof's pubkey given a `key_id` + timestamp.
///
/// Returns the pubkey entry whose `key_id` matches AND whose validity window
/// contains `at_timestamp` (valid_from <= at <= valid_until OR valid_until is
/// None meaning still-current at bundle generation). Returns None if no
/// matching entry is found.
///
/// Note: "outside validity window" does NOT mean "untrusted for historical
/// verification". The validity window is informational metadata about when
/// the key was the actively-rotated authority; old AuditProofs signed under
/// rotated keys remain verifiable in perpetuity (forever-archive discipline).
pub fn resolve_parent_key<'a>(
    bundle: &'a PortablePubkeyBundle,
    key_id: &str,
    at_timestamp: DateTime<Utc>,
) -> Option<&'a PubKeyEntry> {
    bundle.pubkeys.iter().find(|entry| {
        if entry.key_id != key_id {
            return false;
        }
        let valid_from = DateTime::parse_from_rfc3339(&entry.valid_from)
            .ok()
            .map(|dt| dt.with_timezone(&Utc));
        let valid_until = entry
            .valid_until
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        match (valid_from, valid_until) {
            (Some(from), Some(until)) => at_timestamp >= from && at_timestamp <= until,
            (Some(from), None) => at_timestamp >= from,
            (None, _) => false,
        }
    })
}

/// Resolve a parent AuditProof's pubkey regardless of validity window
/// (forever-archive lookup for historical verification).
///
/// Used when a historical AuditProof signed under a rotated key needs
/// verification — the rotated key's `valid_until` is in the past but the
/// signature must still verify. Returns the FIRST matching `key_id`.
pub fn resolve_parent_key_forever<'a>(
    bundle: &'a PortablePubkeyBundle,
    key_id: &str,
) -> Option<&'a PubKeyEntry> {
    bundle.pubkeys.iter().find(|entry| entry.key_id == key_id)
}

fn validate_entry(entry: &PubKeyEntry, idx: usize) -> Result<(), PubkeyBundleError> {
    if entry.algorithm != "Ed25519" {
        return Err(PubkeyBundleError::InvalidEntry {
            idx,
            reason: format!("unsupported algorithm {}", entry.algorithm),
        });
    }
    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(strip_base64_prefix(&entry.public_key))
        .map_err(|e| PubkeyBundleError::InvalidEntry {
            idx,
            reason: format!("base64 decode failed: {e}"),
        })?;
    if pub_bytes.len() != 32 {
        return Err(PubkeyBundleError::InvalidEntry {
            idx,
            reason: format!("public_key wrong size: got {}, want 32", pub_bytes.len()),
        });
    }
    if entry.key_id.is_empty() {
        return Err(PubkeyBundleError::InvalidEntry {
            idx,
            reason: "key_id empty".to_string(),
        });
    }
    Ok(())
}

/// Canonicalize the bundle for signing/verification via RFC 8785 JCS.
///
/// The bundle's `bundle_signature.signature` field is cleared before
/// canonicalization so signing is deterministic.
fn canonical_bytes_for_signing(
    bundle: &PortablePubkeyBundle,
) -> Result<Vec<u8>, PubkeyBundleError> {
    let mut input = bundle.clone();
    input.bundle_signature.signature = String::new();
    let value = serde_json::to_value(&input).map_err(|e| {
        PubkeyBundleError::Canonicalization(format!("serde_json::to_value failed: {e}"))
    })?;
    serde_jcs::to_vec(&value)
        .map_err(|e| PubkeyBundleError::Canonicalization(format!("serde_jcs::to_vec failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signer() -> (SigningKey, VerifyingKey, String) {
        let seed = [7u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        let signer_key_id = "nrx-bundle-publisher-test-v1".to_string();
        (signing, verifying, signer_key_id)
    }

    fn make_test_pubkey_entry(key_id: &str) -> PubKeyEntry {
        let seed = [9u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(vk.to_bytes());
        PubKeyEntry {
            key_id: key_id.to_string(),
            algorithm: "Ed25519".to_string(),
            public_key: pub_b64,
            valid_from: "2026-01-01T00:00:00Z".to_string(),
            valid_until: Some("2027-01-01T00:00:00Z".to_string()),
            issued_by_org: "vendor:test".to_string(),
        }
    }

    #[test]
    fn build_pubkey_bundle_succeeds() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        assert_eq!(bundle.bundle_version, "1.0");
        assert_eq!(bundle.bundle_type, "pubkey");
        assert_eq!(bundle.pubkeys.len(), 1);
        assert!(!bundle.bundle_signature.signature.is_empty());
    }

    #[test]
    fn verify_pubkey_bundle_round_trip() {
        let (sk, vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        verify_pubkey_bundle(&bundle, &vk).expect("bundle verifies");
    }

    #[test]
    fn verify_pubkey_bundle_wrong_publisher_rejected() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let attacker_seed = [99u8; 32];
        let attacker_pubkey = SigningKey::from_bytes(&attacker_seed).verifying_key();
        let err = verify_pubkey_bundle(&bundle, &attacker_pubkey).unwrap_err();
        assert!(matches!(err, PubkeyBundleError::BundleSignatureFailed));
    }

    #[test]
    fn verify_pubkey_bundle_tampered_pubkey_rejected() {
        let (sk, vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let mut bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        // Tamper a pubkey entry — signature should no longer verify.
        bundle.pubkeys[0].issued_by_org = "vendor:hacked".to_string();
        let err = verify_pubkey_bundle(&bundle, &vk).unwrap_err();
        assert!(matches!(err, PubkeyBundleError::BundleSignatureFailed));
    }

    #[test]
    fn verify_pubkey_bundle_tampered_issuer_rejected() {
        let (sk, vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let mut bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        bundle.issuer_organization = "issuer:hacked".to_string();
        let err = verify_pubkey_bundle(&bundle, &vk).unwrap_err();
        assert!(matches!(err, PubkeyBundleError::BundleSignatureFailed));
    }

    #[test]
    fn resolve_parent_key_within_window_succeeds() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let mid = "2026-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let resolved = resolve_parent_key(&bundle, "key-1", mid);
        assert!(resolved.is_some());
    }

    #[test]
    fn resolve_parent_key_before_window_returns_none() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let before = "2025-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let resolved = resolve_parent_key(&bundle, "key-1", before);
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_parent_key_after_window_returns_none() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let after = "2030-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let resolved = resolve_parent_key(&bundle, "key-1", after);
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_parent_key_forever_finds_outside_window() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let after = "2030-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        // Within-window resolver returns None for historic AuditProof verification need.
        assert!(resolve_parent_key(&bundle, "key-1", after).is_none());
        // Forever-archive resolver returns the entry regardless of window.
        assert!(resolve_parent_key_forever(&bundle, "key-1").is_some());
    }

    #[test]
    fn resolve_parent_key_unknown_id_returns_none() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let now = "2026-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let resolved = resolve_parent_key(&bundle, "unknown-key", now);
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_parent_key_open_ended_window() {
        let (sk, _vk, key_id) = make_signer();
        let mut entry = make_test_pubkey_entry("key-current");
        entry.valid_until = None;
        let bundle = build_pubkey_bundle(vec![entry], &sk, &key_id, "issuer:test").unwrap();
        let later = "2030-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let resolved = resolve_parent_key(&bundle, "key-current", later);
        assert!(resolved.is_some(), "null valid_until = still-current key");
    }

    #[test]
    fn build_bundle_with_multiple_keys() {
        let (sk, vk, key_id) = make_signer();
        let entries = vec![
            make_test_pubkey_entry("key-1"),
            make_test_pubkey_entry("key-2"),
            make_test_pubkey_entry("key-3"),
        ];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        assert_eq!(bundle.pubkeys.len(), 3);
        verify_pubkey_bundle(&bundle, &vk).unwrap();
    }

    #[test]
    fn build_empty_bundle_rejected() {
        let (sk, _vk, key_id) = make_signer();
        let err = build_pubkey_bundle(Vec::new(), &sk, &key_id, "issuer:test").unwrap_err();
        assert!(matches!(err, PubkeyBundleError::EmptyBundle));
    }

    #[test]
    fn build_bundle_with_invalid_algorithm_rejected() {
        let (sk, _vk, key_id) = make_signer();
        let mut entry = make_test_pubkey_entry("key-1");
        entry.algorithm = "RSA-2048".to_string();
        let err = build_pubkey_bundle(vec![entry], &sk, &key_id, "issuer:test").unwrap_err();
        assert!(matches!(err, PubkeyBundleError::InvalidEntry { .. }));
    }

    #[test]
    fn build_bundle_with_wrong_pubkey_size_rejected() {
        let (sk, _vk, key_id) = make_signer();
        let mut entry = make_test_pubkey_entry("key-1");
        entry.public_key = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let err = build_pubkey_bundle(vec![entry], &sk, &key_id, "issuer:test").unwrap_err();
        assert!(matches!(err, PubkeyBundleError::InvalidEntry { .. }));
    }

    #[test]
    fn bundle_disclaimer_factual_language() {
        for forbidden in ["COMPLIANT", "SATISFIED", "PASSED", "MEETS"] {
            assert!(
                !PORTABLE_PUBKEY_BUNDLE_DISCLAIMER.contains(forbidden),
                "disclaimer must not contain forbidden term {forbidden}"
            );
        }
    }

    #[test]
    fn bundle_disclaimer_mentions_out_of_band_rotation() {
        assert!(
            PORTABLE_PUBKEY_BUNDLE_DISCLAIMER
                .to_lowercase()
                .contains("out-of-band"),
            "disclaimer must mention out-of-band rotation verification"
        );
    }

    #[test]
    fn bundle_serializes_round_trips() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let roundtripped: PortablePubkeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, roundtripped);
    }

    #[test]
    fn bundle_version_pinned_to_1_0() {
        let (sk, vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let mut bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        bundle.bundle_version = "2.0".to_string();
        let err = verify_pubkey_bundle(&bundle, &vk).unwrap_err();
        assert!(matches!(err, PubkeyBundleError::UnsupportedVersion(_)));
    }

    #[test]
    fn bundle_type_pinned_to_pubkey() {
        let (sk, vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let mut bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        bundle.bundle_type = "receipt".to_string();
        let err = verify_pubkey_bundle(&bundle, &vk).unwrap_err();
        assert!(matches!(err, PubkeyBundleError::WrongBundleType(_)));
    }

    #[test]
    fn bundle_json_no_forbidden_compliance_terms() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries, &sk, &key_id, "issuer:test").unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        for forbidden in ["COMPLIANT", "SATISFIED", "PASSED", "MEETS"] {
            assert!(
                !json.contains(forbidden),
                "bundle JSON must not contain {forbidden}"
            );
        }
    }

    #[test]
    fn bundle_jcs_canonicalization_deterministic() {
        let (sk, _vk, key_id) = make_signer();
        let entries = vec![make_test_pubkey_entry("key-1")];
        let bundle = build_pubkey_bundle(entries.clone(), &sk, &key_id, "issuer:test").unwrap();
        let canonical_1 = canonical_bytes_for_signing(&bundle).unwrap();
        let canonical_2 = canonical_bytes_for_signing(&bundle).unwrap();
        assert_eq!(canonical_1, canonical_2);
    }
}
