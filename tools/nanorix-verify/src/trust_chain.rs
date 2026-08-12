//! Trust-chain manifest — authority public keys with archive-forever discipline.
//!
//! Per the verifier specification (G2 long-term verifiability, addendum 2026-05-06):
//! "An AuditProof signed today with signing_key_version 7 must be verifiable
//! in 2032 even after we've rotated to version 12. Healthcare retention is
//! 7-30 years. Without archive-forever discipline encoded now, we ship a
//! product whose proofs become unverifiable on rotation."
//!
//! This module's discipline:
//!
//! - `TrustChainManifest` holds BOTH `active_versions` and `archived_versions`
//!   per authority. Lookups span both.
//! - Archived entries **MUST NEVER be removed** from the manifest (enforced by
//!   policy + by the manifest's own internal signature, which would break if
//!   archived rows were stripped).
//! - The manifest itself is signed by Nanorix's long-term identity key whose
//!   fingerprint is published statically at
//!   `https://nanorix.io/.well-known/identity.txt` and on every GitHub
//!   release.
//!
//! Provides the data model, key lookup, and (trust-chain anchoring) manifest-signature
//! verification + the assemble-and-sign tool. The live
//! `https://nanorix.io/.well-known/trust-chain.json` fetch and the real
//! HSM-rooted identity key are provisioned just-in-time at first-client
//! onboarding; until then the verifier consumes a manifest via `--trust-chain`
//! and pins the identity fingerprint via `--identity-fingerprint`.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Full trust-chain manifest, fetched from
/// `https://nanorix.io/.well-known/trust-chain.json` or loaded from a local
/// file via `--trust-chain`.
///
/// Forever-stable schema per the Forever-Standard wire discipline — once published, fields are
/// additive only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustChainManifest {
    /// Schema version. V1 = `"1"`. Will be bumped only for additive changes.
    pub schema_version: String,

    /// When this manifest was issued. RFC 3339 UTC.
    pub issued_at: String,

    /// One entry per signing authority (e.g., `us-kms-nanorix-v1`,
    /// `eu-kms-nanorix-v1`). The map key is the authority ID that appears in
    /// AuditProof attestations.
    pub authorities: HashMap<String, AuthorityRecord>,

    /// Long-term identity-key fingerprint that signed this manifest.
    pub identity_fingerprint: String,

    /// The long-term identity PUBLIC key (Ed25519, base64, no prefix) whose
    /// SHA-256 fingerprint is `identity_fingerprint`. Carried inline so an
    /// offline verifier needs only the short fingerprint pinned out-of-band
    /// (from `nanorix.io/.well-known/identity.txt`, GitHub releases, docs) to
    /// check this signature. `#[serde(default)]` for forward-compat; manifest
    /// verification fails closed when this is empty.
    #[serde(default)]
    pub identity_public_key_b64: String,

    /// Ed25519 signature over a canonical-JCS form of the manifest minus
    /// this field and `pqc_manifest_signature`. base64 (with `base64:` prefix).
    pub manifest_signature: String,

    /// Reserved for the post-quantum manifest dual-signature (the specification:
    /// SLH-DSA-SHA2-256s) over the same `signed_payload()` bytes as
    /// `manifest_signature`. Always `None` until the specification Phase 1; absent from
    /// the JSON until then, so pre-PQC manifests are byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_manifest_signature: Option<String>,
}

/// One authority's keys — both active (for current signing) and archived
/// (forever-retained for verification of historical AuditProofs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthorityRecord {
    /// Display name for human-readable output.
    pub display_name: String,

    /// Currently-active signing keys. Multiple may be active during overlap
    /// periods (e.g., during a key rotation). At least one element required.
    pub active_versions: Vec<KeyVersionRecord>,

    /// Archived signing keys. Once a version moves here it MUST NEVER be
    /// removed — that would break verification of historical AuditProofs
    /// signed under that version.
    #[serde(default)]
    pub archived_versions: Vec<KeyVersionRecord>,

    /// True if the entire authority has been revoked (all its keys, active
    /// AND archived, should be considered untrusted for future verifications).
    /// Distinct from individual key archival.
    #[serde(default)]
    pub revoked: bool,
}

/// One key version's record. Schema is identical for active and archived
/// entries; the only difference is which list they live in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyVersionRecord {
    /// Wire-stable version identifier (e.g., `"7"`, `"v7"`, `"2026-04-01-rev-1"`).
    /// Matches the `signing_key_version` field in AuditProof attestations.
    pub signing_key_version: String,

    /// Ed25519 public key, base64-encoded (no `base64:` prefix here — that's
    /// a wire-format convention, not a storage convention).
    pub public_key_b64: String,

    /// SHA-256 fingerprint over the public key bytes, hex-encoded with
    /// `sha256:` prefix per the Forever-Standard wire discipline prefix discipline.
    pub public_key_fingerprint: String,

    /// When this key first became valid for signing. RFC 3339 UTC.
    pub effective_from: String,

    /// When this key was archived (moved out of `active_versions`). RFC 3339
    /// UTC. None for currently-active keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,

    /// Signature algorithm for this key version. Absent means `"Ed25519"`
    /// (every pre-the specification key). Added per the specification.1 BEFORE first public
    /// manifest publication so the forever-stable schema carries algorithm
    /// agility from day one; hybrid-era key versions will name their PQC
    /// algorithm here (e.g., `"ML-DSA-65"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

impl KeyVersionRecord {
    /// The effective signature algorithm: the explicit `algorithm` field, or
    /// `"Ed25519"` when absent (the specification.1 default).
    pub fn algorithm_or_default(&self) -> &str {
        self.algorithm.as_deref().unwrap_or("Ed25519")
    }
}

impl TrustChainManifest {
    /// Look up a public key for a (authority_id, signing_key_version) pair.
    /// Returns the key whether it's currently active OR archived.
    ///
    /// This is the load-bearing function for archive-forever verification:
    /// an AuditProof signed under version 7 must resolve to a public key
    /// even after we've rotated to version 12.
    pub fn find_key<'a>(
        &'a self,
        authority_id: &str,
        signing_key_version: &str,
    ) -> Option<KeyLookupResult<'a>> {
        let authority = self.authorities.get(authority_id)?;

        if let Some(record) = authority
            .active_versions
            .iter()
            .find(|r| r.signing_key_version == signing_key_version)
        {
            return Some(KeyLookupResult {
                record,
                authority_record: authority,
                status: KeyStatus::Active,
            });
        }

        if let Some(record) = authority
            .archived_versions
            .iter()
            .find(|r| r.signing_key_version == signing_key_version)
        {
            return Some(KeyLookupResult {
                record,
                authority_record: authority,
                status: KeyStatus::Archived,
            });
        }

        None
    }

    /// Total number of keys this manifest can verify against (active +
    /// archived across all authorities). Useful for `print-trust-chain`.
    pub fn total_keys(&self) -> usize {
        self.authorities
            .values()
            .map(|a| a.active_versions.len() + a.archived_versions.len())
            .sum()
    }

    /// Number of active keys (i.e., keys currently usable for signing new
    /// AuditProofs).
    pub fn active_keys_count(&self) -> usize {
        self.authorities
            .values()
            .filter(|a| !a.revoked)
            .map(|a| a.active_versions.len())
            .sum()
    }

    /// Number of archived keys (forever-retained for historical
    /// verification).
    pub fn archived_keys_count(&self) -> usize {
        self.authorities
            .values()
            .map(|a| a.archived_versions.len())
            .sum()
    }

    /// Deterministic signing payload: RFC-8785 JCS of this manifest with the
    /// `manifest_signature` AND `pqc_manifest_signature` keys removed. Signer
    /// and verifier MUST build the payload identically — both go through this
    /// one function. Excluding the (reserved) PQC field NOW fixes the payload
    /// contract before any manifest ships: at the specification Phase 1 both signatures
    /// independently cover this same payload, with no ordering dependency.
    fn signed_payload(&self) -> Result<Vec<u8>, ManifestError> {
        let mut value = serde_json::to_value(self).map_err(|_| ManifestError::Malformed)?;
        if let Some(obj) = value.as_object_mut() {
            obj.remove("manifest_signature");
            obj.remove("pqc_manifest_signature");
        }
        serde_jcs::to_vec(&value).map_err(|_| ManifestError::Malformed)
    }

    /// Verify the manifest's own Ed25519 signature against the long-term
    /// identity key — the trust-chain anchoring trust root.
    ///
    /// Everything the verifier trusts reduces to `pinned_fingerprint`, which
    /// the auditor obtains independently over multiple channels
    /// (`nanorix.io/.well-known/identity.txt`, GitHub releases, docs) so it can
    /// be cross-confirmed without trusting Nanorix infrastructure.
    ///
    /// Checks: (1) the inline `identity_public_key_b64` hashes to BOTH the
    /// manifest's own `identity_fingerprint` (self-consistency) and to
    /// `pinned_fingerprint` (the trust decision); (2) `manifest_signature`
    /// verifies over `signed_payload()` under that key.
    pub fn verify_signature(&self, pinned_fingerprint: &str) -> Result<(), ManifestError> {
        let pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(strip_b64(&self.identity_public_key_b64))
            .map_err(|_| ManifestError::Malformed)?;
        let pub_array: [u8; 32] = pub_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ManifestError::Malformed)?;
        let verifying_key =
            VerifyingKey::from_bytes(&pub_array).map_err(|_| ManifestError::Malformed)?;

        // The fingerprint must match both the manifest's own claim and the
        // out-of-band pin. The pin is the actual trust decision.
        let computed = fingerprint(&pub_array);
        if computed != self.identity_fingerprint || computed != pinned_fingerprint {
            return Err(ManifestError::FingerprintMismatch {
                pinned: pinned_fingerprint.to_string(),
                computed,
            });
        }

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(strip_b64(&self.manifest_signature))
            .map_err(|_| ManifestError::SignatureInvalid)?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ManifestError::SignatureInvalid)?;
        let signature = Signature::from_bytes(&sig_array);

        let payload = self.signed_payload()?;
        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| ManifestError::SignatureInvalid)
    }

    /// Assemble + sign a manifest with a long-term identity key — the
    /// "sign tool". For pre-build / test the key is an in-process `SigningKey`;
    /// at first-client JIT provisioning the identity key lives in an HSM and
    /// signing goes through the HSM/KMS sign API. Either way the payload
    /// contract is `signed_payload()`.
    pub fn build_and_sign(
        schema_version: &str,
        issued_at: &str,
        authorities: HashMap<String, AuthorityRecord>,
        identity_key: &SigningKey,
    ) -> TrustChainManifest {
        let pub_bytes = identity_key.verifying_key().to_bytes();
        let mut manifest = TrustChainManifest {
            schema_version: schema_version.to_string(),
            issued_at: issued_at.to_string(),
            authorities,
            identity_fingerprint: fingerprint(&pub_bytes),
            identity_public_key_b64: base64::engine::general_purpose::STANDARD.encode(pub_bytes),
            manifest_signature: String::new(),
            pqc_manifest_signature: None,
        };
        let payload = manifest
            .signed_payload()
            .expect("manifest serializes for signing");
        let sig = identity_key.sign(&payload);
        manifest.manifest_signature = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
        );
        manifest
    }
}

/// `sha256:`-prefixed lowercase-hex fingerprint over Ed25519 public-key bytes.
/// Matches the `public_key_fingerprint` convention on `KeyVersionRecord`.
fn fingerprint(pubkey: &[u8; 32]) -> String {
    let digest = Sha256::digest(pubkey);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

fn strip_b64(s: &str) -> &str {
    s.strip_prefix("base64:").unwrap_or(s)
}

/// Why a trust-chain manifest failed verification. A manifest failure is a
/// trust-ROOT setup error (the supplied root is broken or is not the pinned
/// one), NOT a per-proof verdict — `main.rs` surfaces it as a hard error before
/// any proof is verified, so it never masquerades as a proof `FailureReason`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("trust-chain manifest is malformed (bad identity key or JSON)")]
    Malformed,
    #[error("identity fingerprint mismatch (pinned {pinned}, manifest {computed})")]
    FingerprintMismatch { pinned: String, computed: String },
    #[error("trust-chain manifest signature did not verify against the identity key")]
    SignatureInvalid,
}

/// Result of looking up a key in the trust chain.
#[derive(Debug, Clone)]
pub struct KeyLookupResult<'a> {
    pub record: &'a KeyVersionRecord,
    pub authority_record: &'a AuthorityRecord,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Key is in the authority's active_versions list.
    Active,
    /// Key is in the authority's archived_versions list.
    /// Verification still succeeds — the key was active when the AuditProof
    /// was signed, and archive-forever discipline says we never remove it.
    Archived,
}

/// V1 stub: load manifest from a local JSON file. V2 (trust-chain anchoring) adds the
/// `https://nanorix.io/.well-known/trust-chain.json` fetch + manifest-
/// signature verification against the long-term identity key.
pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<TrustChainManifest> {
    let bytes = std::fs::read(path)?;
    let manifest: TrustChainManifest = serde_json::from_slice(&bytes)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_manifest() -> TrustChainManifest {
        let mut authorities = HashMap::new();
        authorities.insert(
            "us-kms-nanorix-v1".to_string(),
            AuthorityRecord {
                display_name: "Nanorix US production KMS".to_string(),
                active_versions: vec![KeyVersionRecord {
                    signing_key_version: "7".to_string(),
                    public_key_b64: "AAAA_active_v7".to_string(),
                    public_key_fingerprint: "sha256:active7".to_string(),
                    effective_from: "2026-04-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                }],
                archived_versions: vec![
                    KeyVersionRecord {
                        signing_key_version: "6".to_string(),
                        public_key_b64: "AAAA_archived_v6".to_string(),
                        public_key_fingerprint: "sha256:archived6".to_string(),
                        effective_from: "2025-10-01T00:00:00Z".to_string(),
                        archived_at: Some("2026-04-01T00:00:00Z".to_string()),
                        algorithm: None,
                    },
                    KeyVersionRecord {
                        signing_key_version: "5".to_string(),
                        public_key_b64: "AAAA_archived_v5".to_string(),
                        public_key_fingerprint: "sha256:archived5".to_string(),
                        effective_from: "2025-04-01T00:00:00Z".to_string(),
                        archived_at: Some("2025-10-01T00:00:00Z".to_string()),
                        algorithm: None,
                    },
                ],
                revoked: false,
            },
        );
        authorities.insert(
            "eu-kms-nanorix-v1".to_string(),
            AuthorityRecord {
                display_name: "Nanorix EU production KMS".to_string(),
                active_versions: vec![KeyVersionRecord {
                    signing_key_version: "1".to_string(),
                    public_key_b64: "AAAA_eu_v1".to_string(),
                    public_key_fingerprint: "sha256:eu1".to_string(),
                    effective_from: "2026-05-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                }],
                archived_versions: vec![],
                revoked: false,
            },
        );

        TrustChainManifest {
            schema_version: "1".to_string(),
            issued_at: "2026-05-06T00:00:00Z".to_string(),
            authorities,
            identity_fingerprint: "sha256:nanorix-identity-v1".to_string(),
            identity_public_key_b64: String::new(),
            manifest_signature: "base64:placeholder".to_string(),
            pqc_manifest_signature: None,
        }
    }

    #[test]
    fn find_key_resolves_active_version() {
        let m = fixture_manifest();
        let result = m.find_key("us-kms-nanorix-v1", "7").unwrap();
        assert_eq!(result.status, KeyStatus::Active);
        assert_eq!(result.record.public_key_fingerprint, "sha256:active7");
    }

    #[test]
    fn find_key_resolves_archived_version() {
        // Archive-forever discipline: AuditProof signed with version 6 must
        // still verify after we've rotated to version 7.
        let m = fixture_manifest();
        let result = m.find_key("us-kms-nanorix-v1", "6").unwrap();
        assert_eq!(result.status, KeyStatus::Archived);
        assert_eq!(result.record.public_key_fingerprint, "sha256:archived6");
        assert!(result.record.archived_at.is_some());
    }

    #[test]
    fn find_key_resolves_deeply_archived_version() {
        // Even older versions still resolve. This is the year-5+ scenario.
        let m = fixture_manifest();
        let result = m.find_key("us-kms-nanorix-v1", "5").unwrap();
        assert_eq!(result.status, KeyStatus::Archived);
    }

    #[test]
    fn find_key_returns_none_for_unknown_version() {
        let m = fixture_manifest();
        assert!(m.find_key("us-kms-nanorix-v1", "999").is_none());
    }

    #[test]
    fn find_key_returns_none_for_unknown_authority() {
        let m = fixture_manifest();
        assert!(m.find_key("nonexistent-authority", "7").is_none());
    }

    #[test]
    fn key_count_helpers() {
        let m = fixture_manifest();
        assert_eq!(m.active_keys_count(), 2); // us active v7 + eu active v1
        assert_eq!(m.archived_keys_count(), 2); // us archived v6 + v5
        assert_eq!(m.total_keys(), 4);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let original = fixture_manifest();
        let json = serde_json::to_string(&original).unwrap();
        let parsed: TrustChainManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn archived_versions_field_defaults_to_empty_when_absent() {
        // Schema flexibility: an authority with only active keys (e.g., a
        // brand-new authority) doesn't need to emit an empty
        // archived_versions array.
        let json = serde_json::json!({
            "schema_version": "1",
            "issued_at": "2026-05-06T00:00:00Z",
            "identity_fingerprint": "sha256:abc",
            "manifest_signature": "base64:xyz",
            "authorities": {
                "new-auth": {
                    "display_name": "Newly added authority",
                    "active_versions": [{
                        "signing_key_version": "1",
                        "public_key_b64": "AAA",
                        "public_key_fingerprint": "sha256:1",
                        "effective_from": "2026-05-06T00:00:00Z",
                    }],
                },
            },
        });
        let manifest: TrustChainManifest = serde_json::from_value(json).unwrap();
        assert_eq!(
            manifest.authorities["new-auth"].archived_versions.len(),
            0,
            "archived_versions should default to empty"
        );
    }

    #[test]
    fn revoked_authority_excluded_from_active_count() {
        let mut m = fixture_manifest();
        m.authorities.get_mut("us-kms-nanorix-v1").unwrap().revoked = true;
        assert_eq!(
            m.active_keys_count(),
            1,
            "revoked authority's keys are not counted as active"
        );
        // But archived keys still count for historical verification:
        assert_eq!(m.archived_keys_count(), 2);
    }

    #[test]
    fn load_from_file_round_trip() {
        let manifest = fixture_manifest();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust-chain.json");
        std::fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();

        let loaded = load_from_file(&path).unwrap();
        assert_eq!(loaded, manifest);
    }

    // ── trust-chain anchoring: manifest-signature verification ──────────────────────

    /// A manifest signed by a test identity key. Returns the manifest, the
    /// identity fingerprint (the value an auditor pins out-of-band), and the
    /// authority signing key (so callers can sign a proof the manifest trusts).
    fn signed_manifest(identity_seed: [u8; 32]) -> (TrustChainManifest, String, SigningKey) {
        let identity = SigningKey::from_bytes(&identity_seed);
        let authority_key = SigningKey::from_bytes(&[9u8; 32]);
        let authority_pub = base64::engine::general_purpose::STANDARD
            .encode(authority_key.verifying_key().to_bytes());
        let mut authorities = HashMap::new();
        authorities.insert(
            "us-kms-nanorix-v1".to_string(),
            AuthorityRecord {
                display_name: "Test US KMS".to_string(),
                active_versions: vec![KeyVersionRecord {
                    signing_key_version: "1".to_string(),
                    public_key_b64: authority_pub,
                    public_key_fingerprint: "sha256:test-authority".to_string(),
                    effective_from: "2026-01-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                }],
                archived_versions: vec![],
                revoked: false,
            },
        );
        let manifest =
            TrustChainManifest::build_and_sign("1", "2026-05-31T00:00:00Z", authorities, &identity);
        let pinned = manifest.identity_fingerprint.clone();
        (manifest, pinned, authority_key)
    }

    #[test]
    fn manifest_signature_verifies_against_pinned_fingerprint() {
        let (manifest, pinned, _) = signed_manifest([3u8; 32]);
        assert!(manifest.verify_signature(&pinned).is_ok());
    }

    #[test]
    fn manifest_rejected_when_pin_differs() {
        // Attacker substitutes their own identity key and re-signs: the manifest
        // is internally self-consistent but does NOT match the fingerprint the
        // auditor obtained out-of-band. This is the core trust-root defense.
        let (forged, _, _) = signed_manifest([42u8; 32]);
        let (_, real_pin, _) = signed_manifest([3u8; 32]);
        assert!(matches!(
            forged.verify_signature(&real_pin),
            Err(ManifestError::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn manifest_rejected_when_body_tampered() {
        let (mut manifest, pinned, _) = signed_manifest([3u8; 32]);
        // Mutate a signed field after signing → JCS payload changes → sig fails.
        manifest
            .authorities
            .get_mut("us-kms-nanorix-v1")
            .unwrap()
            .active_versions[0]
            .public_key_b64 = "AAAAtampered".to_string();
        assert_eq!(
            manifest.verify_signature(&pinned),
            Err(ManifestError::SignatureInvalid)
        );
    }

    #[test]
    fn manifest_rejected_when_signature_garbled() {
        let (mut manifest, pinned, _) = signed_manifest([3u8; 32]);
        manifest.manifest_signature = "base64:Z2FyYmFnZQ==".to_string();
        assert_eq!(
            manifest.verify_signature(&pinned),
            Err(ManifestError::SignatureInvalid)
        );
    }

    #[test]
    fn manifest_rejected_when_identity_key_empty() {
        // Pre-sub-B placeholder manifests (empty identity key) fail closed.
        let m = fixture_manifest();
        assert_eq!(
            m.verify_signature("sha256:anything"),
            Err(ManifestError::Malformed)
        );
    }

    // ── the specification.1-2: algorithm agility + reserved PQC dual-signature ────

    #[test]
    fn algorithm_defaults_to_ed25519_and_is_absent_from_json_when_none() {
        // Pre-the specification manifests carry no algorithm field: it must parse as
        // None, mean Ed25519, and round-trip back to absent (byte-compat for
        // the JCS signing payload).
        let m = fixture_manifest();
        let record = &m.authorities["us-kms-nanorix-v1"].active_versions[0];
        assert_eq!(record.algorithm, None);
        assert_eq!(record.algorithm_or_default(), "Ed25519");

        let json = serde_json::to_value(&m).unwrap();
        let record_json = &json["authorities"]["us-kms-nanorix-v1"]["active_versions"][0];
        assert!(
            record_json.get("algorithm").is_none(),
            "algorithm: None must not serialize"
        );
        assert!(
            json.get("pqc_manifest_signature").is_none(),
            "pqc_manifest_signature: None must not serialize"
        );
    }

    #[test]
    fn explicit_algorithm_round_trips() {
        let mut m = fixture_manifest();
        m.authorities
            .get_mut("us-kms-nanorix-v1")
            .unwrap()
            .active_versions[0]
            .algorithm = Some("ML-DSA-65".to_string());
        let json = serde_json::to_string(&m).unwrap();
        let parsed: TrustChainManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.authorities["us-kms-nanorix-v1"].active_versions[0].algorithm_or_default(),
            "ML-DSA-65"
        );
    }

    #[test]
    fn ed25519_manifest_signature_independent_of_pqc_field() {
        // The dual-sign contract: signed_payload() excludes BOTH signature
        // fields, so adding a pqc_manifest_signature at Phase 1 must not
        // invalidate the Ed25519 signature (and vice versa — no ordering
        // dependency between the two signatures).
        let (mut manifest, pinned, _) = signed_manifest([3u8; 32]);
        assert!(manifest.verify_signature(&pinned).is_ok());
        manifest.pqc_manifest_signature = Some("base64:future-slh-dsa-sig".to_string());
        assert!(
            manifest.verify_signature(&pinned).is_ok(),
            "Ed25519 signature must remain valid when the PQC field is filled"
        );
    }

    #[test]
    fn manifest_with_unknown_fields_still_parses() {
        // Additive-evolution insurance (the specification C.2): future manifest fields
        // at every level must be ignored by this build, not rejected.
        let json = serde_json::json!({
            "schema_version": "1",
            "issued_at": "2026-05-06T00:00:00Z",
            "identity_fingerprint": "sha256:abc",
            "manifest_signature": "base64:xyz",
            "future_manifest_field": { "anything": true },
            "authorities": {
                "new-auth": {
                    "display_name": "A",
                    "future_authority_field": 7,
                    "active_versions": [{
                        "signing_key_version": "1",
                        "public_key_b64": "AAA",
                        "public_key_fingerprint": "sha256:1",
                        "effective_from": "2026-05-06T00:00:00Z",
                        "future_key_field": "x",
                    }],
                },
            },
        });
        let manifest: TrustChainManifest = serde_json::from_value(json).unwrap();
        assert_eq!(manifest.authorities["new-auth"].active_versions.len(), 1);
    }
}
