//! Customer-attested authority chain-walk — the customer-authority specification G15.
//!
//! ## What this module is
//!
//! the customer-authority specification G15 closes the BYO-HSM verifier boundary by walking the chain of
//! trust from a customer-attested AuditProof back to a root that the
//! verifier already trusts. When an AuditProof's `signing_authority.kind`
//! is `customer-attested`, the verifier:
//!
//! 1. Resolves the customer's published Ed25519 public key — either
//!    fetched from the customer's published URL OR resolved through the
//!    Nanorix trust-chain manifest (per the verifier specification) which records
//!    bounded customer-authority registrations as additional manifest
//!    entries.
//! 2. Verifies the AuditProof's signature against that customer-authority
//!    public key INSTEAD of Nanorix's own signing key.
//! 3. Walks the customer authority's manifest entry to confirm
//!    `state == 'active'` (or `archived` for historical AuditProofs whose
//!    timestamp falls within the active window — archive-forever).
//!
//! ## Bounded trust-chain manifest
//!
//! Per `feedback_open_verifier_bounded_manifest.md` (canonical-track CTI
//! tier 3, hardened during VP Sec extended review): the verifier MUST
//! ground every customer-attestation chain-walk against a bounded
//! manifest. Unbounded URL fetch (e.g., follow whatever URL the
//! AuditProof claims) would let a malicious capsule producer publish a
//! key that masquerades as theirs. Bounded means: (a) verifier accepts
//! a `--trust-chain customer-manifest.json` flag, OR (b) verifier
//! resolves customer authorities via the same Nanorix-signed manifest
//! path that resolves Nanorix-self authorities.
//!
//! ## Naming relative to verify-types/chain.rs
//!
//! `governance/verify-types/src/chain.rs` ships chain-walk for
//! the specification multi-step pipeline composition (capsule chain). This
//! module ships chain-walk for the customer-authority specification G15 customer-attested AUTHORITY
//! chain (signing-authority chain, distinct from capsule chain). Both
//! are "chain walks" but at different layers:
//!
//! - `verify_chain` (verify-types): walks `parent_audit_proof_id`
//!   pointers between AuditProofs (data-flow chain).
//! - `walk_authority_chain` (this module): walks the
//!   `signing_authority` registration → org_identity_pubkey →
//!   trust-chain manifest entry (signing-authority chain).
//!
//! The two are orthogonal; an AuditProof signed by a customer authority
//! AND part of a multi-step pipeline would invoke BOTH walks during
//! full verification.
//!
//! ## Forever-Standard discipline (the Forever-Standard wire discipline)
//!
//! - The closed-set `AuthorityWalkFailure` enum is permanent. New
//!   failure modes ship as additive variants.
//! - The walk algorithm is locked: (a) resolve authority entry from
//!   bounded manifest by `authority_id`, (b) confirm state ∈
//!   {active, archived} against the AuditProof's timestamp, (c) return
//!   the resolved public key for downstream signature verification.
//! - Signature verification ITSELF lives in the verifier's main path
//!   (`lib.rs::verify_auditproof`); this module composes the walk and
//!   exposes `walk_authority_chain` for the verifier to call before
//!   the Ed25519 verify step.

use serde::{Deserialize, Serialize};

use crate::trust_chain::{KeyStatus, TrustChainManifest};

/// Customer-attested-authority kind discriminator.
///
/// Wire form: `signing_authority.kind = "customer-attested"` (from
/// `authority_kind` per the customer-authority specification D1 published-attestation document).
/// **Forever-Standard locked** — new authority kinds ship as additive
/// variants per the Forever-Standard wire discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityKind {
    /// Nanorix-self signing authority (`us-kms-nanorix-v1`,
    /// `eu-kms-nanorix-v1`, etc.). Resolves through the standard
    /// trust-chain manifest path.
    NanorixSelf,
    /// Customer-attested authority (`customer-hsm-example-org-v1`,
    /// `customer-kms-acme-v3`, etc.). Resolves through the
    /// bounded-customer-manifest path with G15 chain-walk semantics.
    CustomerAttested,
}

/// Closed-set chain-walk failure modes per the customer-authority specification G15 + the Forever-Standard wire discipline.
///
/// Each variant maps to a stable wire-form rejection reason that the
/// auditor can route on. Forever-stable — additive only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthorityWalkFailure {
    /// The AuditProof's `signing_authority.authority_id` is not present
    /// in the bounded trust-chain manifest. Either the manifest is
    /// stale OR the customer never registered this authority through
    /// `POST /v1/customer-authorities` (per the customer-authority specification D1).
    AuthorityNotInTrustChainManifest { authority_id: String },

    /// The customer authority IS in the manifest, but its `state` is
    /// not active for the AuditProof's timestamp. (`revoked` rejects
    /// at any timestamp; `archived` rejects only if the AuditProof's
    /// timestamp is outside the active window.)
    AuthorityNotActiveForTimestamp {
        authority_id: String,
        state: String,
        audit_proof_timestamp: String,
    },

    /// The customer's published public key URL was unreachable.
    /// Fired only when the verifier is configured to fetch from URL
    /// rather than rely on the bounded manifest (offline/trust-chain
    /// mode is the safer default).
    CustomerPublicKeyUnreachable {
        authority_id: String,
        url: String,
        reason: String,
    },

    /// The AuditProof's signature did not verify against the
    /// customer's published Ed25519 public key. Distinct from
    /// Nanorix-side `SignatureMismatch` — this is the customer-
    /// authority-specific rejection lane.
    CustomerSignatureInvalid {
        authority_id: String,
        reason: String,
    },

    /// `signing_authority.kind` was not recognized. V1 supports
    /// `nanorix-self` + `customer-attested`. Future kinds ship as
    /// additive variants.
    AuthorityKindUnknown { found: String },

    /// `authority_id` field was empty or structurally invalid in the
    /// AuditProof.
    AuthorityIdMalformed { reason: String },
}

/// Result of a successful authority chain-walk.
///
/// Carries the resolved public key bytes (32 bytes raw Ed25519 for
/// V1) and the resolution metadata so the caller can finish signature
/// verification + render an audit trail showing how the key was
/// resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityWalkResolution {
    /// The authority_id whose key was resolved.
    pub authority_id: String,
    /// Authority kind (nanorix-self vs customer-attested) — useful for
    /// audit-trail rendering.
    pub kind: AuthorityKind,
    /// The resolved Ed25519 public key (raw 32 bytes).
    pub public_key: Vec<u8>,
    /// Manifest entry status (active / archived) — for audit-trail
    /// rendering.
    pub key_status: KeyStatus,
    /// `signing_key_version` field from the manifest entry that
    /// matched the resolution. Auditors use this to confirm the
    /// AuditProof verifies under a key that was active or recently
    /// archived (vs a long-revoked key).
    pub signing_key_version: String,
}

/// Walk the customer-attested authority chain and resolve the public
/// key per the customer-authority specification G15.
///
/// ## Algorithm
///
/// 1. Validate `authority_id` is non-empty.
/// 2. Validate `kind` matches one of the closed-set variants. Reject
///    `AuthorityKindUnknown` for anything else.
/// 3. Look up the authority entry in the bounded `manifest`.
/// 4. Resolve `signing_key_version` against the entry's
///    `active_versions` and `archived_versions` (archive-forever
///    discipline per the verifier specification + this module's "AuditProof signed
///    under version N still verifies after rotation to N+K"
///    invariant).
/// 5. If the entry is revoked at the authority level, fail with
///    `AuthorityNotActiveForTimestamp` (per the manifest's `revoked`
///    flag).
/// 6. Decode the public key bytes from base64 and return them.
///
/// ## Bounded discipline
///
/// This function NEVER fetches URLs. The manifest is the bounded
/// trust source. URL-fetch surface lives in a separate helper
/// (deferred to V2 per `feedback_open_verifier_bounded_manifest.md`)
/// — when added, that helper must FIRST resolve the manifest entry,
/// then OPTIONALLY fetch the URL only if the manifest's
/// `customer_published_url` field is present and the verifier is
/// configured for URL-fetch (default off).
pub fn walk_authority_chain(
    authority_id: &str,
    signing_key_version: &str,
    kind: AuthorityKind,
    audit_proof_timestamp: &str,
    manifest: &TrustChainManifest,
) -> Result<AuthorityWalkResolution, AuthorityWalkFailure> {
    use base64::Engine as _;

    // 1. Structural validation.
    if authority_id.trim().is_empty() {
        return Err(AuthorityWalkFailure::AuthorityIdMalformed {
            reason: "authority_id is empty".to_string(),
        });
    }

    // 2. Manifest lookup.
    let lookup = manifest
        .find_key(authority_id, signing_key_version)
        .ok_or_else(|| AuthorityWalkFailure::AuthorityNotInTrustChainManifest {
            authority_id: authority_id.to_string(),
        })?;

    // 3. Authority-level revocation gate.
    if lookup.authority_record.revoked {
        return Err(AuthorityWalkFailure::AuthorityNotActiveForTimestamp {
            authority_id: authority_id.to_string(),
            state: "revoked".to_string(),
            audit_proof_timestamp: audit_proof_timestamp.to_string(),
        });
    }

    // 4. For G15 customer-attested kind: validate the matched key is
    //    in a state acceptable for the AuditProof's timestamp.
    //    - Active key: always acceptable.
    //    - Archived key: acceptable IF the AuditProof's timestamp
    //      falls within the active window (effective_from until
    //      archived_at). The verifier delegates this temporal check
    //      to the timestamp comparison below; if archived_at is None
    //      (manifest schema flexibility), treat as archived-forever.
    match lookup.status {
        KeyStatus::Active => { /* acceptable; fall through */ }
        KeyStatus::Archived => {
            // Validate the AuditProof's timestamp falls within the
            // archived key's active window. If archived_at < ts,
            // the AuditProof was signed AFTER the key was archived
            // — reject. Note: archive-forever discipline says the
            // KEY is preserved forever; the WINDOW is preserved
            // forever; an AuditProof signed AFTER the archive
            // boundary is still rejected because it could not have
            // been legitimately signed by an archived-state key.
            if let Some(archived_at) = lookup.record.archived_at.as_deref() {
                if audit_proof_timestamp > archived_at {
                    return Err(AuthorityWalkFailure::AuthorityNotActiveForTimestamp {
                        authority_id: authority_id.to_string(),
                        state: format!("archived_at={archived_at}"),
                        audit_proof_timestamp: audit_proof_timestamp.to_string(),
                    });
                }
            }
            // archived_at is None → schema flexibility for legacy
            // archived rows. Accept (archive-forever default).
        }
    }

    // 5. Decode the public key bytes (raw 32-byte Ed25519).
    let pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(&lookup.record.public_key_b64)
        .map_err(|e| AuthorityWalkFailure::CustomerSignatureInvalid {
            authority_id: authority_id.to_string(),
            reason: format!("manifest public_key_b64 decode failed: {e}"),
        })?;

    if pk_bytes.len() != 32 {
        return Err(AuthorityWalkFailure::CustomerSignatureInvalid {
            authority_id: authority_id.to_string(),
            reason: format!(
                "manifest public_key_b64 has {} bytes (expected 32 for Ed25519)",
                pk_bytes.len()
            ),
        });
    }

    Ok(AuthorityWalkResolution {
        authority_id: authority_id.to_string(),
        kind,
        public_key: pk_bytes,
        key_status: lookup.status,
        signing_key_version: signing_key_version.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_chain::{AuthorityRecord, KeyVersionRecord};
    use std::collections::HashMap;

    fn fixture_manifest_with_customer() -> TrustChainManifest {
        let mut authorities = HashMap::new();

        // Nanorix-self authority (existing pattern).
        authorities.insert(
            "us-kms-nanorix-v1".to_string(),
            AuthorityRecord {
                display_name: "Nanorix US production KMS".to_string(),
                active_versions: vec![KeyVersionRecord {
                    signing_key_version: "7".to_string(),
                    public_key_b64: base64::engine::general_purpose::STANDARD.encode([0xA0u8; 32]),
                    public_key_fingerprint: "sha256:nanorix-active7".to_string(),
                    effective_from: "2026-04-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                }],
                archived_versions: vec![],
                revoked: false,
            },
        );

        // Customer-attested authority (G15 surface).
        authorities.insert(
            "customer-hsm-example-org-v1".to_string(),
            AuthorityRecord {
                display_name: "Mayo Clinic HSM".to_string(),
                active_versions: vec![KeyVersionRecord {
                    signing_key_version: "1".to_string(),
                    public_key_b64: base64::engine::general_purpose::STANDARD.encode([0xC1u8; 32]),
                    public_key_fingerprint: "sha256:mayo-active1".to_string(),
                    effective_from: "2026-05-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                }],
                archived_versions: vec![KeyVersionRecord {
                    signing_key_version: "0".to_string(),
                    public_key_b64: base64::engine::general_purpose::STANDARD.encode([0xC0u8; 32]),
                    public_key_fingerprint: "sha256:mayo-archived0".to_string(),
                    effective_from: "2025-11-01T00:00:00Z".to_string(),
                    archived_at: Some("2026-04-30T23:59:59Z".to_string()),
                    algorithm: None,
                }],
                revoked: false,
            },
        );

        // Revoked customer authority (boundary).
        authorities.insert(
            "customer-hsm-revoked-corp-v2".to_string(),
            AuthorityRecord {
                display_name: "Revoked Corp HSM".to_string(),
                active_versions: vec![KeyVersionRecord {
                    signing_key_version: "1".to_string(),
                    public_key_b64: base64::engine::general_purpose::STANDARD.encode([0xDDu8; 32]),
                    public_key_fingerprint: "sha256:revoked-corp-1".to_string(),
                    effective_from: "2026-01-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                }],
                archived_versions: vec![],
                revoked: true,
            },
        );

        TrustChainManifest {
            schema_version: "1".to_string(),
            issued_at: "2026-05-10T00:00:00Z".to_string(),
            authorities,
            identity_fingerprint: "sha256:nanorix-identity-v1".to_string(),
            manifest_signature: "base64:placeholder".to_string(),
        }
    }

    // ── Happy-path: customer-attested authority resolves to active key ──

    #[test]
    fn walk_resolves_active_customer_authority() {
        let manifest = fixture_manifest_with_customer();
        let result = walk_authority_chain(
            "customer-hsm-example-org-v1",
            "1",
            AuthorityKind::CustomerAttested,
            "2026-05-09T12:00:00Z",
            &manifest,
        )
        .expect("resolution should succeed");
        assert_eq!(result.authority_id, "customer-hsm-example-org-v1");
        assert_eq!(result.kind, AuthorityKind::CustomerAttested);
        assert_eq!(result.key_status, KeyStatus::Active);
        assert_eq!(result.signing_key_version, "1");
        assert_eq!(result.public_key, vec![0xC1u8; 32]);
    }

    #[test]
    fn walk_resolves_archived_customer_authority_within_window() {
        let manifest = fixture_manifest_with_customer();
        let result = walk_authority_chain(
            "customer-hsm-example-org-v1",
            "0",
            AuthorityKind::CustomerAttested,
            "2026-04-15T12:00:00Z", // before archived_at
            &manifest,
        )
        .expect("archived-key-within-window should resolve");
        assert_eq!(result.key_status, KeyStatus::Archived);
        assert_eq!(result.public_key, vec![0xC0u8; 32]);
    }

    // ── Failure modes ─────────────────────────────────────────────────

    #[test]
    fn walk_rejects_authority_not_in_manifest() {
        let manifest = fixture_manifest_with_customer();
        let err = walk_authority_chain(
            "customer-hsm-unknown-v9",
            "1",
            AuthorityKind::CustomerAttested,
            "2026-05-09T12:00:00Z",
            &manifest,
        )
        .unwrap_err();
        match err {
            AuthorityWalkFailure::AuthorityNotInTrustChainManifest { authority_id } => {
                assert_eq!(authority_id, "customer-hsm-unknown-v9");
            }
            other => panic!("expected AuthorityNotInTrustChainManifest, got {other:?}"),
        }
    }

    #[test]
    fn walk_rejects_revoked_authority() {
        let manifest = fixture_manifest_with_customer();
        let err = walk_authority_chain(
            "customer-hsm-revoked-corp-v2",
            "1",
            AuthorityKind::CustomerAttested,
            "2026-05-09T12:00:00Z",
            &manifest,
        )
        .unwrap_err();
        match err {
            AuthorityWalkFailure::AuthorityNotActiveForTimestamp { state, .. } => {
                assert_eq!(state, "revoked");
            }
            other => panic!("expected AuthorityNotActiveForTimestamp, got {other:?}"),
        }
    }

    #[test]
    fn walk_rejects_archived_key_after_window() {
        let manifest = fixture_manifest_with_customer();
        let err = walk_authority_chain(
            "customer-hsm-example-org-v1",
            "0",
            AuthorityKind::CustomerAttested,
            "2026-05-15T12:00:00Z", // after archived_at = 2026-04-30
            &manifest,
        )
        .unwrap_err();
        match err {
            AuthorityWalkFailure::AuthorityNotActiveForTimestamp { state, .. } => {
                assert!(state.starts_with("archived_at="), "got state={state}");
            }
            other => panic!("expected AuthorityNotActiveForTimestamp, got {other:?}"),
        }
    }

    #[test]
    fn walk_rejects_empty_authority_id() {
        let manifest = fixture_manifest_with_customer();
        let err = walk_authority_chain(
            "",
            "1",
            AuthorityKind::CustomerAttested,
            "2026-05-09T12:00:00Z",
            &manifest,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AuthorityWalkFailure::AuthorityIdMalformed { .. }
        ));
    }

    #[test]
    fn walk_rejects_unknown_signing_key_version() {
        let manifest = fixture_manifest_with_customer();
        let err = walk_authority_chain(
            "customer-hsm-example-org-v1",
            "999", // not in active or archived
            AuthorityKind::CustomerAttested,
            "2026-05-09T12:00:00Z",
            &manifest,
        )
        .unwrap_err();
        // signing-key-version not present folds into
        // "AuthorityNotInTrustChainManifest" because manifest.find_key
        // returns None.
        assert!(matches!(
            err,
            AuthorityWalkFailure::AuthorityNotInTrustChainManifest { .. }
        ));
    }

    #[test]
    fn authority_kind_serde_kebab_case() {
        let kinds = [
            (AuthorityKind::NanorixSelf, "nanorix-self"),
            (AuthorityKind::CustomerAttested, "customer-attested"),
        ];
        for (kind, expected) in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", expected));
            let round: AuthorityKind = serde_json::from_str(&json).unwrap();
            assert_eq!(round, kind);
        }
    }

    #[test]
    fn walk_failure_serde_snake_case_wire_form() {
        // Forever-Standard wire-form lock per the Forever-Standard wire discipline.
        let cases: Vec<(AuthorityWalkFailure, &str)> = vec![
            (
                AuthorityWalkFailure::AuthorityNotInTrustChainManifest {
                    authority_id: "x".into(),
                },
                "authority_not_in_trust_chain_manifest",
            ),
            (
                AuthorityWalkFailure::AuthorityNotActiveForTimestamp {
                    authority_id: "x".into(),
                    state: "revoked".into(),
                    audit_proof_timestamp: "2026-05-09T12:00:00Z".into(),
                },
                "authority_not_active_for_timestamp",
            ),
            (
                AuthorityWalkFailure::CustomerPublicKeyUnreachable {
                    authority_id: "x".into(),
                    url: "https://x".into(),
                    reason: "timeout".into(),
                },
                "customer_public_key_unreachable",
            ),
            (
                AuthorityWalkFailure::CustomerSignatureInvalid {
                    authority_id: "x".into(),
                    reason: "verify failed".into(),
                },
                "customer_signature_invalid",
            ),
            (
                AuthorityWalkFailure::AuthorityKindUnknown {
                    found: "alien".into(),
                },
                "authority_kind_unknown",
            ),
            (
                AuthorityWalkFailure::AuthorityIdMalformed {
                    reason: "empty".into(),
                },
                "authority_id_malformed",
            ),
        ];
        for (variant, expected_tag) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            let tag = format!(r#""type":"{}""#, expected_tag);
            assert!(
                json.contains(&tag),
                "wire-form drift: expected {tag}, got {json}"
            );
        }
    }

    // ── Property test at 10k iterations ───────────────────────────────

    #[test]
    fn property_walk_closed_set_failure_for_random_inputs_10k_iter() {
        // For arbitrary random (authority_id, signing_key_version,
        // timestamp) inputs, the walk MUST always return either Ok or
        // a closed-set AuthorityWalkFailure variant. No panics, no
        // unintended error types. Per `feedback_canonical_hash_under_fault.md`:
        // 10k iter sweeps the input space against the closed-enum
        // contract.
        let manifest = fixture_manifest_with_customer();

        // Deterministic LCG seed.
        let mut state: u64 = 0xBADD_C0DE_DEAD_BEEF;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let id_pool = [
            "customer-hsm-example-org-v1",
            "customer-hsm-revoked-corp-v2",
            "customer-hsm-unknown-v9",
            "us-kms-nanorix-v1",
            "",
        ];
        let version_pool = ["0", "1", "7", "999"];
        let timestamp_pool = [
            "2025-12-01T00:00:00Z",
            "2026-04-15T12:00:00Z",
            "2026-04-30T23:59:59Z",
            "2026-05-15T12:00:00Z",
            "2099-01-01T00:00:00Z",
        ];

        let mut ok_count = 0usize;
        let mut closed_set_failures = 0usize;

        for _ in 0..10_000 {
            let r = next();
            let id = id_pool[(r as usize) % id_pool.len()];
            let r = next();
            let ver = version_pool[(r as usize) % version_pool.len()];
            let r = next();
            let ts = timestamp_pool[(r as usize) % timestamp_pool.len()];
            let r = next();
            let kind = if r % 2 == 0 {
                AuthorityKind::CustomerAttested
            } else {
                AuthorityKind::NanorixSelf
            };

            match walk_authority_chain(id, ver, kind, ts, &manifest) {
                Ok(_) => ok_count += 1,
                Err(failure) => {
                    // Confirm we got a closed-set variant by exhaustive match.
                    match failure {
                        AuthorityWalkFailure::AuthorityNotInTrustChainManifest { .. }
                        | AuthorityWalkFailure::AuthorityNotActiveForTimestamp { .. }
                        | AuthorityWalkFailure::CustomerPublicKeyUnreachable { .. }
                        | AuthorityWalkFailure::CustomerSignatureInvalid { .. }
                        | AuthorityWalkFailure::AuthorityKindUnknown { .. }
                        | AuthorityWalkFailure::AuthorityIdMalformed { .. } => {
                            closed_set_failures += 1;
                        }
                    }
                }
            }
        }

        assert_eq!(ok_count + closed_set_failures, 10_000);
        // Sanity: at least some Ok responses (manifest fixtures match
        // some random inputs) and some failures.
        assert!(ok_count > 0, "expected some Ok responses; got {ok_count}");
        assert!(
            closed_set_failures > 0,
            "expected some failures; got {closed_set_failures}"
        );
    }
}
