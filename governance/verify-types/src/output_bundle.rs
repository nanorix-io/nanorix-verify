//! Output Bundle manifest + envelope types (the specification).
//!
//! The **Output Bundle** is an UNSIGNED delivery envelope that binds a
//! customer's opaque work-product (by hash only) to its VERBATIM AuditProof +
//! per-record receipts (the per-record receipt specification) + cross-org lineage (the receipt-batching specification), delivered to
//! the customer's own sink. It is the "how they actually want it" surface of
//! the raw-at-rest store-displacement model: the capsule swaps the raw layer of
//! the customer's existing store for `{derived work-product + proof}`.
//!
//! ## What lives here, and what does NOT
//!
//! This module defines the **manifest** (advisory structural binding the
//! verifier/SDK re-derive) and the **envelope** carriers. The signed evidence
//! (AuditProof, receipts, lineage) is carried **VERBATIM as opaque strings** —
//! the exact bytes the customer retrieved from `GET /v1/capsules/:id/cdp` and
//! `POST /v1/capsules/:id/record`. It is **NEVER** produced by re-serializing a
//! parsed struct: doing so reorders keys + drops `skip_serializing_if = None`
//! fields and silently breaks the Forever-Standard wire discipline byte-equivalence — a bug that is
//! *invisible to signature verification* (the Ed25519 signature is over
//! `final_hash`, not the JSON), so it would ship undetected. The property test
//! [`tests::verbatim_embed_roundtrip_preserves_bytes`] pins this guard.
//!
//! ## The manifest is NEVER a trust root
//!
//! Per the specification (crypto-review F3, confused-deputy guard): the manifest is
//! UNSIGNED advisory packaging. Trust derives **solely** from the customer
//! re-deriving `sha512(work_product)` and comparing to the **signed** receipt's
//! `record_output_hash`, then walking the ladder: `record_chain_hash` →
//! receipts Merkle root → signed Step-8 amendment → Ed25519-verify the
//! AuditProof. Output-hash equality alone is *necessary, not sufficient*. The
//! [`OutputBundleManifest::signed`] field is the structural marker (always
//! `false`) so a parser cannot conflate the manifest with the signed block.
//!
//! ## Forever-Standard discipline (the Forever-Standard wire discipline)
//!
//! Wire form (serde `rename_all = "snake_case"`) is the contract auditors rely
//! on. Variants/fields ship ADDITIVE only — never renamed, removed, or
//! repurposed.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Provenance of a binding's `record_output_hash` (the specification crypto-review F1).
///
/// The equality `sha512(work_product) == record_output_hash` is a
/// Nanorix-**attested** fact only when the hash was computed by Nanorix over the
/// in-capsule bytes ([`CapsuleComputed`](OutputHashOrigin::CapsuleComputed) —
/// the EEE batch/exec path). On the public records API path the hash is
/// **customer-declared** ([`CustomerDeclared`](OutputHashOrigin::CustomerDeclared)):
/// Nanorix never sees the bytes, so the binding is a customer self-assertion the
/// verifier MUST NOT treat as Nanorix-attested. Closed enum; additive only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputHashOrigin {
    /// `record_output_hash` was computed by Nanorix as `sha512(raw bytes)` over
    /// the in-capsule work-product (EEE batch/exec). The binding is a
    /// Nanorix-attested fact.
    CapsuleComputed,
    /// `record_output_hash` was supplied by the customer via the records API;
    /// Nanorix never saw the bytes. The binding is a customer self-assertion.
    CustomerDeclared,
}

/// One work-product ↔ receipt binding inside an Output Bundle manifest.
///
/// Advisory: every hash here MUST be independently re-derived by the verifier
/// from the verbatim signed primitives. See module docs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputBinding {
    /// Identifier of the work-product part (e.g. output filename). Opaque to
    /// Nanorix — never read, only named.
    pub work_product_name: String,
    /// `sha512:{hex}` digest of the delivered work-product bytes. Advisory — the
    /// verifier MUST re-derive this from the delivered bytes, not trust it.
    pub work_product_hash: String,
    /// The the per-record receipt specification receipt `record_output_hash` (`sha512:{hex}`) this part binds
    /// to — the path to the signed anchor (record_chain_hash → receipts Merkle
    /// root → signed Step-8 amendment → Ed25519).
    pub record_output_hash: String,
    /// Whether `record_output_hash` is Nanorix-computed or customer-declared.
    pub output_hash_origin: OutputHashOrigin,
}

/// Advisory manifest of an Output Bundle (the specification). UNSIGNED packaging — never a
/// trust root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputBundleManifest {
    /// Manifest schema version (additive; `"1.0"` at GA).
    pub manifest_version: String,
    /// Structural marker that this manifest is UNSIGNED advisory packaging.
    /// **Always `false`.** A consumer that trusts manifest fields without
    /// re-deriving them from the verbatim signed primitives has a bug
    /// (the specification confused-deputy guard).
    pub signed: bool,
    pub capsule_id: String,
    pub created_at: String,
    pub destroyed_at: String,
    /// Customer-declared sink target (endpoint host / `bucket/prefix` / webhook
    /// URL) — **never a credential** (the specification customer-sole-declarer).
    pub sink_target: String,
    /// `final_hash` of the carried AuditProof (`sha512:{hex}`). Advisory.
    pub audit_proof_final_hash: String,
    /// Receipts Merkle root for N>1 record runs (`sha512:{hex}`) — the value
    /// bound into the signed Step-8 amendment. `None` for a single binding.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub receipts_merkle_root: Option<String>,
    /// One binding per work-product part. At least one (N≥1) for any bundle that
    /// carries a work-product — there is no whole-capsule output hash by design
    /// (the specification: adding one would touch the signed CDP / a trust anchor).
    pub bindings: Vec<OutputBinding>,
}

/// An Output Bundle (the specification): the UNSIGNED delivery envelope.
///
/// `audit_proof` / `receipts` / `lineage` carry **verbatim source bytes** as
/// opaque strings — see module docs for why these are `String` and never
/// re-serialized structs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputBundle {
    pub manifest: OutputBundleManifest,
    /// Verbatim AuditProof JSON bytes (opaque). Carried, never re-encoded.
    pub audit_proof: String,
    /// Verbatim per-record receipt JSON bytes (the per-record receipt specification). Carried, never re-encoded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<String>,
    /// Verbatim cross-org lineage JSON bytes (the receipt-batching specification). Carried, never re-encoded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage: Vec<String>,
}

/// Structural-validation failure for an Output Bundle manifest. The legal /
/// content meaning of the work-product is NEVER inspected — these checks are
/// purely structural (the specification: Nanorix never reads the content).
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum OutputBundleError {
    /// A bundle that carries a work-product must bind ≥1 receipt (the specification).
    #[error("output bundle manifest has no bindings (a work-product bundle must bind >= 1 receipt per the specification)")]
    NoBindings,
    /// A hash field is not in canonical `sha512:`-prefixed form.
    #[error("hash field `{field}` is not in canonical `sha512:` form: `{value}`")]
    UnprefixedHash { field: String, value: String },
    /// The structural unsigned marker was tampered to `true`.
    #[error("manifest.signed must be false — the manifest is unsigned advisory packaging, never a trust root (the specification)")]
    SignedMarkerTampered,
}

const SHA512_PREFIX: &str = "sha512:";

fn require_sha512(field: &str, value: &str) -> Result<(), OutputBundleError> {
    if value.starts_with(SHA512_PREFIX) {
        Ok(())
    } else {
        Err(OutputBundleError::UnprefixedHash {
            field: field.to_string(),
            value: value.to_string(),
        })
    }
}

impl OutputBundleManifest {
    /// Structural sanity check. Does **not** verify any signature or re-derive
    /// any hash (that is the verifier's job over the verbatim signed
    /// primitives); it only confirms the manifest is well-formed: unsigned
    /// marker intact, ≥1 binding, all hashes `sha512:`-prefixed.
    pub fn validate(&self) -> Result<(), OutputBundleError> {
        if self.signed {
            return Err(OutputBundleError::SignedMarkerTampered);
        }
        if self.bindings.is_empty() {
            return Err(OutputBundleError::NoBindings);
        }
        require_sha512("audit_proof_final_hash", &self.audit_proof_final_hash)?;
        if let Some(root) = &self.receipts_merkle_root {
            require_sha512("receipts_merkle_root", root)?;
        }
        for (i, b) in self.bindings.iter().enumerate() {
            require_sha512(
                &format!("bindings[{i}].work_product_hash"),
                &b.work_product_hash,
            )?;
            require_sha512(
                &format!("bindings[{i}].record_output_hash"),
                &b.record_output_hash,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_manifest() -> OutputBundleManifest {
        OutputBundleManifest {
            manifest_version: "1.0".into(),
            signed: false,
            capsule_id: "cap_test".into(),
            created_at: "2026-06-10T00:00:00Z".into(),
            destroyed_at: "2026-06-10T00:01:00Z".into(),
            sink_target: "https://ehr.example.org/fhir".into(),
            audit_proof_final_hash: "sha512:aa".into(),
            receipts_merkle_root: None,
            bindings: vec![OutputBinding {
                work_product_name: "result.json".into(),
                work_product_hash: "sha512:bb".into(),
                record_output_hash: "sha512:bb".into(),
                output_hash_origin: OutputHashOrigin::CapsuleComputed,
            }],
        }
    }

    /// Pin the closed-enum wire form for `OutputHashOrigin`. Drift breaks the
    /// auditor-side distinction between Nanorix-attested and customer-declared
    /// output-hash bindings.
    #[test]
    fn output_hash_origin_wire_form_is_locked() {
        assert_eq!(
            serde_json::to_string(&OutputHashOrigin::CapsuleComputed).unwrap(),
            r#""capsule_computed""#
        );
        assert_eq!(
            serde_json::to_string(&OutputHashOrigin::CustomerDeclared).unwrap(),
            r#""customer_declared""#
        );
    }

    /// The structural unsigned marker is always emitted (never skipped), so a
    /// consumer can always find it and refuse to trust the manifest as evidence.
    #[test]
    fn manifest_signed_marker_is_always_false_and_present() {
        let json = serde_json::to_string(&sample_manifest()).unwrap();
        assert!(json.contains(r#""signed":false"#), "got {json}");
    }

    #[test]
    fn validate_accepts_well_formed_manifest() {
        assert_eq!(sample_manifest().validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_empty_bindings() {
        let mut m = sample_manifest();
        m.bindings.clear();
        assert_eq!(m.validate(), Err(OutputBundleError::NoBindings));
    }

    #[test]
    fn validate_rejects_unprefixed_hash() {
        let mut m = sample_manifest();
        m.bindings[0].work_product_hash = "deadbeef".into();
        assert!(matches!(
            m.validate(),
            Err(OutputBundleError::UnprefixedHash { .. })
        ));
    }

    #[test]
    fn validate_rejects_tampered_signed_marker() {
        let mut m = sample_manifest();
        m.signed = true;
        assert_eq!(m.validate(), Err(OutputBundleError::SignedMarkerTampered));
    }

    // THE crypto guard (the specification "Implementation guards", highest risk): a
    // verbatim-carried AuditProof/receipt must survive embed → serialize →
    // deserialize → extract BYTE-IDENTICAL. This fails the moment anyone types
    // the carrier as a struct instead of an opaque string. We feed arbitrary
    // bytes (incl. JSON with key ordering + None-skipped fields a re-serialize
    // would mangle).
    proptest! {
        #[test]
        fn verbatim_embed_roundtrip_preserves_bytes(s in ".*") {
            let mut m = sample_manifest();
            m.audit_proof_final_hash = "sha512:aa".into();
            let bundle = OutputBundle {
                manifest: m,
                audit_proof: s.clone(),
                receipts: vec![s.clone()],
                lineage: vec![s.clone()],
            };
            let wire = serde_json::to_string(&bundle).unwrap();
            let back: OutputBundle = serde_json::from_str(&wire).unwrap();
            prop_assert_eq!(&back.audit_proof, &s);
            prop_assert_eq!(&back.receipts[0], &s);
            prop_assert_eq!(&back.lineage[0], &s);
        }
    }

    /// Concrete witness of the bug the carrier prevents: an AuditProof-shaped
    /// JSON with a deliberate key order and an omitted optional field survives
    /// verbatim, whereas a struct re-serialize would reorder/insert.
    #[test]
    fn verbatim_carrier_preserves_key_order_and_omitted_fields() {
        // `pqc_signature` omitted; keys NOT alphabetical — exactly what a
        // round-trip through a typed struct would "fix" and thereby corrupt.
        let original =
            r#"{"cdp_version":"2.1","final_hash":"sha512:zz","hash_algorithm":"sha512"}"#;
        let bundle = OutputBundle {
            manifest: sample_manifest(),
            audit_proof: original.to_string(),
            receipts: vec![],
            lineage: vec![],
        };
        let wire = serde_json::to_string(&bundle).unwrap();
        let back: OutputBundle = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.audit_proof, original, "verbatim bytes drifted");
    }

    #[test]
    fn bundle_roundtrips_via_serde() {
        let bundle = OutputBundle {
            manifest: sample_manifest(),
            audit_proof: r#"{"cdp_version":"2.1"}"#.into(),
            receipts: vec![r#"{"record_id":"rec_0"}"#.into()],
            lineage: vec![],
        };
        let wire = serde_json::to_string(&bundle).unwrap();
        let back: OutputBundle = serde_json::from_str(&wire).unwrap();
        assert_eq!(bundle, back);
    }
}
