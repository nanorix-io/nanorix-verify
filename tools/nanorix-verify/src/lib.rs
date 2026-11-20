//! Nanorix AuditProof verifier — standalone library.
//!
//! Implements the 8-step verification pipeline against an AuditProof
//! JSON document. Independent of any Nanorix service: this crate has no HTTP
//! client, so every verification is local. The trust-chain manifest, when one
//! is used, is supplied as a local file and is itself signed.
//!
//! Per the verifier specification: "auditor
//! verification CLI — the literal moment-of-truth artifact when an OCR
//! auditor walks in."
//!
//! # Trust model
//!
//! The verifier needs ONE thing the customer cannot tamper with: a trusted
//! public key for the AuditProof's signing authority. Two paths:
//!
//! 1. **Trust-chain manifest** — supplied as a local file via `--trust-chain`,
//!    and pinned with `--identity-fingerprint`. The manifest is itself signed
//!    by a long-term identity key. Nothing is retrieved over the network; if
//!    you obtain a manifest from a published location, you fetch it yourself.
//! 2. **Direct override** (`--public-key`) — for offline / sovereign-auditor
//!    use cases where customer brings the public key themselves.
//!
//! # Verification stages
//!
//!
//! 1. Schema validation (required fields present, types correct)
//! 2. cdp_version recognized (1.0 / 2.1 / 2.2)
//! 3. Chain reproducibility (recompute SHA-512 chain from genesis)
//! 4. Final hash binding (final_hash matches last step's chain_hash)
//! 5. Canonical hash binding (v2.x; canonical_hash recompute matches)
//! 6. Signing key resolution (signing_key_version → public key)
//! 7. Ed25519 signature verification
//! 8. Authority status (active / revoked / fingerprint stale)
//!
//! Each stage emits a typed `FailureReason` on failure (per the verifier specification).

// `VerificationResult::valid` is deprecated for callers; this crate sets it on
// every path and forms `status()` from it.
#![allow(deprecated)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

pub mod boundary;
pub mod bundle;
pub mod canonical_recompute;
pub mod checkpoint;
pub mod customer_activity;
pub mod ed25519_strict;
pub mod mldsa;
pub mod population_head;
pub mod population_tick;
pub mod pqc_transcript;
pub mod pubkey_bundle;
pub mod streaming_merkle;
pub mod trust_chain;
pub use boundary::{
    recompute_activity_commitment, recompute_boundary_canonical_hash, verify_boundary_attestation,
    verify_boundary_chain, verify_disclosed_activity_trail, BoundaryChainResult,
    BoundaryFailureReason, BoundaryMetadata, BoundaryVerificationResult, BOUNDARY_ATTESTATION_KIND,
    BOUNDARY_CONTINUATION_STATEMENT, BOUNDARY_OBSERVATION_METHODS, BOUNDARY_SUPPORTED_VERSIONS,
};
pub use bundle::{
    bundle_verdict_text, extract_receipt_bundle, verify_receipt_bundle,
    verify_receipt_bundle_detailed, AuditProofAnchors, BundleError, BundleVerification,
    PortableReceiptBundle, PORTABLE_RECEIPT_BUNDLE_DISCLAIMER,
    SIGNATURE_TARGET_DOCUMENT_CANONICAL_HASH, SIGNATURE_TARGET_STEP8_CHAIN_HASH,
};
pub use customer_activity::{
    check_declared_activity_root_shape, compute_customer_declared_activity_root,
    gate_declared_activity_root, verify_customer_declared_activity, CANONICAL_VIEW_SIGNED_VERSIONS,
    CUSTOMER_DECLARED_ACTIVITY_ROOT_FIELD,
};
pub use pubkey_bundle::{
    build_pubkey_bundle, resolve_parent_key, resolve_parent_key_forever, verify_pubkey_bundle,
    BundleSignature, PortablePubkeyBundle, PubKeyEntry, PubkeyBundleError,
    PORTABLE_PUBKEY_BUNDLE_DISCLAIMER,
};
pub use trust_chain::{
    AuthorityRecord, KeyLookupResult, KeyStatus, KeyVersionRecord, TrustChainManifest,
};

pub const NANORIX_GENESIS_HASH: &str =
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
pub const NANORIX_CHAIN_STEPS: usize = 8;

/// Authority a proof anchors under when it carries no top-level
/// `authority_id` (the Nanorix-hosted signing path).
pub const DEFAULT_AUTHORITY_ID: &str = "us-kms-nanorix-v1";

/// The authority a proof is anchored under: the top-level `authority_id`, or
/// `DEFAULT_AUTHORITY_ID` when that field is absent or not a string. Only
/// cdp_version 2.1 and 2.2 sign that field (the canonical view binds it); on
/// 1.0 nothing signed covers it, which the pin gate handles, and 2.0 is
/// refused at the version gate before any of this is read. The policy-pin gate
/// and the trust-chain lookup both read it from here so they cannot disagree,
/// and the CLI and the hosted `/v1/verify` route call it rather than repeat
/// the default.
pub fn effective_authority_id(json: &serde_json::Value) -> &str {
    json.get("authority_id")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_AUTHORITY_ID)
}

/// The `signing_mode` a proof carries when the install's customer authority
/// signed it (Part A). Compared byte for byte.
pub const SIGNING_MODE_CUSTOMER_ONLY: &str = "customer_only";

/// The byte strings that make an authority id customer-classified.
///
/// This is the issuer's test, `AuthorityKind::from_authority_id` in
/// the reference server implementation, and the
/// amendment's Terms: a segment anywhere in the id, byte-exact and
/// case-sensitive, not anchored at the start and with no normalization.
/// the hosted verification endpoint holds a test that the two classify the
/// same probe ids the same way.
pub const CUSTOMER_AUTHORITY_SEGMENTS: [&str; 4] = [
    "customer-hsm-",
    "customer-kms-",
    "customer-tee-",
    "customer-byo-",
];

/// Whether `authority_id` is customer-classified (see
/// [`CUSTOMER_AUTHORITY_SEGMENTS`]). Every other id is Nanorix-classified.
pub fn is_customer_authority(authority_id: &str) -> bool {
    CUSTOMER_AUTHORITY_SEGMENTS
        .iter()
        .any(|segment| authority_id.contains(segment))
}

/// The consistency rule of the amendment, section 4: on cdp_version
/// 2.1 and 2.2, a proof whose `signing_mode` is exactly `customer_only` while
/// its `authority_id` is Nanorix-classified is refused. An absent, null or
/// non-string `authority_id` is Nanorix-classified. Returns `None` when the
/// pair is consistent or the version signs neither label.
///
/// Both labels are inside the canonical view, so the rule tests what the
/// signature covers, never which key signed. A `nanorix_only` proof under a
/// customer-classified authority passes; the amendment's "Legacy proofs"
/// section rules it.
pub fn signing_mode_authority_mismatch(
    json: &serde_json::Value,
    cdp_version: &str,
) -> Option<FailureReason> {
    if !CANONICAL_VIEW_SIGNED_VERSIONS.contains(&cdp_version) {
        return None;
    }
    let claimed = json.get("authority_id").and_then(|v| v.as_str());
    let customer_only =
        json.get("signing_mode").and_then(|v| v.as_str()) == Some(SIGNING_MODE_CUSTOMER_ONLY);
    if !customer_only || claimed.is_some_and(is_customer_authority) {
        return None;
    }
    Some(FailureReason::SigningModeAuthorityMismatch {
        claimed_authority_id: claimed.map(String::from),
    })
}

/// Activity event an issuer writes when a capsule ran in diagnostic mode.
pub const DIAGNOSTIC_MODE_EVENT: &str = "diagnostic_mode_enabled";

/// Whether the activity trail holds an entry whose `event` is
/// `DIAGNOSTIC_MODE_EVENT`. The trail is signed only on 2.1 and 2.2 with a
/// signature, so a `false` here proves nothing on 1.0 or on an unsigned 2.1 or
/// 2.2 proof; the diagnostic gate refuses those outright for that reason.
fn records_diagnostic_mode(json: &serde_json::Value) -> bool {
    json.get("activity")
        .and_then(|v| v.as_array())
        .is_some_and(|events| {
            events
                .iter()
                .any(|e| e.get("event").and_then(|t| t.as_str()) == Some(DIAGNOSTIC_MODE_EVENT))
        })
}

/// Reserved attestation slots that sit outside `CanonicalCdpView`
/// AND that no Nanorix signer populates.
///
/// Every construction site in the workspace hard-codes these to `None`, so the
/// signature never covered them and a genuine document never carries them. A
/// populated one is either a schema this build does not know or an outsider
/// edit to an authentic proof — indistinguishable to the signature, which is
/// why presence alone has to be the rejection.
///
/// `per_event_attestations` is the ninth reserved slot and is deliberately
/// ABSENT from this list: the reference server implementation drains
/// `capsule_event_attestations` into it at destroy, so genuine proofs do carry
/// it. The slot sits outside the signed hash and is accepted unchecked: its
/// entries prove nothing about who signed, and verifying or binding them is
/// separate work.
pub const UNSIGNED_RESERVED_SLOTS: [&str; 7] = [
    "customer_attestation",
    "policy_attestation",
    "third_party_attestation",
    "retention_policy_attestation",
    "witness_signatures",
    "pqc_attestation",
    "customer_pqc_attestation",
];

/// First reserved slot carrying anything other than JSON `null`.
///
/// Genuine documents emit these keys with an explicit `null` (the fields have
/// no `skip_serializing_if`), so absence and `null` are both normal. Anything
/// else — including an empty array — is a shape no signer produces.
/// Iteration follows `UNSIGNED_RESERVED_SLOTS` order, so a document with
/// several populated slots always names the same one.
fn populated_unsigned_slot(json: &serde_json::Value) -> Option<&'static str> {
    UNSIGNED_RESERVED_SLOTS
        .iter()
        .copied()
        .find(|slot| json.get(*slot).is_some_and(|v| !v.is_null()))
}

/// Number of `parent_proof_hashes` links carrying attribution the signature
/// does not cover.
///
/// Only `parent_chain_hash` feeds the signed Merkle root
/// (the reference chain implementation), so `parent_key_id`, `parent_signature`,
/// `parent_role`, `parent_jurisdiction` and `parent_organization_tag` are
/// rewritable by anyone holding the document and no key. They are also the
/// fields the multi-vendor lineage UI renders, which is what makes counting
/// them worth surfacing in the verdict.
fn count_unattested_parent_attribution(json: &serde_json::Value) -> Option<usize> {
    const ATTRIBUTION_FIELDS: [&str; 5] = [
        "parent_key_id",
        "parent_signature",
        "parent_role",
        "parent_jurisdiction",
        "parent_organization_tag",
    ];
    let parents = json.get("parent_proof_hashes")?.as_array()?;
    let n = parents
        .iter()
        .filter(|p| {
            ATTRIBUTION_FIELDS
                .iter()
                .any(|f| p.get(*f).is_some_and(|v| !v.is_null()))
        })
        .count();
    (n > 0).then_some(n)
}

/// The canonical 8-step chain identity: `(subsystem, method)` at each index.
///
/// Forever-Standard — the order, the count, the
/// subsystem names, and each subsystem's fixed method are all fixed for the
/// life of the format. Mirrors `CHAIN_DEFS` / `CANONICAL_SUBSYSTEMS` in
/// the chain specification, duplicated here because the auditor verifier
/// ships standalone and takes no service-side dependency (the verifier specification).
///
/// The chain walk hashes THESE values, never the ones the document declares.
/// A document cannot choose what a step is; it can only fail to match.
pub const CANONICAL_CHAIN: [(&str, &str); NANORIX_CHAIN_STEPS] = [
    ("eee_namespace", "procfs_verification"),
    ("eee_tmpfs", "mountinfo_verification"),
    ("eee_memory", "dod_5220_multipass_wipe"),
    ("dire_keys", "ed25519_key_destruction"),
    ("dire_identity", "credential_incineration"),
    ("fgx_forensic", "merkle_tree_verification"),
    ("rzl_audit", "hash_chain_validation"),
    ("capsule_destroy", "capsule_lifecycle_verification"),
];

/// Output of a verification attempt. Mirrors the wire shape that the
/// authenticated `POST /v1/verify` endpoint will return once the specification ships.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    /// True when the chain and the signature hold under the key used: the key
    /// resolved in `policy.trust_chain` (stage 8) or, without one, the key the
    /// proof carries (stage 7). Also true at stage 4, where the chain
    /// reproduced and no signature was checked. On its own it says nothing
    /// about who signed: verified is `valid && stage_reached >= 8`.
    ///
    /// Stage 8 is reached only when `policy.trust_chain` is a manifest whose
    /// own signature holds under `policy.pinned_identity_fingerprint`, which
    /// this call checks. A manifest placed without a pin anchors nothing: a
    /// proof whose key it lists ends at stage 7.
    ///
    /// Deprecated as a verdict: read [`VerificationResult::status`], which is
    /// `"verified"` only at stage 8, or [`VerificationResult::ok`]. The field
    /// and its JSON meaning stay.
    #[deprecated(
        note = "valid is not a verdict: it is also true at stage 7 (the key the proof carries) and stage 4; read status() or ok()"
    )]
    pub valid: bool,

    /// Populated when `valid` is false. Closed enum aligned with the API
    /// surface (per the specification).
    pub failure_reason: Option<FailureReason>,

    /// 1..=8 indicating the highest stage reached (advisory; matches the authority-agnostic signing rules
    /// I8 step numbering).
    pub stage_reached: u8,

    /// Populated diagnostic metadata (no payload bytes; structural only).
    pub metadata: VerificationMetadata,
}

impl VerificationResult {
    /// The three-state verdict: `"verified"` when `valid` holds at stage 8
    /// (the key anchored in a trust-chain manifest), `"not_anchored"` when it
    /// holds at stage 7 (the key the proof carries), and `"not_verified"`
    /// otherwise, which includes a chain with no signature checked (stage 4).
    ///
    /// Stage 8 needs both [`VerifierPolicy::trust_chain`] and
    /// [`VerifierPolicy::pinned_identity_fingerprint`], and the manifest's
    /// signature holding under that pin. A manifest without a pin gives
    /// `"not_anchored"` at most.
    pub fn status(&self) -> &'static str {
        if self.valid && self.stage_reached >= 8 {
            "verified"
        } else if self.valid && self.stage_reached == 7 {
            "not_anchored"
        } else {
            "not_verified"
        }
    }

    /// True only when [`VerificationResult::status`] is `"verified"`.
    pub fn ok(&self) -> bool {
        self.status() == "verified"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationMetadata {
    pub cdp_version: Option<String>,
    pub capsule_id: Option<String>,
    pub region: Option<String>,
    /// Read from `attestation.signing_key_version` when present, else the
    /// top-level `signing_key_version` string, as written. Outside every
    /// signature: the canonical view does not bind
    /// `attestation.signing_key_version`, and it binds the top-level value
    /// only as its integer parse, which `authority_signed` describes. The
    /// issuer does not write the attestation field.
    pub signing_key_version: Option<String>,
    pub algorithm: Option<String>,
    pub step_count: Option<usize>,
    pub activity_event_count: Option<usize>,

    /// `Some(ts)` when the document carried no usable `destroyed_at` and the
    /// chain timestamp was recovered from `attestation.key_id` (pre-restoration
    /// proofs). `None` means the timestamp was read from the
    /// document's own `destroyed_at` field. An auditor reading a verdict can
    /// therefore always tell which route produced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_chain_timestamp: Option<String>,

    /// `Some(n)` when `n` parent links carry attribution fields that the
    /// signature does not cover — `parent_key_id`, `parent_signature`,
    /// `parent_role`, `parent_jurisdiction`, `parent_organization_tag`. Only
    /// `parent_chain_hash` feeds the signed Merkle root, so those values are
    /// rewritable by an outsider on an otherwise-authentic proof. `None` when
    /// the proof has no parent links or none of them carry attribution.
    ///
    /// A verdict is not entitled to stay silent about this: the lineage UI
    /// renders exactly these fields, and a reader who has just been told
    /// "integrity verified" will take them as attested unless told otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unattested_parent_attribution: Option<usize>,

    /// The `customer_declared_activity_root` the proof carries, as
    /// written. `None` when the proof declares none. Disclosed whether or not
    /// the record was supplied: a verdict that stays silent about a declared
    /// root invites a reader to assume it was checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_declared_activity_root: Option<String>,

    /// `Some(true)` when the customer's activity record was supplied
    /// (`VerifierPolicy::customer_activity`) and its recomputed root matched
    /// the declared one; `Some(false)` when the proof declares a root but no
    /// record was supplied — declared, not checked. `None` when the proof
    /// declares no root. A mismatch is a failure, not a `false` here. Never
    /// `Some(true)` outside cdp_version 2.1 / 2.2: on any other version a
    /// declared root is unsigned and the proof is rejected before this point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_declared_activity_checked: Option<bool>,

    /// The proof's own top-level `authority_id` string, as written. Absent
    /// when the proof has none or a non-string, so a reader can tell a value
    /// the proof carries from the Nanorix default (`DEFAULT_AUTHORITY_ID`),
    /// which the issuer applies only on read; on 2.1 and 2.2 the canonical
    /// view then binds `null` or that non-string value, not the default. A
    /// verifier output field, not a receipt field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,

    /// Whether the verified signature covers the proof's top-level
    /// `authority_id`, `signing_mode` and `signing_key_version` as the
    /// canonical view binds them (the key version as its integer parse, 0 when
    /// absent or unparseable). It does not extend to the metadata
    /// `signing_key_version` above, which is read from the unsigned
    /// `attestation.signing_key_version` first. `Some(true)` once a signature
    /// verified against the proof's own key on cdp_version 2.1 or 2.2, whose
    /// signed message is the canonical view; `Some(false)` once one verified on
    /// 1.0, which signs `final_hash` only; absent when no signature verified
    /// (the result stops before the signature check, carries no signature, or
    /// its signature failed). Set only from the signature check, never from the
    /// version alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_signed: Option<bool>,

    /// The proof's own top-level `signing_mode` string, as written. Absent
    /// when the proof has none or a non-string; on 2.1 and 2.2 the canonical
    /// view then binds `null` or that value, while the issuer reads the
    /// default `nanorix_only`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_mode: Option<String>,

    /// The identity fingerprint pinned for the key list the proof was checked
    /// against. Set once the list's signature verified against that pin, before
    /// the key lookup, so a failed lookup still reports it. Absent on the
    /// library path when a key list was given without a pin: there the list's
    /// signature was not checked against any pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_chain_identity_fingerprint: Option<String>,

    /// The `issued_at` of the key list (trust-chain manifest) the proof was
    /// checked against, set at the same point as
    /// `trust_chain_identity_fingerprint`. On the library path without a pin it
    /// is still set, and that list's signature was not checked against any pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_chain_issued_at: Option<String>,
}

// Trust-chain anchoring (commit landing this re-export): closed-enum verification
// failure reasons + signature sub-reasons extracted to the
// `nanorix-verify-types` workspace crate (governance/verify-types).
// Re-exporting here preserves the `nanorix_verify::{FailureReason,
// SignatureFailureReason}` public surface so existing callers (CLI
// `main.rs`, `tests/integration_tests.rs`, downstream auditor tooling)
// keep working with zero call-site change.
//
// the reference server implementation now consumes the SAME definition from this single source
// of truth — no more "must stay in lockstep" comment, no more drift
// surface. Forever-Standard wire form (serde tag = "type", rename_all =
// "snake_case") locked in the shared crate's tests.
pub use nanorix_verify_types::{AuthorityIdMismatchReason, FailureReason, SignatureFailureReason};

/// Verifier policy. Customer / auditor decides what to refuse.
///
/// This struct is field-additive
/// Forever-Standard. Pre-amendment callers passing
/// `VerifierPolicy::default()` continue to behave identically — every
/// new field defaults to its "accept anything" semantics. New fields
/// land via the `..Default::default()` struct-update syntax, NEVER as
/// breaking-shape changes.
#[derive(Debug, Clone, Default)]
pub struct VerifierPolicy {
    /// If true, refuse at stage 2, with `FailureReason::DiagnosticProofRefused`,
    /// an AuditProof whose signed activity trail records diagnostic mode (a
    /// `diagnostic_mode_enabled` event), and every AuditProof that cannot show
    /// it does not: one whose trail is unsigned, which is cdp_version 1.0, or
    /// 2.1 or 2.2 without a signature, so the event could be removed and the
    /// proof would still verify. Only a stage 8 (`verified`) result ties the
    /// trail to a Nanorix key; at stage 7 the key is the one the proof carries.
    /// Default: false (diagnostic-mode proofs are accepted).
    pub reject_diagnostic: bool,

    /// If Some, require the region on the signed `capsule_started` activity
    /// event to match, else reject with `RegionMismatch`. An AuditProof whose
    /// trail is unsigned (cdp_version 1.0, or 2.1 or 2.2 without a signature)
    /// is rejected with an empty `actual`. Only a stage 8 (`verified`) result
    /// ties the region to a Nanorix key. None = accept any region.
    pub required_region: Option<String>,

    /// If `Some(authority_id)`, require the AuditProof's top-level
    /// `authority_id` (absent means `us-kms-nanorix-v1`) to equal it, else reject with
    /// `FailureReason::AuthorityIdMismatch`. An unsigned
    /// `signing_authority.authority_id` that disagrees with the top-level
    /// value is rejected too and can never make a proof match.
    /// And VP Security extended-review F4.3. Only cdp_version 2.1 and 2.2 sign
    /// the top-level `authority_id`; on 1.0 nothing signed covers it, so a
    /// string other than `us-kms-nanorix-v1` there is rejected and a pin
    /// accepts only the Nanorix default authority. cdp_version 2.0 is refused
    /// at the version gate before the pin is read. Without a trust-chain
    /// manifest the authority is only as trustworthy as the embedded key, so
    /// a pin is a full authority check only when the result reaches stage 8.
    ///
    /// Default `None` — no policy pin. AuditProofs with any signing
    /// authority (Nanorix-default OR customer-HSM) verify successfully
    /// against this gate.
    pub required_authority_id: Option<String>,

    /// Trust-chain anchoring trust root. When `Some`, the verifier resolves the proof's
    /// signing key against this manifest and re-verifies the signature
    /// against the manifest key — reaching stage 8 ("verify without trusting
    /// Nanorix"). `None` (default) → integrity-only stage 7 (embedded-key
    /// check).
    ///
    /// The manifest is a trust root only with `pinned_identity_fingerprint`
    /// set: [`verify_auditproof`] checks its signature against that pin.
    /// Without a pin the list is still read and can refuse a proof, but a
    /// proof it holds ends at stage 7 (`not_anchored`). A manifest from
    /// [`trust_chain::TrustChainManifest::into_verified`] is no exception:
    /// this field cannot tell where it came from, so set the pin with it.
    ///
    /// Under a `hybrid1-sha256:` pin, or a manifest whose own
    /// `identity_fingerprint` is one, every record is refused with
    /// `algorithm_unsupported`, with or without a manifest.
    pub trust_chain: Option<crate::trust_chain::TrustChainManifest>,

    /// The out-of-band-pinned identity fingerprint the `trust_chain` manifest
    /// was verified against. When both are set, every [`verify_auditproof`]
    /// call re-checks the manifest's signature against this pin and fails at
    /// stage 6 with `SigningKeyVersionUnknown` if it does not hold: no key
    /// resolves in a list the pin did not sign. `None` with a manifest set
    /// caps a success at stage 7. A `hybrid1-sha256:` pin here, or a
    /// `trust_chain` manifest whose own `identity_fingerprint` is one, refuses
    /// every record with `algorithm_unsupported`, with or without a manifest.
    ///
    /// Boundary verification ([`verify_boundary_attestation`] and
    /// [`verify_boundary_chain`]) reads only this pin's form, and the
    /// `trust_chain` manifest's own `identity_fingerprint`: when either is a
    /// `hybrid1-sha256:` pin it refuses every BoundaryAttestation, which has no
    /// hybrid form. It never checks the manifest's signature against this pin:
    /// otherwise it trusts `trust_chain` as given, so give it only a manifest
    /// obtained through [`trust_chain::TrustChainManifest::into_verified`].
    pub pinned_identity_fingerprint: Option<String>,

    /// The raw bytes of the customer's activity record, when the
    /// reader has it. The proof carries only `customer_declared_activity_root`;
    /// with the record in hand the verifier recomputes the root and compares
    /// (`customer_activity`). Supplying a record to a proof that declares no
    /// root is a failure (`RequiredFieldMissing`), not a no-op. `None`
    /// (default) → a declared root is disclosed in the verdict as "declared,
    /// not checked".
    pub customer_activity: Option<Vec<u8>>,
}

/// Stub trusted-authority record. Real implementation reads from trust-chain
/// manifest or `--public-key` flag.
#[derive(Debug, Clone)]
pub struct TrustedAuthority {
    pub authority_id: String,
    pub signing_key_version: String,
    pub public_key_b64: String,
    pub revoked: bool,
}

/// Top-level verify entrypoint. Loads AuditProof JSON, runs 8-stage
/// verification returns structured result.
///
/// **NOTE:** This is the V1 implementation scaffold. Per the verifier specification ship plan, the
/// full the stage 5 (canonical_hash recompute) and stage 6 (signing
/// key resolution from trust chain) need the shared verification crate
/// extracted from the AuditProof document builder to avoid divergence.
/// V1 provides chain integrity (stages 1-4) which catches the common
/// tamper cases.
pub fn verify_auditproof(
    json: &serde_json::Value,
    _trust: &[TrustedAuthority],
    policy: &VerifierPolicy,
) -> VerificationResult {
    let mut metadata = VerificationMetadata {
        cdp_version: None,
        capsule_id: None,
        region: None,
        signing_key_version: None,
        algorithm: None,
        step_count: None,
        activity_event_count: None,
        recovered_chain_timestamp: None,
        unattested_parent_attribution: None,
        customer_declared_activity_root: None,
        customer_declared_activity_checked: None,
        authority_id: None,
        authority_signed: None,
        signing_mode: None,
        trust_chain_identity_fingerprint: None,
        trust_chain_issued_at: None,
    };

    // Stage 1: schema validation — cdp_version present
    let cdp_version = match json.get("cdp_version").and_then(|v| v.as_str()) {
        Some(v) => {
            metadata.cdp_version = Some(v.to_string());
            v.to_string()
        }
        None => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::RequiredFieldMissing {
                    field: "cdp_version".into(),
                }),
                stage_reached: 1,
                metadata,
            };
        }
    };

    // Stage 2: cdp_version recognized.
    //
    // "2.2" is verified exactly as "2.1": the canonical
    // view, the signed-message form and every stage below are unchanged. What
    // 2.2 adds is carried inside fields the 2.1 recompute already covers — new
    // activity-trail events, and `customer_declared_activity_root`, which the
    // recompute includes whenever present.
    if !["1.0", "2.1", "2.2"].contains(&cdp_version.as_str()) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::CdpVersionUnsupported { found: cdp_version }),
            stage_reached: 2,
            metadata,
        };
    }

    // Reserved-slot gate. A slot outside the signature carrying a value no
    // signer emits means the bytes in front of us are not the bytes that were
    // signed, even though the signature over the covered subset still checks
    // out. Running before the policy pins and the chain walk because the
    // document is structurally impossible on its own terms, independent of
    // what any customer policy asks for. Stage 2 matches the other
    // pre-chain-walk gates below.
    if let Some(slot) = populated_unsigned_slot(json) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::UnsignedFieldPopulated {
                field: slot.to_string(),
            }),
            stage_reached: 2,
            metadata,
        };
    }

    // Gate on `customer_declared_activity_root`, same position and
    // same reasoning as the reserved-slot gate. The root is signed only where
    // the signed message is the canonical view (2.1 / 2.2); on 1.0 the message
    // is `final_hash`, so a root there is a value anyone can write and the
    // signature cannot tell. On 2.1 / 2.2 a
    // root that is not a `sha512:` + 128-lowercase-hex string is a shape no
    // signer emits, named here before any recompute consumes it so the
    // verdict blames the field and not the signature or the record.
    if let Err(failure) = customer_activity::gate_declared_activity_root(json, &cdp_version) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(failure),
            stage_reached: 2,
            metadata,
        };
    }

    // The capsule id as the document states it. The record-receipt check below
    // hashes it on every version, so it is read here whatever the version.
    let document_capsule_id = json.get("capsule_id").and_then(|v| v.as_str());

    // The metadata names a capsule and a region only on a version whose
    // signature covers them. A 1.0 signature covers `final_hash` alone, which
    // binds `destroyed_at` and the two optional Merkle roots. It does not bind
    // the capsule_id itself (only through record receipts, which a holder can
    // remove), the region or the key id, so on 1.0 neither is reported: a
    // reader would take them as signed.
    let names_signed_fields = CANONICAL_VIEW_SIGNED_VERSIONS.contains(&cdp_version.as_str());
    // The region is read from the activity trail, so it is reported only when
    // the signature step below will check a signature over that trail: on a
    // proof without a signature or key, no return names it.
    let trail_checked = names_signed_fields
        && !matches!(
            canonical_recompute::verify_signature(json, &cdp_version),
            canonical_recompute::SignatureCheck::Absent
        );
    metadata.capsule_id = document_capsule_id
        .filter(|_| names_signed_fields)
        .map(String::from);

    // Region resolves from the `capsule_started` activity event only, on 2.1
    // and 2.2 carrying a signature.
    //
    // On 2.1 and 2.2 the activity trail is inside `CanonicalCdpView`, so a
    // region carried there cannot be altered without breaking the signature.
    // An unsigned 2.1 or 2.2 proof reports no region. The two paths
    // this replaced — `/environment/region` and top-level `region` — are both
    // outside the canonical hash: `environment` is a derived projection built
    // by `FullCdp::to_verification()` and its struct has no region field at
    // all, and top-level `region` is emitted by nothing. Reading either meant
    // the residency pin below consulted a value an outsider could add to a
    // genuine signed proof with no key, while the signed value went unread.
    metadata.region = json
        .get("activity")
        .filter(|_| trail_checked)
        .and_then(|v| v.as_array())
        .and_then(|events| {
            events
                .iter()
                .find(|e| e.get("event").and_then(|t| t.as_str()) == Some("capsule_started"))
        })
        .and_then(|e| e.get("region"))
        .and_then(|v| v.as_str())
        .map(String::from);

    metadata.signing_key_version = json
        .pointer("/attestation/signing_key_version")
        .or_else(|| json.get("signing_key_version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    metadata.algorithm = json
        .pointer("/attestation/algorithm")
        .and_then(|v| v.as_str())
        .map(String::from);

    metadata.authority_id = json
        .get("authority_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    metadata.signing_mode = json
        .get("signing_mode")
        .and_then(|v| v.as_str())
        .map(String::from);

    // Policy-pin gate (the customer-authority specification / VP Security F4.3).
    //
    // When the customer / auditor pins `required_authority_id`, it is compared
    // with the top-level `authority_id`: the field the trust-chain lookup reads
    // and, on cdp_version 2.1 and 2.2 only, the one the canonical view binds
    // (so the signature covers it). On 1.0 nothing signed covers it: 1.0
    // signs `final_hash`, and no issuer writes `authority_id` on it. cdp_version
    // 2.0 never reaches this gate: the version gate above refuses it first.
    // An absent or non-string `authority_id` means the Nanorix default,
    // `DEFAULT_AUTHORITY_ID`, exactly as `effective_authority_id` resolves it
    // for the chain walk, so the gate and the anchor cannot read different
    // values.
    //
    // `signing_authority` is not in the canonical view today and
    // no issuer emits it, so it can never widen what a pin accepts:
    //
    // - cdp_version not in `CANONICAL_VIEW_SIGNED_VERSIONS` and a top-level
    //   `authority_id` that is a string other than `DEFAULT_AUTHORITY_ID`
    //   (the empty string included) → reject with
    //   `verifier_policy_authority_id_mismatch`, claimed = that value. The
    //   field is unsigned there, so adding it to a genuine proof would
    //   otherwise satisfy any pin with no key. On those versions the
    //   effective authority can only be the default.
    // - `signing_authority.authority_id` present and different from the
    //   top-level `authority_id` → reject with
    //   `verifier_policy_authority_id_mismatch`, claimed = the
    //   `signing_authority` value. An unsigned object cannot be told apart
    //   from a forged one, so any disagreement is refused.
    // - `signing_authority` absent, `null`, or without `authority_id` → ignored.
    // - effective authority differs from the pin → reject; claimed is null
    //   with `verifier_policy_demands_customer_hsm_audit_proof_has_none` when
    //   the top-level field is absent, else the top-level value with
    //   `verifier_policy_authority_id_mismatch`.
    //
    // Without a trust-chain manifest the authority is only as trustworthy as
    // the embedded key, so a pin is a full authority check only when the
    // result reaches stage 8.
    //
    // The gate runs BEFORE chain integrity checks because the policy
    // decision is independent of chain validity — a customer who pinned
    // the wrong authority should learn that quickly, not after a 7-step
    // SHA-512 chain walk. Stage_reached carries the conventional value
    // 2 (post-version-check, pre-chain-walk).
    if let Some(required) = policy.required_authority_id.as_ref() {
        let top_level = json.get("authority_id").and_then(|v| v.as_str());
        let effective = effective_authority_id(json);
        if !CANONICAL_VIEW_SIGNED_VERSIONS.contains(&cdp_version.as_str()) {
            if let Some(unsigned) = top_level.filter(|t| *t != DEFAULT_AUTHORITY_ID) {
                return VerificationResult {
                    valid: false,
                    failure_reason: Some(FailureReason::AuthorityIdMismatch {
                        claimed_authority_id: Some(unsigned.to_string()),
                        expected_authority_id: required.clone(),
                        reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
                    }),
                    stage_reached: 2,
                    metadata,
                };
            }
        }
        let unsigned_claim = json
            .pointer("/signing_authority/authority_id")
            .and_then(|v| v.as_str());
        if let Some(conflict) = unsigned_claim.filter(|c| *c != effective) {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::AuthorityIdMismatch {
                    claimed_authority_id: Some(conflict.to_string()),
                    expected_authority_id: required.clone(),
                    reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
                }),
                stage_reached: 2,
                metadata,
            };
        }
        if effective != required.as_str() {
            let (claimed, reason) = match top_level {
                None => (
                    None,
                    AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
                ),
                Some(t) => (
                    Some(t.to_string()),
                    AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
                ),
            };
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::AuthorityIdMismatch {
                    claimed_authority_id: claimed,
                    expected_authority_id: required.clone(),
                    reason,
                }),
                stage_reached: 2,
                metadata,
            };
        }
    }

    // The residency pin and the diagnostic gate read the activity trail, so
    // each trusts it only when the signature step below will check a signature
    // over it: the version's signed message is the canonical view (2.1 / 2.2)
    // and that step does not end as `Absent`. A 1.0 trail, and the trail of a
    // 2.1 or 2.2 proof without a signature or key, is unsigned: anyone could
    // add a region equal to the pin, or delete a `diagnostic_mode_enabled`
    // event, and the proof would still verify. Computed only under a policy
    // that reads the trail.
    let trail_signed =
        (policy.required_region.is_some() || policy.reject_diagnostic) && trail_checked;

    // Residency-pin gate.
    //
    // Same shape and rationale as the authority pin above: when the auditor
    // pins `required_region`, a proof asserting a different region is rejected
    // before the chain walk. A proof that carries no region at all cannot
    // satisfy a residency pin — it is rejected with an empty `actual` rather
    // than accepted, so the pin fails closed.
    //
    // Only a signed region counts: on an unsigned trail the pin reads no
    // region and refuses with an empty `actual`.
    if let Some(required) = policy.required_region.as_ref() {
        let actual = if trail_signed {
            metadata.region.clone().unwrap_or_default()
        } else {
            String::new()
        };
        if actual != *required {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::RegionMismatch {
                    required: required.clone(),
                    actual,
                }),
                stage_reached: 2,
                metadata,
            };
        }
    }

    // Diagnostic-mode gate, after the residency pin and before
    // the chain walk, like the other policy pins. A proof whose trail is
    // unsigned (1.0, or 2.1 or 2.2 without a signature) cannot show it was not
    // run in diagnostic mode, since the event could be deleted and the proof
    // would still verify: the setting refuses every one.
    if policy.reject_diagnostic && (!trail_signed || records_diagnostic_mode(json)) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::DiagnosticProofRefused),
            stage_reached: 2,
            metadata,
        };
    }

    // Stage 3: chain reproducibility
    let chain = match json.get("chain").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::RequiredFieldMissing {
                    field: "chain".into(),
                }),
                stage_reached: 3,
                metadata,
            };
        }
    };
    metadata.step_count = Some(chain.len());

    if chain.len() != NANORIX_CHAIN_STEPS {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::StepCountInvalid {
                expected: NANORIX_CHAIN_STEPS,
                found: chain.len(),
            }),
            stage_reached: 3,
            metadata,
        };
    }

    // Proofs issued before `destroyed_at` was restored to the wire
    // document carry the chain timestamp only in `attestation.key_id`. Recover
    // it there so authentic pre-restoration proofs reproduce their chain; the
    // recovered value is disclosed in the verdict metadata, never silently
    // substituted.
    let (timestamp, recovered) = resolve_chain_timestamp(json);
    let timestamp = timestamp.as_str();
    metadata.recovered_chain_timestamp = recovered;

    // The receipt pipeline (2026-05-12) — extract optional Merkle roots
    // for Step 8 amendment. None for pre-the receipt pipeline proofs (both branches collapse
    // to the legacy formula → byte-identical chain walk).
    let rrmr_opt = json
        .get("record_receipts_merkle_root")
        .and_then(|v| v.as_str());
    let ppmr_opt = json
        .get("parent_proofs_merkle_root")
        .and_then(|v| v.as_str());

    // Canonical-identity chain walk.
    //
    // The hash inputs are taken from `CANONICAL_CHAIN` by INDEX, never from
    // the document. Before this, `subsystem` was read out of the step and fed
    // straight into the hash, with `lookup_method` mapping anything unknown to
    // an empty method — so any self-consistent 8-entry chain reproduced
    // itself. Eight entries named `a`..`h`, the canonical eight in scrambled
    // order, and `eee_namespace` repeated eight times all verified clean, and
    // "8/8" meant only "eight of something".
    //
    // Two distinct faults, reported distinctly:
    //   * hashes that do not reproduce against the canonical inputs
    //     -> `StepHashMismatch` (unchanged verdict for every existing fixture)
    //   * hashes that DO reproduce beside a subsystem label that is not the
    //     canonical one for that index -> `ChainStepIdentityMismatch`
    let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
    for (idx, step) in chain.iter().enumerate() {
        let (canonical_subsystem, canonical_method) = CANONICAL_CHAIN[idx];
        let declared_subsystem = step.get("subsystem").and_then(|v| v.as_str()).unwrap_or("");
        let claimed_chain_hash = step
            .get("chain_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let recomputed = if idx == NANORIX_CHAIN_STEPS - 1 {
            // The per-record receipt specification + the cross-organisation chain specification Step 8 amendment — presence-conditional
            // Merkle-root incorporation. The (None, None) branch returns the
            // legacy formula bit-for-bit (Forever-Standard). The branch was
            // additionally keyed on the DECLARED subsystem being
            // `capsule_destroy`; index 8 is `capsule_destroy` by definition
            // now, so the declared value no longer selects the formula.
            compute_step_8_amended_verifier(&prev_hash, timestamp, rrmr_opt, ppmr_opt)
        } else {
            compute_step_hash(
                &prev_hash,
                canonical_subsystem,
                "destroy",
                canonical_method,
                timestamp,
            )
        };

        if recomputed != strip_hash_prefix(claimed_chain_hash) {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::StepHashMismatch {
                    step_idx: idx,
                    subsystem: declared_subsystem.to_string(),
                }),
                stage_reached: 3,
                metadata,
            };
        }

        // The hashes reproduced. The label beside them still has to be the
        // right one — a genuine chain carrying a forged subsystem name would
        // otherwise verify clean and be read by an auditor as attesting to a
        // step it does not describe.
        if declared_subsystem != canonical_subsystem {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::ChainStepIdentityMismatch {
                    step_idx: idx,
                    expected_subsystem: canonical_subsystem.to_string(),
                    found_subsystem: declared_subsystem.to_string(),
                }),
                stage_reached: 3,
                metadata,
            };
        }

        prev_hash = recomputed;
    }

    // ── receipt set verification (Mode A step 3) ──
    // If `record_receipts` is present, recompute the Merkle root from the
    // receipts in order and compare to the claimed `record_receipts_merkle_root`.
    // Each receipt's `record_chain_hash` is also recomputed from its fields.
    if let Some(receipts) = json.get("record_receipts").and_then(|v| v.as_array()) {
        if let Some(failure) =
            verify_record_receipts(receipts, document_capsule_id.unwrap_or(""), rrmr_opt)
        {
            return VerificationResult {
                valid: false,
                failure_reason: Some(failure),
                stage_reached: 3,
                metadata,
            };
        }
    }

    // ── parent-proof set verification ──
    // If `parent_proof_hashes` is present, recompute the parent Merkle root
    // from each link's `parent_chain_hash` and compare to the claimed root.
    // Per-link signature verification (independent pubkey resolution) is
    // out of scope here; a Portable Pubkey Bundle supplies it.
    if let Some(parents) = json.get("parent_proof_hashes").and_then(|v| v.as_array()) {
        if let Some(failure) = verify_parent_proofs(parents, ppmr_opt) {
            return VerificationResult {
                valid: false,
                failure_reason: Some(failure),
                stage_reached: 3,
                metadata,
            };
        }
        // The root binds `parent_chain_hash` and nothing else. Everything the
        // lineage UI actually displays is outside it, so the verdict has to
        // carry the count rather than let a reader infer coverage.
        metadata.unattested_parent_attribution = count_unattested_parent_attribution(json);
    }

    // ── Streaming-egress Merkle root verification ──
    // `streaming_egress_completed.streaming_merkle_root` commits to the
    // `streaming_egress_chunk` leaves emitted beside it. It was signed from the
    // day it shipped and read by nothing — the third instance of the shape this
    // review found: a value in a proof is not evidence unless something reads
    // it AND something signs it.
    //
    // Recomputed only when the leaves are fully disclosed; a root standing
    // alone is the truncated shape and is carried past, as before. Placed with
    // the other sub-structure Merkle checks and therefore BEFORE the signature
    // stages, so it also covers the `SignatureCheck::Absent` path, where the
    // activity trail carries no signature protection at all.
    if let Some(activity) = json.get("activity").and_then(|v| v.as_array()) {
        if let Some(failure) = streaming_merkle::verify_streaming_merkle_roots(activity) {
            return VerificationResult {
                valid: false,
                failure_reason: Some(failure),
                stage_reached: 3,
                metadata,
            };
        }
    }

    // ── customer-declared activity root ──
    // The stage-2 gate above has already rejected a root on a version that
    // does not sign it and a root of any shape no signer emits, so a root
    // read here is a well-formed string on 2.1 / 2.2 and is canonical-bound:
    // the signature stages below bind it to the signer regardless.
    // Recomputing it needs the customer's record, which the reader supplies
    // through the policy. With the other sub-structure Merkle checks, so it
    // also covers the `SignatureCheck::Absent` path.
    metadata.customer_declared_activity_root =
        customer_activity::declared_activity_root(json).map(String::from);
    match policy.customer_activity.as_deref() {
        Some(record) => match customer_activity::verify_customer_declared_activity(json, record) {
            Ok(_) => metadata.customer_declared_activity_checked = Some(true),
            Err(failure) => {
                return VerificationResult {
                    valid: false,
                    failure_reason: Some(failure),
                    stage_reached: 3,
                    metadata,
                };
            }
        },
        None => {
            if metadata.customer_declared_activity_root.is_some() {
                metadata.customer_declared_activity_checked = Some(false);
            }
        }
    }

    // Stage 4: final_hash binding
    let claimed_final = json
        .get("final_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let last_chain_hash = chain
        .last()
        .and_then(|s| s.get("chain_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if strip_hash_prefix(claimed_final) != strip_hash_prefix(last_chain_hash) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::FinalHashMismatch {
                claimed: claimed_final.to_string(),
                computed: last_chain_hash.to_string(),
            }),
            stage_reached: 4,
            metadata,
        };
    }

    // Algorithm dispatch precedes byte-shape checks: a proof
    // declaring a non-Ed25519 signature algorithm fails typed as
    // AlgorithmUnsupported here — it must never fall through to the 64/32-byte
    // decode gates and report as "malformed". Absent or "Ed25519" proceeds
    // unchanged (every proof issued to date).
    if let Some(found) = declared_non_ed25519_algorithm(json) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::AlgorithmUnsupported { found }),
            stage_reached: 4,
            metadata,
        };
    }

    // Consistency gate on the two signed labels. Runs before the signature
    // check, so an unsigned proof carrying the contradiction is refused too
    // rather than passing as "chain verified, signature not checked".
    if let Some(failure) = signing_mode_authority_mismatch(json, &cdp_version) {
        return VerificationResult {
            valid: false,
            failure_reason: Some(failure),
            stage_reached: 4,
            metadata,
        };
    }

    // Stages 5-8: signature verification. sub-A verifies the Ed25519 signature
    // over the version/mode-appropriate message (v1.0 final_hash, v2.1
    // and v2.2 nanorix_only or customer_only canonical_hash) against the key EMBEDDED
    // in the proof — integrity (stage 7). sub-B then ANCHORS that to the Nanorix
    // trust root: if a verified trust-chain manifest is supplied, resolve the
    // signing key from it and re-verify against the manifest key — authenticity
    // (stage 8).
    match canonical_recompute::verify_signature(json, &cdp_version) {
        // Embedded-key signature valid → integrity proven. Attempt sub-B
        // trust-anchoring to reach stage 8.
        canonical_recompute::SignatureCheck::Verified => {
            let mut metadata = metadata;
            metadata.authority_signed =
                Some(CANONICAL_VIEW_SIGNED_VERSIONS.contains(&cdp_version.as_str()));
            anchor_to_trust_chain(json, &cdp_version, policy, metadata)
        }
        // Chain reproduced but the proof carries no signature (an unsigned
        // partial; a declared mode this build cannot check is the Unsupported
        // arm below). Honest: this is NOT a full
        // cryptographic verification — the CLI prints "Chain verified ·
        // signature NOT checked" at stage 4. Fail-closing the exit code in this
        // case is a policy decision deferred to sub-B.
        canonical_recompute::SignatureCheck::Absent => {
            if under_hybrid_pin(policy) {
                return hybrid_record_refusal(4, metadata);
            }
            // No signature covers the activity trail here, so the region read
            // from it is not reported.
            let mut metadata = metadata;
            metadata.region = None;
            VerificationResult {
                valid: true,
                failure_reason: None,
                stage_reached: 4,
                metadata,
            }
        }
        // A signature was present and did not verify → reject.
        // Declared a signing_mode this build cannot verify. NOT the same as
        // "no signature": signing_mode is inside the canonical hash and is
        // attacker-controllable, so treating an unrecognised mode as a partial
        // success turns a rejection into reassurance — a downgrade oracle.
        // AlgorithmUnsupported is the existing Forever-Standard reason for
        // "this build cannot perform the verification this document requires";
        // the resolution (upgrade the verifier) is identical.
        canonical_recompute::SignatureCheck::Unsupported(mode) => VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::AlgorithmUnsupported {
                found: format!("signing_mode={mode}"),
            }),
            stage_reached: 4,
            metadata,
        },
        canonical_recompute::SignatureCheck::Failed(reason) => VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::SignatureMismatch { reason }),
            stage_reached: 7,
            metadata,
        },
    }
}

/// The signature algorithm the proof declares, when it is not Ed25519.
///
/// Reads `attestation.algorithm` and the top-level `signature_algorithm`;
/// either declaring anything other than the exact canonical string `"Ed25519"`
/// makes the proof unverifiable by this build. Both absent is the pre-field
/// era, which is Ed25519 by definition.
fn declared_non_ed25519_algorithm(json: &serde_json::Value) -> Option<String> {
    [
        json.pointer("/attestation/algorithm"),
        json.get("signature_algorithm"),
    ]
    .into_iter()
    .flatten()
    .filter_map(|v| v.as_str())
    .find(|s| *s != "Ed25519")
    .map(str::to_string)
}

/// Trust-chain anchoring — anchor an integrity-verified proof (sub-A passed, stage 7) to
/// the Nanorix trust root.
///
/// With a verified trust-chain manifest in `policy.trust_chain`, resolve the
/// proof's `(authority_id, signing_key_version)` to the manifest's published
/// key (archive-forever: resolves rotated-away versions too), re-verify the
/// signature against THAT key, and check the authority is not revoked. Success
/// is stage 8 — "verify without trusting Nanorix", and the point at which a
/// forged proof (carrying its own embedded key, not the manifest key) is
/// rejected. Without a manifest, or with one but no pin, the proof stays at
/// honest stage 7 (integrity only), except under a `hybrid1-sha256:` pin or a
/// manifest whose own `identity_fingerprint` is one: there every record is
/// refused with `algorithm_unsupported`, with or without a manifest.
fn anchor_to_trust_chain(
    json: &serde_json::Value,
    cdp_version: &str,
    policy: &VerifierPolicy,
    mut metadata: VerificationMetadata,
) -> VerificationResult {
    let manifest = match &policy.trust_chain {
        Some(m) => m,
        None if under_hybrid_pin(policy) => return hybrid_record_refusal(7, metadata),
        None => {
            return VerificationResult {
                valid: true,
                failure_reason: None,
                stage_reached: 7,
                metadata,
            };
        }
    };

    let authority_id = effective_authority_id(json);
    let signing_key_version = json
        .pointer("/attestation/signing_key_version")
        .or_else(|| json.get("signing_key_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // FailureReason is a released wire type, so a list the pin did not sign
    // reuses the stage-6 "no trusted list holds this key" reason.
    //
    // A list with no pin is the caller's say-so: stages 6 to 8 still run on
    // it and can refuse the proof, but a success ends at stage 7
    // (`not_anchored`), never stage 8.
    let pinned = match policy.pinned_identity_fingerprint.as_deref() {
        Some(pin) => {
            if manifest.verify_signature(pin).is_err() {
                return VerificationResult {
                    valid: false,
                    failure_reason: Some(FailureReason::SigningKeyVersionUnknown {
                        version: signing_key_version.to_string(),
                    }),
                    stage_reached: 6,
                    metadata,
                };
            }
            true
        }
        None => false,
    };

    // The key list the proof is checked against, named in the output from here
    // on: past the pin check when a pin was given.
    metadata.trust_chain_identity_fingerprint = policy.pinned_identity_fingerprint.clone();
    metadata.trust_chain_issued_at = Some(manifest.issued_at.clone());

    // Stage 6: resolve the signing key against the trust chain.
    let lookup = match manifest.find_key(authority_id, signing_key_version) {
        Some(l) => l,
        None => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::SigningKeyVersionUnknown {
                    version: signing_key_version.to_string(),
                }),
                stage_reached: 6,
                metadata,
            };
        }
    };

    // Stage 7: re-verify the signature against the MANIFEST key (not embedded).
    // Genuine proof: embedded key == manifest key → verifies. Forged proof: its
    // own embedded key passed sub-A but is not the manifest key → fails here.
    match canonical_recompute::verify_signature_against(
        json,
        cdp_version,
        &lookup.record.public_key_b64,
    ) {
        canonical_recompute::SignatureCheck::Verified => {}
        canonical_recompute::SignatureCheck::Failed(reason) => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::SignatureMismatch { reason }),
                stage_reached: 7,
                metadata,
            };
        }
        // Defensive: sub-A already confirmed a signature is present and the
        // version/mode is verifiable, so neither is reachable here. Unsupported
        // in particular cannot occur — sub-A rejects it before stage 8.
        canonical_recompute::SignatureCheck::Unsupported(mode) => {
            return VerificationResult {
                valid: false,
                failure_reason: Some(FailureReason::AlgorithmUnsupported {
                    found: format!("signing_mode={mode}"),
                }),
                stage_reached: 7,
                metadata,
            };
        }
        canonical_recompute::SignatureCheck::Absent => {
            if under_hybrid_pin(policy) {
                return hybrid_record_refusal(7, metadata);
            }
            return VerificationResult {
                valid: true,
                failure_reason: None,
                stage_reached: 7,
                metadata,
            };
        }
    }

    // Stage 8: authority status. A revoked authority's keys are untrusted.
    if lookup.authority_record.revoked {
        return VerificationResult {
            valid: false,
            failure_reason: Some(FailureReason::AuthorityRevoked),
            stage_reached: 8,
            metadata,
        };
    }

    // A 1.0 signature covers `final_hash` alone, which binds `destroyed_at` and
    // the two optional Merkle roots. It does not bind the capsule_id itself
    // (only through record receipts, which a holder can remove), the region or
    // the key id. So a key list cannot tie it to a capsule: a 1.0 proof runs
    // the lookup, the re-verify and the revocation check above as 2.x does,
    // and where 2.x would reach stage 8 it ends at stage 7, never anchored.
    // Under a hybrid pin it is refused there, as every record is.
    if cdp_version == "1.0" {
        if under_hybrid_pin(policy) {
            return hybrid_record_refusal(7, metadata);
        }
        return VerificationResult {
            valid: true,
            failure_reason: None,
            stage_reached: 7,
            metadata,
        };
    }

    // Under a hybrid pin a record is anchored only with its ML-DSA-65 half
    // checked, which this build does not do yet, so the Ed25519 check above
    // never stands alone as stage 8.
    if under_hybrid_pin(policy) {
        return hybrid_record_refusal(8, metadata);
    }

    // Signature verified against the listed key + authority active. Only a
    // pinned list makes that "verify without trusting Nanorix".
    VerificationResult {
        valid: true,
        failure_reason: None,
        stage_reached: if pinned { 8 } else { 7 },
        metadata,
    }
}

/// The `found` text of the refusal every record gets under a hybrid pin until
/// this verifier checks the record's ML-DSA-65 half. The shared vectors fix
/// it, so every verifier gives the same text.
pub const HYBRID_RECORD_CHECK_MISSING: &str = "ML-DSA-65 record check (hybrid pin)";

/// Whether a record is refused for want of its ML-DSA-65 half: the pin is a
/// `hybrid1-sha256:` pin, or the key list's own `identity_fingerprint` is
/// one, which also covers a list given with no pin.
fn under_hybrid_pin(policy: &VerifierPolicy) -> bool {
    policy
        .pinned_identity_fingerprint
        .as_deref()
        .is_some_and(trust_chain::is_hybrid_pin)
        || policy
            .trust_chain
            .as_ref()
            .is_some_and(|m| trust_chain::is_hybrid_pin(&m.identity_fingerprint))
}

/// The refusal a record gets under a hybrid pin, at the stage where it would
/// otherwise have ended valid: signed, unsigned, or with no key list.
fn hybrid_record_refusal(stage: u8, metadata: VerificationMetadata) -> VerificationResult {
    VerificationResult {
        valid: false,
        failure_reason: Some(FailureReason::AlgorithmUnsupported {
            found: HYBRID_RECORD_CHECK_MISSING.to_string(),
        }),
        stage_reached: stage,
        metadata,
    }
}

/// Compute one step's hash. Mirrors `compute_step_hash` in the reference chain implementation.
///
/// Format: SHA-512(prev_hash \x00 subsystem \x00 action \x00 method \x00 timestamp)
pub fn compute_step_hash(
    prev_hash: &str,
    subsystem: &str,
    action: &str,
    method: &str,
    timestamp: &str,
) -> String {
    let mut hasher = Sha512::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\x00");
    hasher.update(subsystem.as_bytes());
    hasher.update(b"\x00");
    hasher.update(action.as_bytes());
    hasher.update(b"\x00");
    hasher.update(method.as_bytes());
    hasher.update(b"\x00");
    hasher.update(timestamp.as_bytes());
    hex::encode(hasher.finalize())
}

/// Recover the chain timestamp from an attestation `key_id`.
///
/// AuditProofs issued before the chain-timestamp recovery rule restored the document-level `destroyed_at`
/// field carry the chain timestamp in exactly one place: the attestation
/// `key_id`, built by the chain specification as
/// `nrx-verify-{terminated_at with ':' replaced by '-'}-{capsule_id[..8]}`.
/// Only the TIME portion ever held colons — the ISO-8601 date carries its own
/// dashes — so restoration splits at `T` and rewrites dashes on the right-hand
/// side only. Fractional seconds and the zone suffix (`Z`, `+00:00`) pass
/// through untouched.
///
/// Returns `None` unless the reconstruction has the exact ISO-8601
/// `YYYY-MM-DDTHH:MM:SS` shape.
///
/// # Why recovering from an attacker-mutable field is sound
///
/// `key_id` is covered by NEITHER signed message: v1.0 signs `final_hash`, and
/// the v2.x canonical view (the AuditProof document builder
/// `CanonicalCdpView` / `CanonicalAttestationSubset`) excludes the whole
/// attestation by construction. So `key_id` can be edited without invalidating
/// a signature — which is precisely why the recovered value is never trusted on
/// its own. It is an INPUT to the chain walk, and the chain hashes it must
/// reproduce ARE signature-bound (v1.0: `final_hash` is the signed message;
/// v2.x: `destruction_chain` sits inside the canonical hash). Exactly one
/// timestamp string reproduces a signed chain, so a mutated `key_id` yields a
/// mismatch and a rejection, never a false accept. This function never guesses:
/// an off-shape `key_id` yields `None` and the caller keeps the pre-existing
/// behaviour.
pub fn recover_timestamp_from_key_id(key_id: &str) -> Option<String> {
    let rest = key_id.strip_prefix("nrx-verify-")?;
    // Strip the trailing `-{capsule_id[..8]}` fragment. Capsule-id fragments
    // are hex, so the LAST dash is the delimiter.
    let (encoded, fragment) = rest.rsplit_once('-')?;
    if fragment.is_empty() {
        return None;
    }
    let (date, encoded_time) = encoded.split_once('T')?;
    let time = encoded_time.replace('-', ":");
    if !is_iso8601_shaped(date, &time) {
        return None;
    }
    Some(format!("{date}T{time}"))
}

/// `YYYY-MM-DD` date + `HH:MM:SS` time prefix. Anything after the seconds
/// (fractional part, zone designator) is a free-form tail.
fn is_iso8601_shaped(date: &str, time: &str) -> bool {
    let d = date.as_bytes();
    let t = time.as_bytes();
    d.len() == 10
        && t.len() >= 8
        && d[4] == b'-'
        && d[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9]
            .iter()
            .all(|&i| d[i].is_ascii_digit())
        && t[2] == b':'
        && t[5] == b':'
        && [0, 1, 3, 4, 6, 7].iter().all(|&i| t[i].is_ascii_digit())
}

/// Resolve the timestamp every chain step hashes.
///
/// Returns `(timestamp, recovered)` where `recovered` is `Some` only on the
/// `key_id` recovery path — the caller records it so the verdict discloses
/// which route was taken.
pub(crate) fn resolve_chain_timestamp(json: &serde_json::Value) -> (String, Option<String>) {
    let declared = json
        .get("destroyed_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !declared.is_empty() {
        return (declared.to_string(), None);
    }
    match json
        .pointer("/attestation/key_id")
        .and_then(|v| v.as_str())
        .and_then(recover_timestamp_from_key_id)
    {
        Some(ts) => (ts.clone(), Some(ts)),
        // No usable key_id — keep the pre-recovery behaviour exactly (an empty
        // timestamp, which fails the chain walk for any real proof).
        None => (declared.to_string(), None),
    }
}

/// Look up the canonical method string for a given subsystem (per the
/// CDP v1.0 chain spec). Forever-stable.
///
/// Unknown subsystems map to the empty string, which is why this must NOT be
/// used to derive a chain-walk hash input from a document-supplied subsystem:
/// an unrecognised name would silently hash under an empty method and a
/// self-consistent chain of unrecognised names would reproduce itself. The
/// walk indexes [`CANONICAL_CHAIN`] instead. This function stays for fixture
/// generation and for the byte-equivalence mirrors in the Go / Python /
/// TypeScript ports.
pub fn lookup_method(subsystem: &str) -> &'static str {
    match subsystem {
        "eee_namespace" => "procfs_verification",
        "eee_tmpfs" => "mountinfo_verification",
        "eee_memory" => "dod_5220_multipass_wipe",
        "dire_keys" => "ed25519_key_destruction",
        "dire_identity" => "credential_incineration",
        "fgx_forensic" => "merkle_tree_verification",
        "rzl_audit" => "hash_chain_validation",
        "capsule_destroy" => "capsule_lifecycle_verification",
        _ => "",
    }
}

/// Strip canonical prefix conventions: `sha512:` from hash fields, `base64:`
/// from key/signature fields. Forever-stable.
pub fn strip_hash_prefix(s: &str) -> &str {
    s.strip_prefix("sha512:").unwrap_or(s)
}

pub fn strip_base64_prefix(s: &str) -> &str {
    s.strip_prefix("base64:").unwrap_or(s)
}

// ─────────────────────────────────────────────────────────────────────────────
// The receipt pipeline verifier extension
//
// Mirrors `wave_n` in the reference chain implementation to keep the verifier independent of any
// service-side dependency (the verifier ships as a standalone auditor
// artifact per the verifier specification). The hash primitives are byte-identical to the
// service-side implementation — pinned by the cross-impl byte-equivalence
// test in the property-test suite.
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Step 8 amended hash combined formula. See
/// `compute_step_8_amended` in the reference chain implementation for the spec; this
/// is a verifier-side mirror.
pub fn compute_step_8_amended_verifier(
    prev_hash: &str,
    timestamp: &str,
    rrmr: Option<&str>,
    ppmr: Option<&str>,
) -> String {
    let base = compute_step_hash(
        prev_hash,
        "capsule_destroy",
        "destroy",
        "capsule_lifecycle_verification",
        timestamp,
    );

    match (rrmr, ppmr) {
        (None, None) => base,
        (Some(rr), None) => {
            let rr = strip_hash_prefix(rr);
            let mut data = Vec::new();
            data.extend_from_slice(base.as_bytes());
            data.push(0x00);
            data.extend_from_slice(rr.as_bytes());
            hex::encode(Sha512::digest(&data))
        }
        (None, Some(pp)) => {
            let pp = strip_hash_prefix(pp);
            let mut data = Vec::new();
            data.extend_from_slice(base.as_bytes());
            data.push(0x00);
            data.extend_from_slice(pp.as_bytes());
            hex::encode(Sha512::digest(&data))
        }
        (Some(rr), Some(pp)) => {
            let rr = strip_hash_prefix(rr);
            let pp = strip_hash_prefix(pp);
            let mut data = Vec::new();
            data.extend_from_slice(base.as_bytes());
            data.push(0x00);
            data.extend_from_slice(rr.as_bytes());
            data.push(0x00);
            data.extend_from_slice(pp.as_bytes());
            hex::encode(Sha512::digest(&data))
        }
    }
}

/// Canonical pair hash for the Merkle tree: `SHA-512(left ‖ \x00 ‖ right)`.
fn verifier_merkle_pair_hash(left: &str, right: &str) -> String {
    let left = strip_hash_prefix(left);
    let right = strip_hash_prefix(right);
    let mut data = Vec::with_capacity(left.len() + 1 + right.len());
    data.extend_from_slice(left.as_bytes());
    data.push(0x00);
    data.extend_from_slice(right.as_bytes());
    hex::encode(Sha512::digest(&data))
}

/// Compute the Merkle root over an ordered slice of SHA-512 leaves. Returns
/// None when leaves is empty; bare-hex root (no `sha512:` prefix) otherwise.
pub fn verifier_merkle_root(leaves: &[String]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }
    if leaves.len() == 1 {
        return Some(strip_hash_prefix(&leaves[0]).to_string());
    }
    let mut level: Vec<String> = leaves
        .iter()
        .map(|h| strip_hash_prefix(h).to_string())
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(verifier_merkle_pair_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(verifier_merkle_pair_hash(&level[i], &level[i]));
                i += 1;
            }
        }
        level = next;
    }
    Some(level.pop().unwrap())
}

/// Compute a per-record chain hash mirroring
/// `compute_record_chain_hash` in the reference chain implementation.
fn verifier_compute_record_chain_hash(
    capsule_id: &str,
    record_index: u32,
    record_id: &str,
    record_input_hash: &str,
    record_output_hash: &str,
    activity_root: &str,
    pattern_tag_wire: Option<&str>,
) -> String {
    let input_h = strip_hash_prefix(record_input_hash);
    let output_h = strip_hash_prefix(record_output_hash);
    let activity_h = strip_hash_prefix(activity_root);
    let idx = record_index.to_string();

    let mut data = Vec::new();
    data.extend_from_slice(capsule_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(idx.as_bytes());
    data.push(0x00);
    data.extend_from_slice(record_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(input_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(output_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(activity_h.as_bytes());
    // Conformance: a declared pattern_tag is a signed primitive and
    // is bound into the chain hash (trailing segment appended only when the
    // receipt carries a tag; activity_root's fixed 128-hex length gives
    // domain separation, so tagged and untagged preimages cannot collide).
    if let Some(tag) = pattern_tag_wire {
        data.push(0x00);
        data.extend_from_slice(tag.as_bytes());
    }

    hex::encode(Sha512::digest(&data))
}

/// Verify the receipt set Mode A step 3. Returns `Some(failure)`
/// if any receipt's chain hash doesn't roundtrip OR the Merkle root doesn't
/// match the claimed root. Returns `None` if all receipts verify.
fn verify_record_receipts(
    receipts: &[serde_json::Value],
    capsule_id: &str,
    claimed_root_opt: Option<&str>,
) -> Option<FailureReason> {
    // A receipt set with no root is unverifiable, and the emitter never
    // produces one: `record_receipts_merkle_root` is `Some` iff
    // `record_receipts` is `Some` (the AuditProof document builder). Skipping
    // the check when the root is absent — which is what this function used to
    // do — let an outsider append a whole fabricated receipt set to a genuine
    // proof: no root means no comparison, and the array is outside the
    // canonical hash, so the signature still verifies.
    let claimed_root = match claimed_root_opt {
        Some(root) => root,
        None if receipts.is_empty() => return None,
        None => {
            return Some(FailureReason::RequiredFieldMissing {
                field: "record_receipts_merkle_root".into(),
            })
        }
    };

    // Recompute each receipt's chain hash from its fields and compare.
    let mut leaf_chain_hashes: Vec<String> = Vec::with_capacity(receipts.len());
    for (i, receipt) in receipts.iter().enumerate() {
        let record_index = receipt
            .get("record_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let record_id = receipt
            .get("record_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let in_h = receipt
            .get("record_input_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let out_h = receipt
            .get("record_output_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let claimed_chain = receipt
            .get("record_chain_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Activity-root recompute: SHA-512 chain over canonical-JSON events.
        let activity_root = receipt
            .get("record_activity_trail")
            .and_then(|v| v.as_array())
            .map(|trail| {
                let mut prev = NANORIX_GENESIS_HASH.to_string();
                for event in trail {
                    let canonical_bytes = serde_jcs_or_json_bytes(event);
                    let event_hash = hex::encode(Sha512::digest(&canonical_bytes));
                    let mut data = Vec::with_capacity(prev.len() + 1 + event_hash.len());
                    data.extend_from_slice(prev.as_bytes());
                    data.push(0x00);
                    data.extend_from_slice(event_hash.as_bytes());
                    prev = hex::encode(Sha512::digest(&data));
                }
                prev
            })
            .unwrap_or_else(|| NANORIX_GENESIS_HASH.to_string());

        let recomputed = verifier_compute_record_chain_hash(
            capsule_id,
            record_index,
            record_id,
            in_h,
            out_h,
            &activity_root,
            receipt.get("pattern_tag").and_then(|v| v.as_str()),
        );

        if recomputed != strip_hash_prefix(claimed_chain) {
            return Some(FailureReason::StepHashMismatch {
                step_idx: i,
                subsystem: format!("record_receipt[{i}]"),
            });
        }

        leaf_chain_hashes.push(recomputed);
    }

    // Recompute Merkle root and compare to claimed.
    let recomputed_root = verifier_merkle_root(&leaf_chain_hashes).unwrap_or_default();
    if recomputed_root != strip_hash_prefix(claimed_root) {
        return Some(FailureReason::FinalHashMismatch {
            claimed: claimed_root.to_string(),
            computed: format!("sha512:{recomputed_root}"),
        });
    }

    None
}

/// Verify the parent-proof set Merkle root. Returns
/// `Some(failure)` if the recomputed root doesn't match claimed.
fn verify_parent_proofs(
    parents: &[serde_json::Value],
    claimed_root_opt: Option<&str>,
) -> Option<FailureReason> {
    // Same fail-closed reasoning as `verify_record_receipts`:
    // `parent_proofs_merkle_root` is `Some` iff `parent_proof_hashes` is
    // `Some`, so a parent set without a root is a set nothing anchors. Left
    // unchecked it made the entire declared lineage of a genuine proof
    // forgeable by anyone holding the document.
    let claimed_root = match claimed_root_opt {
        Some(root) => root,
        None if parents.is_empty() => return None,
        None => {
            return Some(FailureReason::RequiredFieldMissing {
                field: "parent_proofs_merkle_root".into(),
            })
        }
    };

    let leaves: Vec<String> = parents
        .iter()
        .map(|p| {
            p.get("parent_chain_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();

    let recomputed = verifier_merkle_root(&leaves).unwrap_or_default();
    if recomputed != strip_hash_prefix(claimed_root) {
        return Some(FailureReason::FinalHashMismatch {
            claimed: claimed_root.to_string(),
            computed: format!("sha512:{recomputed}"),
        });
    }

    None
}

/// Canonical JSON bytes for activity events — RFC 8785 JCS, byte-identical
/// to the service-side `compute_activity_root` canonical form. Falls back
/// to plain serde_json on the (unreachable in practice) JCS serialization
/// failure path.
fn serde_jcs_or_json_bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_jcs::to_vec(v).unwrap_or_else(|_| serde_json::to_vec(v).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_v1_proof() -> serde_json::Value {
        // Build a minimally-valid v1.0 AuditProof for unit testing the chain.
        let timestamp = "2026-05-06T12:00:00Z";
        let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
        let subsystems = [
            "eee_namespace",
            "eee_tmpfs",
            "eee_memory",
            "dire_keys",
            "dire_identity",
            "fgx_forensic",
            "rzl_audit",
            "capsule_destroy",
        ];
        let mut chain = Vec::new();
        for subsystem in subsystems {
            let method = lookup_method(subsystem);
            let chain_hash = compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
            chain.push(serde_json::json!({
                "subsystem": subsystem,
                "method": method,
                "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }

        let final_hash = chain
            .last()
            .and_then(|s| s.get("chain_hash"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        serde_json::json!({
            "cdp_version": "1.0",
            "capsule_id": "cap_test",
            "destroyed_at": timestamp,
            "chain": chain,
            "final_hash": final_hash,
        })
    }

    // ── the chain-timestamp recovery rule — chain-timestamp recovery from attestation key_id ────────
    //
    // Production issued AuditProofs before `destroyed_at` was restored to the
    // wire document. Those proofs are authentic and signed, but the timestamp
    // every chain step hashes survives only inside `attestation.key_id`.

    #[test]
    fn recovers_production_key_id_with_millis_and_z() {
        // The exact shape the chain specification emits for a production
        // `Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)` timestamp.
        assert_eq!(
            recover_timestamp_from_key_id("nrx-verify-2026-03-01T00-05-00.000Z-550e8400"),
            Some("2026-03-01T00:05:00.000Z".to_string())
        );
    }

    #[test]
    fn recovers_key_id_whose_colons_were_never_replaced() {
        // The fixture generator writes key_id without the ':' -> '-' pass.
        // Restoring ':' for '-' in the time portion is a no-op there, so the
        // same parser handles both encodings.
        assert_eq!(
            recover_timestamp_from_key_id("nrx-verify-2026-05-08T00:00:00Z-cap12345"),
            Some("2026-05-08T00:00:00Z".to_string())
        );
    }

    #[test]
    fn recovery_refuses_off_shape_key_ids() {
        // Every rejection here means "fall back to the pre-recovery behaviour",
        // i.e. reject the proof. The parser never guesses.
        for bad in [
            "",
            "nrx-verify-",
            "some-other-prefix-2026-03-01T00-05-00Z-550e8400",
            // No 'T' separator — cannot tell date from time.
            "nrx-verify-2026-03-01-00-05-00Z-550e8400",
            // No trailing capsule fragment.
            "nrx-verify-2026-03-01T00:05:00Z",
            // Trailing delimiter with an empty fragment.
            "nrx-verify-2026-03-01T00:05:00Z-",
            // Date portion not YYYY-MM-DD.
            "nrx-verify-26-3-1T00-05-00Z-550e8400",
            // Time portion not HH:MM:SS.
            "nrx-verify-2026-03-01Tnoon-550e8400",
            // Non-digit smuggled into the time portion.
            "nrx-verify-2026-03-01T0a-05-00Z-550e8400",
        ] {
            assert_eq!(
                recover_timestamp_from_key_id(bad),
                None,
                "must refuse to recover from {bad:?}"
            );
        }
    }

    /// A v1.0 proof exactly as production issued it before the restoration:
    /// authentic 8-step chain, signed, and NO `destroyed_at` key at all.
    fn make_pre_restoration_v1_proof() -> serde_json::Value {
        let mut proof = make_minimal_v1_proof();
        let timestamp = "2026-05-06T12:00:00Z";
        proof.as_object_mut().unwrap().remove("destroyed_at");
        proof["attestation"] = serde_json::json!({
            "algorithm": "Ed25519",
            "key_id": format!("nrx-verify-{}-cap_test", timestamp.replace(':', "-")),
        });
        proof
    }

    #[test]
    fn pre_restoration_proof_verifies_via_key_id_recovery() {
        let proof = make_pre_restoration_v1_proof();
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(
            result.valid,
            "authentic pre-restoration proof must verify; got {result:?}"
        );
        assert_eq!(
            result.metadata.recovered_chain_timestamp.as_deref(),
            Some("2026-05-06T12:00:00Z"),
            "the recovered route must be visible in the verdict, not silent"
        );
    }

    #[test]
    fn native_path_does_not_report_a_recovered_timestamp() {
        // A proof carrying its own `destroyed_at` must be indistinguishable
        // from pre-change behaviour, and must NOT claim recovery.
        let proof = make_minimal_v1_proof();
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid);
        assert_eq!(result.metadata.recovered_chain_timestamp, None);
    }

    #[test]
    fn recovery_without_a_key_id_still_rejects() {
        // Removing `destroyed_at` with nothing to recover from must keep the
        // pre-change verdict: reject. This is the control proving the recovery
        // path — not some weakened chain check — is what accepts the fixture.
        let mut proof = make_pre_restoration_v1_proof();
        proof.as_object_mut().unwrap().remove("attestation");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid, "no timestamp anywhere must reject");
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepHashMismatch { step_idx: 0, .. })
        ));
    }

    /// SECURITY-CRITICAL. `key_id` is covered by neither signed message, so an
    /// attacker can rewrite it freely. Recovery must therefore be unable to
    /// launder a mutated key_id into a passing verdict: the recovered value is
    /// an INPUT to the chain walk, and the chain hashes it must reproduce are
    /// signature-bound. Any key_id but the true one yields a mismatch.
    #[test]
    fn mutated_key_id_cannot_be_weaponised() {
        let authentic = make_pre_restoration_v1_proof();
        assert!(verify_auditproof(&authentic, &[], &VerifierPolicy::default()).valid);

        for forged_timestamp in [
            "2026-05-06T12:00:01Z", // one second later
            "2020-01-01T00:00:00Z", // backdated years
            "2099-12-31T23:59:59Z", // postdated
        ] {
            let mut tampered = authentic.clone();
            tampered["attestation"]["key_id"] = serde_json::Value::String(format!(
                "nrx-verify-{}-cap_test",
                forged_timestamp.replace(':', "-")
            ));
            let result = verify_auditproof(&tampered, &[], &VerifierPolicy::default());
            assert!(
                !result.valid,
                "key_id rewritten to {forged_timestamp} must NOT verify; got {result:?}"
            );
            assert!(
                matches!(
                    result.failure_reason,
                    Some(FailureReason::StepHashMismatch { step_idx: 0, .. })
                ),
                "must fail the chain walk at step 0; got {:?}",
                result.failure_reason
            );
        }
    }

    /// Recovery must not weaken tamper detection anywhere else in the chain.
    #[test]
    fn recovered_proof_still_fails_on_a_mutated_chain_step() {
        let mut proof = make_pre_restoration_v1_proof();
        proof["chain"][5]["chain_hash"] = serde_json::Value::String("0".repeat(128));
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepHashMismatch { step_idx: 5, .. })
        ));
    }

    /// A document-supplied `destroyed_at` always wins over `key_id`. An
    /// attacker cannot bypass a failing declared timestamp by ALSO supplying a
    /// key_id that would recover to a passing one.
    #[test]
    fn declared_destroyed_at_takes_precedence_over_key_id() {
        let mut proof = make_minimal_v1_proof();
        proof["destroyed_at"] = serde_json::Value::String("2020-01-01T00:00:00Z".into());
        proof["attestation"] = serde_json::json!({
            "algorithm": "Ed25519",
            // Recovers to the timestamp that WOULD reproduce the chain.
            "key_id": "nrx-verify-2026-05-06T12-00-00Z-cap_test",
        });
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(
            !result.valid,
            "a wrong declared destroyed_at must reject even when key_id would rescue it"
        );
        assert_eq!(result.metadata.recovered_chain_timestamp, None);
    }

    #[test]
    fn verify_minimal_v1_proof_succeeds() {
        let proof = make_minimal_v1_proof();
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.metadata.cdp_version.as_deref(), Some("1.0"));
        assert_eq!(result.metadata.step_count, Some(8));
    }

    // ── trust-chain anchoring: trust-chain anchoring (stage 8) ──────────────────────

    /// A chain-valid v2.1 `nanorix_only` proof whose `canonical_hash` is signed
    /// by `authority_key`. `embedded_pub_b64` is what lands in the attestation
    /// (the authority's own pubkey for a genuine proof; a different key models a
    /// forgery whose embedded key is not the manifest key).
    fn make_signed_v21_proof(
        authority_key: &ed25519_dalek::SigningKey,
        embedded_pub_b64: &str,
        signing_key_version: &str,
    ) -> serde_json::Value {
        use ed25519_dalek::Signer as _;
        let timestamp = "2026-05-06T12:00:00Z";
        let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
        let subsystems = [
            "eee_namespace",
            "eee_tmpfs",
            "eee_memory",
            "dire_keys",
            "dire_identity",
            "fgx_forensic",
            "rzl_audit",
            "capsule_destroy",
        ];
        let mut chain = Vec::new();
        for subsystem in subsystems {
            let method = lookup_method(subsystem);
            let chain_hash = compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
            chain.push(serde_json::json!({
                "subsystem": subsystem, "method": method, "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }
        let final_hash = chain
            .last()
            .and_then(|s| s.get("chain_hash"))
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let mut proof = serde_json::json!({
            "cdp_version": "2.1",
            "capsule_id": "cap_test_subb",
            "destroyed_at": timestamp,
            "chain": chain,
            "final_hash": final_hash,
            "signing_mode": "nanorix_only",
            "jurisdiction": "us",
            "authority_id": "us-kms-nanorix-v1",
            "org_id": "00000000-0000-0000-0000-000000000001",
            "signing_key_version": signing_key_version,
            "destruction_state": "complete",
            "hash_algorithm": "SHA-512",
            "signature_algorithm": "Ed25519",
            "activity": [],
        });

        let canonical = crate::canonical_recompute::recompute_canonical_hash(&proof);
        let sig = authority_key.sign(canonical.as_bytes());
        proof["attestation"] = serde_json::json!({
            "algorithm": "Ed25519",
            "public_key": embedded_pub_b64,
            "signature": base64_encode(&sig.to_bytes()),
            "signing_key_version": signing_key_version,
        });
        proof
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A signed manifest trusting `authority_key` under
    /// `(us-kms-nanorix-v1, version)`. Returns (manifest, pinned fingerprint).
    fn manifest_trusting(
        identity_seed: [u8; 32],
        authority_key: &ed25519_dalek::SigningKey,
        version: &str,
        revoked: bool,
    ) -> (crate::trust_chain::TrustChainManifest, String) {
        let identity = ed25519_dalek::SigningKey::from_bytes(&identity_seed);
        let authority_pub = base64_encode(&authority_key.verifying_key().to_bytes());
        let mut authorities = std::collections::HashMap::new();
        authorities.insert(
            "us-kms-nanorix-v1".to_string(),
            crate::trust_chain::AuthorityRecord {
                display_name: "Test US KMS".to_string(),
                active_versions: vec![crate::trust_chain::KeyVersionRecord {
                    signing_key_version: version.to_string(),
                    public_key_b64: authority_pub,
                    public_key_fingerprint: "sha256:test".to_string(),
                    effective_from: "2026-01-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                    pqc_partner_version: None,
                }],
                archived_versions: vec![],
                revoked,
                emits_population_heads: false,
            },
        );
        let manifest = crate::trust_chain::TrustChainManifest::build_and_sign(
            "1",
            "2026-05-31T00:00:00Z",
            authorities,
            &identity,
        );
        let pin = manifest.identity_fingerprint.clone();
        (manifest, pin)
    }

    fn policy_with(
        manifest: crate::trust_chain::TrustChainManifest,
        pin: String,
    ) -> VerifierPolicy {
        VerifierPolicy {
            trust_chain: Some(manifest),
            pinned_identity_fingerprint: Some(pin),
            ..Default::default()
        }
    }

    /// The pin gate and the trust-chain lookup read the same effective
    /// authority: a signed proof with no top-level `authority_id` anchors under
    /// the default authority and satisfies a pin on it, reaching stage 8.
    #[test]
    fn pin_and_anchor_agree_when_authority_id_absent() {
        use ed25519_dalek::Signer as _;
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let mut proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        proof.as_object_mut().unwrap().remove("authority_id");
        let canonical = crate::canonical_recompute::recompute_canonical_hash(&proof);
        let sig = authority.sign(canonical.as_bytes());
        proof["attestation"]["signature"] = serde_json::json!(base64_encode(&sig.to_bytes()));
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", false);
        let mut policy = policy_with(manifest, pin);
        policy.required_authority_id = Some(NANORIX.into());
        let result = verify_auditproof(&proof, &[], &policy);
        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 8);
    }

    #[test]
    fn subb_genuine_proof_reaches_stage_8() {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(
            result.stage_reached, 8,
            "trust-anchored proof must reach stage 8"
        );
    }

    #[test]
    fn subb_without_manifest_stops_at_stage_7() {
        // sub-A only: integrity proven, but key not anchored to a Nanorix root.
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid);
        assert_eq!(
            result.stage_reached, 7,
            "no manifest → integrity-only stage 7"
        );
    }

    /// A list the pin did not sign anchors nothing, even when it holds the
    /// proof's key: the pinned fingerprint is another identity's, or the list
    /// was edited after signing.
    #[test]
    fn manifest_not_signed_by_the_pin_never_reaches_stage_8() {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&authority, &authority_pub, "1");

        let (manifest, _) = manifest_trusting([7u8; 32], &authority, "1", false);
        let (_, other_pin) = manifest_trusting([8u8; 32], &authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, other_pin));
        assert!(
            !result.valid,
            "a list under another pin must not anchor; got {result:?}"
        );
        assert_eq!(result.stage_reached, 6);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::SigningKeyVersionUnknown {
                version: "1".to_string()
            })
        );

        let (mut edited, pin) = manifest_trusting([7u8; 32], &authority, "1", false);
        edited.issued_at = "2026-06-01T00:00:00Z".to_string();
        let result = verify_auditproof(&proof, &[], &policy_with(edited.clone(), pin));
        assert!(
            !result.valid,
            "an edited list must not anchor; got {result:?}"
        );
        assert_eq!(result.stage_reached, 6);

        // Without a pin the list anchors nothing: the proof ends at stage 7.
        let unpinned = VerifierPolicy {
            trust_chain: Some(edited),
            ..Default::default()
        };
        let result = verify_auditproof(&proof, &[], &unpinned);
        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 7);
        assert_eq!(result.status(), "not_anchored");
    }

    #[test]
    fn subb_forged_proof_rejected_against_manifest_key() {
        // The attacker signs with their OWN key and embeds their own pubkey:
        // self-consistent, so it passes sub-A. But the manifest's authority key
        // is the REAL key, so the signature fails against it — forgery caught.
        let attacker = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let attacker_pub = base64_encode(&attacker.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&attacker, &attacker_pub, "1");
        let real_authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let (manifest, pin) = manifest_trusting([7u8; 32], &real_authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(
            !result.valid,
            "forged proof must be rejected; got {result:?}"
        );
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::SignatureMismatch { .. })
        ));
    }

    #[test]
    fn subb_unknown_key_version_rejected() {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        // Proof claims version "9" but the manifest only carries "1".
        let proof = make_signed_v21_proof(&authority, &authority_pub, "9");
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::SigningKeyVersionUnknown { .. })
        ));
    }

    #[test]
    fn subb_revoked_authority_rejected() {
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", true);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::AuthorityRevoked)
        ));
    }

    /// A 2.0-labelled document whose declared `document_hash` is signed by the
    /// manifest's own authority key is still refused at the version gate: no
    /// manifest, key or signature is consulted for a version outside the
    /// supported set.
    #[test]
    fn subb_2_0_document_with_anchored_key_is_refused_at_stage_2() {
        use ed25519_dalek::Signer as _;
        let authority = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let authority_pub = base64_encode(&authority.verifying_key().to_bytes());
        let mut proof = make_signed_v21_proof(&authority, &authority_pub, "1");
        let declared = "ab".repeat(64);
        proof["cdp_version"] = serde_json::Value::String("2.0".into());
        proof["document_hash"] = serde_json::Value::String(format!("sha512:{declared}"));
        let sig = authority.sign(declared.as_bytes());
        proof["attestation"]["signature"] =
            serde_json::Value::String(base64_encode(&sig.to_bytes()));
        let (manifest, pin) = manifest_trusting([7u8; 32], &authority, "1", false);
        let result = verify_auditproof(&proof, &[], &policy_with(manifest, pin));
        assert!(!result.valid, "expected refusal; got {result:?}");
        assert_eq!(result.stage_reached, 2);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::CdpVersionUnsupported {
                found: "2.0".into()
            })
        );
    }

    #[test]
    fn verify_missing_cdp_version_fails_at_stage_1() {
        let proof = serde_json::json!({"foo": "bar"});
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 1);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::RequiredFieldMissing { ref field }) if field == "cdp_version"
        ));
    }

    #[test]
    fn verify_unsupported_cdp_version_fails_at_stage_2() {
        let proof = serde_json::json!({"cdp_version": "99.0"});
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 2);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::CdpVersionUnsupported { ref found }) if found == "99.0"
        ));
    }

    #[test]
    fn verify_missing_chain_fails_at_stage_3() {
        let proof = serde_json::json!({"cdp_version": "1.0"});
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 3);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::RequiredFieldMissing { ref field }) if field == "chain"
        ));
    }

    #[test]
    fn verify_wrong_step_count_fails_at_stage_3() {
        let proof = serde_json::json!({
            "cdp_version": "1.0",
            "chain": [{"subsystem": "x", "chain_hash": "y"}, {"subsystem": "x", "chain_hash": "y"}]
        });
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 3);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepCountInvalid {
                expected: 8,
                found: 2
            })
        ));
    }

    #[test]
    fn verify_tampered_step_hash_fails_at_stage_3() {
        let mut proof = make_minimal_v1_proof();
        // Tamper step 4's chain_hash
        proof["chain"][4]["chain_hash"] = serde_json::Value::String("0".repeat(128));

        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 3);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::StepHashMismatch { step_idx: 4, .. })
        ));
    }

    #[test]
    fn verify_mismatched_final_hash_fails_at_stage_4() {
        let mut proof = make_minimal_v1_proof();
        proof["final_hash"] = serde_json::Value::String("0".repeat(128));

        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 4);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::FinalHashMismatch { .. })
        ));
    }

    #[test]
    fn genesis_hash_constant_matches_sha512_of_empty() {
        // Per the CDP v1.0 chain spec "Genesis: SHA-512('') = cf83e1357..."
        let mut hasher = Sha512::new();
        hasher.update(b"");
        let computed = hex::encode(hasher.finalize());
        assert_eq!(computed, NANORIX_GENESIS_HASH);
    }

    #[test]
    fn lookup_method_covers_all_8_subsystems() {
        let subsystems = [
            "eee_namespace",
            "eee_tmpfs",
            "eee_memory",
            "dire_keys",
            "dire_identity",
            "fgx_forensic",
            "rzl_audit",
            "capsule_destroy",
        ];
        for s in subsystems {
            assert!(!lookup_method(s).is_empty(), "no method for {s}");
        }
        assert_eq!(lookup_method("unknown_subsystem"), "");
    }

    #[test]
    fn strip_prefix_helpers_handle_present_and_absent_prefix() {
        assert_eq!(strip_hash_prefix("sha512:abc"), "abc");
        assert_eq!(strip_hash_prefix("abc"), "abc");
        assert_eq!(strip_base64_prefix("base64:xyz"), "xyz");
        assert_eq!(strip_base64_prefix("xyz"), "xyz");
    }

    // ── the customer-authority specification — Verifier policy `required_authority_id` pin ──────
    //
    // The pin compares the top-level `authority_id`; the tests below
    // cover each gate rule, the attack, a full decision table and a property
    // test, plus the no-pin cases.
    //
    // Plus a property test asserting that for any (audit_proof) when the
    // policy is `None`, verification result is identical to the no-policy
    // verifier path (≥10k iterations).

    const PIN: &str = "customer-hsm-example-org-v1";
    const NANORIX: &str = "us-kms-nanorix-v1";

    fn pin_policy(pin: &str) -> VerifierPolicy {
        VerifierPolicy {
            required_authority_id: Some(pin.into()),
            ..Default::default()
        }
    }

    /// The unsigned minimal proof relabelled as `version`. The pin gate runs
    /// before any signature check, so its verdict does not depend on the
    /// version's signed message.
    fn make_pin_proof(version: &str) -> serde_json::Value {
        let mut proof = make_minimal_v1_proof();
        proof["cdp_version"] = serde_json::json!(version);
        proof
    }

    /// `make_pin_proof(version)` with `activity` set, when given, and signed
    /// over its canonical view with an embedded key, so a policy that reads the
    /// trail reads one the signature covers. Verifies at stage 7 with no policy.
    fn make_signed_pin_proof(
        version: &str,
        activity: Option<serde_json::Value>,
    ) -> serde_json::Value {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let mut proof = make_pin_proof(version);
        if let Some(trail) = activity {
            proof["activity"] = trail;
        }
        let canonical = crate::canonical_recompute::recompute_canonical_hash(&proof);
        proof["attestation"] = serde_json::json!({
            "algorithm": "Ed25519",
            "public_key": base64_encode(key.verifying_key().as_bytes()),
            "signature": base64_encode(&key.sign(canonical.as_bytes()).to_bytes()),
        });
        proof
    }

    /// The pin rule restated independently of the implementation, behind the
    /// version gate that runs first: `Some` is the exact stage-2 failure,
    /// `None` means the gate passes. `top` is a string top-level
    /// `authority_id`; `sa` the string `signing_authority.authority_id`.
    fn pin_oracle(
        version: &str,
        top: Option<&str>,
        sa: Option<&str>,
        pin: &str,
    ) -> Option<FailureReason> {
        use AuthorityIdMismatchReason::{
            VerifierPolicyAuthorityIdMismatch as Mismatch,
            VerifierPolicyDemandsCustomerHsmAuditProofHasNone as HasNone,
        };
        fn refuse(
            claimed: Option<&str>,
            pin: &str,
            reason: AuthorityIdMismatchReason,
        ) -> Option<FailureReason> {
            Some(FailureReason::AuthorityIdMismatch {
                claimed_authority_id: claimed.map(str::to_string),
                expected_authority_id: pin.to_string(),
                reason,
            })
        }
        // The version gate: 2.0 is retired, so no pin is ever read for it.
        if !matches!(version, "1.0" | "2.1" | "2.2") {
            return Some(FailureReason::CdpVersionUnsupported {
                found: version.to_string(),
            });
        }
        let signed = version == "2.1" || version == "2.2";
        // Rule 0: nothing signed covers the top-level field on 1.0.
        if let (false, Some(t)) = (signed, top) {
            if t != NANORIX {
                return refuse(Some(t), pin, Mismatch);
            }
        }
        let effective = top.unwrap_or(NANORIX);
        if let Some(c) = sa {
            if c != effective {
                return refuse(Some(c), pin, Mismatch);
            }
        }
        if effective != pin {
            return match top {
                None => refuse(None, pin, HasNone),
                Some(t) => refuse(Some(t), pin, Mismatch),
            };
        }
        None
    }

    /// Asserts `result` equals the oracle's verdict: the exact failure at
    /// stage 2, or the gate passing and the proof verifying at stage 4.
    fn assert_matches_oracle(
        result: &VerificationResult,
        want: Option<FailureReason>,
        label: &str,
    ) {
        match want {
            None => {
                assert!(result.valid, "{label}: expected valid; got {result:?}");
                assert_eq!(result.stage_reached, 4, "{label}");
            }
            Some(reason) => {
                assert!(!result.valid, "{label}: expected reject; got {result:?}");
                assert_eq!(result.stage_reached, 2, "{label}");
                assert_eq!(result.failure_reason, Some(reason), "{label}");
            }
        }
    }

    /// Asserts a gate rejection at stage 2 with the exact wire fields.
    fn assert_authority_reject(
        result: &VerificationResult,
        claimed: Option<&str>,
        expected: &str,
        reason: AuthorityIdMismatchReason,
    ) {
        assert!(!result.valid, "expected reject; got {result:?}");
        assert_eq!(result.stage_reached, 2);
        match &result.failure_reason {
            Some(FailureReason::AuthorityIdMismatch {
                claimed_authority_id,
                expected_authority_id,
                reason: got,
            }) => {
                assert_eq!(claimed_authority_id.as_deref(), claimed);
                assert_eq!(expected_authority_id, expected);
                assert_eq!(*got, reason);
            }
            other => panic!("expected AuthorityIdMismatch; got {other:?}"),
        }
    }

    /// Pin equals the top-level `authority_id`, no `signing_authority`: the
    /// gate passes and the chain checks run.
    #[test]
    fn policy_pin_equal_to_top_level_authority_accepted() {
        let mut proof = make_pin_proof("2.1");
        proof["authority_id"] = serde_json::json!(PIN);
        let result = verify_auditproof(&proof, &[], &pin_policy(PIN));
        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 4);
    }

    /// Pin differs from the top-level `authority_id`: mismatch, claimed is the
    /// top-level value.
    #[test]
    fn policy_pin_differs_from_top_level_authority_rejected() {
        let mut proof = make_pin_proof("2.1");
        proof["authority_id"] = serde_json::json!(NANORIX);
        let result = verify_auditproof(&proof, &[], &pin_policy(PIN));
        assert_authority_reject(
            &result,
            Some(NANORIX),
            PIN,
            AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
        );
    }

    /// Top-level `authority_id` absent means the Nanorix default: a pin on the
    /// default passes, any other pin is refused with the has-none reason.
    #[test]
    fn policy_pin_absent_top_level_means_nanorix_default() {
        let proof = make_pin_proof("2.1");
        let ok = verify_auditproof(&proof, &[], &pin_policy(NANORIX));
        assert!(ok.valid, "expected valid; got {ok:?}");
        assert_eq!(ok.stage_reached, 4);

        let result = verify_auditproof(&proof, &[], &pin_policy(PIN));
        assert_authority_reject(
            &result,
            None,
            PIN,
            AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
        );
    }

    /// A non-string top-level `authority_id` resolves to the default exactly
    /// as the trust-chain lookup resolves it.
    #[test]
    fn policy_pin_non_string_top_level_means_nanorix_default() {
        let mut proof = make_pin_proof("2.1");
        proof["authority_id"] = serde_json::json!(7);
        let ok = verify_auditproof(&proof, &[], &pin_policy(NANORIX));
        assert!(ok.valid, "expected valid; got {ok:?}");
        let result = verify_auditproof(&proof, &[], &pin_policy(PIN));
        assert_authority_reject(
            &result,
            None,
            PIN,
            AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone,
        );
    }

    /// The attack: a genuine proof under the Nanorix authority plus an
    /// unsigned `signing_authority` naming the pin. The unsigned object
    /// conflicts with the signed authority, so the proof is refused and never
    /// matches the pin.
    #[test]
    fn policy_pin_unsigned_signing_authority_cannot_match_pin() {
        for top_level in [Some(NANORIX), None] {
            let mut proof = make_pin_proof("2.1");
            if let Some(t) = top_level {
                proof["authority_id"] = serde_json::json!(t);
            }
            proof["signing_authority"] = serde_json::json!({ "authority_id": PIN });
            let result = verify_auditproof(&proof, &[], &pin_policy(PIN));
            assert_authority_reject(
                &result,
                Some(PIN),
                PIN,
                AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
            );
        }
    }

    /// Exact result of every row: cdp_version (1.0 / 2.0 / 2.1 / 2.2) x
    /// top-level (absent / default / equal to pin / other / empty) x
    /// `signing_authority` (absent / null / no id / equal to top-level /
    /// different), against the oracle that restates the rule. Every 2.0 row
    /// is the version refusal, so no pin or label can reopen 2.0.
    #[test]
    fn policy_pin_decision_table() {
        const OTHER: &str = "customer-hsm-other-v1";
        const DIFF: &str = "customer-hsm-forged-v1";
        let tops: [Option<&str>; 5] = [None, Some(NANORIX), Some(PIN), Some(OTHER), Some("")];
        let mut rows = 0;
        for version in ["1.0", "2.0", "2.1", "2.2"] {
            for top in tops {
                let effective = top.unwrap_or(NANORIX);
                // (label, signing_authority value, its string id)
                let shapes: [(&str, Option<serde_json::Value>, Option<&str>); 5] = [
                    ("absent", None, None),
                    ("null", Some(serde_json::Value::Null), None),
                    ("no_id", Some(serde_json::json!({ "x": 1 })), None),
                    (
                        "equal_top",
                        Some(serde_json::json!({ "authority_id": effective })),
                        Some(effective),
                    ),
                    (
                        "different",
                        Some(serde_json::json!({ "authority_id": DIFF })),
                        Some(DIFF),
                    ),
                ];
                for (name, value, sa_id) in shapes {
                    let mut proof = make_pin_proof(version);
                    if let Some(t) = top {
                        proof["authority_id"] = serde_json::json!(t);
                    }
                    if let Some(v) = value {
                        proof["signing_authority"] = v;
                    }
                    let result = verify_auditproof(&proof, &[], &pin_policy(PIN));
                    let label = format!("v{version} top={top:?} sa={name}");
                    assert_matches_oracle(&result, pin_oracle(version, top, sa_id, PIN), &label);
                    rows += 1;
                }
            }
        }
        assert_eq!(rows, 100);
    }

    /// The rows by name, with literal expectations rather than the oracle: on
    /// 1.0 a top-level `authority_id` other than the default is refused
    /// whatever the pin, and a pin accepts only the default. The same proofs
    /// labelled 2.0 are all refused at the version gate, pin or no pin, so a
    /// pin can never reopen 2.0.
    #[test]
    fn policy_pin_unsigned_authority_on_v1_0_and_v2_0_refused_first() {
        use AuthorityIdMismatchReason::{
            VerifierPolicyAuthorityIdMismatch as Mismatch,
            VerifierPolicyDemandsCustomerHsmAuditProofHasNone as HasNone,
        };
        // Relabel: top-level equal to the pin is refused, claimed = it.
        let mut relabelled = make_pin_proof("1.0");
        relabelled["authority_id"] = serde_json::json!(PIN);
        let result = verify_auditproof(&relabelled, &[], &pin_policy(PIN));
        assert_authority_reject(&result, Some(PIN), PIN, Mismatch);
        // The empty string is a string other than the default.
        let mut empty = make_pin_proof("1.0");
        empty["authority_id"] = serde_json::json!("");
        let result = verify_auditproof(&empty, &[], &pin_policy(PIN));
        assert_authority_reject(&result, Some(""), PIN, Mismatch);
        // A pin on the default accepts the unlabelled proof and the default
        // label, and any other pin on the unlabelled proof is has_none.
        let unlabelled = make_pin_proof("1.0");
        let ok = verify_auditproof(&unlabelled, &[], &pin_policy(NANORIX));
        assert!(ok.valid, "v1.0: expected valid; got {ok:?}");
        assert_eq!(ok.stage_reached, 4);
        let mut labelled = make_pin_proof("1.0");
        labelled["authority_id"] = serde_json::json!(NANORIX);
        assert!(verify_auditproof(&labelled, &[], &pin_policy(NANORIX)).valid);
        let result = verify_auditproof(&unlabelled, &[], &pin_policy(PIN));
        assert_authority_reject(&result, None, PIN, HasNone);
        // The conflict rule still applies after rule 0.
        let mut attack = make_pin_proof("1.0");
        attack["signing_authority"] = serde_json::json!({ "authority_id": PIN });
        let result = verify_auditproof(&attack, &[], &pin_policy(PIN));
        assert_authority_reject(&result, Some(PIN), PIN, Mismatch);
        // No pin: the label is accepted, as before.
        assert!(verify_auditproof(&relabelled, &[], &VerifierPolicy::default()).valid);

        // Every one of those proofs and policies on 2.0: the version refusal.
        let cases = [
            (&relabelled, pin_policy(PIN)),
            (&empty, pin_policy(PIN)),
            (&unlabelled, pin_policy(NANORIX)),
            (&labelled, pin_policy(NANORIX)),
            (&unlabelled, pin_policy(PIN)),
            (&attack, pin_policy(PIN)),
            (&relabelled, VerifierPolicy::default()),
        ];
        for (i, (proof, policy)) in cases.into_iter().enumerate() {
            let mut proof = proof.clone();
            proof["cdp_version"] = serde_json::json!("2.0");
            let result = verify_auditproof(&proof, &[], &policy);
            assert!(
                !result.valid,
                "v2.0 case {i}: expected refusal; got {result:?}"
            );
            assert_eq!(result.stage_reached, 2, "v2.0 case {i}");
            assert_eq!(
                result.failure_reason,
                Some(FailureReason::CdpVersionUnsupported {
                    found: "2.0".into()
                }),
                "v2.0 case {i}"
            );
        }
    }

    // ── Residency pin ────────────────────────────────────────────────────

    /// A pinned region that the proof does not match is rejected before the
    /// chain walk. Until this gate existed, `--required-region` parsed fine and
    /// then did nothing — an auditor pinning EU residency got a clean "valid"
    /// on a us-central1 proof.
    #[test]
    fn residency_pin_rejects_disagreeing_region() {
        for version in CANONICAL_VIEW_SIGNED_VERSIONS {
            let proof = make_signed_pin_proof(
                version,
                Some(serde_json::json!([
                    { "event": "capsule_started", "region": "us-central1" }
                ])),
            );

            let policy = VerifierPolicy {
                required_region: Some("europe-west1".into()),
                ..Default::default()
            };

            let result = verify_auditproof(&proof, &[], &policy);

            assert!(
                !result.valid,
                "{version}: expected rejection; got {result:?}"
            );
            assert_eq!(result.stage_reached, 2, "{version}");
            assert!(
                matches!(
                    result.failure_reason,
                    Some(FailureReason::RegionMismatch { ref required, ref actual })
                        if required == "europe-west1" && actual == "us-central1"
                ),
                "{version}: {result:?}"
            );
        }
    }

    /// A proof carrying no region at all cannot satisfy a residency pin — the
    /// pin fails closed rather than treating "absent" as "anything".
    #[test]
    fn residency_pin_fails_closed_when_proof_declares_no_region() {
        let proof = make_minimal_v1_proof();
        let policy = VerifierPolicy {
            required_region: Some("europe-west1".into()),
            ..Default::default()
        };

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(!result.valid, "expected rejection; got {result:?}");
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::RegionMismatch { ref actual, .. }) if actual.is_empty()
        ));
    }

    /// A matching pin on a signed trail is transparent — the proof continues
    /// to the chain and signature checks.
    #[test]
    fn residency_pin_accepts_matching_region() {
        for version in CANONICAL_VIEW_SIGNED_VERSIONS {
            let proof = make_signed_pin_proof(
                version,
                Some(serde_json::json!([
                    { "event": "capsule_started", "region": "europe-west1" }
                ])),
            );

            let policy = VerifierPolicy {
                required_region: Some("europe-west1".into()),
                ..Default::default()
            };

            let result = verify_auditproof(&proof, &[], &policy);

            assert!(result.valid, "{version}: expected valid; got {result:?}");
            assert_eq!(result.stage_reached, 7, "{version}");
        }
    }

    /// cdp_version 1.0 signs only `final_hash`, so its activity trail, and the
    /// region in it, is unsigned: anyone could add a `capsule_started` region
    /// equal to the pin to a genuine 1.0 proof. Under a residency pin every 1.0
    /// proof is refused with an empty `actual`, whatever region it states;
    /// without a pin it verifies as before.
    #[test]
    fn residency_pin_refuses_every_v1_0_proof() {
        for stated in [Some("europe-west1"), Some("us-central1"), None] {
            let mut proof = make_minimal_v1_proof();
            if let Some(region) = stated {
                proof["activity"] = serde_json::json!([
                    { "event": "capsule_started", "region": region }
                ]);
            }
            let policy = VerifierPolicy {
                required_region: Some("europe-west1".into()),
                ..Default::default()
            };

            let result = verify_auditproof(&proof, &[], &policy);

            assert!(
                !result.valid,
                "{stated:?}: expected rejection; got {result:?}"
            );
            assert_eq!(result.stage_reached, 2, "{stated:?}");
            assert_eq!(
                result.failure_reason,
                Some(FailureReason::RegionMismatch {
                    required: "europe-west1".into(),
                    actual: String::new(),
                }),
                "{stated:?}"
            );
            assert!(
                verify_auditproof(&proof, &[], &VerifierPolicy::default()).valid,
                "{stated:?}: without a pin the proof verifies"
            );
        }
    }

    /// A 2.1 or 2.2 proof without a signature has an unsigned trail: under a
    /// residency pin it is refused at stage 2, and no return names the region
    /// it states, here or where it ends without a pin.
    #[test]
    fn an_unsigned_proof_names_no_region_on_any_return() {
        for version in ["2.1", "2.2"] {
            let mut proof = make_signed_pin_proof(
                version,
                Some(serde_json::json!([
                    { "event": "capsule_started", "region": "europe-west1" }
                ])),
            );
            proof["attestation"]
                .as_object_mut()
                .unwrap()
                .remove("signature");
            let pinned = VerifierPolicy {
                required_region: Some("europe-west1".into()),
                ..Default::default()
            };
            let result = verify_auditproof(&proof, &[], &pinned);
            assert_eq!(result.stage_reached, 2, "{version}: {result:?}");
            assert_eq!(result.metadata.region, None, "{version}: {result:?}");
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert_eq!(result.metadata.region, None, "{version}: {result:?}");
        }
    }

    /// An outsider must not be able to satisfy a residency pin by appending a
    /// region to a genuine, correctly-signed proof.
    ///
    /// Regression test for a demonstrated defect, not a hypothetical. Region
    /// used to resolve from `/environment/region` or top-level `region`.
    /// Neither is inside `CanonicalCdpView`: `environment` is a projection
    /// built by `FullCdp::to_verification()` whose struct carries no region
    /// field at all, and top-level `region` is emitted by nothing. So the pin
    /// consulted a field anyone could append to a correctly-signed document
    /// with no key — and because real proofs carry no region, the control
    /// could only ever be satisfied by a forged one. True-positive rate zero,
    /// false-positive rate one.
    ///
    /// Region now resolves only from the `capsule_started` activity event,
    /// which is inside the signed canonical view.
    #[test]
    fn residency_pin_ignores_unsigned_region_fields() {
        for injected_at in ["region", "environment"] {
            let mut proof = make_signed_pin_proof(
                "2.1",
                Some(serde_json::json!([
                    { "event": "capsule_started", "region": "us-central1" }
                ])),
            );
            if injected_at == "region" {
                proof["region"] = serde_json::json!("europe-west1");
            } else {
                proof["environment"] = serde_json::json!({ "region": "europe-west1" });
            }

            let policy = VerifierPolicy {
                required_region: Some("europe-west1".into()),
                ..Default::default()
            };

            let result = verify_auditproof(&proof, &[], &policy);

            assert!(
                !result.valid,
                "unsigned `{injected_at}` must not satisfy a residency pin; got {result:?}"
            );
            assert!(
                matches!(
                    result.failure_reason,
                    Some(FailureReason::RegionMismatch { ref actual, .. })
                        if actual == "us-central1"
                ),
                "must report the SIGNED region, not the injected one; got {result:?}"
            );
        }
    }

    /// No pin means no residency opinion — the pre-gate behaviour of every
    /// existing caller is unchanged.
    #[test]
    fn no_residency_pin_accepts_any_region() {
        let mut proof = make_minimal_v1_proof();
        proof["region"] = serde_json::json!("asia-east1");

        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());

        assert!(result.valid, "expected valid; got {result:?}");
    }

    // ── Diagnostic-mode refusal ──────────────────────────────────────────

    fn reject_diagnostic() -> VerifierPolicy {
        VerifierPolicy {
            reject_diagnostic: true,
            ..Default::default()
        }
    }

    fn assert_diagnostic_refused(result: &VerificationResult, label: &str) {
        assert!(!result.valid, "{label}: {result:?}");
        assert_eq!(result.stage_reached, 2, "{label}");
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::DiagnosticProofRefused),
            "{label}"
        );
    }

    /// With the setting on, a proof on a signed-activity version whose trail
    /// holds a `diagnostic_mode_enabled` entry, wherever it sits, is refused
    /// at stage 2. Without the setting the same proof is accepted.
    #[test]
    fn reject_diagnostic_refuses_a_proof_recording_diagnostic_mode() {
        let started = serde_json::json!({ "event": "capsule_started", "region": "us-central1" });
        let diagnostic =
            serde_json::json!({ "event": "diagnostic_mode_enabled", "at": "2026-05-06T12:00:00Z" });
        for version in ["2.1", "2.2"] {
            for trail in [
                serde_json::json!([started, diagnostic]),
                serde_json::json!([diagnostic, started]),
                serde_json::json!([diagnostic]),
            ] {
                let proof = make_signed_pin_proof(version, Some(trail.clone()));
                let label = format!("{version} {trail}");
                assert_diagnostic_refused(
                    &verify_auditproof(&proof, &[], &reject_diagnostic()),
                    &label,
                );
                let accepted = verify_auditproof(&proof, &[], &VerifierPolicy::default());
                assert!(
                    accepted.valid,
                    "{label}: accepted without the setting: {accepted:?}"
                );
                assert_eq!(accepted.stage_reached, 7, "{label}");
            }
        }
    }

    /// The setting refuses only what it names: a signed proof without the
    /// event, or with a different or differently spelled event, continues to
    /// the chain and signature checks.
    #[test]
    fn reject_diagnostic_accepts_a_proof_without_the_event() {
        for version in ["2.1", "2.2"] {
            for trail in [
                None,
                Some(serde_json::json!([])),
                Some(serde_json::json!([{ "event": "capsule_started", "region": "us-central1" }])),
                Some(serde_json::json!([{ "event": "Diagnostic_Mode_Enabled" }])),
                Some(serde_json::json!([{ "event": "diagnostic_mode" }])),
                Some(serde_json::json!([{ "diagnostic_mode_enabled": true }])),
            ] {
                let proof = make_signed_pin_proof(version, trail.clone());
                let result = verify_auditproof(&proof, &[], &reject_diagnostic());
                assert!(result.valid, "{version} {trail:?}: {result:?}");
                assert_eq!(result.stage_reached, 7, "{version} {trail:?}");
            }
        }
    }

    /// cdp_version 1.0 signs only `final_hash`, so a holder could delete the
    /// event from a genuine diagnostic-mode 1.0 proof and the signature would
    /// still hold. The setting therefore refuses every 1.0 proof, with or
    /// without an activity trail, and accepts it when off.
    #[test]
    fn reject_diagnostic_refuses_every_v1_0_proof() {
        for trail in [
            None,
            Some(serde_json::json!([])),
            Some(serde_json::json!([{ "event": "capsule_started", "region": "us-central1" }])),
            Some(serde_json::json!([{ "event": "diagnostic_mode_enabled" }])),
        ] {
            let mut proof = make_minimal_v1_proof();
            if let Some(trail) = &trail {
                proof["activity"] = trail.clone();
            }
            let label = format!("1.0 {trail:?}");
            assert_diagnostic_refused(
                &verify_auditproof(&proof, &[], &reject_diagnostic()),
                &label,
            );
            assert!(
                verify_auditproof(&proof, &[], &VerifierPolicy::default()).valid,
                "{label}: accepted without the setting"
            );
        }
    }

    /// The gate sits after the authority and residency pins and before the
    /// chain walk: a pin that refuses names itself first, and a broken chain is
    /// never reached.
    #[test]
    fn reject_diagnostic_runs_after_the_pins_and_before_the_chain_walk() {
        let mut proof = make_signed_pin_proof(
            "2.2",
            Some(serde_json::json!([
                { "event": "capsule_started", "region": "us-central1" },
                { "event": "diagnostic_mode_enabled" }
            ])),
        );

        let region = VerifierPolicy {
            required_region: Some("europe-west1".into()),
            ..reject_diagnostic()
        };
        assert!(matches!(
            verify_auditproof(&proof, &[], &region).failure_reason,
            Some(FailureReason::RegionMismatch { .. })
        ));
        let authority = VerifierPolicy {
            required_authority_id: Some("customer-hsm-example-org-v1".into()),
            ..reject_diagnostic()
        };
        assert!(matches!(
            verify_auditproof(&proof, &[], &authority).failure_reason,
            Some(FailureReason::AuthorityIdMismatch { .. })
        ));
        let matching = VerifierPolicy {
            required_region: Some("us-central1".into()),
            required_authority_id: Some(DEFAULT_AUTHORITY_ID.into()),
            ..reject_diagnostic()
        };
        assert_diagnostic_refused(&verify_auditproof(&proof, &[], &matching), "pins match");

        proof["chain"] = serde_json::json!([]);
        assert_diagnostic_refused(
            &verify_auditproof(&proof, &[], &reject_diagnostic()),
            "empty chain",
        );
        let mut v1 = make_minimal_v1_proof();
        v1["chain"] = serde_json::json!([]);
        assert_diagnostic_refused(
            &verify_auditproof(&v1, &[], &reject_diagnostic()),
            "1.0 empty chain",
        );
    }

    /// A 2.1 or 2.2 proof whose signature step ends as `Absent` has an
    /// unsigned trail, like a 1.0 proof: both policies refuse it at stage 2.
    /// The four inputs are the ones `verify_signature` reads as Absent: no
    /// signature, an empty signature, no key, and an empty `public_key` beside
    /// a valid `verification_key` (an empty `public_key` does not fall back).
    /// Each is asserted Absent here, so the gate and stage 4 cannot disagree.
    #[test]
    fn trail_policies_refuse_a_proof_whose_signature_step_ends_absent() {
        let trail = serde_json::json!([
            { "event": "capsule_started", "region": "europe-west1" }
        ]);
        let region = VerifierPolicy {
            required_region: Some("europe-west1".into()),
            ..Default::default()
        };
        for version in CANONICAL_VIEW_SIGNED_VERSIONS {
            let signed = make_signed_pin_proof(version, Some(trail.clone()));
            for (policy, label) in [(&region, "pin"), (&reject_diagnostic(), "setting")] {
                let result = verify_auditproof(&signed, &[], policy);
                assert!(result.valid, "{version} signed, {label}: {result:?}");
                assert_eq!(result.stage_reached, 7, "{version} signed, {label}");
            }
            let key = signed["attestation"]["public_key"].clone();
            let mut inputs = Vec::new();
            let mut no_signature = signed.clone();
            no_signature["attestation"]
                .as_object_mut()
                .unwrap()
                .remove("signature");
            inputs.push(("no signature", no_signature));
            let mut empty_signature = signed.clone();
            empty_signature["attestation"]["signature"] = serde_json::json!("");
            inputs.push(("empty signature", empty_signature));
            let mut no_key = signed.clone();
            no_key["attestation"]
                .as_object_mut()
                .unwrap()
                .remove("public_key");
            inputs.push(("no key", no_key));
            let mut empty_public_key = signed.clone();
            empty_public_key["attestation"]["public_key"] = serde_json::json!("");
            empty_public_key["attestation"]["verification_key"] = key;
            inputs.push(("empty public_key", empty_public_key));

            for (name, proof) in inputs {
                let label = format!("{version} {name}");
                assert_eq!(
                    canonical_recompute::verify_signature(&proof, version),
                    canonical_recompute::SignatureCheck::Absent,
                    "{label}"
                );
                assert_diagnostic_refused(
                    &verify_auditproof(&proof, &[], &reject_diagnostic()),
                    &label,
                );
                let pinned = verify_auditproof(&proof, &[], &region);
                assert!(!pinned.valid, "{label}: {pinned:?}");
                assert_eq!(pinned.stage_reached, 2, "{label}");
                assert_eq!(
                    pinned.failure_reason,
                    Some(FailureReason::RegionMismatch {
                        required: "europe-west1".into(),
                        actual: String::new(),
                    }),
                    "{label}"
                );
                let plain = verify_auditproof(&proof, &[], &VerifierPolicy::default());
                assert!(plain.valid, "{label}: without a policy: {plain:?}");
                assert_eq!(plain.stage_reached, 4, "{label}");
            }
        }
    }

    /// Only the no-signature case is refused at stage 2. A signature that is
    /// present but no longer covers the trail fails at stage 7, and a
    /// `signing_mode` this build cannot verify fails at stage 4, as without
    /// the setting.
    #[test]
    fn reject_diagnostic_leaves_a_present_signature_to_the_signature_step() {
        for version in CANONICAL_VIEW_SIGNED_VERSIONS {
            let mut stripped = make_signed_pin_proof(
                version,
                Some(serde_json::json!([
                    { "event": "capsule_started", "region": "us-central1" },
                    { "event": "diagnostic_mode_enabled" }
                ])),
            );
            stripped["activity"]
                .as_array_mut()
                .unwrap()
                .retain(|e| e["event"] != DIAGNOSTIC_MODE_EVENT);
            let result = verify_auditproof(&stripped, &[], &reject_diagnostic());
            assert!(!result.valid, "{version} stripped: {result:?}");
            assert_eq!(result.stage_reached, 7, "{version} stripped");
            assert!(
                matches!(
                    result.failure_reason,
                    Some(FailureReason::SignatureMismatch { .. })
                ),
                "{version} stripped: {result:?}"
            );

            let mut unsupported = make_signed_pin_proof(version, None);
            unsupported["signing_mode"] = serde_json::json!("dual_signature");
            let result = verify_auditproof(&unsupported, &[], &reject_diagnostic());
            assert_eq!(result.stage_reached, 4, "{version} unsupported");
            assert!(
                matches!(
                    result.failure_reason,
                    Some(FailureReason::AlgorithmUnsupported { .. })
                ),
                "{version} unsupported: {result:?}"
            );
        }
    }

    /// Fixture 4 — policy is None (default), AuditProof has no
    /// `signing_authority` field. Accept (Nanorix-default path; pre-G7
    /// behavior preserved).
    #[test]
    fn policy_none_audit_proof_none_accepted() {
        let proof = make_minimal_v1_proof();
        let policy = VerifierPolicy::default();

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 4);
    }

    /// Fixture 5 — policy is None (default), AuditProof has a populated
    /// `signing_authority`. Accept (the gate doesn't fire when policy is
    /// None regardless of AuditProof shape).
    #[test]
    fn policy_none_audit_proof_some_accepted() {
        let mut proof = make_minimal_v1_proof();
        proof["signing_authority"] = serde_json::json!({
            "authority_id": "customer-hsm-example-org-v1",
        });

        let policy = VerifierPolicy::default();

        let result = verify_auditproof(&proof, &[], &policy);

        assert!(result.valid, "expected valid; got {result:?}");
        assert_eq!(result.stage_reached, 4);
    }

    /// Fault-injection property: for any AuditProof variant (with /
    /// without `signing_authority`, with arbitrary `authority_id`),
    /// when the policy is `None`, verification result is byte-equivalent
    /// to the no-policy verifier path. ≥10k iterations.
    ///
    /// Locks the invariant
    /// that the policy-pin gate is a NO-OP when the gate is unconfigured.
    /// Any future change to the gate that accidentally activates it under
    /// `None` policy is caught here.
    #[test]
    fn policy_none_invariant_under_random_signing_authority_payloads_10k() {
        // Deterministic LCG seed; any deterministic seed works.
        let mut state: u64 = 0xC0DE_5117_FACE_FEED;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let auth_id_pool = [
            "customer-hsm-example-org-v1",
            "customer-hsm-other-v1",
            "us-kms-nanorix-v1",
            "europe-west1.daemon.nanorix.io",
            "auth_xyz_health",
            "",
        ];

        for iter in 0..10_000 {
            let r = next();
            let mut proof = make_minimal_v1_proof();

            let payload_kind = r % 4;
            match payload_kind {
                0 => {
                    // No `signing_authority` field at all.
                }
                1 => {
                    // `signing_authority` is JSON null.
                    proof["signing_authority"] = serde_json::Value::Null;
                }
                2 => {
                    // `signing_authority` populated with random authority_id.
                    let auth = auth_id_pool[((r >> 8) as usize) % auth_id_pool.len()];
                    proof["signing_authority"] = serde_json::json!({
                        "authority_id": auth,
                    });
                }
                _ => {
                    // `signing_authority` populated but missing the
                    // `authority_id` field — verifier should still tolerate it.
                    proof["signing_authority"] = serde_json::json!({
                        "other_field": "value",
                    });
                }
            }

            let policy = VerifierPolicy::default();
            let result = verify_auditproof(&proof, &[], &policy);

            assert!(
                result.valid,
                "iter {} (kind {}): policy=None must accept any signing_authority \
                 shape; got failure_reason {:?}",
                iter, payload_kind, result.failure_reason
            );
            assert_eq!(
                result.stage_reached, 4,
                "iter {} (kind {}): expected stage_reached=4 (chain checks pass) under \
                 policy=None",
                iter, payload_kind
            );
        }
    }

    /// Fault-injection property: for any cdp_version, pin, top-level
    /// `authority_id` and unsigned `signing_authority` shape, the gate follows
    /// the decided rule. At least 10k iterations over all four versions, 2.0
    /// expecting the version refusal; the oracle restates the rule
    /// independently of the implementation.
    #[test]
    fn policy_pin_decision_under_random_inputs_10k() {
        let mut state: u64 = 0xBEEF_DEAD_C0DE_F00D;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let pool = [
            "customer-hsm-example-org-v1",
            "customer-hsm-other-v1",
            "customer-hsm-acme-prod-2026-q2",
            "us-kms-nanorix-v1",
        ];
        let versions = ["1.0", "2.0", "2.1", "2.2"];

        for iter in 0..10_000 {
            let r = next();
            let version = versions[((r >> 28) as usize) % versions.len()];
            let mut proof = make_pin_proof(version);
            let pinned = pool[((r >> 4) as usize) % pool.len()].to_string();

            let top: Option<String> = if (r >> 8) & 3 == 0 {
                None
            } else {
                Some(pool[((r >> 10) as usize) % pool.len()].to_string())
            };
            if let Some(t) = &top {
                proof["authority_id"] = serde_json::json!(t);
            }

            let sa: Option<String> = match (r >> 16) & 3 {
                0 => None,
                1 => {
                    proof["signing_authority"] = serde_json::Value::Null;
                    None
                }
                2 => {
                    proof["signing_authority"] = serde_json::json!({ "other": 1 });
                    None
                }
                _ => {
                    let c = pool[((r >> 20) as usize) % pool.len()].to_string();
                    proof["signing_authority"] = serde_json::json!({ "authority_id": c });
                    Some(c)
                }
            };

            let want = pin_oracle(version, top.as_deref(), sa.as_deref(), &pinned);
            let result = verify_auditproof(&proof, &[], &pin_policy(&pinned));
            assert_matches_oracle(&result, want, &format!("iter {iter} v{version}"));
        }
    }

    // ── the wire-format evolution policy an earlier release-A cdp_kind verifier byte-equivalence pins ──────
    //
    // The cdp_kind reserved-slot lives at the FullCdp / VerificationCdp
    // canonical-hash layer (the AuditProof document builder), NOT in the
    // 8-step destruction chain that this verifier reproduces.
    //
    // Therefore: the verifier MUST process AuditProofs identically whether
    // `cdp_kind` is absent (V1 default), `Some("workload")`, `Some("request")`,
    // `Some("call")`, or `Some("batch")`. The chain hash + final_hash binding
    // are computed from `chain` array + `destroyed_at` only.
    //
    // These properties lock the invariant: cdp_kind is structurally invisible
    // to the chain-walk verifier. Any future regression that accidentally
    // makes cdp_kind participate in chain hash inputs trips these tests.

    /// Fault-injection property: for any cdp_kind value attached to an
    /// otherwise-valid AuditProof, verification result MUST be byte-equivalent
    /// to the same proof with cdp_kind omitted. ≥10k iterations.
    #[test]
    fn cdp_kind_is_invisible_to_chain_verification_10k() {
        let cdp_kind_pool = [
            None,
            Some("workload"),
            Some("request"),
            Some("call"),
            Some("batch"),
        ];

        let mut state: u64 = 0x0001_6ACD_C0DE_C0DE;
        let mut next = || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state
        };

        let baseline_proof = make_minimal_v1_proof();
        let baseline_result = verify_auditproof(&baseline_proof, &[], &VerifierPolicy::default());
        // Baseline must be valid; the proof is intentionally constructed valid.
        assert!(baseline_result.valid, "baseline must verify");

        for iter in 0..10_000 {
            let r = next();
            let kind = cdp_kind_pool[(r as usize) % cdp_kind_pool.len()];

            let mut proof = make_minimal_v1_proof();
            if let Some(k) = kind {
                proof["cdp_kind"] = serde_json::Value::String(k.into());
            }

            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());

            assert_eq!(
                result.valid, baseline_result.valid,
                "iter {iter}: cdp_kind={kind:?} must NOT change verification verdict"
            );
            assert_eq!(
                result.stage_reached, baseline_result.stage_reached,
                "iter {iter}: cdp_kind={kind:?} must NOT change stage_reached"
            );
            assert_eq!(
                result.failure_reason, baseline_result.failure_reason,
                "iter {iter}: cdp_kind={kind:?} must NOT change failure_reason"
            );
            // metadata fields are deterministic functions of the proof's
            // version / capsule_id / chain shape — none of which depend on
            // cdp_kind. They must match the baseline exactly.
            assert_eq!(
                result.metadata, baseline_result.metadata,
                "iter {iter}: cdp_kind={kind:?} must NOT change metadata"
            );
        }
    }

    /// cdp_kind populated → verifier still recomputes the same final_hash.
    /// Reason: cdp_kind is NOT in chain step inputs (subsystem / action /
    /// method / timestamp). The chain layer is upstream of cdp_kind binding.
    #[test]
    fn cdp_kind_does_not_perturb_chain_recompute() {
        let baseline = make_minimal_v1_proof();
        let baseline_result = verify_auditproof(&baseline, &[], &VerifierPolicy::default());
        let baseline_step_count = baseline_result.metadata.step_count;

        for k in ["workload", "request", "call", "batch"] {
            let mut proof = baseline.clone();
            proof["cdp_kind"] = serde_json::Value::String(k.into());
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert!(
                result.valid,
                "valid proof with cdp_kind={k:?} must remain valid"
            );
            assert_eq!(
                result.metadata.step_count, baseline_step_count,
                "step_count must be unchanged when only cdp_kind differs"
            );
        }
    }

    // ── the EU signing profile — algorithm dispatch + additive-evolution tolerance ─

    #[test]
    fn non_ed25519_attestation_algorithm_fails_typed_at_stage_4() {
        let mut proof = make_minimal_v1_proof();
        proof["attestation"] = serde_json::json!({ "algorithm": "ML-DSA-65" });
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 4);
        assert!(
            matches!(
                result.failure_reason,
                Some(FailureReason::AlgorithmUnsupported { ref found }) if found == "ML-DSA-65"
            ),
            "must fail typed as AlgorithmUnsupported, never as malformed; got {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn non_ed25519_top_level_signature_algorithm_fails_typed() {
        let mut proof = make_minimal_v1_proof();
        proof["signature_algorithm"] = serde_json::json!("ECDSA-P256");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::AlgorithmUnsupported { .. })
        ));
    }

    #[test]
    fn unknown_fields_do_not_disturb_verification() {
        // Additive-evolution insurance: a proof carrying fields
        // this build has never heard of must verify exactly as without them.
        let mut proof = make_minimal_v1_proof();
        proof["future_sibling_artifact"] = serde_json::json!({ "anything": [1, 2, 3] });
        proof["pqc_signature_hint"] = serde_json::json!("reserved");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(
            result.valid,
            "unknown fields must be ignored; got {result:?}"
        );
    }

    // ── Reserved attestation slots: fail closed on a populated one ──
    //
    // The distinction against `unknown_fields_do_not_disturb_verification`
    // above is deliberate. A field this build has never heard of is ignored,
    // because additive evolution has to stay possible. A field this build
    // knows to be BOTH outside the signature AND never emitted is rejected,
    // because there is no benign way for it to be there.

    #[test]
    fn every_populated_reserved_slot_is_rejected() {
        for slot in UNSIGNED_RESERVED_SLOTS {
            let mut proof = make_minimal_v1_proof();
            proof[slot] = serde_json::json!([{ "signature": "base64:AAAA" }]);
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert!(!result.valid, "{slot} populated must be rejected");
            match result.failure_reason {
                Some(FailureReason::UnsignedFieldPopulated { ref field }) => {
                    assert_eq!(field, slot)
                }
                other => panic!("{slot}: expected unsigned_field_populated, got {other:?}"),
            }
            assert_eq!(result.stage_reached, 2);
        }
    }

    #[test]
    fn reserved_slots_emitted_as_null_still_verify() {
        // The positive control that keeps the gate honest: genuine documents
        // carry every one of these keys with an explicit `null`, because the
        // fields have no `skip_serializing_if`. Rejecting those would reject
        // every proof Nanorix has ever issued.
        let mut proof = make_minimal_v1_proof();
        for slot in UNSIGNED_RESERVED_SLOTS {
            proof[slot] = serde_json::Value::Null;
        }
        proof["per_event_attestations"] = serde_json::Value::Null;
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "null slots must verify; got {result:?}");
    }

    #[test]
    fn per_event_attestations_is_not_rejected_when_populated() {
        // The one reserved slot the server genuinely fills, drained from
        // `capsule_event_attestations` at destroy. Rejecting a populated one
        // would reject authentic proofs from per-event-signed capsules.
        let mut proof = make_minimal_v1_proof();
        proof["per_event_attestations"] = serde_json::json!([{
            "algorithm": "Ed25519",
            "public_key": "base64:AAAA",
            "signature": "base64:BBBB",
            "event_id": "evt_1",
        }]);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(
            result.valid,
            "per_event_attestations must stay accepted; got {result:?}"
        );
    }

    #[test]
    fn injected_witness_signatures_no_longer_reads_as_untampered() {
        // The reproduction from FINDING_unsigned_slot_injection.md: take a
        // proof that verifies, add a fabricated witness countersignature,
        // change nothing else. Before this gate the verdict was "Integrity
        // verified (proof not tampered since signing)" — false in exactly the
        // case the sentence exists to rule out, and asserting an independent
        // corroboration that never happened.
        let clean = make_minimal_v1_proof();
        assert!(verify_auditproof(&clean, &[], &VerifierPolicy::default()).valid);

        let mut tampered = clean;
        tampered["witness_signatures"] = serde_json::json!([{
            "algorithm": "Ed25519",
            "public_key": "base64:AAAA",
            "signature": "base64:ZZZZ",
            "key_id": "witness-that-never-signed",
        }]);
        let result = verify_auditproof(&tampered, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::UnsignedFieldPopulated { .. })
        ));
    }

    #[test]
    fn empty_array_in_a_reserved_slot_is_rejected() {
        // No signer emits `[]` either — the shape is `null` or absent. An
        // empty array carries no claim, but accepting it would mean the gate
        // reasons about content rather than about who could have written it.
        let mut proof = make_minimal_v1_proof();
        proof["witness_signatures"] = serde_json::json!([]);
        assert!(!verify_auditproof(&proof, &[], &VerifierPolicy::default()).valid);
    }

    // ── Unanchored sets: a set with no Merkle root is a set nothing binds ──

    #[test]
    fn parent_set_without_root_is_rejected() {
        // Wholesale lineage injection: `parent_proof_hashes` is outside the
        // canonical view and the root is `skip_serializing_if`, so appending
        // an entire fabricated array to a genuine proof used to leave the
        // signature intact AND the Merkle comparison skipped.
        let mut proof = make_minimal_v1_proof();
        proof["parent_proof_hashes"] = serde_json::json!([{
            "parent_chain_hash": "sha512:00",
            "parent_key_id": "cust-auth-fabricated",
            "parent_signature": "base64:AAAA",
            "parent_organization_tag": "vendor:never-involved",
        }]);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        match result.failure_reason {
            Some(FailureReason::RequiredFieldMissing { ref field }) => {
                assert_eq!(field, "parent_proofs_merkle_root")
            }
            other => panic!("expected required_field_missing, got {other:?}"),
        }
    }

    #[test]
    fn receipt_set_without_root_is_rejected() {
        let mut proof = make_minimal_v1_proof();
        proof["record_receipts"] = serde_json::json!([{
            "record_index": 0,
            "record_id": "rec_fabricated",
            "record_chain_hash": "sha512:00",
        }]);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        match result.failure_reason {
            Some(FailureReason::RequiredFieldMissing { ref field }) => {
                assert_eq!(field, "record_receipts_merkle_root")
            }
            other => panic!("expected required_field_missing, got {other:?}"),
        }
    }
    // ── B1.4 — canonical chain identity ───────────────────────────────────
    //
    // Eight entries is a count, not an identity. Before this gate the walk
    // hashed whatever `subsystem` the document declared and mapped anything
    // unrecognised to an empty method, so any self-consistent 8-entry chain
    // reproduced itself and verified clean. These pin the three shapes that
    // used to pass and the one shape that now has its own verdict.

    /// Build a self-consistent v1.0 chain over an arbitrary subsystem list —
    /// exactly what a signer authoring a non-canonical chain would produce.
    fn make_self_consistent_v1_proof(subsystems: [&str; NANORIX_CHAIN_STEPS]) -> serde_json::Value {
        let timestamp = "2026-05-06T12:00:00Z";
        let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
        let mut chain = Vec::new();
        for subsystem in subsystems {
            let method = lookup_method(subsystem);
            let chain_hash = compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
            chain.push(serde_json::json!({
                "subsystem": subsystem,
                "method": method,
                "chain_hash": chain_hash.clone(),
            }));
            prev_hash = chain_hash;
        }
        serde_json::json!({
            "cdp_version": "1.0",
            "capsule_id": "cap_identity_test",
            "destroyed_at": timestamp,
            "chain": chain,
            "final_hash": prev_hash,
        })
    }

    /// Positive control. The canonical eight still verify — the gate rejects
    /// non-canonical identity, it does not reject proofs.
    #[test]
    fn canonical_chain_still_verifies() {
        let canonical = [
            "eee_namespace",
            "eee_tmpfs",
            "eee_memory",
            "dire_keys",
            "dire_identity",
            "fgx_forensic",
            "rzl_audit",
            "capsule_destroy",
        ];
        let proof = make_self_consistent_v1_proof(canonical);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "canonical chain must verify; got {result:?}");
        assert_eq!(result.metadata.step_count, Some(8));
    }

    #[test]
    fn canonical_chain_table_matches_lookup_method() {
        for (subsystem, method) in CANONICAL_CHAIN {
            assert_eq!(lookup_method(subsystem), method, "{subsystem}");
        }
    }

    #[test]
    fn scrambled_canonical_order_is_rejected() {
        let proof = make_self_consistent_v1_proof([
            "capsule_destroy",
            "rzl_audit",
            "fgx_forensic",
            "dire_identity",
            "dire_keys",
            "eee_memory",
            "eee_tmpfs",
            "eee_namespace",
        ]);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid, "scrambled order must not verify");
        assert_eq!(result.stage_reached, 3);
        assert!(
            matches!(
                result.failure_reason,
                Some(FailureReason::StepHashMismatch { step_idx: 0, .. })
            ),
            "got {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn unknown_subsystems_are_rejected_not_mapped_to_empty_method() {
        let proof = make_self_consistent_v1_proof(["a", "b", "c", "d", "e", "f", "g", "h"]);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid, "unknown subsystems must not verify");
        assert!(
            matches!(
                result.failure_reason,
                Some(FailureReason::StepHashMismatch { step_idx: 0, .. })
            ),
            "got {:?}",
            result.failure_reason
        );
    }

    #[test]
    fn duplicated_subsystem_is_rejected() {
        let proof = make_self_consistent_v1_proof(["eee_namespace"; NANORIX_CHAIN_STEPS]);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid, "a repeated subsystem must not verify");
        assert!(
            matches!(
                result.failure_reason,
                Some(FailureReason::StepHashMismatch { step_idx: 1, .. })
            ),
            "got {:?}",
            result.failure_reason
        );
    }

    /// The residual the new variant exists for: genuine hashes, lying label.
    /// The chain walk reproduces every hash because the inputs come from the
    /// canonical table — only the declared name is wrong, and nothing but an
    /// explicit identity check can see it.
    #[test]
    fn genuine_hashes_with_a_forged_subsystem_label_are_rejected() {
        let mut proof = make_minimal_v1_proof();
        proof["chain"][3]["subsystem"] = serde_json::json!("dire_identity");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid, "a forged step label must not verify");
        assert_eq!(result.stage_reached, 3);
        match result.failure_reason {
            Some(FailureReason::ChainStepIdentityMismatch {
                step_idx,
                ref expected_subsystem,
                ref found_subsystem,
            }) => {
                assert_eq!(step_idx, 3);
                assert_eq!(expected_subsystem, "dire_keys");
                assert_eq!(found_subsystem, "dire_identity");
            }
            other => panic!("expected ChainStepIdentityMismatch, got {other:?}"),
        }
    }

    #[test]
    fn empty_sets_without_root_still_verify() {
        // A pre-the receipt pipeline proof carries neither key; an empty array anchors
        // nothing and claims nothing, so neither may become a rejection.
        let mut proof = make_minimal_v1_proof();
        proof["parent_proof_hashes"] = serde_json::json!([]);
        proof["record_receipts"] = serde_json::json!([]);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "empty sets must verify; got {result:?}");
    }

    #[test]
    fn missing_subsystem_field_is_rejected() {
        let mut proof = make_minimal_v1_proof();
        proof["chain"][0]
            .as_object_mut()
            .unwrap()
            .remove("subsystem");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid, "an unlabelled step must not verify");
        assert!(
            matches!(
                result.failure_reason,
                Some(FailureReason::ChainStepIdentityMismatch { step_idx: 0, .. })
            ),
            "got {:?}",
            result.failure_reason
        );
    }

    // ── customer_only, the consistency gate, the signer metadata ────

    const CUSTOMER: &str = "us-customer-kms-acme-v1";

    /// Re-sign `proof`'s canonical view with `key` after its labels changed.
    fn resign(proof: &mut serde_json::Value, key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer as _;
        let canonical = crate::canonical_recompute::recompute_canonical_hash(proof);
        proof["attestation"]["signature"] =
            serde_json::json!(base64_encode(&key.sign(canonical.as_bytes()).to_bytes()));
    }

    /// A chain-valid signed proof carrying `mode` and `authority` (`None`
    /// removes `authority_id`), signed by `key` over its own canonical view.
    fn signed_with_labels(
        key: &ed25519_dalek::SigningKey,
        version: &str,
        mode: &str,
        authority: Option<&str>,
    ) -> serde_json::Value {
        let embedded = base64_encode(&key.verifying_key().to_bytes());
        let mut proof = make_signed_v21_proof(key, &embedded, "1");
        proof["cdp_version"] = serde_json::json!(version);
        proof["signing_mode"] = serde_json::json!(mode);
        match authority {
            Some(a) => proof["authority_id"] = serde_json::json!(a),
            None => {
                proof.as_object_mut().unwrap().remove("authority_id");
            }
        }
        resign(&mut proof, key);
        proof
    }

    /// A signed key list trusting `key` under `(authority, version)`.
    fn key_list_for(
        authority: &str,
        key: &ed25519_dalek::SigningKey,
        version: &str,
    ) -> (crate::trust_chain::TrustChainManifest, String) {
        let identity = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let mut authorities = std::collections::HashMap::new();
        authorities.insert(
            authority.to_string(),
            crate::trust_chain::AuthorityRecord {
                display_name: "Test customer KMS".to_string(),
                active_versions: vec![crate::trust_chain::KeyVersionRecord {
                    signing_key_version: version.to_string(),
                    public_key_b64: base64_encode(&key.verifying_key().to_bytes()),
                    public_key_fingerprint: "sha256:test".to_string(),
                    effective_from: "2026-01-01T00:00:00Z".to_string(),
                    archived_at: None,
                    algorithm: None,
                    pqc_partner_version: None,
                }],
                archived_versions: vec![],
                revoked: false,
                emits_population_heads: false,
            },
        );
        let manifest = crate::trust_chain::TrustChainManifest::build_and_sign(
            "1",
            "2026-10-01T00:00:00Z",
            authorities,
            &identity,
        );
        let pin = manifest.identity_fingerprint.clone();
        (manifest, pin)
    }

    #[test]
    fn customer_only_recomputes_the_canonical_hash_on_2_1_and_2_2() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        for version in ["2.1", "2.2"] {
            let proof = signed_with_labels(&key, version, "customer_only", Some(CUSTOMER));
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert!(result.valid, "{version}: got {result:?}");
            assert_eq!(result.stage_reached, 7, "{version}");
            assert_eq!(result.metadata.authority_id.as_deref(), Some(CUSTOMER));
            assert_eq!(result.metadata.authority_signed, Some(true));
            assert_eq!(
                result.metadata.signing_mode.as_deref(),
                Some("customer_only")
            );
            assert_eq!(result.metadata.trust_chain_identity_fingerprint, None);
        }
    }

    #[test]
    fn customer_only_reaches_stage_8_against_the_customer_key_list() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let proof = signed_with_labels(&key, "2.1", "customer_only", Some(CUSTOMER));
        let (list, pin) = key_list_for(CUSTOMER, &key, "1");
        let result = verify_auditproof(&proof, &[], &policy_with(list, pin.clone()));
        assert!(result.valid, "got {result:?}");
        assert_eq!(result.stage_reached, 8);
        assert_eq!(
            result.metadata.trust_chain_identity_fingerprint.as_deref(),
            Some(pin.as_str())
        );
        assert_eq!(
            result.metadata.trust_chain_issued_at.as_deref(),
            Some("2026-10-01T00:00:00Z")
        );
    }

    #[test]
    fn customer_only_with_its_mode_edited_fails_the_signature() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let mut proof = signed_with_labels(&key, "2.1", "customer_only", Some(CUSTOMER));
        proof["signing_mode"] = serde_json::json!("nanorix_only");
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 7);
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::SignatureMismatch {
                reason: SignatureFailureReason::DoesNotVerify
            })
        );
    }

    #[test]
    fn customer_only_under_a_nanorix_authority_is_refused() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let cases: [Option<&str>; 8] = [
            Some(NANORIX),
            None,
            Some("us-Customer-kms-acme-v1"),
            Some("us-Customer-KMS-acme-v1"),
            Some("us-customerkms-acme-v1"),
            Some("us-customer-kms"),
            Some("customer-"),
            Some("us-customer_kms-acme-v1"),
        ];
        for version in ["2.1", "2.2"] {
            for authority in cases {
                let proof = signed_with_labels(&key, version, "customer_only", authority);
                let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
                assert!(!result.valid, "{version} {authority:?}: got {result:?}");
                assert_eq!(result.stage_reached, 4, "{version} {authority:?}");
                assert_eq!(
                    result.failure_reason,
                    Some(FailureReason::SigningModeAuthorityMismatch {
                        claimed_authority_id: authority.map(String::from),
                    }),
                    "{version} {authority:?}"
                );
            }
        }
        // A null or non-string authority_id is Nanorix-classified and is
        // reported as no claimed authority.
        for value in [serde_json::Value::Null, serde_json::json!(7)] {
            let mut proof = signed_with_labels(&key, "2.1", "customer_only", Some(NANORIX));
            proof["authority_id"] = value.clone();
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert_eq!(
                result.failure_reason,
                Some(FailureReason::SigningModeAuthorityMismatch {
                    claimed_authority_id: None,
                }),
                "{value}"
            );
        }
        // The algorithm check runs first (corpus vector 5).
        let mut other_algorithm = signed_with_labels(&key, "2.1", "customer_only", Some(NANORIX));
        other_algorithm["attestation"]["algorithm"] = serde_json::json!("ML-DSA-65");
        let result = verify_auditproof(&other_algorithm, &[], &VerifierPolicy::default());
        assert_eq!(
            result.failure_reason,
            Some(FailureReason::AlgorithmUnsupported {
                found: "ML-DSA-65".into()
            })
        );
        // An unsigned proof carrying the contradiction is refused as well,
        // never "chain verified, signature not checked".
        let mut unsigned = signed_with_labels(&key, "2.1", "customer_only", Some(NANORIX));
        unsigned.as_object_mut().unwrap().remove("attestation");
        let result = verify_auditproof(&unsigned, &[], &VerifierPolicy::default());
        assert!(!result.valid, "got {result:?}");
        assert!(matches!(
            result.failure_reason,
            Some(FailureReason::SigningModeAuthorityMismatch { .. })
        ));
    }

    #[test]
    fn every_customer_segment_passes_the_gate_anywhere_in_the_id() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        for segment in CUSTOMER_AUTHORITY_SEGMENTS {
            for authority in [
                format!("{segment}acme-v2"),
                format!("eu-{segment}acme-v2"),
                format!("eu-west-1-acme-{segment}v2"),
            ] {
                assert!(is_customer_authority(&authority), "{authority}");
                let proof = signed_with_labels(&key, "2.1", "customer_only", Some(&authority));
                let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
                assert!(result.valid, "{authority}: got {result:?}");
                assert_eq!(result.status(), "not_anchored", "{authority}");
            }
        }
        for not_customer in [
            "us-Customer-KMS-acme-v1",
            "us-customer-KMS-acme-v1",
            "us-customer-kms",
            "us-customerkms-acme-v1",
            "",
            NANORIX,
        ] {
            assert!(!is_customer_authority(not_customer), "{not_customer}");
        }
    }

    #[test]
    fn legacy_nanorix_only_under_a_customer_authority_still_verifies() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        for version in ["2.1", "2.2"] {
            let proof = signed_with_labels(&key, version, "nanorix_only", Some(CUSTOMER));
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert!(result.valid, "{version}: got {result:?}");
            assert_eq!(result.stage_reached, 7);
            assert_eq!(
                result.metadata.signing_mode.as_deref(),
                Some("nanorix_only")
            );
            assert_eq!(result.metadata.authority_id.as_deref(), Some(CUSTOMER));
        }
    }

    #[test]
    fn modes_other_than_the_two_exact_values_are_still_refused() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        for mode in [
            "Customer_Only",
            "CUSTOMER_ONLY",
            "customer_onlyx",
            "customer_only ",
            "customer",
            "customer-only",
            "customer_dual",
            "dual_signature",
            "tee_attested",
            "",
        ] {
            let proof = signed_with_labels(&key, "2.1", mode, Some(CUSTOMER));
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert!(!result.valid, "{mode:?}: got {result:?}");
            assert_eq!(result.stage_reached, 4, "{mode:?}");
            assert_eq!(
                result.failure_reason,
                Some(FailureReason::AlgorithmUnsupported {
                    found: format!("signing_mode={mode}")
                }),
                "{mode:?}"
            );
        }
    }

    #[test]
    fn signer_metadata_marks_v1_0_labels_as_not_signed() {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let sign_v1 = |proof: &mut serde_json::Value| {
            let message = proof["final_hash"]
                .as_str()
                .unwrap()
                .trim_start_matches("sha512:")
                .to_string();
            proof["attestation"] = serde_json::json!({
                "public_key": base64_encode(&key.verifying_key().to_bytes()),
                "signature": base64_encode(&key.sign(message.as_bytes()).to_bytes()),
            });
        };
        let mut proof = make_minimal_v1_proof();
        sign_v1(&mut proof);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "got {result:?}");
        assert_eq!(result.stage_reached, 7, "got {result:?}");
        assert_eq!(result.metadata.authority_id, None);
        assert_eq!(result.metadata.authority_signed, Some(false));
        assert_eq!(result.metadata.signing_mode, None);

        // v1.0 signs final_hash only, so a mode label there is not gated.
        let mut labelled = make_minimal_v1_proof();
        labelled["signing_mode"] = serde_json::json!("customer_only");
        sign_v1(&mut labelled);
        let result = verify_auditproof(&labelled, &[], &VerifierPolicy::default());
        assert!(result.valid, "got {result:?}");
        assert_eq!(result.metadata.authority_signed, Some(false));
        assert_eq!(
            result.metadata.signing_mode.as_deref(),
            Some("customer_only")
        );
    }

    #[test]
    fn absent_labels_are_reported_absent_not_as_the_default() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let mut proof = signed_with_labels(&key, "2.1", "nanorix_only", None);
        proof.as_object_mut().unwrap().remove("signing_mode");
        resign(&mut proof, &key);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "got {result:?}");
        assert_eq!(result.stage_reached, 7);
        assert_eq!(result.metadata.signing_mode, None);
        assert_eq!(result.metadata.authority_id, None);
        assert_eq!(result.metadata.authority_signed, Some(true));
        let wire = serde_json::to_value(&result.metadata).unwrap();
        assert!(wire.get("authority_id").is_none(), "{wire}");
        assert!(wire.get("signing_mode").is_none(), "{wire}");
        assert_eq!(wire["authority_signed"], serde_json::json!(true));

        proof["authority_id"] = serde_json::json!(7);
        resign(&mut proof, &key);
        let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(result.valid, "got {result:?}");
        assert_eq!(result.metadata.authority_id, None);
        assert_eq!(result.metadata.authority_signed, Some(true));
    }

    #[test]
    fn authority_signed_is_absent_when_no_signature_verified() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let signed = signed_with_labels(&key, "2.1", "customer_only", Some(CUSTOMER));

        let mut unsigned = signed.clone();
        unsigned.as_object_mut().unwrap().remove("attestation");
        let result = verify_auditproof(&unsigned, &[], &VerifierPolicy::default());
        assert!(result.valid, "got {result:?}");
        assert_eq!(result.stage_reached, 4);
        assert_eq!(result.metadata.authority_signed, None);
        let wire = serde_json::to_value(&result.metadata).unwrap();
        assert!(wire.get("authority_signed").is_none(), "{wire}");
        assert_eq!(result.metadata.authority_id.as_deref(), Some(CUSTOMER));

        let mut tampered = signed.clone();
        tampered["jurisdiction"] = serde_json::json!("eu");
        let result = verify_auditproof(&tampered, &[], &VerifierPolicy::default());
        assert!(!result.valid);
        assert_eq!(result.stage_reached, 7);
        assert_eq!(result.metadata.authority_signed, None);

        let mut mismatch = signed;
        mismatch["authority_id"] = serde_json::json!(NANORIX);
        resign(&mut mismatch, &key);
        let result = verify_auditproof(&mismatch, &[], &VerifierPolicy::default());
        assert_eq!(result.stage_reached, 4);
        assert_eq!(result.metadata.authority_signed, None);
    }
}
