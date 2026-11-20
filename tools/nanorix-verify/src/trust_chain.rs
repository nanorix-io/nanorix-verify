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
//! Provides the data model, key lookup, manifest-signature verification, and
//! an assemble-and-sign helper for a party running its own trust root. This
//! crate has no HTTP client: a manifest is supplied as a file via
//! `--trust-chain`, and the identity fingerprint is pinned with
//! `--identity-fingerprint`.

use crate::ed25519_strict::VerifyCanonicalStrict;
use crate::mldsa::{verify_ml_dsa, MlDsaParameterSet};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Full trust-chain manifest, fetched from
/// `https://nanorix.io/.well-known/trust-chain.json` or loaded from a local
/// file via `--trust-chain`.
///
/// Forever-stable schema — once published, fields are
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

    /// The post-quantum list signature. On a BYOC list it is ML-DSA-87, pure, empty context, over
    /// [`KEY_LIST_PQC_TAG`], a 0x00 byte and [`Self::signed_payload`]: see
    /// [`Self::pqc_signed_message`]. The specification names SLH-DSA-SHA2-256s for the
    /// hosted root, which no verifier reads yet. Absent from a classical list,
    /// so its bytes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_manifest_signature: Option<String>,

    /// The post-quantum identity key's algorithm, `ML-DSA-87` on a BYOC list.
    /// Signed by both list signatures. Absent from
    /// a classical list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_identity_algorithm: Option<String>,

    /// The post-quantum identity public key, the raw 2592-byte ML-DSA-87
    /// encoding in standard padded base64 (an optional `base64:` prefix is
    /// read and dropped). With the Ed25519 identity key it makes the hybrid
    /// pin ([`hybrid_pin`]). Absent from a classical list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_identity_public_key_b64: Option<String>,
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

    /// True when this authority emits the population heads. Absent means
    /// it does not, and a manifest with no marked authority keeps its signed
    /// bytes. A verifier that predates this field drops it from the signed
    /// payload, so it refuses a manifest that sets it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub emits_population_heads: bool,
}

/// One key version's record. Schema is identical for active and archived
/// entries; the only difference is which list they live in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyVersionRecord {
    /// Wire-stable version identifier, matching the `signing_key_version`
    /// field in AuditProof attestations. A population read (check
    /// (f)) takes only the decimal text of an integer from 1 to 2^63 - 1, such
    /// as `"7"`, and refuses the whole list for any other text, `"v7"` among
    /// them (Appendix A.3).
    pub signing_key_version: String,

    /// The public key in standard padded base64, of the length its
    /// `algorithm` names. An optional `base64:` prefix is read and dropped.
    pub public_key_b64: String,

    /// SHA-256 fingerprint over the public key bytes, hex-encoded with
    /// `sha256:` prefix prefix discipline.
    pub public_key_fingerprint: String,

    /// When this key first became valid for signing. RFC 3339 UTC.
    pub effective_from: String,

    /// When this key was archived (moved out of `active_versions`). RFC 3339
    /// UTC. None for currently-active keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,

    /// Signature algorithm for this key version. Absent means `"Ed25519"`
    /// (every earlier key). Added BEFORE first public
    /// manifest publication so the forever-stable schema carries algorithm
    /// agility from day one; hybrid-era key versions will name their PQC
    /// algorithm here (e.g., `"ML-DSA-65"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,

    /// On an Ed25519 record of a BYOC list, the `signing_key_version` of its
    /// ML-DSA-65 partner, a record of the same authority.
    /// Under a hybrid pin every Ed25519 record must name one. Absent
    /// everywhere else, so a classical list keeps its bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_partner_version: Option<String>,
}

/// A manifest whose signature verified against a pinned identity fingerprint.
/// [`TrustChainManifest::into_verified`] is the only way to obtain one, so a
/// function taking this type cannot be handed an unverified key list.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedManifest(TrustChainManifest);

impl VerifiedManifest {
    /// The verified manifest.
    pub fn manifest(&self) -> &TrustChainManifest {
        &self.0
    }
}

impl KeyVersionRecord {
    /// The effective signature algorithm: the explicit `algorithm` field, or
    /// `"Ed25519"` when absent (default).
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
    /// Whether the manifest carries any key for `authority_id` at all. A
    /// hosted verifier uses this to decide whether the document can be
    /// anchored here or was signed by an authority this manifest does not
    /// speak for.
    pub fn names_authority(&self, authority_id: &str) -> bool {
        self.authorities.contains_key(authority_id)
    }

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
    /// contract before any manifest ships. The Ed25519 signature covers these
    /// bytes as they are; the ML-DSA-87 signature of a BYOC list covers them
    /// behind its tag ([`Self::pqc_signed_message`]).
    pub fn signed_payload(&self) -> Result<Vec<u8>, ManifestError> {
        let value = self.signed_value().map_err(|_| ManifestError::Malformed)?;
        serde_jcs::to_vec(&value).map_err(|_| ManifestError::Malformed)
    }

    /// The exact message the ML-DSA-87 list signature covers (
    /// Key-list row): [`KEY_LIST_PQC_TAG`], a 0x00 byte, then
    /// [`Self::signed_payload`]. Pure ML-DSA with an empty context: the tag is
    /// part of the message, never the FIPS 204 context.
    pub fn pqc_signed_message(&self) -> Result<Vec<u8>, ManifestError> {
        let payload = self.signed_payload()?;
        let mut message = Vec::with_capacity(KEY_LIST_PQC_TAG.len() + 1 + payload.len());
        message.extend_from_slice(KEY_LIST_PQC_TAG.as_bytes());
        message.push(0);
        message.extend_from_slice(&payload);
        Ok(message)
    }

    fn signed_value(&self) -> Result<Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        if let Some(obj) = value.as_object_mut() {
            for name in SIGNATURE_MEMBERS {
                obj.remove(name);
            }
        }
        Ok(value)
    }

    /// The first member of `bytes`, the text this list was parsed from, that
    /// its signature does not cover, as [`member_not_carried`] finds it. The
    /// values of `manifest_signature` and `pqc_manifest_signature` are not
    /// compared, since no signature covers them, but either name written
    /// twice is still found. The result means something only for a list that
    /// verified, as one reached through [`VerifiedManifest::manifest`].
    pub fn member_not_signed(
        &self,
        bytes: &[u8],
    ) -> Result<Option<MemberNotCarried>, serde_json::Error> {
        let mut written: Written = serde_json::from_slice(bytes)?;
        if let Written::Object(members) = &mut written {
            if let Some(name) = first_repeat(members) {
                let mut path = String::new();
                push_pointer_token(&mut path, name);
                return Ok(Some(MemberNotCarried::Repeated(path)));
            }
            members.retain(|(name, _)| !SIGNATURE_MEMBERS.contains(&name.as_str()));
        }
        Ok(first_not_carried(
            &written,
            &self.signed_value()?,
            &mut String::new(),
        ))
    }

    /// Verify the key list against `pinned_fingerprint`, the pin the relying
    /// party obtained apart from the list. The pin's form chooses the check.
    ///
    /// A `hybrid1-sha256:` pin runs the whole hybrid
    /// check here, so every caller of this function runs it: the pin
    /// recomputed from both inline identity keys, both list signatures, the
    /// partner and role rules, and the authority id rules. Any other pin runs
    /// the classical check below, and then the authority id rules and the
    /// refusal of post-quantum identity members, which a list that loads under
    /// a classical pin must not carry.
    pub fn verify_signature(&self, pinned_fingerprint: &str) -> Result<(), ManifestError> {
        if is_hybrid_pin(pinned_fingerprint) {
            return self.verify_hybrid(pinned_fingerprint);
        }
        self.verify_classical(pinned_fingerprint)?;
        if self.pqc_identity_algorithm.is_some() || self.pqc_identity_public_key_b64.is_some() {
            return Err(ManifestError::PqcIdentityUnderClassicalPin);
        }
        check_authority_ids(self, None)
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
    fn verify_classical(&self, pinned_fingerprint: &str) -> Result<(), ManifestError> {
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
            .verify_canonical_strict(&payload, &signature)
            .map_err(|_| ManifestError::SignatureInvalid)
    }

    /// The hybrid check (H4.8's list side, H5's
    /// Key-list row, H7.2): both identity keys decoded strictly, the pin
    /// recomputed from them and required to equal both the list's
    /// `identity_fingerprint` and the given pin, the Ed25519 signature over
    /// the payload, the ML-DSA-87 signature over the tagged payload, then the
    /// record policy and the authority id rules.
    fn verify_hybrid(&self, pinned: &str) -> Result<(), ManifestError> {
        let ed25519_identity: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(strip_b64(&self.identity_public_key_b64))
            .map_err(|_| ManifestError::Malformed)?
            .as_slice()
            .try_into()
            .map_err(|_| ManifestError::Malformed)?;
        let verifying_key =
            VerifyingKey::from_bytes(&ed25519_identity).map_err(|_| ManifestError::Malformed)?;
        match self.pqc_identity_algorithm.as_deref() {
            None => return Err(ManifestError::PqcIdentityMissing),
            Some(PQC_IDENTITY_ALGORITHM) => {}
            Some(other) => {
                return Err(ManifestError::PqcAlgorithmUnsupported {
                    found: other.to_string(),
                })
            }
        }
        let mldsa_identity = decode_canonical(
            self.pqc_identity_public_key_b64
                .as_deref()
                .ok_or(ManifestError::PqcIdentityMissing)?,
            "pqc_identity_public_key_b64",
        )?;
        if mldsa_identity.len() != MlDsaParameterSet::MlDsa87.public_key_len() {
            return Err(ManifestError::Malformed);
        }

        let computed = hybrid_pin(&ed25519_identity, &mldsa_identity);
        if computed != self.identity_fingerprint || computed != pinned {
            return Err(ManifestError::FingerprintMismatch {
                pinned: pinned.to_string(),
                computed,
            });
        }

        let sig_array: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(strip_b64(&self.manifest_signature))
            .map_err(|_| ManifestError::SignatureInvalid)?
            .as_slice()
            .try_into()
            .map_err(|_| ManifestError::SignatureInvalid)?;
        verifying_key
            .verify_canonical_strict(&self.signed_payload()?, &Signature::from_bytes(&sig_array))
            .map_err(|_| ManifestError::SignatureInvalid)?;

        let pqc_signature = decode_canonical(
            self.pqc_manifest_signature
                .as_deref()
                .ok_or(ManifestError::PqcSignatureMissing)?,
            "pqc_manifest_signature",
        )?;
        verify_ml_dsa(
            MlDsaParameterSet::MlDsa87,
            &mldsa_identity,
            &self.pqc_signed_message()?,
            &pqc_signature,
        )
        .map_err(|_| ManifestError::PqcSignatureInvalid)?;

        check_hybrid_records(self, &[&ed25519_identity[..], &mldsa_identity[..]])?;
        check_authority_ids(self, Some(&computed[HYBRID_PIN_PREFIX.len()..]))
    }

    /// The ML-DSA-65 partner of an Ed25519 key version:
    /// the record its `pqc_partner_version` names, in the same
    /// authority. `None` when the version is not on the list, names no
    /// partner, or names one that is not an ML-DSA-65 record.
    ///
    /// The answer means something only for a list verified under a hybrid
    /// pin, where [`Self::verify_signature`] has applied the partner rules.
    pub fn hybrid_partner(
        &self,
        authority_id: &str,
        ed25519_version: &str,
    ) -> Option<PartnerRecord<'_>> {
        let ed25519 = self.find_key(authority_id, ed25519_version)?;
        if !is_ed25519(ed25519.record) {
            return None;
        }
        let version = ed25519.record.pqc_partner_version.as_deref()?;
        let partner = self.find_key(authority_id, version)?;
        (partner.record.algorithm.as_deref() == Some(ML_DSA_65)).then_some(PartnerRecord {
            version: &partner.record.signing_key_version,
            record: partner.record,
        })
    }

    /// Build a BYOC key list with both identity keys and no signatures, for a
    /// signer to sign out of process ([`Self::signed_payload`] for Ed25519,
    /// [`Self::pqc_signed_message`] for ML-DSA-87) and [`Self::attach`] to
    /// complete. Its `identity_fingerprint` is the hybrid pin.
    pub fn build_unsigned_hybrid(
        schema_version: &str,
        issued_at: &str,
        authorities: HashMap<String, AuthorityRecord>,
        ed25519_identity: &[u8; 32],
        mldsa87_identity: &[u8],
    ) -> TrustChainManifest {
        let engine = base64::engine::general_purpose::STANDARD;
        TrustChainManifest {
            schema_version: schema_version.to_string(),
            issued_at: issued_at.to_string(),
            authorities,
            identity_fingerprint: hybrid_pin(ed25519_identity, mldsa87_identity),
            identity_public_key_b64: engine.encode(ed25519_identity),
            manifest_signature: String::new(),
            pqc_manifest_signature: None,
            pqc_identity_algorithm: Some(PQC_IDENTITY_ALGORITHM.to_string()),
            pqc_identity_public_key_b64: Some(engine.encode(mldsa87_identity)),
        }
    }

    /// Attach both list signatures to a list from
    /// [`Self::build_unsigned_hybrid`], then verify the result under its own
    /// hybrid pin. A signature over any other bytes, or a list that breaks a
    /// rule, is refused and nothing is returned.
    pub fn attach(
        mut self,
        ed25519_signature: &[u8; 64],
        mldsa87_signature: &[u8],
    ) -> Result<VerifiedManifest, ManifestError> {
        let engine = base64::engine::general_purpose::STANDARD;
        self.manifest_signature = format!("base64:{}", engine.encode(ed25519_signature));
        self.pqc_manifest_signature = Some(format!("base64:{}", engine.encode(mldsa87_signature)));
        let pin = self.identity_fingerprint.clone();
        if !is_hybrid_pin(&pin) {
            return Err(ManifestError::PqcIdentityMissing);
        }
        self.into_verified(&pin)
    }

    /// [`Self::verify_signature`], keeping the manifest as proof of the check.
    pub fn into_verified(
        self,
        pinned_fingerprint: &str,
    ) -> Result<VerifiedManifest, ManifestError> {
        self.verify_signature(pinned_fingerprint)?;
        Ok(VerifiedManifest(self))
    }

    /// Assemble and sign a manifest with a long-term identity key.
    ///
    /// A verifier does not need this; it is here so that a party running its
    /// own trust root can produce a manifest this verifier will accept, given
    /// the corresponding `--identity-fingerprint`. Whatever holds the key,
    /// the signed payload is whatever `signed_payload()` returns.
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
            pqc_identity_algorithm: None,
            pqc_identity_public_key_b64: None,
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

/// The members a key list's signature leaves out of its signed payload.
const SIGNATURE_MEMBERS: [&str; 2] = ["manifest_signature", "pqc_manifest_signature"];

/// The prefix of a hybrid identity pin. A pin with
/// this prefix selects the hybrid check, and every consumer that cannot yet
/// check its object's hybrid half refuses under it.
pub const HYBRID_PIN_PREFIX: &str = "hybrid1-sha256:";

/// The domain tag in front of the ML-DSA-87 list signature's message
/// (Key-list row).
pub const KEY_LIST_PQC_TAG: &str = "nanorix-key-list-pqc-v1";

/// The first field of the hybrid pin's pre-image.
const IDENTITY_HYBRID_DOMAIN: &str = "nanorix-identity-hybrid-v1";

/// The post-quantum identity algorithm a BYOC list carries.
/// It is the only one this build accepts.
pub const PQC_IDENTITY_ALGORITHM: &str = "ML-DSA-87";

/// The per-record post-quantum algorithm.
const ML_DSA_65: &str = "ML-DSA-65";

/// True when `pin` is of the hybrid kind, read from the pin string alone.
pub fn is_hybrid_pin(pin: &str) -> bool {
    pin.starts_with(HYBRID_PIN_PREFIX)
}

/// The hybrid pin of an identity: `hybrid1-sha256:`
/// and the lowercase hex SHA-256 of `nanorix-identity-hybrid-v1` 0x00
/// `Ed25519` 0x00 <32 key bytes> 0x00 `ML-DSA-87` 0x00 <2592 key bytes>.
pub fn hybrid_pin(ed25519_identity: &[u8; 32], mldsa87_identity: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_HYBRID_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(b"Ed25519");
    hasher.update([0]);
    hasher.update(ed25519_identity);
    hasher.update([0]);
    hasher.update(PQC_IDENTITY_ALGORITHM.as_bytes());
    hasher.update([0]);
    hasher.update(mldsa87_identity);
    format!("{HYBRID_PIN_PREFIX}{}", hex::encode(hasher.finalize()))
}

/// The ML-DSA-65 partner of an Ed25519 key version, as
/// [`TrustChainManifest::hybrid_partner`] finds it.
#[derive(Debug, Clone, Copy)]
pub struct PartnerRecord<'a> {
    /// The partner's `signing_key_version`. A record's ML-DSA-65 key id is
    /// `nrx-pqc-v` followed by this text.
    pub version: &'a str,
    /// The partner's record, its ML-DSA-65 key in `public_key_b64`.
    pub record: &'a KeyVersionRecord,
}

/// Compare two key lists from one identity, both verified.
/// Every record of `earlier` must appear in `later` under the
/// same authority and version, with the same algorithm and the same decoded
/// key bytes, and every partner `earlier` names must be named again with the
/// same decoded key bytes. Any difference refuses both lists.
pub fn compare_partners(
    earlier: &VerifiedManifest,
    later: &VerifiedManifest,
) -> Result<(), ManifestError> {
    let (earlier, later) = (earlier.manifest(), later.manifest());
    let mut ids: Vec<&String> = earlier.authorities.keys().collect();
    ids.sort();
    for id in ids {
        let authority = &earlier.authorities[id];
        for record in authority
            .active_versions
            .iter()
            .chain(&authority.archived_versions)
        {
            let version = &record.signing_key_version;
            let changed = || ManifestError::PartnerChanged {
                authority_id: id.clone(),
                version: version.clone(),
            };
            let now = later.find_key(id, version).ok_or_else(changed)?;
            if now.record.algorithm_or_default() != record.algorithm_or_default()
                || record_key(record) != record_key(now.record)
            {
                return Err(changed());
            }
            if record.pqc_partner_version.is_some() {
                let then_partner = earlier.hybrid_partner(id, version).ok_or_else(changed)?;
                let now_partner = later.hybrid_partner(id, version).ok_or_else(changed)?;
                if record_key(then_partner.record) != record_key(now_partner.record) {
                    return Err(changed());
                }
            }
        }
    }
    Ok(())
}

fn record_key(record: &KeyVersionRecord) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(strip_b64(&record.public_key_b64))
        .ok()
}

fn is_ed25519(record: &KeyVersionRecord) -> bool {
    record.algorithm_or_default() == "Ed25519"
}

/// Decode canonical standard padded base64 after an optional `base64:`
/// prefix. The engine refuses missing padding and set trailing bits.
fn decode_canonical(text: &str, member: &str) -> Result<Vec<u8>, ManifestError> {
    base64::engine::general_purpose::STANDARD
        .decode(strip_b64(text))
        .map_err(|_| ManifestError::NonCanonicalEncoding {
            member: member.to_string(),
        })
}

/// A version's integer value as digits without leading zeros, when its text
/// is decimal digits only, so `"1"` and `"01"` read as one version at any
/// length.
fn version_number(version: &str) -> Option<&str> {
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(version.trim_start_matches('0'))
}

/// The record rules under a hybrid pin,
/// applied to each authority in byte order of its id
/// and to its active records before its archived ones:
/// - each label is absent, `Ed25519` or `ML-DSA-65`;
/// - each key is canonical base64 of its label's length, and its
///   `public_key_fingerprint` is the SHA-256 of the decoded key;
/// - no authority holds one version twice, as text or as an integer;
/// - every Ed25519 record names a partner that is an ML-DSA-65 record of the
///   same authority, no two name one partner, and no ML-DSA-65 record names
///   one;
/// - no decoded key appears twice anywhere on the list, the identity keys
///   included (`identity_keys`).
fn check_hybrid_records(
    manifest: &TrustChainManifest,
    identity_keys: &[&[u8]],
) -> Result<(), ManifestError> {
    let mut seen_keys: HashSet<Vec<u8>> = identity_keys.iter().map(|k| k.to_vec()).collect();
    let mut ids: Vec<&String> = manifest.authorities.keys().collect();
    ids.sort();
    for id in ids {
        let authority = &manifest.authorities[id];
        let records: Vec<&KeyVersionRecord> = authority
            .active_versions
            .iter()
            .chain(&authority.archived_versions)
            .collect();
        let mut texts = HashSet::new();
        let mut numbers = HashSet::new();
        let mut algorithms: HashMap<&str, &str> = HashMap::new();
        for record in &records {
            let version = &record.signing_key_version;
            let at = |make: fn(String, String) -> ManifestError| make(id.clone(), version.clone());
            let length = match record.algorithm.as_deref() {
                None | Some("Ed25519") => 32,
                Some(ML_DSA_65) => MlDsaParameterSet::MlDsa65.public_key_len(),
                Some(found) => {
                    return Err(ManifestError::KeyLabelUnknown {
                        authority_id: id.clone(),
                        version: version.clone(),
                        found: found.to_string(),
                    })
                }
            };
            let key = decode_canonical(&record.public_key_b64, "public_key_b64")?;
            if key.len() != length {
                return Err(at(|authority_id, version| ManifestError::RecordKeyLength {
                    authority_id,
                    version,
                }));
            }
            if record.public_key_fingerprint
                != format!("sha256:{}", hex::encode(Sha256::digest(&key)))
            {
                return Err(at(|authority_id, version| {
                    ManifestError::FingerprintNotOfKey {
                        authority_id,
                        version,
                    }
                }));
            }
            let repeated = !texts.insert(version.as_str())
                || version_number(version).is_some_and(|n| !numbers.insert(n));
            if repeated {
                return Err(at(|authority_id, version| ManifestError::VersionRepeated {
                    authority_id,
                    version,
                }));
            }
            if !seen_keys.insert(key) {
                return Err(at(|authority_id, version| ManifestError::KeyInTwoRoles {
                    authority_id,
                    version,
                }));
            }
            algorithms.insert(version.as_str(), record.algorithm_or_default());
        }
        let mut partners = HashSet::new();
        for record in &records {
            let version = &record.signing_key_version;
            let partner = record.pqc_partner_version.as_deref();
            if !is_ed25519(record) {
                if let Some(partner) = partner {
                    return Err(ManifestError::PartnerInvalid {
                        authority_id: id.clone(),
                        version: version.clone(),
                        partner: partner.to_string(),
                    });
                }
                continue;
            }
            let partner = partner.ok_or_else(|| ManifestError::PartnerMissing {
                authority_id: id.clone(),
                version: version.clone(),
            })?;
            if algorithms.get(partner) != Some(&ML_DSA_65) {
                return Err(ManifestError::PartnerInvalid {
                    authority_id: id.clone(),
                    version: version.clone(),
                    partner: partner.to_string(),
                });
            }
            if !partners.insert(partner) {
                return Err(ManifestError::PartnerShared {
                    authority_id: id.clone(),
                    partner: partner.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// The authority id rules of the specification, list side, applied to
/// each id in byte order: under a hybrid pin the id alphabet; then for an id
/// containing `hybrid1` the exact form `<base>-hybrid1.<p>-v<n>`; then the
/// pin's kind. `hybrid_pin_hex` is the 64 hex digits of the hybrid pin the
/// list verified under, or `None` under a classical pin.
///
/// Under a classical pin the alphabet is not checked here: population check
/// (f) refuses an id outside it with its own typed reason (the specification's
/// vectors), and this build leaves that refusal there.
fn check_authority_ids(
    manifest: &TrustChainManifest,
    hybrid_pin_hex: Option<&str>,
) -> Result<(), ManifestError> {
    let mut ids: Vec<&String> = manifest.authorities.keys().collect();
    ids.sort();
    for id in ids {
        let authority_id = id.clone();
        if hybrid_pin_hex.is_some() && !crate::population_head::is_head_identifier(id) {
            return Err(ManifestError::AuthorityIdMalformed { authority_id });
        }
        let byoc = id.contains("hybrid1");
        let carried = if byoc {
            Some(
                byoc_pin_hex(id).ok_or(ManifestError::ByocAuthorityIdMalformed {
                    authority_id: authority_id.clone(),
                })?,
            )
        } else {
            None
        };
        match (hybrid_pin_hex, carried) {
            (None, Some(_)) => {
                return Err(ManifestError::ByocAuthorityNeedsHybridPin { authority_id })
            }
            (Some(pin), carried) if carried != Some(pin) => {
                return Err(ManifestError::ByocAuthorityPinMismatch { authority_id })
            }
            _ => {}
        }
    }
    Ok(())
}

/// The pin hex an authority id of BYOC form carries, when the id is exactly
/// `<base>-hybrid1.<p>-v<n>`: `<base>` non-empty and free of `hybrid1`, `<p>`
/// 64 lowercase hex digits, `<n>` a decimal from 1 with no leading zero, and
/// `hybrid1` exactly once.
fn byoc_pin_hex(id: &str) -> Option<&str> {
    if id.matches("hybrid1").count() != 1 {
        return None;
    }
    let (base, rest) = id.split_once("-hybrid1.")?;
    if base.is_empty() || rest.len() < 64 + 3 || !rest.is_char_boundary(64) {
        return None;
    }
    let (hex_part, suffix) = rest.split_at(64);
    let number = suffix.strip_prefix("-v")?;
    let hex_ok = hex_part
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let number_ok = !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
        && !number.starts_with('0');
    (hex_ok && number_ok).then_some(hex_part)
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
    /// Under a hybrid pin, the list lacks `pqc_identity_algorithm` or
    /// `pqc_identity_public_key_b64`.
    #[error("the key list carries no post-quantum identity key, which a hybrid pin requires")]
    PqcIdentityMissing,
    /// Under a hybrid pin, the identity algorithm is not `ML-DSA-87`.
    #[error("post-quantum identity algorithm {found:?} is not supported (ML-DSA-87 is)")]
    PqcAlgorithmUnsupported { found: String },
    /// Under a hybrid pin, the list has no `pqc_manifest_signature`.
    #[error("the key list carries no post-quantum signature, which a hybrid pin requires")]
    PqcSignatureMissing,
    /// Under a hybrid pin, the ML-DSA-87 list signature does not verify.
    #[error("the key list's ML-DSA-87 signature did not verify against its identity key")]
    PqcSignatureInvalid,
    /// A member that must be canonical standard padded base64 is not.
    #[error("key list member {member} is not canonical standard padded base64")]
    NonCanonicalEncoding { member: String },
    /// Under a hybrid pin, a record names an algorithm outside `Ed25519` and
    /// `ML-DSA-65`.
    #[error("authority {authority_id} version {version} names algorithm {found:?}, which a hybrid list cannot carry")]
    KeyLabelUnknown {
        authority_id: String,
        version: String,
        found: String,
    },
    /// Under a hybrid pin, a record's key is not its algorithm's length.
    #[error("authority {authority_id} version {version} carries a key of the wrong length for its algorithm")]
    RecordKeyLength {
        authority_id: String,
        version: String,
    },
    /// Under a hybrid pin, an authority holds one version twice, as text or
    /// as an integer.
    #[error("authority {authority_id} holds version {version} more than once")]
    VersionRepeated {
        authority_id: String,
        version: String,
    },
    /// Under a hybrid pin, a record's `public_key_fingerprint` is not the
    /// SHA-256 of its key.
    #[error("authority {authority_id} version {version}: public_key_fingerprint is not the SHA-256 of the key")]
    FingerprintNotOfKey {
        authority_id: String,
        version: String,
    },
    /// Under a hybrid pin, an Ed25519 record names no partner.
    #[error("authority {authority_id} Ed25519 version {version} names no ML-DSA-65 partner")]
    PartnerMissing {
        authority_id: String,
        version: String,
    },
    /// Under a hybrid pin, a named partner is not an ML-DSA-65 record of the
    /// same authority, or an ML-DSA-65 record names a partner of its own.
    #[error("authority {authority_id} version {version}: partner {partner:?} is not an ML-DSA-65 record of the same authority")]
    PartnerInvalid {
        authority_id: String,
        version: String,
        partner: String,
    },
    /// Under a hybrid pin, two Ed25519 versions name one partner.
    #[error("authority {authority_id}: two Ed25519 versions name the partner {partner}")]
    PartnerShared {
        authority_id: String,
        partner: String,
    },
    /// Under a hybrid pin, one decoded public key appears twice: as two
    /// records, or as a record and an identity key.
    #[error(
        "one public key appears twice on the key list (authority {authority_id} version {version})"
    )]
    KeyInTwoRoles {
        authority_id: String,
        version: String,
    },
    /// Two lists from one identity disagree on a version's key or partner, or
    /// the later one drops a version.
    #[error("two key lists disagree on authority {authority_id} version {version}")]
    PartnerChanged {
        authority_id: String,
        version: String,
    },
    /// Under a classical pin, the list carries post-quantum identity members.
    #[error("the key list carries a post-quantum identity, so it needs its install's hybrid1-sha256: pin, not a sha256: pin")]
    PqcIdentityUnderClassicalPin,
    /// An authority id outside 1 to 128 bytes of `a`-`z`, `0`-`9`, `.`, `_`
    /// and `-`.
    #[error("authority id {authority_id:?} is outside the authority id alphabet")]
    AuthorityIdMalformed { authority_id: String },
    /// An authority id that contains `hybrid1` but is not exactly
    /// `<base>-hybrid1.<p>-v<n>`.
    #[error(
        "authority id {authority_id:?} contains hybrid1 but is not <base>-hybrid1.<pin hex>-v<n>"
    )]
    ByocAuthorityIdMalformed { authority_id: String },
    /// Under a classical pin, an authority id of BYOC form.
    #[error(
        "authority id {authority_id:?} is a BYOC id, so it needs its install's hybrid1-sha256: pin"
    )]
    ByocAuthorityNeedsHybridPin { authority_id: String },
    /// Under a hybrid pin, an authority id not of BYOC form, or one carrying
    /// another pin.
    #[error("authority id {authority_id:?} does not carry the given hybrid pin")]
    ByocAuthorityPinMismatch { authority_id: String },
}

impl ManifestError {
    /// The refusal's name in the shared vectors, the same in every verifier.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::FingerprintMismatch { .. } => "fingerprint_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::PqcIdentityMissing => "pqc_identity_missing",
            Self::PqcAlgorithmUnsupported { .. } => "pqc_algorithm_unsupported",
            Self::PqcSignatureMissing => "pqc_signature_missing",
            Self::PqcSignatureInvalid => "pqc_signature_invalid",
            Self::NonCanonicalEncoding { .. } => "non_canonical_encoding",
            Self::KeyLabelUnknown { .. } => "key_label_unknown",
            Self::RecordKeyLength { .. } => "record_key_length",
            Self::VersionRepeated { .. } => "version_repeated",
            Self::FingerprintNotOfKey { .. } => "fingerprint_not_of_key",
            Self::PartnerMissing { .. } => "partner_missing",
            Self::PartnerInvalid { .. } => "partner_invalid",
            Self::PartnerShared { .. } => "partner_shared",
            Self::KeyInTwoRoles { .. } => "key_in_two_roles",
            Self::PartnerChanged { .. } => "partner_changed",
            Self::PqcIdentityUnderClassicalPin => "pqc_identity_under_classical_pin",
            Self::AuthorityIdMalformed { .. } => "authority_id_malformed",
            Self::ByocAuthorityIdMalformed { .. } => "byoc_authority_id_malformed",
            Self::ByocAuthorityNeedsHybridPin { .. } => "byoc_authority_needs_hybrid_pin",
            Self::ByocAuthorityPinMismatch { .. } => "byoc_authority_pin_mismatch",
        }
    }
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

/// A member of a JSON text that a value parsed from it does not carry, as
/// [`member_not_carried`] finds it. Each path is an RFC 6901 JSON Pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberNotCarried {
    /// One object holds this member name more than once. A parser keeps one
    /// copy, so no check reads the others and no signature covers them.
    Repeated(String),
    /// The parsed value does not hold this member, or holds another value.
    NotCarried(String),
}

impl fmt::Display for MemberNotCarried {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemberNotCarried::Repeated(path) => write!(f, "member {path:?} is written twice"),
            MemberNotCarried::NotCarried(path) => {
                write!(f, "member {path:?} is not covered by the signature")
            }
        }
    }
}

/// A JSON value as written: every object member in text order, repeats kept.
enum Written {
    Scalar(Value),
    Array(Vec<Written>),
    Object(Vec<(String, Written)>),
}

impl<'de> Deserialize<'de> for Written {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct WrittenVisitor;
        impl<'de> Visitor<'de> for WrittenVisitor {
            type Value = Written;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Written, E> {
                Ok(Written::Scalar(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Written, E> {
                Ok(Written::Scalar(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Written, E> {
                Ok(Written::Scalar(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Written, E> {
                Ok(Written::Scalar(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Written, E> {
                Ok(Written::Scalar(Value::from(v)))
            }
            fn visit_unit<E>(self) -> Result<Written, E> {
                Ok(Written::Scalar(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Written, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Written::Array(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Written, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry()? {
                    members.push(member);
                }
                Ok(Written::Object(members))
            }
        }
        deserializer.deserialize_any(WrittenVisitor)
    }
}

/// The first member of the JSON text `bytes` that `parsed`, a value parsed
/// from it and serialized again, does not carry with the same value. Objects
/// are read depth first in text order, and a repeated name in an object is
/// found before any of its members is read. Members `parsed` holds that the
/// text leaves out, such as a default, are not looked for.
///
/// A key list's signature covers its parsed form, so a member this finds in
/// a key list that verified is covered by no signature.
pub fn member_not_carried(
    bytes: &[u8],
    parsed: &Value,
) -> Result<Option<MemberNotCarried>, serde_json::Error> {
    let written: Written = serde_json::from_slice(bytes)?;
    Ok(first_not_carried(&written, parsed, &mut String::new()))
}

/// The first member name the JSON text `bytes` writes twice in one object,
/// as an RFC 6901 JSON Pointer, read in the order [`member_not_carried`]
/// reads. A parser keeps one copy of such a member, so no check reads the
/// others.
pub fn repeated_member(bytes: &[u8]) -> Result<Option<String>, serde_json::Error> {
    let written: Written = serde_json::from_slice(bytes)?;
    Ok(first_repeated(&written, &mut String::new()))
}

fn first_repeated(written: &Written, path: &mut String) -> Option<String> {
    let start = path.len();
    match written {
        Written::Scalar(_) => None,
        Written::Array(items) => items.iter().enumerate().find_map(|(index, item)| {
            path.truncate(start);
            path.push_str(&format!("/{index}"));
            first_repeated(item, path)
        }),
        Written::Object(members) => {
            if let Some(name) = first_repeat(members) {
                push_pointer_token(path, name);
                return Some(path.clone());
            }
            members.iter().find_map(|(name, value)| {
                path.truncate(start);
                push_pointer_token(path, name);
                first_repeated(value, path)
            })
        }
    }
}

/// The first name in `members` that an earlier member already carries.
fn first_repeat(members: &[(String, Written)]) -> Option<&str> {
    let mut names = HashSet::new();
    members
        .iter()
        .find(|(name, _)| !names.insert(name))
        .map(|(name, _)| name.as_str())
}

fn first_not_carried(
    written: &Written,
    parsed: &Value,
    path: &mut String,
) -> Option<MemberNotCarried> {
    let start = path.len();
    match (written, parsed) {
        (Written::Object(members), Value::Object(carried)) => {
            if let Some(name) = first_repeat(members) {
                push_pointer_token(path, name);
                return Some(MemberNotCarried::Repeated(path.clone()));
            }
            for (name, value) in members {
                push_pointer_token(path, name);
                let found = match carried.get(name) {
                    Some(carried) => first_not_carried(value, carried, path),
                    None => Some(MemberNotCarried::NotCarried(path.clone())),
                };
                if found.is_some() {
                    return found;
                }
                path.truncate(start);
            }
            None
        }
        (Written::Array(items), Value::Array(carried)) if items.len() == carried.len() => {
            for (index, (item, carried)) in items.iter().zip(carried).enumerate() {
                path.push_str(&format!("/{index}"));
                let found = first_not_carried(item, carried, path);
                if found.is_some() {
                    return found;
                }
                path.truncate(start);
            }
            None
        }
        (Written::Scalar(value), carried) if value == carried => None,
        _ => Some(MemberNotCarried::NotCarried(path.clone())),
    }
}

fn push_pointer_token(path: &mut String, name: &str) {
    path.push('/');
    path.push_str(&name.replace('~', "~0").replace('/', "~1"));
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
                    pqc_partner_version: None,
                }],
                archived_versions: vec![
                    KeyVersionRecord {
                        signing_key_version: "6".to_string(),
                        public_key_b64: "AAAA_archived_v6".to_string(),
                        public_key_fingerprint: "sha256:archived6".to_string(),
                        effective_from: "2025-10-01T00:00:00Z".to_string(),
                        archived_at: Some("2026-04-01T00:00:00Z".to_string()),
                        algorithm: None,
                        pqc_partner_version: None,
                    },
                    KeyVersionRecord {
                        signing_key_version: "5".to_string(),
                        public_key_b64: "AAAA_archived_v5".to_string(),
                        public_key_fingerprint: "sha256:archived5".to_string(),
                        effective_from: "2025-04-01T00:00:00Z".to_string(),
                        archived_at: Some("2025-10-01T00:00:00Z".to_string()),
                        algorithm: None,
                        pqc_partner_version: None,
                    },
                ],
                revoked: false,
                emits_population_heads: false,
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
                    pqc_partner_version: None,
                }],
                archived_versions: vec![],
                revoked: false,
                emits_population_heads: false,
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
            pqc_identity_algorithm: None,
            pqc_identity_public_key_b64: None,
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
    fn a_member_not_carried_is_found_depth_first_in_text_order() {
        let parsed = serde_json::json!({"a": [{"x": 1}, {"y": [true]}], "b": "s"});
        let found = |text: &str| member_not_carried(text.as_bytes(), &parsed).unwrap();
        assert_eq!(found(r#"{"b": "s", "a": [{"x": 1}, {"y": [true]}]}"#), None);
        assert_eq!(
            found(r#"{"a": [{"x": 1}]}"#),
            Some(MemberNotCarried::NotCarried("/a".into()))
        );
        assert_eq!(
            found(r#"{"a": [{"x": 1, "x": 1}, {"y": [true]}], "c": 0}"#),
            Some(MemberNotCarried::Repeated("/a/0/x".into()))
        );
        assert_eq!(
            found(r#"{"c": 0, "b": "s", "b": "s"}"#),
            Some(MemberNotCarried::Repeated("/b".into()))
        );
        assert_eq!(
            found(r#"{"a": [{"x": 1}, {"y": [false]}], "c": 0}"#),
            Some(MemberNotCarried::NotCarried("/a/1/y/0".into()))
        );
        assert_eq!(
            found(r#"{"b": "s", "a/~": null}"#),
            Some(MemberNotCarried::NotCarried("/a~1~0".into()))
        );
    }

    #[test]
    fn a_repeated_member_is_found_depth_first_in_text_order() {
        let found = |text: &str| repeated_member(text.as_bytes()).unwrap();
        assert_eq!(found(r#"[{"a": {"x": 1}}, {"b": [true]}]"#), None);
        assert_eq!(found(r#"{"y": 0, "x": 1}"#), None);
        assert_eq!(
            found(r#"[{"a": {"b": 1}}, {"c": 1, "c": 2}]"#),
            Some("/1/c".into())
        );
        assert_eq!(
            found(r#"[{"b": [{"x": 1, "x": 1}], "c": 0, "c": 0}]"#),
            Some("/0/c".into())
        );
        assert_eq!(
            found(r#"[[], [{"z": [], "z": []}]]"#),
            Some("/1/0/z".into())
        );
        assert_eq!(
            found(r#"{"a": {"b": 1}, "c": {"d": 0, "d": 1}}"#),
            Some("/c/d".into())
        );
        assert_eq!(
            found(r#"{"a/~": {"y": 0, "y": 1}}"#),
            Some("/a~1~0/y".into())
        );
    }

    #[test]
    fn member_not_signed_compares_every_member_but_the_signature_values() {
        let (manifest, _, _) = signed_manifest([3u8; 32]);
        let text = serde_json::to_string(&manifest).unwrap();
        let found = |text: String| manifest.member_not_signed(text.as_bytes()).unwrap();
        assert_eq!(found(text.clone()), None);
        assert_eq!(
            found(text.replacen('{', r#"{"pqc_manifest_signature":null,"#, 1)),
            None
        );
        assert_eq!(
            found(text.replacen('{', r#"{"manifest_signature":"base64:AAAA","#, 1)),
            Some(MemberNotCarried::Repeated("/manifest_signature".into()))
        );
        assert_eq!(
            found(text.replacen('{', r#"{"issued_at":null,"#, 1)),
            Some(MemberNotCarried::Repeated("/issued_at".into()))
        );
        assert_eq!(
            found(text.replacen('{', r#"{"note":"x","#, 1)),
            Some(MemberNotCarried::NotCarried("/note".into()))
        );
    }

    #[test]
    fn a_field_written_twice_does_not_load_but_an_authority_keeps_its_last_copy() {
        let (manifest, _, _) = signed_manifest([3u8; 32]);
        let text = serde_json::to_string(&manifest).unwrap();
        let marker = text.replacen(
            r#""display_name""#,
            r#""emits_population_heads":false,"emits_population_heads":false,"display_name""#,
            1,
        );
        assert_ne!(marker, text);
        let error = serde_json::from_str::<TrustChainManifest>(&marker).unwrap_err();
        assert!(error.to_string().contains("duplicate field"), "{error}");
        let authority = text.replacen(
            r#""us-kms-nanorix-v1":{"#,
            r#""us-kms-nanorix-v1":{"display_name":"first","active_versions":[]},"us-kms-nanorix-v1":{"#,
            1,
        );
        assert_ne!(authority, text);
        let loaded: TrustChainManifest = serde_json::from_str(&authority).unwrap();
        assert_eq!(loaded, manifest);
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
                    pqc_partner_version: None,
                }],
                archived_versions: vec![],
                revoked: false,
                emits_population_heads: false,
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

    // ── the specification: algorithm agility + reserved PQC dual-signature ────

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
        // Additive-evolution insurance: future manifest fields
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
