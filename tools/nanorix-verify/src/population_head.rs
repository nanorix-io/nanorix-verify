//! Population head chain: canonical encoding, signed message and the
//! offline checks (a), (b), (c) and (f).
//!
//! A head names one proof by its leaf and links to the head
//! before it, one chain per signing authority. The head is a sibling
//! primitive: nothing here reads or changes the AuditProof's
//! canonical view.
//!
//! ## Encoding
//!
//! ```text
//! canonical_bytes = JCS(head)                      RFC 8785, the verifier's serde_jcs
//! head_hash       = "sha512:" ‖ hex(SHA-512(canonical_bytes))
//! signed_message  = "nanorix-population-head-v1:" ‖ hex(SHA-512(canonical_bytes))
//! genesis link    = "sha512:" ‖ hex(SHA-512(""))   carried by the head at sequence 1
//! ```
//!
//! A version 2 head has the same members and `head_hash`. Its
//! Ed25519 message starts `nanorix-population-head-v2:` in place of the
//! version 1 tag, still 155 bytes, and its ML-DSA-65 half signs
//!
//! ```text
//! pqc_signed_message = "nanorix-population-head-pqc-v2" ‖ 0x00 ‖ signed_message
//! ```
//!
//! pure ML-DSA with an empty context, under the partner of the head's Ed25519
//! key version. Under a hybrid pin (f) refuses a
//! version 1 head; under a classical pin it refuses a version 2 head.
//!
//! `head_hash` is the next head's `prev_head_hash` and the commitment
//! the population-head appendix names. The signed message is 155 ASCII bytes and holds a
//! `:` and letters outside hex, while every proof signature target (v1.0
//! `final_hash`, v2.1 and v2.2 `canonical_hash`) and every BoundaryAttestation
//! target is exactly 128 lowercase hex characters. Under strict Ed25519 a
//! signature binds one message, so a head signature never verifies as a proof
//! signature and a proof signature never verifies as a head signature. The
//! caller applies the tag, so the proof signer signs the string unchanged.
//!
//! ## Checks
//!
//! (a), (b), (c) and (f) run here. (d) and (e) read a transparency log and
//! always report `not_checked` with the reason "needs a transparency log",
//! and every result carries the label "population not externally
//! witnessed" (population-head appendix). A proof no head names is listed as unwitnessed
//! and never fails, and its reason rests on what it verified to, because its
//! own fields can be edited with no key. A head that names a proof signed by
//! the local signer or under an authority the key list does not mark as
//! emitting heads fails (f).
//!
//! (f) reads the key list under a closed record grammar before anything else
//! ([`refused_key_record`]). A list holding any record outside it fails (f)
//! whatever the heads, and gives no proof the reason `local_signer` or
//! `unmarked_authority`.

use std::collections::{BTreeSet, HashMap, HashSet};

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use crate::canonical_recompute::recompute_canonical_hash;
use crate::checkpoint::{self, Digest64};
use crate::ed25519_strict::VerifyCanonicalStrict;
use crate::mldsa::{verify_ml_dsa, MlDsaError, MlDsaParameterSet};
use crate::trust_chain::{
    KeyLookupResult, KeyStatus, KeyVersionRecord, TrustChainManifest, VerifiedManifest,
};
use crate::{
    effective_authority_id, resolve_chain_timestamp, strip_base64_prefix, verify_auditproof,
    SignatureFailureReason, VerificationResult, VerifierPolicy, CANONICAL_VIEW_SIGNED_VERSIONS,
    NANORIX_GENESIS_HASH,
};

pub use nanorix_verify_types::population_head::*;

/// `signing_key_version` of the local signer, which emits no heads.
pub const LOCAL_SIGNER_KEY_VERSION: &str = "local-ephemeral";

/// The stage a proof reaches on its chain and embedded-key signature alone.
const INTEGRITY_STAGE: u8 = 7;

/// The stage a proof reaches under the key list.
const ANCHORED_STAGE: u8 = 8;

/// The genesis link the head at sequence 1 carries: `sha512:` plus the
/// `SHA-512("")` constant the destruction chain starts from.
pub fn genesis_prev_head_hash() -> String {
    format!("sha512:{NANORIX_GENESIS_HASH}")
}

/// The head's RFC 8785 canonical bytes. `None` only if serialization fails,
/// which a head of strings and an integer does not do.
pub fn canonical_bytes(head: &PopulationHead) -> Option<Vec<u8>> {
    serde_jcs::to_vec(head).ok()
}

fn head_digest(head: &PopulationHead) -> Option<Digest64> {
    canonical_bytes(head).map(|b| Sha512::digest(&b).into())
}

/// `sha512:` plus the hex SHA-512 of the head's canonical bytes: the value
/// the next head carries as `prev_head_hash`.
pub fn head_hash(head: &PopulationHead) -> Option<String> {
    head_digest(head).map(|d| format!("sha512:{}", checkpoint::hex(&d)))
}

/// The UTF-8 string a head's Ed25519 signature covers: the head's type
/// (`nanorix-population-head-v1` or `nanorix-population-head-v2`), a `:`, then
/// the hex SHA-512 of the canonical bytes. `None` for a head of any other
/// type, whose tag this format does not know.
pub fn signed_message(head: &PopulationHead) -> Option<String> {
    let tag = match head.head_type.as_str() {
        POPULATION_HEAD_TYPE_V1 => POPULATION_HEAD_TYPE_V1,
        POPULATION_HEAD_TYPE_V2 => POPULATION_HEAD_TYPE_V2,
        _ => return None,
    };
    head_digest(head).map(|d| format!("{tag}:{}", checkpoint::hex(&d)))
}

/// The bytes a version 2 head's ML-DSA-65 half signs:
/// [`POPULATION_HEAD_PQC_TAG_V2`], a 0x00 byte, then [`signed_message`].
/// `None` for a head of any other type.
pub fn pqc_signed_message(head: &PopulationHead) -> Option<Vec<u8>> {
    if head.head_type != POPULATION_HEAD_TYPE_V2 {
        return None;
    }
    let message = signed_message(head)?;
    let mut out = Vec::with_capacity(POPULATION_HEAD_PQC_TAG_V2.len() + 1 + message.len());
    out.extend_from_slice(POPULATION_HEAD_PQC_TAG_V2.as_bytes());
    out.push(0x00);
    out.extend_from_slice(message.as_bytes());
    Some(out)
}

/// The `tip_proof_hash` a head names this proof by: `sha512:` plus the hex
/// Leaf. `None` when the proof has no leaf: a head may name only
/// a leaf a transparency log can hold, so it follows the log's own reader,
/// `checkpoint::leaf_inputs_from_proof`.
pub fn tip_proof_hash(proof: &Value) -> Option<String> {
    let leaf = checkpoint::leaf_inputs_from_proof(proof).ok()?.leaf_hash();
    Some(format!("sha512:{}", checkpoint::hex(&leaf)))
}

/// Verify one authority's population from the proofs and signed heads an
/// auditor was handed.
///
/// `manifest` is the published key list, verified against its pinned identity
/// fingerprint. Without it, (f) checks what it can without keys and reports
/// `not_checked`, and only the local signer is known to emit no heads.
pub fn verify_population(
    proofs: &[Value],
    heads: &[Value],
    manifest: Option<&VerifiedManifest>,
) -> PopulationResult {
    let manifest = manifest.map(VerifiedManifest::manifest);
    let key_list = match manifest.map(KeyIndex::read) {
        None => KeyList::Absent,
        Some(Ok(index)) => KeyList::Read(index),
        Some(Err(reason)) => KeyList::Refused(reason),
    };
    // A verified manifest's own fingerprint is the pin it was checked against
    // (`TrustChainManifest::verify_signature` requires both to match).
    let anchor_policy = key_list.index().map(|index| VerifierPolicy {
        trust_chain: Some(index.manifest.clone()),
        pinned_identity_fingerprint: Some(index.manifest.identity_fingerprint.clone()),
        ..Default::default()
    });
    let facts: Vec<ProofFacts> = proofs
        .iter()
        .map(|p| ProofFacts::of(p, anchor_policy.as_ref()))
        .collect();

    let mut parsed = Vec::with_capacity(heads.len());
    let mut malformed = None;
    for (index, value) in heads.iter().enumerate() {
        match parse_head(index, value) {
            Ok(head) => parsed.push(head),
            Err(reason) => {
                malformed.get_or_insert(reason);
            }
        }
    }
    parsed.sort_by_key(|h| (h.sequence(), h.index));
    let mut merged = HashSet::new();
    let distinct: Vec<&ParsedHead> = parsed
        .iter()
        .filter(|h| merged.insert((h.hash.as_str(), h.signed.signing_key_version.as_str())))
        .collect();
    let by_leaf = proofs_by_leaf(&facts);

    let log = || PopulationCheck::NotChecked {
        reason: NotCheckedReason::NeedsTransparencyLog,
    };
    let not_checked = |reason| PopulationCheck::NotChecked { reason };
    // A refused list fails (f) whatever the heads, so no head shape hides it.
    let refused = match &key_list {
        KeyList::Refused(reason) => Some(failed(reason.clone())),
        _ => None,
    };
    let checks = if heads.is_empty() {
        PopulationChecks {
            a_chain_links: not_checked(NotCheckedReason::NoHeadsHanded),
            b_sequence_contiguous: not_checked(NotCheckedReason::NoHeadsHanded),
            c_tips_match_proofs: not_checked(NotCheckedReason::NoHeadsHanded),
            d_log_inclusion: log(),
            e_log_population: log(),
            f_head_signatures: refused
                .unwrap_or_else(|| not_checked(NotCheckedReason::NoHeadsHanded)),
        }
    } else if let Some(reason) = malformed {
        PopulationChecks {
            a_chain_links: PopulationCheck::Failed { reason },
            b_sequence_contiguous: not_checked(NotCheckedReason::HeadsMalformed),
            c_tips_match_proofs: not_checked(NotCheckedReason::HeadsMalformed),
            d_log_inclusion: log(),
            e_log_population: log(),
            f_head_signatures: refused
                .unwrap_or_else(|| not_checked(NotCheckedReason::HeadsMalformed)),
        }
    } else {
        PopulationChecks {
            a_chain_links: check_links(&distinct),
            b_sequence_contiguous: check_sequence(&distinct),
            c_tips_match_proofs: check_tips(&distinct, &facts, &by_leaf),
            d_log_inclusion: log(),
            e_log_population: log(),
            f_head_signatures: refused.unwrap_or_else(|| {
                hybrid_gate(manifest, &parsed).unwrap_or_else(|| {
                    check_signatures(&parsed, &facts, &by_leaf, key_list.index())
                })
            }),
        }
    };

    let named: HashSet<&str> = parsed.iter().map(|h| h.tip()).collect();
    let unwitnessed_proofs = facts
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.leaf.as_deref().is_some_and(|l| named.contains(l)))
        .map(|(proof_index, f)| UnwitnessedProof {
            proof_index,
            tip_proof_hash: f.leaf.clone(),
            reason: f.unwitnessed_reason(&key_list),
        })
        .collect();

    PopulationResult {
        verdict: if checks.any_failed() {
            PopulationVerdict::Failed
        } else {
            PopulationVerdict::NotExternallyWitnessed
        },
        honesty_label: Some(HonestyLabel::PopulationNotExternallyWitnessed),
        checks,
        authority_id: parsed.first().map(|h| h.signed.head.authority_id.clone()),
        head_count: heads.len(),
        proof_count: proofs.len(),
        first_sequence: parsed.first().map(ParsedHead::sequence),
        last_sequence: parsed.last().map(ParsedHead::sequence),
        unwitnessed_proofs,
        key_list: manifest.map(|m| KeyListRead {
            issued_at: m.issued_at.clone(),
            identity_fingerprint: m.identity_fingerprint.clone(),
        }),
    }
}

/// The pin gate: a key list verified under a hybrid pin takes only version 2
/// heads, both halves checked in [`check_signatures`], and one verified under
/// a classical pin takes only version 1 heads, because its partner members
/// are not checked. The first head of the other type is refused. The list's
/// `identity_fingerprint` is the pin it verified under
/// (`TrustChainManifest::verify_signature` requires both to match).
fn hybrid_gate(
    manifest: Option<&TrustChainManifest>,
    parsed: &[ParsedHead],
) -> Option<PopulationCheck> {
    let manifest = manifest?;
    let (refused_type, found) = if crate::trust_chain::is_hybrid_pin(&manifest.identity_fingerprint)
    {
        (POPULATION_HEAD_TYPE_V1, HYBRID_HEAD_CHECK_MISSING)
    } else {
        (POPULATION_HEAD_TYPE_V2, VERSION_2_HEAD_UNDER_CLASSICAL_PIN)
    };
    let head = parsed
        .iter()
        .find(|h| h.signed.head.head_type == refused_type)?;
    Some(failed(PopulationFailureReason::HeadAlgorithmUnsupported {
        proof_sequence: head.sequence(),
        found: found.to_string(),
    }))
}

/// The `found` text of the refusal a version 1 head gets under a hybrid pin.
/// The shared vectors fix it.
pub const HYBRID_HEAD_CHECK_MISSING: &str = "Ed25519 (hybrid pin)";

/// The `found` text of the refusal a version 2 head gets under a classical
/// pin.
pub const VERSION_2_HEAD_UNDER_CLASSICAL_PIN: &str = "nanorix-population-head-v2 (classical pin)";

/// True when a verification ended valid at `stage` or later.
fn reached(result: &VerificationResult, stage: u8) -> bool {
    result.valid && result.stage_reached >= stage
}

/// What the checks need from one handed proof, computed once.
struct ProofFacts {
    leaf: Option<String>,
    authority: String,
    /// The top-level field. A proof verifier prefers a copy inside the
    /// attestation, which no signature covers on any version.
    key_version: String,
    /// The embedded key, read as the proof verifier reads it.
    public_key: Option<Vec<u8>>,
    /// The destruction time the proof's chain hashes.
    destroyed_at: String,
    cdp_version: Option<String>,
    /// The message the proof's signature covers, the recomputed
    /// `canonical_hash`, on the versions that sign one; otherwise the leaf.
    /// Two proofs with one identity are one document, even when their leaves
    /// differ in fields the signature does not cover.
    identity: Option<String>,
    /// Chain and embedded-key signature, no key list.
    integrity: VerificationResult,
    /// Under the key list, when one was supplied.
    anchored: Option<VerificationResult>,
}

impl ProofFacts {
    fn of(proof: &Value, anchor_policy: Option<&VerifierPolicy>) -> Self {
        let integrity = verify_auditproof(proof, &[], &VerifierPolicy::default());
        let leaf = tip_proof_hash(proof);
        let cdp_version = integrity.metadata.cdp_version.clone();
        ProofFacts {
            identity: if signs_its_authority(cdp_version.as_deref()) {
                Some(recompute_canonical_hash(proof))
            } else {
                leaf.clone()
            },
            leaf,
            authority: effective_authority_id(proof).to_string(),
            destroyed_at: resolve_chain_timestamp(proof).0,
            key_version: proof
                .get("signing_key_version")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            public_key: proof
                .pointer("/attestation/public_key")
                .or_else(|| proof.pointer("/attestation/verification_key"))
                .and_then(Value::as_str)
                .and_then(decode_public_key),
            cdp_version,
            anchored: anchor_policy.map(|p| verify_auditproof(proof, &[], p)),
            integrity,
        }
    }

    fn headless_signer(&self, manifest: Option<&TrustChainManifest>) -> Option<HeadlessSigner> {
        headless_signer(&self.authority, &self.key_version, manifest)
    }

    /// True when the signature covers an authority naming the local signer,
    /// as that signer writes it. A proof that keeps another authority cannot
    /// claim the local signer without a new signature that gives the name up.
    fn names_the_local_signer(&self) -> bool {
        signs_its_authority(self.cdp_version.as_deref())
            && self.authority == LOCAL_SIGNER_KEY_VERSION
    }

    /// Why no head names this proof. Only verification can say that no head
    /// was expected, so a claim the proof makes for itself reports
    /// `no_handed_head`, and so does every proof under a refused key list,
    /// which says nothing a reason could rest on.
    fn unwitnessed_reason(&self, key_list: &KeyList) -> UnwitnessedReason {
        if !reached(&self.integrity, INTEGRITY_STAGE) {
            return UnwitnessedReason::ProofNotVerified;
        }
        let index = match key_list {
            KeyList::Refused(_) => return UnwitnessedReason::NoHandedHead,
            KeyList::Read(index) => Some(index),
            KeyList::Absent => None,
        };
        let listed = self
            .public_key
            .as_ref()
            .zip(index)
            .is_some_and(|(key, index)| index.authorities_by_key.contains_key(key));
        let anchored = self
            .anchored
            .as_ref()
            .is_some_and(|result| reached(result, ANCHORED_STAGE));
        match self.headless_signer(index.map(|index| index.manifest)) {
            Some(HeadlessSigner::LocalSigner) if !listed && self.names_the_local_signer() => {
                UnwitnessedReason::LocalSigner
            }
            Some(HeadlessSigner::UnmarkedAuthority) if anchored => {
                UnwitnessedReason::UnmarkedAuthority
            }
            _ => UnwitnessedReason::NoHandedHead,
        }
    }
}

/// True for a `cdp_version` whose signature covers the proof's authority.
fn signs_its_authority(cdp_version: Option<&str>) -> bool {
    cdp_version.is_some_and(|v| CANONICAL_VIEW_SIGNED_VERSIONS.contains(&v))
}

/// The signer this pair names that the key list does not mark for heads, if
/// any. An authority the key list does not carry is not one: a head under it
/// fails on its key.
fn headless_signer(
    authority_id: &str,
    signing_key_version: &str,
    manifest: Option<&TrustChainManifest>,
) -> Option<HeadlessSigner> {
    if signing_key_version == LOCAL_SIGNER_KEY_VERSION {
        return Some(HeadlessSigner::LocalSigner);
    }
    let authority = manifest?.authorities.get(authority_id)?;
    (!authority.emits_population_heads).then_some(HeadlessSigner::UnmarkedAuthority)
}

struct ParsedHead {
    index: usize,
    signed: SignedPopulationHead,
    hash: String,
    message: String,
}

impl ParsedHead {
    fn sequence(&self) -> u64 {
        self.signed.head.proof_sequence
    }

    fn tip(&self) -> &str {
        &self.signed.head.tip_proof_hash
    }
}

fn malformed(head_index: usize, field: &str, detail: impl Into<String>) -> PopulationFailureReason {
    PopulationFailureReason::HeadMalformed {
        head_index,
        field: field.to_string(),
        detail: detail.into(),
    }
}

fn is_sha512_ref(s: &str) -> bool {
    s.strip_prefix("sha512:").is_some_and(|hex| {
        hex.len() == 128 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The alphabet of a head's `authority_id` and `signing_key_version`, and of
/// each `authority_id` in a key list (f) reads: 1 to 128 bytes of `a`-`z`,
/// `0`-`9`, `.`, `_` and `-`. Each such text has one RFC 8785 encoding and one
/// order in bytes, code points and UTF-16, and none can write control
/// characters into a verifier's output. The authority registry accepts only
/// ids inside it, so every registered id can sign a list (f) reads.
pub fn is_head_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_HEAD_AUTHORITY_ID_LEN
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// True when `s` is inside the time grammar every population read compares
/// (see [`epoch_second`]). The key-list signer runs it on each key version's
/// `effective_from` and `archived_at`, so it never signs a time (f) cannot
/// read, under which no head would be inside the key's window.
pub fn is_population_time(s: &str) -> bool {
    epoch_second(s).is_some()
}

/// A head's `issued_at`: the time grammar with no fraction.
fn is_utc_second(s: &str) -> bool {
    s.len() == 20 && epoch_second(s).is_some()
}

/// Longest fraction of a second the time grammar reads: nanoseconds.
const MAX_FRACTION_DIGITS: usize = 9;

/// Seconds since the epoch, any fraction dropped, of a time in the grammar
/// every population read compares (Appendix A.3, "Times"):
/// `YYYY-MM-DDTHH:MM:SS`, then an optional `.` and 1 to 9 digits, then `Z`.
/// Upper case `T` and `Z` only, no offset, no space, a real date from year
/// 0001, and seconds from 00 to 59. Anything else is `None`, so a check
/// comparing it fails closed.
fn epoch_second(s: &str) -> Option<i64> {
    let body = s.strip_suffix('Z')?;
    let (base, fraction) = match body.split_once('.') {
        Some((base, fraction)) => (base, Some(fraction)),
        None => (body, None),
    };
    if let Some(fraction) = fraction {
        if fraction.is_empty()
            || fraction.len() > MAX_FRACTION_DIGITS
            || !fraction.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
    }
    let b = base.as_bytes();
    let shape = b.len() == 19
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        });
    // chrono reads second 60 on any date and year 0000; the grammar does not.
    if !shape || &base[17..19] > "59" || &base[..4] == "0000" {
        return None;
    }
    chrono::NaiveDateTime::parse_from_str(base, "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|t| t.and_utc().timestamp())
}

/// The first field that breaks the head format, as its dotted path and what
/// the format expects. An emitter runs this before signing, so it cannot sign
/// a head a verifier refuses.
pub fn validate_head(
    head: &PopulationHead,
    signing_key_version: &str,
) -> Result<(), (&'static str, String)> {
    let identifier =
        || format!("expected 1 to {MAX_HEAD_AUTHORITY_ID_LEN} of a-z, 0-9, ., _ and -");
    if head.head_type != POPULATION_HEAD_TYPE_V1 && head.head_type != POPULATION_HEAD_TYPE_V2 {
        return Err((
            "head.type",
            format!("expected {POPULATION_HEAD_TYPE_V1} or {POPULATION_HEAD_TYPE_V2}"),
        ));
    }
    if !is_head_identifier(&head.authority_id) {
        return Err(("head.authority_id", identifier()));
    }
    if head.proof_sequence == 0 || head.proof_sequence > MAX_PROOF_SEQUENCE {
        return Err((
            "head.proof_sequence",
            "expected an integer from 1 to 2^53 - 1".to_string(),
        ));
    }
    for (field, value) in [
        ("head.prev_head_hash", &head.prev_head_hash),
        ("head.tip_proof_hash", &head.tip_proof_hash),
    ] {
        if !is_sha512_ref(value) {
            return Err((field, "expected sha512: + 128 lowercase hex".to_string()));
        }
    }
    if !is_utc_second(&head.issued_at) {
        return Err((
            "head.issued_at",
            "expected YYYY-MM-DDTHH:MM:SSZ".to_string(),
        ));
    }
    if !is_head_identifier(signing_key_version) {
        return Err(("signing_key_version", identifier()));
    }
    Ok(())
}

/// The ML-DSA-65 members of a head's carrier: both present on a version 2
/// head, `pqc_signing_key_version` in the head identifier alphabet and
/// `pqc_signature` written `base64:`, and both absent on a version 1 head.
fn validate_carrier(signed: &SignedPopulationHead) -> Result<(), (&'static str, String)> {
    let version_2 = signed.head.head_type == POPULATION_HEAD_TYPE_V2;
    let members = [
        ("pqc_signing_key_version", &signed.pqc_signing_key_version),
        ("pqc_signature", &signed.pqc_signature),
    ];
    for (field, value) in members {
        if value.is_some() != version_2 {
            let expected = if version_2 {
                format!("required on a {POPULATION_HEAD_TYPE_V2} head")
            } else {
                format!("absent on a {POPULATION_HEAD_TYPE_V1} head")
            };
            return Err((field, expected));
        }
    }
    if let Some(version) = &signed.pqc_signing_key_version {
        if !is_head_identifier(version) {
            return Err((
                "pqc_signing_key_version",
                format!("expected 1 to {MAX_HEAD_AUTHORITY_ID_LEN} of a-z, 0-9, ., _ and -"),
            ));
        }
    }
    if signed
        .pqc_signature
        .as_deref()
        .is_some_and(|s| !s.starts_with("base64:"))
    {
        return Err((
            "pqc_signature",
            "expected base64: + 3309 signature bytes".to_string(),
        ));
    }
    Ok(())
}

fn parse_head(index: usize, value: &Value) -> Result<ParsedHead, PopulationFailureReason> {
    // The carrier reads `null` as absent, so a version 1 head would carry a
    // member its signature does not cover.
    for member in ["pqc_signing_key_version", "pqc_signature"] {
        if value.get(member).is_some_and(Value::is_null) {
            return Err(malformed(
                index,
                member,
                "expected a value; an absent member is left out, never null",
            ));
        }
    }
    let signed: SignedPopulationHead =
        serde_json::from_value(value.clone()).map_err(|e| malformed(index, "", e.to_string()))?;
    let head = &signed.head;
    validate_head(head, &signed.signing_key_version)
        .map_err(|(field, detail)| malformed(index, field, detail))?;
    if !signed.signature.starts_with("base64:") {
        return Err(malformed(
            index,
            "signature",
            "expected base64: + 64 signature bytes",
        ));
    }
    validate_carrier(&signed).map_err(|(field, detail)| malformed(index, field, detail))?;
    let (Some(hash), Some(message)) = (head_hash(head), signed_message(head)) else {
        return Err(malformed(index, "head", "has no canonical encoding"));
    };
    Ok(ParsedHead {
        index,
        signed,
        hash,
        message,
    })
}

fn failed(reason: PopulationFailureReason) -> PopulationCheck {
    PopulationCheck::Failed { reason }
}

/// (a) Every handed head after the first links to a head at the greatest
/// lower handed sequence; the head at sequence 1 links to genesis, and no
/// other head does.
fn check_links(parsed: &[&ParsedHead]) -> PopulationCheck {
    let genesis = genesis_prev_head_hash();
    let first_sequence = parsed[0].sequence();
    let by_sequence: HashSet<(u64, &str)> = parsed
        .iter()
        .map(|p| (p.sequence(), p.hash.as_str()))
        .collect();
    for h in parsed {
        let sequence = h.sequence();
        let prev = &h.signed.head.prev_head_hash;
        if sequence == 1 {
            if *prev != genesis {
                return failed(PopulationFailureReason::PrevHeadHashMismatch {
                    proof_sequence: sequence,
                    expected: genesis,
                    found: prev.clone(),
                });
            }
            continue;
        }
        if *prev == genesis {
            return failed(PopulationFailureReason::GenesisMisplaced {
                proof_sequence: sequence,
            });
        }
        if sequence == first_sequence {
            continue;
        }
        let before = parsed[parsed.partition_point(|p| p.sequence() < sequence) - 1];
        if !by_sequence.contains(&(before.sequence(), prev.as_str())) {
            return failed(PopulationFailureReason::PrevHeadHashMismatch {
                proof_sequence: sequence,
                expected: before.hash.clone(),
                found: prev.clone(),
            });
        }
    }
    PopulationCheck::Ok
}

/// (b) Sequences run 1, 2, 3, ... with no gap and no repeat, and no head was
/// issued before the head below it. `issued_at` has one fixed-width UTC form,
/// so it sorts as text; two heads may share a second.
fn check_sequence(parsed: &[&ParsedHead]) -> PopulationCheck {
    let mut expected = 1u64;
    let mut last: Option<&ParsedHead> = None;
    for h in parsed {
        let sequence = h.sequence();
        if last.is_some_and(|previous| previous.sequence() == sequence) {
            return failed(PopulationFailureReason::DuplicateSequence {
                proof_sequence: sequence,
            });
        }
        if sequence != expected {
            return failed(PopulationFailureReason::SequenceGap {
                expected,
                found: sequence,
            });
        }
        if let Some(previous) = last {
            let (issued_at, previous_issued_at) =
                (&h.signed.head.issued_at, &previous.signed.head.issued_at);
            if issued_at < previous_issued_at {
                return failed(PopulationFailureReason::HeadIssuedBeforePrevious {
                    proof_sequence: sequence,
                    issued_at: issued_at.clone(),
                    previous_issued_at: previous_issued_at.clone(),
                });
            }
        }
        last = Some(h);
        expected = sequence + 1;
    }
    PopulationCheck::Ok
}

/// Every handed proof by leaf, each list in handed order. Copies of one proof
/// can share a leaf and still differ in fields the leaf does not cover, so
/// each copy is checked.
fn proofs_by_leaf(facts: &[ProofFacts]) -> HashMap<&str, Vec<usize>> {
    let mut by_leaf: HashMap<&str, Vec<usize>> = HashMap::new();
    for (index, fact) in facts.iter().enumerate() {
        if let Some(leaf) = &fact.leaf {
            by_leaf.entry(leaf).or_default().push(index);
        }
    }
    by_leaf
}

/// (c) Each tip is the leaf of a handed proof, every handed proof with that
/// leaf verifies with its chain and embedded-key signature and ended no later
/// than the head was issued, and no two heads name one proof, judged by what
/// the proofs' signatures cover.
fn check_tips(
    parsed: &[&ParsedHead],
    facts: &[ProofFacts],
    by_leaf: &HashMap<&str, Vec<usize>>,
) -> PopulationCheck {
    let mut seen: HashMap<&str, u64> = HashMap::new();
    for h in parsed {
        let sequence = h.sequence();
        let Some(copies) = by_leaf.get(h.tip()) else {
            return failed(PopulationFailureReason::TipMatchesNoProof {
                proof_sequence: sequence,
                tip_proof_hash: h.tip().to_string(),
            });
        };
        for &proof_index in copies {
            let integrity = &facts[proof_index].integrity;
            if !reached(integrity, INTEGRITY_STAGE) {
                return failed(PopulationFailureReason::NamedProofNotVerified {
                    proof_sequence: sequence,
                    proof_index,
                    stage_reached: integrity.stage_reached,
                    failure_reason: integrity.failure_reason.clone(),
                });
            }
        }
        let issued_at = &h.signed.head.issued_at;
        for &proof_index in copies {
            let destroyed_at = &facts[proof_index].destroyed_at;
            let issued_after = epoch_second(issued_at)
                .zip(epoch_second(destroyed_at))
                .is_some_and(|(issued, destroyed)| issued >= destroyed);
            if !issued_after {
                return failed(PopulationFailureReason::HeadIssuedBeforeProof {
                    proof_sequence: sequence,
                    proof_index,
                    issued_at: issued_at.clone(),
                    destroyed_at: destroyed_at.clone(),
                });
            }
        }
        let identities: BTreeSet<&str> = copies
            .iter()
            .filter_map(|&i| facts[i].identity.as_deref())
            .collect();
        for identity in identities {
            if let Some(first_sequence) = seen.insert(identity, sequence) {
                return failed(PopulationFailureReason::TipNamedTwice {
                    tip_proof_hash: h.tip().to_string(),
                    first_sequence,
                    second_sequence: sequence,
                });
            }
        }
    }
    PopulationCheck::Ok
}

fn decode_public_key(public_key_b64: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(strip_base64_prefix(public_key_b64))
        .ok()
}

/// Each algorithm label a key list record may carry, with its key length in
/// bytes. An absent label reads as `Ed25519`; ML-DSA-65 is the
/// per-proof algorithm. A label outside this set refuses the list, so adding a
/// label to a published list is a flag day for population verifiers.
const KEY_RECORD_LABELS: [(&str, usize); 2] = [("Ed25519", 32), ("ML-DSA-65", 1952)];

/// The record's key bytes and version, or the first field outside the record
/// grammar: a known label, a key that is that label's length in standard
/// padded base64 (after an optional `base64:`), a fingerprint that is
/// `sha256:` and the lowercase hex SHA-256 of the key, and a version that is
/// the decimal text of an integer from 1 to 2^63 - 1, as the canonical view
/// reads a proof's version. With the authority id read first, each authority,
/// key and version then has one text.
fn read_record(record: &KeyVersionRecord) -> Result<(Vec<u8>, i64), &'static str> {
    let (_, length) = KEY_RECORD_LABELS
        .iter()
        .find(|(label, _)| *label == record.algorithm_or_default())
        .ok_or("algorithm")?;
    // STANDARD decodes only canonical text: padded, with no stray bits.
    let key = base64::engine::general_purpose::STANDARD
        .decode(strip_base64_prefix(&record.public_key_b64))
        .ok()
        .filter(|key| key.len() == *length)
        .ok_or("public_key_b64")?;
    if record.public_key_fingerprint != format!("sha256:{}", hex::encode(Sha256::digest(&key))) {
        return Err("public_key_fingerprint");
    }
    let version = &record.signing_key_version;
    // The canonical view reads a version it cannot parse as 0, and the
    // registry writes versions from 1.
    let number = version
        .parse::<i64>()
        .ok()
        .filter(|n| *n >= 1 && n.to_string() == *version)
        .ok_or("signing_key_version")?;
    Ok((key, number))
}

/// One record of the key list, as [`TrustChainManifest::find_key`] returns
/// it.
struct IndexedRecord<'a> {
    lookup: KeyLookupResult<'a>,
    key: Vec<u8>,
    /// True when no other record of the authority carries this version,
    /// compared as an integer, or this key, compared as bytes. A list holding
    /// two gives that key no one window.
    sole: bool,
}

/// The key list read once, every record inside the record grammar, so each
/// head copy costs a few map reads however many records the list holds.
struct KeyIndex<'a> {
    manifest: &'a TrustChainManifest,
    /// For each authority and version text, the record `find_key` returns:
    /// the first active one, else the first archived one.
    records: HashMap<&'a str, HashMap<&'a str, IndexedRecord<'a>>>,
    /// Every key, active or archived, with the authorities that list it.
    authorities_by_key: HashMap<Vec<u8>, BTreeSet<&'a str>>,
}

impl<'a> KeyIndex<'a> {
    /// Reads authorities in byte order of `authority_id`, and for each its id,
    /// then its active records before its archived ones, each list in its
    /// order. The first id or record outside the grammar refuses the list; an
    /// authority with no records has its id read all the same.
    fn read(manifest: &'a TrustChainManifest) -> Result<Self, PopulationFailureReason> {
        let mut authorities: Vec<_> = manifest.authorities.iter().collect();
        authorities.sort_by_key(|(id, _)| id.as_str());
        let mut records: HashMap<&str, HashMap<&str, (IndexedRecord, i64)>> = HashMap::new();
        let mut per_version: HashMap<(&str, i64), usize> = HashMap::new();
        let mut per_key: HashMap<(&str, Vec<u8>), usize> = HashMap::new();
        let mut authorities_by_key: HashMap<Vec<u8>, BTreeSet<&str>> = HashMap::new();
        for (id, authority_record) in authorities {
            let id = id.as_str();
            if !is_head_identifier(id) {
                return Err(PopulationFailureReason::KeyListRecordRefused {
                    authority_id: id.to_string(),
                    signing_key_version: String::new(),
                    field: "authority_id".to_string(),
                });
            }
            let active = authority_record
                .active_versions
                .iter()
                .map(|record| (record, KeyStatus::Active));
            let archived = authority_record
                .archived_versions
                .iter()
                .map(|record| (record, KeyStatus::Archived));
            for (record, status) in active.chain(archived) {
                let (key, version) = read_record(record).map_err(|field| {
                    PopulationFailureReason::KeyListRecordRefused {
                        authority_id: id.to_string(),
                        signing_key_version: record.signing_key_version.clone(),
                        field: field.to_string(),
                    }
                })?;
                *per_version.entry((id, version)).or_default() += 1;
                *per_key.entry((id, key.clone())).or_default() += 1;
                authorities_by_key
                    .entry(key.clone())
                    .or_default()
                    .insert(id);
                let lookup = KeyLookupResult {
                    record,
                    authority_record,
                    status,
                };
                let indexed = IndexedRecord {
                    lookup,
                    key,
                    sole: false,
                };
                records
                    .entry(id)
                    .or_default()
                    .entry(record.signing_key_version.as_str())
                    .or_insert((indexed, version));
            }
        }
        let records = records
            .into_iter()
            .map(|(id, versions)| {
                let versions = versions
                    .into_iter()
                    .map(|(text, (mut indexed, version))| {
                        indexed.sole = per_version[&(id, version)] == 1
                            && per_key[&(id, indexed.key.clone())] == 1;
                        (text, indexed)
                    })
                    .collect();
                (id, versions)
            })
            .collect();
        Ok(KeyIndex {
            manifest,
            records,
            authorities_by_key,
        })
    }

    fn find(&self, authority_id: &str, signing_key_version: &str) -> Option<&IndexedRecord<'a>> {
        self.records.get(authority_id)?.get(signing_key_version)
    }
}

/// The key list as (f) and the unwitnessed reasons read it.
enum KeyList<'a> {
    Absent,
    Read(KeyIndex<'a>),
    Refused(PopulationFailureReason),
}

impl<'a> KeyList<'a> {
    fn index(&self) -> Option<&KeyIndex<'a>> {
        match self {
            KeyList::Read(index) => Some(index),
            _ => None,
        }
    }
}

/// The reason (f) reports for the first authority id or record of the key list
/// outside the record grammar, read in byte order of `authority_id`, each id
/// before its records, active records before archived ones, each list in its
/// order. A list signer runs this before
/// signing, so it never publishes a list every population read refuses.
pub fn refused_key_record(manifest: &TrustChainManifest) -> Option<PopulationFailureReason> {
    KeyIndex::read(manifest).err()
}

/// True when `issued_at` is at or after the key version's `effective_from`
/// and at or before its `archived_at`, compared to the second. A time that
/// cannot be read is not inside the window, and an archived version with no
/// `archived_at` has no recorded end, so nothing is.
fn issued_inside_key_window(issued_at: &str, record: &KeyVersionRecord, status: KeyStatus) -> bool {
    let Some(issued) = epoch_second(issued_at) else {
        return false;
    };
    let from_ok = epoch_second(&record.effective_from).is_some_and(|from| from <= issued);
    let until_ok = match &record.archived_at {
        Some(archived_at) => epoch_second(archived_at).is_some_and(|until| issued <= until),
        None => status == KeyStatus::Active,
    };
    from_ok && until_ok
}

/// (f) Each head is under the chain's authority, is not tied to a signer the
/// key list does not mark for heads, names only proofs whose signature covers their authority,
/// is under the same authority as every handed proof it names, and verifies
/// strictly under a registered key of that authority, held in one record,
/// that no other authority lists and whose window holds its `issued_at`; every
/// handed proof it names verifies under the key list, so its key is of the
/// same family. Every copy of a repeated head is checked.
fn check_signatures(
    parsed: &[ParsedHead],
    facts: &[ProofFacts],
    by_leaf: &HashMap<&str, Vec<usize>>,
    index: Option<&KeyIndex>,
) -> PopulationCheck {
    let manifest = index.map(|index| index.manifest);
    let chain_authority = &parsed[0].signed.head.authority_id;
    let mut unchecked = None;
    let mut walked = HashSet::new();
    for h in parsed {
        let sequence = h.sequence();
        let signed = &h.signed;
        let authority_id = &signed.head.authority_id;
        if authority_id != chain_authority {
            return failed(PopulationFailureReason::ChainAuthorityMismatch {
                proof_sequence: sequence,
                chain_authority: chain_authority.clone(),
                head_authority: authority_id.clone(),
            });
        }
        if let Some(signer) = headless_signer(authority_id, &signed.signing_key_version, manifest) {
            return failed(PopulationFailureReason::SignerNotMarkedForHeads {
                proof_sequence: sequence,
                signer,
            });
        }
        let named = by_leaf.get(h.tip()).map_or(&[][..], Vec::as_slice);
        // Copied heads and proofs would otherwise cost their product, and every
        // head here shares one authority, so one walk per tip decides them all.
        let walk = if walked.insert(h.tip()) { named } else { &[] };
        for &proof_index in walk {
            let proof = &facts[proof_index];
            if let Some(signer) = proof.headless_signer(manifest) {
                return failed(PopulationFailureReason::SignerNotMarkedForHeads {
                    proof_sequence: sequence,
                    signer,
                });
            }
            if !signs_its_authority(proof.cdp_version.as_deref()) {
                return failed(PopulationFailureReason::NamedProofVersionUnsupported {
                    proof_sequence: sequence,
                    proof_index,
                    cdp_version: proof.cdp_version.clone(),
                });
            }
            if proof.authority != *authority_id {
                return failed(PopulationFailureReason::NamedProofAuthorityMismatch {
                    proof_sequence: sequence,
                    head_authority: authority_id.clone(),
                    proof_authority: proof.authority.clone(),
                });
            }
        }
        let Some(index) = index else {
            unchecked.get_or_insert(NotCheckedReason::NeedsRegisteredKeyList);
            continue;
        };
        let Some(indexed) = index.find(authority_id, &signed.signing_key_version) else {
            return failed(PopulationFailureReason::HeadSigningKeyUnknown {
                proof_sequence: sequence,
                authority_id: authority_id.clone(),
                signing_key_version: signed.signing_key_version.clone(),
            });
        };
        if !indexed.sole {
            return failed(PopulationFailureReason::HeadKeyRecordNotUnique {
                proof_sequence: sequence,
                authority_id: authority_id.clone(),
                signing_key_version: signed.signing_key_version.clone(),
            });
        }
        let lookup = &indexed.lookup;
        if lookup.authority_record.revoked {
            return failed(PopulationFailureReason::HeadAuthorityRevoked {
                proof_sequence: sequence,
                authority_id: authority_id.clone(),
            });
        }
        let algorithm = lookup.record.algorithm_or_default();
        if algorithm != "Ed25519" {
            return failed(PopulationFailureReason::HeadAlgorithmUnsupported {
                proof_sequence: sequence,
                found: algorithm.to_string(),
            });
        }
        if !issued_inside_key_window(&signed.head.issued_at, lookup.record, lookup.status) {
            return failed(PopulationFailureReason::HeadOutsideKeyWindow {
                proof_sequence: sequence,
                signing_key_version: signed.signing_key_version.clone(),
                issued_at: signed.head.issued_at.clone(),
                effective_from: lookup.record.effective_from.clone(),
                archived_at: lookup.record.archived_at.clone(),
            });
        }
        let listing = index.authorities_by_key.get(&indexed.key);
        if let Some(authorities) = listing.filter(|a| a.len() > 1) {
            return failed(PopulationFailureReason::HeadKeyUnderSeveralAuthorities {
                proof_sequence: sequence,
                authority_ids: authorities.iter().map(|id| id.to_string()).collect(),
            });
        }
        if let Err(reason) =
            verify_head_signature(&h.message, &signed.signature, &lookup.record.public_key_b64)
        {
            return failed(PopulationFailureReason::HeadSignatureMismatch {
                proof_sequence: sequence,
                reason,
            });
        }
        if signed.head.head_type == POPULATION_HEAD_TYPE_V2 {
            if let Err(reason) = verify_head_pqc_half(index.manifest, sequence, signed) {
                return failed(reason);
            }
        }
        if named.is_empty() {
            unchecked.get_or_insert(NotCheckedReason::NamedProofNotHanded);
            continue;
        }
        for &proof_index in walk {
            if let Some(anchored) = &facts[proof_index].anchored {
                if !reached(anchored, ANCHORED_STAGE) {
                    return failed(PopulationFailureReason::NamedProofNotAnchored {
                        proof_sequence: sequence,
                        proof_index,
                        stage_reached: anchored.stage_reached,
                        failure_reason: anchored.failure_reason.clone(),
                    });
                }
            }
        }
    }
    match unchecked {
        Some(reason) => PopulationCheck::NotChecked { reason },
        None => PopulationCheck::Ok,
    }
}

/// A version 2 head's ML-DSA-65 half: `pqc_signing_key_version` must name the
/// partner of the head's Ed25519 key version in the head's authority
/// ([`TrustChainManifest::hybrid_partner`]), and the signature must verify
/// under that partner's key over [`pqc_signed_message`]. Run after the
/// Ed25519 half verifies, under a list verified under a hybrid pin.
fn verify_head_pqc_half(
    manifest: &TrustChainManifest,
    sequence: u64,
    signed: &SignedPopulationHead,
) -> Result<(), PopulationFailureReason> {
    let head = &signed.head;
    let pqc_version = signed.pqc_signing_key_version.clone().unwrap_or_default();
    let partner = manifest
        .hybrid_partner(&head.authority_id, &signed.signing_key_version)
        .filter(|partner| partner.version == pqc_version)
        .ok_or_else(|| PopulationFailureReason::HeadSigningKeyUnknown {
            proof_sequence: sequence,
            authority_id: head.authority_id.clone(),
            signing_key_version: pqc_version.clone(),
        })?;
    let invalid = |reason| PopulationFailureReason::HeadPqcSignatureInvalid {
        proof_sequence: sequence,
        pqc_signing_key_version: pqc_version.clone(),
        reason,
    };
    let key = decode_public_key(&partner.record.public_key_b64)
        .ok_or_else(|| invalid(SignatureFailureReason::PublicKeyMalformed))?;
    let signature = signed
        .pqc_signature
        .as_deref()
        .and_then(|text| {
            base64::engine::general_purpose::STANDARD
                .decode(strip_base64_prefix(text))
                .ok()
        })
        .ok_or_else(|| invalid(SignatureFailureReason::Malformed))?;
    let message =
        pqc_signed_message(head).ok_or_else(|| invalid(SignatureFailureReason::Malformed))?;
    verify_ml_dsa(MlDsaParameterSet::MlDsa65, &key, &message, &signature).map_err(|e| {
        invalid(match e {
            MlDsaError::SignatureLength { .. } => SignatureFailureReason::Malformed,
            MlDsaError::SignatureInvalid { .. } => SignatureFailureReason::DoesNotVerify,
            _ => SignatureFailureReason::PublicKeyMalformed,
        })
    })
}

/// Strict Ed25519 over the head's signed message: refuses a non-canonical or
/// small-order key, a small-order or non-canonical `R`, and a non-canonical
/// `S`.
fn verify_head_signature(
    message: &str,
    signature_b64: &str,
    public_key_b64: &str,
) -> Result<(), SignatureFailureReason> {
    let decode = |s: &str| base64::engine::general_purpose::STANDARD.decode(strip_base64_prefix(s));
    let signature: [u8; 64] = decode(signature_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(SignatureFailureReason::Malformed)?;
    let key: [u8; 32] = decode(public_key_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(SignatureFailureReason::PublicKeyMalformed)?;
    let key =
        VerifyingKey::from_bytes(&key).map_err(|_| SignatureFailureReason::PublicKeyMalformed)?;
    key.verify_canonical_strict(message.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|_| SignatureFailureReason::DoesNotVerify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::AttestationEnvelope;
    use crate::strip_hash_prefix;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const AUTHORITY: &str = "customer-kms-example-v1";

    fn head(sequence: u64, prev: &str, tip: &str) -> PopulationHead {
        PopulationHead {
            head_type: POPULATION_HEAD_TYPE_V1.to_string(),
            authority_id: AUTHORITY.to_string(),
            proof_sequence: sequence,
            prev_head_hash: prev.to_string(),
            tip_proof_hash: tip.to_string(),
            issued_at: "2026-10-28T00:00:00Z".to_string(),
        }
    }

    fn tip(n: u8) -> String {
        format!("sha512:{}", format!("{n:02x}").repeat(64))
    }

    fn signed_value(h: &PopulationHead, key: &SigningKey) -> Value {
        // A type outside the format has no signed message; sign its own text.
        let message = signed_message(h).unwrap_or_else(|| {
            format!(
                "{}:{}",
                h.head_type,
                checkpoint::hex(&head_digest(h).unwrap())
            )
        });
        let signature = key.sign(message.as_bytes()).to_bytes();
        json!({
            "head": h,
            "signing_key_version": "1",
            "signature": format!(
                "base64:{}",
                base64::engine::general_purpose::STANDARD.encode(signature)
            ),
        })
    }

    /// The hybrid-pin gate: under the vectors' hybrid key list a version 1
    /// head is refused in (f) with the typed reason, before any head
    /// signature is read.
    #[test]
    fn a_version_1_head_under_a_hybrid_pin_fails_f_with_the_typed_reason() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/trust_chain_hybrid");
        let cases: Value =
            serde_json::from_slice(&std::fs::read(format!("{dir}/cases.json")).unwrap()).unwrap();
        let case = cases["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "hybrid_list_verifies_under_hybrid_pin")
            .unwrap();
        let list = std::fs::read(format!("{dir}/{}", case["key_list"].as_str().unwrap())).unwrap();
        let manifest: TrustChainManifest = serde_json::from_slice(&list).unwrap();
        let verified = manifest
            .into_verified(case["pin"].as_str().unwrap())
            .expect("the vectors' hybrid list loads");
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let heads = vec![signed_value(
            &head(1, &genesis_prev_head_hash(), &tip(1)),
            &key,
        )];
        let result = verify_population(&[], &heads, Some(&verified));
        assert_eq!(
            result.checks.f_head_signatures,
            PopulationCheck::Failed {
                reason: PopulationFailureReason::HeadAlgorithmUnsupported {
                    proof_sequence: 1,
                    found: HYBRID_HEAD_CHECK_MISSING.to_string(),
                },
            }
        );
        assert_eq!(result.verdict, PopulationVerdict::Failed);
    }

    #[test]
    fn a_version_2_head_signs_under_its_own_tags() {
        let mut h = head(7, &genesis_prev_head_hash(), &tip(1));
        assert_eq!(pqc_signed_message(&h), None);
        h.head_type = POPULATION_HEAD_TYPE_V2.to_string();
        let digest = hex::encode(Sha512::digest(canonical_bytes(&h).unwrap()));
        let text = format!("nanorix-population-head-v2:{digest}");
        assert_eq!(signed_message(&h).as_deref(), Some(text.as_str()));
        assert_eq!(text.len(), 155);
        let mut expected = b"nanorix-population-head-pqc-v2".to_vec();
        expected.push(0x00);
        expected.extend_from_slice(text.as_bytes());
        assert_eq!(pqc_signed_message(&h), Some(expected));
        assert_eq!(head_hash(&h), Some(format!("sha512:{digest}")));
    }

    #[test]
    fn no_signed_message_is_built_for_another_head_type() {
        let mut h = head(7, &genesis_prev_head_hash(), &tip(1));
        assert!(signed_message(&h)
            .unwrap()
            .starts_with("nanorix-population-head-v1:"));
        h.head_type = "nanorix-population-head-v3".to_string();
        assert_eq!(signed_message(&h), None);
        assert_eq!(pqc_signed_message(&h), None);
    }

    #[test]
    fn canonical_bytes_are_jcs_with_sorted_keys_and_an_integer_sequence() {
        let h = head(7, &genesis_prev_head_hash(), &tip(1));
        let bytes = String::from_utf8(canonical_bytes(&h).unwrap()).unwrap();
        let expected = format!(
            "{{\"authority_id\":\"{}\",\"issued_at\":\"2026-10-28T00:00:00Z\",\
             \"prev_head_hash\":\"{}\",\"proof_sequence\":7,\"tip_proof_hash\":\"{}\",\
             \"type\":\"{}\"}}",
            AUTHORITY,
            genesis_prev_head_hash(),
            tip(1),
            POPULATION_HEAD_TYPE_V1
        );
        assert_eq!(bytes, expected);
        let max = head(MAX_PROOF_SEQUENCE, &genesis_prev_head_hash(), &tip(1));
        let max_bytes = String::from_utf8(canonical_bytes(&max).unwrap()).unwrap();
        assert!(max_bytes.contains("\"proof_sequence\":9007199254740991,"));
    }

    #[test]
    fn head_hash_and_signed_message_share_one_digest_under_distinct_forms() {
        let h = head(1, &genesis_prev_head_hash(), &tip(2));
        let digest = hex::encode(Sha512::digest(canonical_bytes(&h).unwrap()));
        assert_eq!(head_hash(&h).unwrap(), format!("sha512:{digest}"));
        let message = signed_message(&h).unwrap();
        assert_eq!(message, format!("nanorix-population-head-v1:{digest}"));
        assert_eq!(message.len(), 155);
    }

    #[test]
    fn relabelling_the_authority_changes_every_signed_value() {
        let h = head(1, &genesis_prev_head_hash(), &tip(2));
        let mut relabelled = h.clone();
        relabelled.authority_id = "customer-kms-other-v1".to_string();
        assert_ne!(signed_message(&h), signed_message(&relabelled));
        assert_ne!(head_hash(&h), head_hash(&relabelled));
    }

    #[test]
    fn an_authority_id_is_one_to_128_bytes_of_the_head_alphabet() {
        assert!(is_head_identifier(AUTHORITY));
        assert!(is_head_identifier("a.b_c-9"));
        assert!(is_head_identifier(&"a".repeat(128)));
        assert!(!is_head_identifier(""));
        assert!(!is_head_identifier(&"a".repeat(129)));
        assert!(!is_head_identifier("Upper"));
        assert!(!is_head_identifier("has space"));
        assert!(!is_head_identifier("caf\u{e9}"));
    }

    #[test]
    fn genesis_link_is_the_destruction_chain_genesis() {
        assert_eq!(
            genesis_prev_head_hash(),
            format!("sha512:{}", hex::encode(Sha512::digest(b"")))
        );
    }

    #[test]
    fn a_head_signature_and_a_proof_signature_never_stand_in_for_each_other() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        let h = head(1, &genesis_prev_head_hash(), &tip(3));
        let head_message = signed_message(&h).unwrap();
        let proof_target = strip_hash_prefix(&head_hash(&h).unwrap()).to_string();
        assert_eq!(proof_target.len(), 128);
        let b64 = |sig: Signature| {
            format!(
                "base64:{}",
                base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
            )
        };
        let head_sig = b64(key.sign(head_message.as_bytes()));
        let proof_sig = b64(key.sign(proof_target.as_bytes()));
        assert!(verify_head_signature(&head_message, &head_sig, &public).is_ok());
        assert_eq!(
            verify_head_signature(&head_message, &proof_sig, &public),
            Err(SignatureFailureReason::DoesNotVerify)
        );
        assert_eq!(
            crate::canonical_recompute::verify_message_with_key(&proof_target, &head_sig, &public),
            crate::canonical_recompute::SignatureCheck::Failed(
                SignatureFailureReason::DoesNotVerify
            )
        );
    }

    fn leaf_proof() -> Value {
        json!({
            "final_hash": format!("sha512:{}", "ab".repeat(64)),
            "attestation": {
                "algorithm": "Ed25519",
                "key_id": "k",
                "public_key": "base64:AAAA",
                "signature": "base64:BBBB"
            }
        })
    }

    fn leaf_envelope() -> AttestationEnvelope {
        AttestationEnvelope {
            algorithm: "Ed25519".into(),
            key_id: "k".into(),
            public_key: "base64:AAAA".into(),
            signature: "base64:BBBB".into(),
        }
    }

    fn expected_tip(final_hash_raw: &str, envelope: &AttestationEnvelope) -> String {
        let leaf = checkpoint::leaf_hash(final_hash_raw, envelope);
        format!("sha512:{}", checkpoint::hex(&leaf))
    }

    /// `leaf_proof` with one edit applied has no tip.
    fn refused(edit: impl FnOnce(&mut Value)) {
        let mut proof = leaf_proof();
        assert!(tip_proof_hash(&proof).is_some());
        edit(&mut proof);
        assert_eq!(tip_proof_hash(&proof), None, "{proof}");
    }

    #[test]
    fn tip_proof_hash_is_the_checkpoint_leaf() {
        let expected = expected_tip(&"ab".repeat(64), &leaf_envelope());
        assert_eq!(tip_proof_hash(&leaf_proof()).unwrap(), expected);
        let mut bare = leaf_proof();
        bare["final_hash"] = json!("ab".repeat(64));
        assert_eq!(tip_proof_hash(&bare).unwrap(), expected);
        let mut null_pqc = leaf_proof();
        null_pqc["pqc_signature"] = Value::Null;
        null_pqc["pqc_attestation"] = Value::Null;
        null_pqc["customer_pqc_attestation"] = Value::Null;
        assert_eq!(tip_proof_hash(&null_pqc).unwrap(), expected);
    }

    #[test]
    fn a_final_hash_that_is_absent_or_not_a_string_refuses_the_tip() {
        refused(|p| {
            p.as_object_mut().unwrap().remove("final_hash");
        });
        refused(|p| p["final_hash"] = Value::Null);
        refused(|p| p["final_hash"] = json!(7));
    }

    #[test]
    fn a_final_hash_that_is_not_128_lowercase_hex_refuses_the_tip() {
        refused(|p| p["final_hash"] = json!(format!("sha512:{}", "AB".repeat(64))));
        refused(|p| p["final_hash"] = json!(format!("sha512:{}a", "ab".repeat(64))));
        refused(|p| p["final_hash"] = json!(format!("sha512:{}", "ab".repeat(63))));
        refused(|p| p["final_hash"] = json!(format!("sha512:{}zz", "ab".repeat(63))));
        refused(|p| p["final_hash"] = json!(format!("sha512: {}", "ab".repeat(64))));
        refused(|p| p["final_hash"] = json!(format!("SHA512:{}", "ab".repeat(64))));
        refused(|p| p["final_hash"] = json!("sha512:short"));
    }

    #[test]
    fn an_attestation_that_is_absent_or_not_an_object_refuses_the_tip() {
        refused(|p| {
            p.as_object_mut().unwrap().remove("attestation");
        });
        refused(|p| p["attestation"] = Value::Null);
        refused(|p| p["attestation"] = json!("Ed25519"));
        refused(|p| p["attestation"] = json!([]));
    }

    #[test]
    fn an_attestation_field_that_is_absent_or_not_a_string_refuses_the_tip() {
        for name in ["algorithm", "key_id", "public_key", "signature"] {
            refused(|p| {
                p["attestation"].as_object_mut().unwrap().remove(name);
            });
            refused(|p| p["attestation"][name] = Value::Null);
            refused(|p| p["attestation"][name] = json!(1));
        }
        refused(|p| {
            let attestation = p["attestation"].as_object_mut().unwrap();
            let key = attestation.remove("public_key").unwrap();
            attestation.insert("verification_key".into(), key);
        });
    }

    #[test]
    fn nul_in_an_attestation_field_refuses_the_tip() {
        for name in ["algorithm", "key_id", "public_key", "signature"] {
            refused(|p| {
                let value = p["attestation"][name].as_str().unwrap();
                p["attestation"][name] = json!(format!("{value}\0x"));
            });
        }
    }

    #[test]
    fn a_populated_pqc_slot_refuses_the_tip_on_every_cdp_version() {
        let complete = json!({
            "algorithm": "ML-DSA-65",
            "key_id": "k",
            "public_key": "base64:CCCC",
            "signature": "base64:DDDD"
        });
        for slot in [
            "pqc_signature",
            "pqc_attestation",
            "customer_pqc_attestation",
        ] {
            for value in [
                json!("base64:CCCC"),
                json!(""),
                json!(1),
                json!(false),
                json!([]),
                json!({}),
                complete.clone(),
            ] {
                for version in [None, Some("1.0"), Some("2.0"), Some("2.1"), Some("2.2")] {
                    refused(|p| {
                        p[slot] = value.clone();
                        if let Some(version) = version {
                            p["cdp_version"] = json!(version);
                        }
                    });
                }
            }
        }
    }

    #[test]
    fn the_refused_record_named_does_not_depend_on_map_order() {
        let authority = |version: &str| {
            json!({
                "display_name": "test",
                "active_versions": [{
                    "signing_key_version": version,
                    "public_key_b64": "not base64",
                    "public_key_fingerprint": "sha256:00",
                    "effective_from": "2026-01-01T00:00:00Z",
                }],
            })
        };
        for _ in 0..32 {
            let manifest: TrustChainManifest = serde_json::from_value(json!({
                "schema_version": "1",
                "issued_at": "2026-10-28T00:00:00Z",
                "authorities": {
                    "authority-a": authority("2"),
                    "authority-b": authority("1"),
                    "authority-c": authority("1"),
                },
                "identity_fingerprint": "sha256:00",
                "manifest_signature": "base64:",
            }))
            .unwrap();
            assert_eq!(
                refused_key_record(&manifest),
                Some(PopulationFailureReason::KeyListRecordRefused {
                    authority_id: "authority-a".to_string(),
                    signing_key_version: "2".to_string(),
                    field: "public_key_b64".to_string(),
                })
            );
        }
    }

    #[test]
    fn the_published_key_list_is_inside_the_record_grammar() {
        // A record outside the grammar would fail every authority's
        // population check under the published list.
        let published = include_str!("../../../static/.well-known/trust-chain.json");
        let manifest: TrustChainManifest = serde_json::from_str(published).unwrap();
        assert!(!manifest.authorities.is_empty());
        assert_eq!(refused_key_record(&manifest), None);
    }

    #[test]
    fn no_heads_reports_every_check_not_checked_and_carries_the_label() {
        let r = verify_population(&[], &[], None);
        assert_eq!(r.verdict, PopulationVerdict::NotExternallyWitnessed);
        assert_eq!(
            r.honesty_label.map(|l| l.as_str()),
            Some("population not externally witnessed")
        );
        for c in [
            &r.checks.a_chain_links,
            &r.checks.b_sequence_contiguous,
            &r.checks.c_tips_match_proofs,
            &r.checks.f_head_signatures,
        ] {
            assert_eq!(
                *c,
                PopulationCheck::NotChecked {
                    reason: NotCheckedReason::NoHeadsHanded
                }
            );
        }
        for c in [&r.checks.d_log_inclusion, &r.checks.e_log_population] {
            assert_eq!(
                *c,
                PopulationCheck::NotChecked {
                    reason: NotCheckedReason::NeedsTransparencyLog
                }
            );
        }
    }

    #[test]
    fn a_malformed_head_fails_a_and_stops_the_other_checks() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let good = head(1, &genesis_prev_head_hash(), &tip(4));
        let cases: Vec<(&str, Value)> = vec![
            ("head.type", {
                let mut h = good.clone();
                h.head_type = "nanorix-population-head-v3".into();
                signed_value(&h, &key)
            }),
            ("head.authority_id", {
                let mut h = good.clone();
                h.authority_id = String::new();
                signed_value(&h, &key)
            }),
            ("head.authority_id", {
                let mut h = good.clone();
                h.authority_id = "Customer".into();
                signed_value(&h, &key)
            }),
            (
                "head.proof_sequence",
                signed_value(&head(0, &genesis_prev_head_hash(), &tip(4)), &key),
            ),
            (
                "head.proof_sequence",
                signed_value(
                    &head(MAX_PROOF_SEQUENCE + 1, &genesis_prev_head_hash(), &tip(4)),
                    &key,
                ),
            ),
            ("head.prev_head_hash", {
                let upper = genesis_prev_head_hash()
                    .to_uppercase()
                    .replace("SHA512:", "sha512:");
                signed_value(&head(1, &upper, &tip(4)), &key)
            }),
            (
                "head.tip_proof_hash",
                signed_value(&head(1, &genesis_prev_head_hash(), "ab"), &key),
            ),
            ("head.issued_at", {
                let mut h = good.clone();
                h.issued_at = "2026-10-28T00:00:00.000Z".into();
                signed_value(&h, &key)
            }),
            ("head.issued_at", {
                let mut h = good.clone();
                h.issued_at = "2026-02-30T00:00:00Z".into();
                signed_value(&h, &key)
            }),
            ("head.issued_at", {
                let mut h = good.clone();
                h.issued_at = "2026-10-28T23:59:60Z".into();
                signed_value(&h, &key)
            }),
            ("", {
                let mut v = signed_value(&good, &key);
                v["head"]["capsule_id"] = json!("cap_1");
                v
            }),
            ("", {
                let mut v = signed_value(&good, &key);
                v["authority_id"] = json!(AUTHORITY);
                v
            }),
            ("signature", {
                let mut v = signed_value(&good, &key);
                v["signature"] = json!(v["signature"].as_str().unwrap().replace("base64:", ""));
                v
            }),
        ];
        for (field, value) in cases {
            let r = verify_population(&[], &[value], None);
            assert_eq!(r.verdict, PopulationVerdict::Failed, "{field}");
            match &r.checks.a_chain_links {
                PopulationCheck::Failed {
                    reason: PopulationFailureReason::HeadMalformed { field: f, .. },
                } => assert_eq!(f, field),
                other => panic!("{field}: {other:?}"),
            }
            for c in [
                &r.checks.b_sequence_contiguous,
                &r.checks.c_tips_match_proofs,
                &r.checks.f_head_signatures,
            ] {
                assert_eq!(
                    *c,
                    PopulationCheck::NotChecked {
                        reason: NotCheckedReason::HeadsMalformed
                    },
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn a_v1_0_proof_named_by_a_head_fails_f_even_with_no_key_list() {
        let proof: Value = serde_json::from_str(include_str!(
            "../fixtures/corpus/06_failure_authority_unknown/0014_v1_0_signed_default_authority_pin.json"
        ))
        .unwrap();
        let integrity = verify_auditproof(&proof, &[], &VerifierPolicy::default());
        assert!(integrity.valid && integrity.stage_reached == 7);
        let mut copy = proof.clone();
        copy["attestation"]["key_id"] = json!("nrx-verify-rewritten");
        let (tip1, tip2) = (
            tip_proof_hash(&proof).unwrap(),
            tip_proof_hash(&copy).unwrap(),
        );
        assert_ne!(tip1, tip2);
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let h1 = head(1, &genesis_prev_head_hash(), &tip1);
        let h2 = head(2, &head_hash(&h1).unwrap(), &tip2);
        let r = verify_population(
            &[proof, copy],
            &[signed_value(&h1, &key), signed_value(&h2, &key)],
            None,
        );
        assert_eq!(
            r.checks.f_head_signatures,
            PopulationCheck::Failed {
                reason: PopulationFailureReason::NamedProofVersionUnsupported {
                    proof_sequence: 1,
                    proof_index: 0,
                    cdp_version: Some("1.0".to_string()),
                }
            }
        );
    }

    #[test]
    fn a_head_time_is_compared_to_the_second() {
        let record = |effective_from: &str, archived_at: Option<&str>| KeyVersionRecord {
            signing_key_version: "1".to_string(),
            public_key_b64: String::new(),
            public_key_fingerprint: String::new(),
            effective_from: effective_from.to_string(),
            archived_at: archived_at.map(str::to_string),
            algorithm: None,
            pqc_partner_version: None,
        };
        let inside = |r: &KeyVersionRecord| {
            issued_inside_key_window("2026-10-28T12:00:00Z", r, KeyStatus::Active)
        };
        assert!(inside(&record("2026-10-28T12:00:00.900Z", None)));
        assert!(inside(&record(
            "2026-10-27T00:00:00Z",
            Some("2026-10-28T12:00:00Z")
        )));
        // An offset is outside the time grammar, so the window has no start.
        assert!(!inside(&record("2026-10-28T14:00:00+02:00", None)));
        assert!(!inside(&record("2026-10-28T12:00:01Z", None)));
        assert!(!inside(&record(
            "2026-10-27T00:00:00Z",
            Some("2026-10-28T11:59:59Z")
        )));
        assert!(!inside(&record("not a time", None)));
        assert!(!inside(&record("2026-10-27T00:00:00Z", Some("not a time"))));
    }

    #[test]
    fn an_archived_version_with_no_end_holds_no_head() {
        let mut record = KeyVersionRecord {
            signing_key_version: "1".to_string(),
            public_key_b64: String::new(),
            public_key_fingerprint: String::new(),
            effective_from: "2026-10-27T00:00:00Z".to_string(),
            archived_at: None,
            algorithm: None,
            pqc_partner_version: None,
        };
        let at = "2026-10-28T12:00:00Z";
        assert!(!issued_inside_key_window(at, &record, KeyStatus::Archived));
        record.archived_at = Some("2026-10-29T00:00:00Z".to_string());
        assert!(issued_inside_key_window(at, &record, KeyStatus::Archived));
    }

    #[test]
    fn issued_at_seconds_run_from_00_to_59() {
        assert!(is_utc_second("2026-10-28T23:59:59Z"));
        assert!(is_utc_second("2026-10-28T00:00:00Z"));
        assert!(!is_utc_second("2026-10-28T23:59:60Z"));
        assert!(!is_utc_second("2016-12-31T23:59:60Z"));
        assert!(!is_utc_second("2026-10-28T00:00:00.5Z"));
    }

    #[test]
    fn the_time_grammar_reads_only_utc_with_z() {
        let at = |s: &str| epoch_second(s);
        let base = at("2026-10-28T00:00:00Z").expect("the plain form reads");
        assert_eq!(at("2026-10-28T00:00:00.123Z"), Some(base));
        assert_eq!(at("2026-10-28T00:00:00.123456789Z"), Some(base));
        assert_eq!(at("0001-01-01T00:00:00Z"), Some(-62_135_596_800));
        for refused in [
            "2026-10-28T00:00:60Z",
            "2026-10-28t00:00:00Z",
            "2026-10-28T00:00:00z",
            "2026-10-28 00:00:00Z",
            "2026-10-28T00:00:00+00:00",
            "2026-10-28T00:00:00-00:00",
            "2026-10-28T14:00:00+14:00",
            "2026-10-28T00:00:00",
            "0000-10-28T00:00:00Z",
            "2026-10-28T00:00:00.1234567890Z",
            "2026-10-28T00:00:00.Z",
            "2026-10-28T00:00:00.12a Z",
            "2026-02-30T00:00:00Z",
            "+2026-10-28T00:00:00Z",
            "2026-10-28T00:00:00ZZ",
            "",
        ] {
            assert_eq!(at(refused), None, "{refused:?} is outside the grammar");
        }
    }

    #[test]
    fn a_small_order_key_never_verifies_a_head() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let public = base64::engine::general_purpose::STANDARD.encode(identity);
        let mut signature = [0u8; 64];
        signature[0] = 1;
        let signature = format!(
            "base64:{}",
            base64::engine::general_purpose::STANDARD.encode(signature)
        );
        let message = signed_message(&head(1, &genesis_prev_head_hash(), &tip(5))).unwrap();
        assert_eq!(
            verify_head_signature(&message, &signature, &public),
            Err(SignatureFailureReason::DoesNotVerify)
        );
    }
}
