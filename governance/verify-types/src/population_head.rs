//! Population head wire types.
//!
//! A population head is a sibling primitive, not part of the
//! AuditProof: no proof field changes and the proof's signed canonical view is
//! the same bytes as before. For each proof a
//! customer-registered authority signs, the deployment emits one head that
//! names the proof by its leaf hash and links to the head before
//! it. There is one head chain per signing authority.
//!
//! This module holds only the wire types: the head, its signed form, and the
//! result a verifier reports for checks (a) to (f) of the population-head appendix. The
//! canonical encoding, the signed message and the checks themselves live in
//! `tools/nanorix-verify/src/population_head.rs`.
//!
//! **No success verdict.** [`PopulationVerdict`] has no variant that says a
//! population holds in full, and [`PopulationResult`] has no `valid` flag. A
//! check that could not run reports [`PopulationCheck::NotChecked`] with its
//! reason, and [`PopulationCheck::is_ok`] is true only for
//! [`PopulationCheck::Ok`]. Checks (d) and (e) need a transparency log, so
//! until a verifier reads one every result carries the label
//! "population not externally witnessed" (population-head appendix).
//!
//! **Forever-Standard discipline:** every variant and field here
//! is additive-only. Wire tags are pinned in
//! `tests/population_head_wire_form.rs`.

use serde::{Deserialize, Serialize};

use crate::{FailureReason, SignatureFailureReason};

/// The `type` tag of a version-1 head. It is inside the head's canonical
/// bytes and it prefixes the head's signed message, which keeps a head
/// signature and a proof signature from ever standing in for each other.
pub const POPULATION_HEAD_TYPE_V1: &str = "nanorix-population-head-v1";

/// The `type` tag of a version-2 head, the type a BYOC chain
/// carries from sequence 1. Its members are those of version 1; the record
/// key signs it with both halves, and the carrier adds the ML-DSA-65 half.
pub const POPULATION_HEAD_TYPE_V2: &str = "nanorix-population-head-v2";

/// The tag in front of a version-2 head's ML-DSA-65 signed message, followed
/// by a 0x00 byte and the head's Ed25519 signed message.
pub const POPULATION_HEAD_PQC_TAG_V2: &str = "nanorix-population-head-pqc-v2";

/// Largest `proof_sequence` a head may carry: 2^53 − 1. The canonical
/// encoding is RFC 8785, which writes numbers as IEEE-754 doubles; above this
/// value two sequences could encode to the same bytes.
pub const MAX_PROOF_SEQUENCE: u64 = 9_007_199_254_740_991;

/// Longest `authority_id` a head may carry, in bytes.
pub const MAX_HEAD_AUTHORITY_ID_LEN: usize = 128;

/// The honesty label's exact text (population-head appendix).
pub const POPULATION_NOT_EXTERNALLY_WITNESSED: &str = "population not externally witnessed";

/// One population head: `{type, authority_id, proof_sequence, prev_head_hash,
/// tip_proof_hash, issued_at}` and nothing else (population-head appendix).
///
/// - `type` is [`POPULATION_HEAD_TYPE_V1`] or [`POPULATION_HEAD_TYPE_V2`].
/// - `authority_id` is the registered authority whose key signs the head: 1
///   to [`MAX_HEAD_AUTHORITY_ID_LEN`] bytes of `a-z`, `0-9`, `.`, `_` and `-`.
///   It is inside the signed bytes, so a head cannot be read as another
///   authority's, and its characters have one RFC 8785 encoding.
/// - `proof_sequence` counts this authority's proofs from 1, one per head.
/// - `prev_head_hash` is `sha512:` plus the lowercase hex SHA-512 of the
///   previous head's canonical bytes; the head at sequence 1 carries the
///   `SHA-512("")` genesis constant the destruction chain already uses.
/// - `tip_proof_hash` is `sha512:` plus the lowercase hex the leaf
///   of the proof this head names.
/// - `issued_at` is UTC in the exact form `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Unknown fields are refused: a head carries no classification, outcome or
/// capsule id, and an extra field would change what the signature covers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PopulationHead {
    /// Head format tag; `type` on the wire.
    #[serde(rename = "type")]
    pub head_type: String,
    /// Registered authority whose key signs this head.
    pub authority_id: String,
    /// Position of the named proof in this authority's chain, from 1.
    pub proof_sequence: u64,
    /// `sha512:` digest of the previous head, or of `""` at sequence 1.
    pub prev_head_hash: String,
    /// `sha512:` leaf of the proof this head names.
    pub tip_proof_hash: String,
    /// UTC issue time, `YYYY-MM-DDTHH:MM:SSZ`.
    pub issued_at: String,
}

/// A head with its signature and the key version that resolves the verifying
/// key in the published key list.
///
/// `signing_key_version` is outside the signed bytes. It binds a key, not its
/// own text, through resolution: a signature verifies only under the key the
/// version resolves to, and that key is looked up under the signed
/// `authority_id`. An `authority_id` beside the head is an unknown field.
///
/// A version 2 head also carries `pqc_signing_key_version` and
/// `pqc_signature`; a version 1 head carries neither, and its bytes on the
/// wire are unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPopulationHead {
    /// The signed head.
    pub head: PopulationHead,
    /// Key version within that authority's published key list.
    pub signing_key_version: String,
    /// `base64:` Ed25519 signature over the head's signed message.
    pub signature: String,
    /// The version of the ML-DSA-65 partner of `signing_key_version`'s
    /// record, in the same authority. Present on a version 2 head only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_signing_key_version: Option<String>,
    /// `base64:` ML-DSA-65 signature, pure, empty context, over
    /// [`POPULATION_HEAD_PQC_TAG_V2`], a 0x00 byte and the head's signed
    /// message. Present on a version 2 head only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_signature: Option<String>,
}

/// Outcome of one check. Internally tagged on `outcome`.
///
/// `NotChecked` is never success: [`PopulationCheck::is_ok`] is false for it,
/// and a verdict is never upgraded because a check did not run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum PopulationCheck {
    /// The check ran over every handed head and found no defect.
    Ok,
    /// The check ran and found a defect; the first one in sequence order.
    Failed {
        /// What failed.
        reason: PopulationFailureReason,
    },
    /// The check did not run, or did not run over every head.
    NotChecked {
        /// Why it did not run.
        reason: NotCheckedReason,
    },
}

impl PopulationCheck {
    /// True only for [`PopulationCheck::Ok`]. `NotChecked` is false.
    pub fn is_ok(&self) -> bool {
        matches!(self, PopulationCheck::Ok)
    }
}

/// Why a check reported `failed`. Internally tagged on `type`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, thiserror::Error)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PopulationFailureReason {
    /// A handed head does not parse as a [`SignedPopulationHead`], or a field
    /// is not the shape the head format defines. Reported under (a); the
    /// other checks then report `not_checked`.
    #[error("head {head_index} is malformed at {field}: {detail}")]
    HeadMalformed {
        /// Position of the head in the handed list, from 0.
        head_index: usize,
        /// Dotted path of the field, empty when the head does not parse.
        field: String,
        /// Free text for a human reader; not a closed vocabulary.
        detail: String,
    },
    /// (a) The head's `prev_head_hash` is not the hash of the handed head
    /// before it, or, at sequence 1, not the genesis constant.
    #[error("head {proof_sequence} links to {found}, expected {expected}")]
    PrevHeadHashMismatch {
        /// Sequence of the head whose link failed.
        proof_sequence: u64,
        /// The hash the link had to carry.
        expected: String,
        /// The hash it carries.
        found: String,
    },
    /// (a) A head after sequence 1 carries the genesis constant as its link.
    #[error("head {proof_sequence} carries the genesis link but is not at sequence 1")]
    GenesisMisplaced {
        /// Sequence of the head.
        proof_sequence: u64,
    },
    /// (b) The handed sequences skip a value. A chain starts at 1.
    #[error("sequence jumps to {found}, expected {expected}")]
    SequenceGap {
        /// The next sequence the chain needed.
        expected: u64,
        /// The next sequence handed.
        found: u64,
    },
    /// (b) Two handed heads carry one sequence: a fork.
    #[error("two heads carry sequence {proof_sequence}")]
    DuplicateSequence {
        /// The shared sequence.
        proof_sequence: u64,
    },
    /// (b) The head's `issued_at` is before that of the head at the sequence
    /// below it, compared to the second. A chain runs forward in time, so a
    /// retired key cannot extend it by writing a date inside its own window.
    #[error(
        "head {proof_sequence} issued {issued_at}, before the head below it at {previous_issued_at}"
    )]
    HeadIssuedBeforePrevious {
        /// Sequence of the head.
        proof_sequence: u64,
        /// The head's issue time.
        issued_at: String,
        /// The issue time of the head at the sequence below it.
        previous_issued_at: String,
    },
    /// (c) No handed proof has the leaf the head names: a withheld proof.
    #[error("head {proof_sequence} names {tip_proof_hash}, which no handed proof has")]
    TipMatchesNoProof {
        /// Sequence of the head.
        proof_sequence: u64,
        /// The leaf it names.
        tip_proof_hash: String,
    },
    /// (c) Two heads name the same proof: proofs whose signatures cover the
    /// same message under the same authority, even when their leaves differ
    /// in fields the signature does not cover.
    #[error(
        "heads {first_sequence} and {second_sequence} both name the proof {tip_proof_hash} names"
    )]
    TipNamedTwice {
        /// The leaf the second head names.
        tip_proof_hash: String,
        /// Sequence of the first head naming it.
        first_sequence: u64,
        /// Sequence of the second.
        second_sequence: u64,
    },
    /// (c) The named proof does not verify with its chain and embedded-key
    /// signature. `failure_reason` is `None` when the proof verified its
    /// chain but carries no signature this build checks.
    #[error("head {proof_sequence} names proof {proof_index}, which does not verify")]
    NamedProofNotVerified {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Position of the proof in the handed list, from 0.
        proof_index: usize,
        /// Highest verification stage the proof reached.
        stage_reached: u8,
        /// The proof verifier's reason, when it failed.
        failure_reason: Option<FailureReason>,
    },
    /// (f) The head's authority or the named proof's signer is one the key
    /// list does not mark as emitting heads: the local signer, or an authority
    /// the handed key list carries without the marker (population-head appendix).
    #[error("head {proof_sequence} is tied to a signer not marked for heads ({signer:?})")]
    SignerNotMarkedForHeads {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Which signer.
        signer: HeadlessSigner,
    },
    /// (f) A head names an authority other than the chain's.
    #[error(
        "head {proof_sequence} is under {head_authority}, the chain is under {chain_authority}"
    )]
    ChainAuthorityMismatch {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Authority of the lowest-sequence handed head.
        chain_authority: String,
        /// Authority this head names.
        head_authority: String,
    },
    /// (f) The head's authority is not the authority of the proof it names.
    #[error("head {proof_sequence} is under {head_authority}, its proof under {proof_authority}")]
    NamedProofAuthorityMismatch {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Authority the head names.
        head_authority: String,
        /// Authority the named proof is anchored under.
        proof_authority: String,
    },
    /// (f) The named proof's `cdp_version` is not one whose signature covers
    /// its authority, so the proof does not show which authority it is under.
    #[error("head {proof_sequence} names proof {proof_index}, whose signature does not cover its authority")]
    NamedProofVersionUnsupported {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Position of the proof in the handed list, from 0.
        proof_index: usize,
        /// The proof's `cdp_version`, when it has one.
        cdp_version: Option<String>,
    },
    /// (f) The published key list has no such key version for the head's
    /// authority, or, on a version 2 head, its `pqc_signing_key_version` is
    /// not the ML-DSA-65 partner of its Ed25519 key version.
    #[error("head {proof_sequence} names key {signing_key_version} of {authority_id}, which is not registered")]
    HeadSigningKeyUnknown {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Authority the head names.
        authority_id: String,
        /// Key version the head names: its `signing_key_version`, or, when
        /// the ML-DSA-65 half names a version that is not the partner, its
        /// `pqc_signing_key_version`.
        signing_key_version: String,
    },
    /// (f) The published key list marks the head's authority revoked.
    #[error("head {proof_sequence} is under revoked authority {authority_id}")]
    HeadAuthorityRevoked {
        /// Sequence of the head.
        proof_sequence: u64,
        /// The revoked authority.
        authority_id: String,
    },
    /// (f) The head's registered key is not an Ed25519 key.
    #[error("head {proof_sequence} key algorithm {found} is not supported")]
    HeadAlgorithmUnsupported {
        /// Sequence of the head.
        proof_sequence: u64,
        /// The algorithm the key list records.
        found: String,
    },
    /// (f) An authority id or a record of the key list is outside the record
    /// grammar: an authority id is outside the head alphabet, read before the
    /// authority's records and also when it has none, or a record's algorithm
    /// is not a label this verifier knows, its key is not that label's length
    /// in standard base64, its fingerprint is not the SHA-256 of its key, or
    /// its version is not the decimal text of an integer from 1 to 2^63 - 1.
    /// Such an id or record could read as a second authority, key or version
    /// beside one the other checks compare, so the whole list is refused.
    #[error("key version {signing_key_version:?} of {authority_id:?} is refused at {field}")]
    KeyListRecordRefused {
        /// The authority holding the record, or the refused authority id.
        authority_id: String,
        /// The record's key version, as written; empty when the authority id
        /// is refused.
        signing_key_version: String,
        /// The first field that is outside the grammar: `authority_id`,
        /// `algorithm`, `public_key_b64`, `public_key_fingerprint` or
        /// `signing_key_version`.
        field: String,
    },
    /// (f) The authority holds more than one record of the head's key
    /// version or of its key, so the key list gives that key no one window.
    #[error("head {proof_sequence} key version {signing_key_version:?} of {authority_id:?} is not one record")]
    HeadKeyRecordNotUnique {
        /// Sequence of the head.
        proof_sequence: u64,
        /// The head's authority.
        authority_id: String,
        /// The key version.
        signing_key_version: String,
    },
    /// (f) The head's registered public key is listed under more than one
    /// authority in the key list, so the head cannot be tied to one of them.
    #[error("head {proof_sequence} key is registered under {authority_ids:?}")]
    HeadKeyUnderSeveralAuthorities {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Every authority whose active or archived versions list the key,
        /// sorted.
        authority_ids: Vec<String>,
    },
    /// (f) The head signature does not verify strictly under the registered
    /// key.
    #[error("head {proof_sequence} signature does not verify ({reason:?})")]
    HeadSignatureMismatch {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Why.
        reason: SignatureFailureReason,
    },
    /// (f) A version 2 head's ML-DSA-65 signature does not verify under the
    /// partner of the head's Ed25519 key version.
    #[error("head {proof_sequence} ML-DSA-65 signature under version {pqc_signing_key_version:?} does not verify ({reason:?})")]
    HeadPqcSignatureInvalid {
        /// Sequence of the head.
        proof_sequence: u64,
        /// The partner key version the head names.
        pqc_signing_key_version: String,
        /// Why.
        reason: SignatureFailureReason,
    },
    /// (f) The named proof does not verify under the published key list,
    /// so it is not shown to be signed under the head's registered authority
    /// and key version family.
    #[error(
        "head {proof_sequence} names proof {proof_index}, which does not verify under the key list"
    )]
    NamedProofNotAnchored {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Position of the proof in the handed list, from 0.
        proof_index: usize,
        /// Highest verification stage the proof reached.
        stage_reached: u8,
        /// The proof verifier's reason, when it failed.
        failure_reason: Option<FailureReason>,
    },
    /// (f) The head's `issued_at` is before the key version's `effective_from`
    /// or after its `archived_at`, compared to the second, one of those key
    /// list times cannot be read, or the version is archived with no
    /// `archived_at`.
    #[error(
        "head {proof_sequence} issued {issued_at} is outside key {signing_key_version}'s window"
    )]
    HeadOutsideKeyWindow {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Key version the head names.
        signing_key_version: String,
        /// The head's issue time.
        issued_at: String,
        /// The key list's `effective_from` for that version.
        effective_from: String,
        /// The key list's `archived_at` for that version, when archived.
        archived_at: Option<String>,
    },
    /// (c) The head's `issued_at` is before the destruction time of a handed
    /// proof it names, compared to the second, or that time cannot be read.
    #[error(
        "head {proof_sequence} issued {issued_at}, before proof {proof_index} ended at {destroyed_at}"
    )]
    HeadIssuedBeforeProof {
        /// Sequence of the head.
        proof_sequence: u64,
        /// Position of the proof in the handed list, from 0.
        proof_index: usize,
        /// The head's issue time.
        issued_at: String,
        /// The destruction time the proof's chain hashes.
        destroyed_at: String,
    },
}

/// A signer the key list does not mark for heads (population-head appendix).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeadlessSigner {
    /// The local signer (`signing_key_version` `local-ephemeral`).
    LocalSigner,
    /// An authority the handed key list carries without the
    /// `emits_population_heads` marker. Every hosted authority is one, and so
    /// is any authority that list's signer leaves unmarked.
    UnmarkedAuthority,
}

/// Why a check reported `not_checked`. The wire value is the reason's
/// exact text.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotCheckedReason {
    /// Checks (d) and (e) read a transparency log; no verifier reads one yet.
    #[serde(rename = "needs a transparency log")]
    NeedsTransparencyLog,
    /// Check (f) resolves head keys from the published key list, and none
    /// was supplied.
    #[serde(rename = "needs a registered key list")]
    NeedsRegisteredKeyList,
    /// No heads were handed, so there is nothing to check.
    #[serde(rename = "no heads handed")]
    NoHeadsHanded,
    /// A handed head is malformed; (a) names it, and the other checks do not
    /// run over a set they cannot read.
    #[serde(rename = "a handed head is malformed")]
    HeadsMalformed,
    /// A head names a proof that was not handed, so (f) cannot compare the
    /// head with it; (c) reports the missing proof.
    #[serde(rename = "a named proof was not handed")]
    NamedProofNotHanded,
}

impl NotCheckedReason {
    /// The reason's exact text, the same as its wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            NotCheckedReason::NeedsTransparencyLog => "needs a transparency log",
            NotCheckedReason::NeedsRegisteredKeyList => "needs a registered key list",
            NotCheckedReason::NoHeadsHanded => "no heads handed",
            NotCheckedReason::HeadsMalformed => "a handed head is malformed",
            NotCheckedReason::NamedProofNotHanded => "a named proof was not handed",
        }
    }
}

/// The population verdict. There is no success variant: without checks (d)
/// and (e) a verifier cannot show that the handed heads are every head.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PopulationVerdict {
    /// At least one check failed.
    Failed,
    /// No check failed, and the population is not externally witnessed.
    NotExternallyWitnessed,
}

/// The honesty label (population-head appendix). The wire value is the label's exact
/// text.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HonestyLabel {
    /// "population not externally witnessed".
    #[serde(rename = "population not externally witnessed")]
    PopulationNotExternallyWitnessed,
}

impl HonestyLabel {
    /// The label's exact text, the same as its wire value.
    pub fn as_str(&self) -> &'static str {
        match self {
            HonestyLabel::PopulationNotExternallyWitnessed => POPULATION_NOT_EXTERNALLY_WITNESSED,
        }
    }
}

/// Checks (a) to (f) of the population-head appendix, one field each.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PopulationChecks {
    /// (a) Each handed head after the first links to the handed head before
    /// it; the head at sequence 1 links to genesis.
    pub a_chain_links: PopulationCheck,
    /// (b) `proof_sequence` runs from 1 with no gap and no repeat, and no
    /// head was issued before the head at the sequence below it.
    pub b_sequence_contiguous: PopulationCheck,
    /// (c) Each head's `tip_proof_hash` is the leaf of a handed proof that
    /// verifies and ended no later than the head was issued, and no two
    /// heads name one proof.
    pub c_tips_match_proofs: PopulationCheck,
    /// (d) Each head's commitment is in a named log near `issued_at`.
    pub d_log_inclusion: PopulationCheck,
    /// (e) Every counted log entry in the period is a handed head.
    pub e_log_population: PopulationCheck,
    /// (f) Each head signature verifies strictly under the same registered
    /// authority and key version family as the proof it names.
    pub f_head_signatures: PopulationCheck,
}

impl PopulationChecks {
    /// True when any check reported `failed`.
    pub fn any_failed(&self) -> bool {
        [
            &self.a_chain_links,
            &self.b_sequence_contiguous,
            &self.c_tips_match_proofs,
            &self.d_log_inclusion,
            &self.e_log_population,
            &self.f_head_signatures,
        ]
        .iter()
        .any(|c| matches!(c, PopulationCheck::Failed { .. }))
    }
}

/// Why a handed proof is listed as unwitnessed.
///
/// `LocalSigner` says the local signer emits no heads. `UnmarkedAuthority` says
/// only what the handed key list carries. Each rests on what the proof verified
/// to, not on what its fields claim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnwitnessedReason {
    /// Verifies with its chain and embedded-key signature, its signature
    /// covers an authority naming the local signer, it carries that signer's
    /// key version, and its key is under no authority in the key list. The
    /// local signer emits no heads.
    LocalSigner,
    /// Verifies under the key list, under an authority that list does not
    /// mark as emitting heads. Whoever signs the list sets the marker, so this
    /// does not show that no head was expected.
    UnmarkedAuthority,
    /// No handed head names it, and nothing shows that none should.
    NoHandedHead,
    /// Does not verify with its chain and embedded-key signature, so nothing
    /// it says about its signer can be read.
    ProofNotVerified,
}

/// A handed proof that no handed head names. Listed, never a failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnwitnessedProof {
    /// Position of the proof in the handed list, from 0.
    pub proof_index: usize,
    /// The proof's `sha512:` leaf, or `None` when it has no usable
    /// `final_hash` to compute one from.
    pub tip_proof_hash: Option<String>,
    /// Why no head witnesses it.
    pub reason: UnwitnessedReason,
}

/// Which key list a run read. Two lists from one identity can disagree on
/// which authorities emit heads, so a result says which it read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyListRead {
    /// The list's signed `issued_at`.
    pub issued_at: String,
    /// The fingerprint of the identity that signed it.
    pub identity_fingerprint: String,
}

/// What a verifier reports for one authority's population.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PopulationResult {
    /// `failed` when any check failed, otherwise `not_externally_witnessed`.
    pub verdict: PopulationVerdict,
    /// The honesty label. Every result carries it until a verifier can show
    /// that the authority anchors (population-head appendix); `None` is reserved for
    /// that case.
    pub honesty_label: Option<HonestyLabel>,
    /// Checks (a) to (f).
    pub checks: PopulationChecks,
    /// Authority of the lowest-sequence handed head, when any head parsed.
    pub authority_id: Option<String>,
    /// Number of heads handed.
    pub head_count: usize,
    /// Number of proofs handed.
    pub proof_count: usize,
    /// Lowest handed sequence, when any head parsed.
    pub first_sequence: Option<u64>,
    /// Highest handed sequence, when any head parsed.
    pub last_sequence: Option<u64>,
    /// Handed proofs no handed head names, in handed order.
    pub unwitnessed_proofs: Vec<UnwitnessedProof>,
    /// The key list this run read, when one was supplied.
    pub key_list: Option<KeyListRead>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_checked_is_never_ok() {
        let nc = PopulationCheck::NotChecked {
            reason: NotCheckedReason::NeedsTransparencyLog,
        };
        assert!(!nc.is_ok());
        assert!(PopulationCheck::Ok.is_ok());
        let failed = PopulationCheck::Failed {
            reason: PopulationFailureReason::DuplicateSequence { proof_sequence: 2 },
        };
        assert!(!failed.is_ok());
    }

    #[test]
    fn reason_text_matches_wire_value() {
        for r in [
            NotCheckedReason::NeedsTransparencyLog,
            NotCheckedReason::NeedsRegisteredKeyList,
            NotCheckedReason::NoHeadsHanded,
            NotCheckedReason::HeadsMalformed,
            NotCheckedReason::NamedProofNotHanded,
        ] {
            let wire = serde_json::to_string(&r).unwrap();
            assert_eq!(wire, format!("\"{}\"", r.as_str()));
        }
        let label = HonestyLabel::PopulationNotExternallyWitnessed;
        assert_eq!(
            serde_json::to_string(&label).unwrap(),
            format!("\"{POPULATION_NOT_EXTERNALLY_WITNESSED}\"")
        );
        assert_eq!(label.as_str(), POPULATION_NOT_EXTERNALLY_WITNESSED);
    }

    #[test]
    fn max_proof_sequence_is_largest_exact_double_integer() {
        assert_eq!(MAX_PROOF_SEQUENCE, (1u64 << 53) - 1);
        assert_eq!(MAX_PROOF_SEQUENCE as f64 as u64, MAX_PROOF_SEQUENCE);
    }
}
