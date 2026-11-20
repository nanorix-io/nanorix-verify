//! The bytes a record's ML-DSA-65 signature covers: the record transcript.
//!
//! The specification defines the transcript and H3 amends it: for `cdp_version` 2.1 and 2.2 in
//! `nanorix_only` or `customer_only` mode its last field is `canonical_hash_raw`, the 128 hex
//! characters the record's Ed25519 signature covers, and every field is ASCII without a 0x00 byte.
//! The transcript is nine fields joined by single 0x00 bytes, with no trailing 0x00:
//!
//! ```text
//! "nanorix-pqc-v1" 0x00 cdp_version 0x00 capsule_id 0x00 key_id 0x00 signature_algorithm 0x00
//! pqc_algorithm 0x00 ed25519_public_key 0x00 pqc_public_key_fingerprint 0x00 canonical_hash_raw
//! ```
//!
//! [`record_transcript`] is the one way to build it, for the signer and for every Rust verifier.
//! The other engines rebuild it from the shared vectors in `fixtures/pqc_transcript/`.

use base64::Engine;
use sha2::{Digest, Sha256};

/// The transcript's first field, its domain tag (H5).
pub const RECORD_TRANSCRIPT_TAG: &str = "nanorix-pqc-v1";

/// The length in bytes of an ML-DSA-65 public key (FIPS 204).
const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// The bytes an ML-DSA-65 record signature covers, built only by [`record_transcript`].
///
/// The field is private, so a transcript cannot be made from arbitrary bytes:
///
/// ```compile_fail
/// let forged = nanorix_verify::pqc_transcript::RecordTranscript(vec![]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordTranscript(Vec<u8>);

impl RecordTranscript {
    /// The transcript bytes, the raw message ML-DSA-65 signs with an empty context (H3).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The record values a transcript is built from, borrowed from the record as emitted.
#[derive(Debug, Clone, Copy)]
pub struct RecordTranscriptInputs<'a> {
    /// The record's `cdp_version`: `2.1` or `2.2`.
    pub cdp_version: &'a str,
    /// The record's `signing_mode`: `nanorix_only` or `customer_only`. It selects the last field
    /// (H3) and is not itself in the transcript.
    pub signing_mode: &'a str,
    /// The record's `capsule_id`.
    pub capsule_id: &'a str,
    /// The Ed25519 attestation's `key_id` as emitted.
    pub key_id: &'a str,
    /// The record's `signature_algorithm`: `Ed25519`.
    pub signature_algorithm: &'a str,
    /// The partner signature's algorithm: `ML-DSA-65`.
    pub pqc_algorithm: &'a str,
    /// The Ed25519 attestation's `public_key` text as emitted: `base64:` and the standard padded
    /// base64 of the 32 key bytes.
    pub ed25519_public_key: &'a str,
    /// The 1952 bytes of the partner ML-DSA-65 public key. The builder computes the
    /// fingerprint field from them.
    pub pqc_public_key: &'a [u8],
    /// The 128 lowercase hex characters the record's Ed25519 signature covers.
    pub canonical_hash_raw: &'a str,
}

/// A text field of [`RecordTranscriptInputs`], named in a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptField {
    /// `cdp_version`.
    CdpVersion,
    /// `signing_mode`.
    SigningMode,
    /// `capsule_id`.
    CapsuleId,
    /// `key_id`.
    KeyId,
    /// `signature_algorithm`.
    SignatureAlgorithm,
    /// `pqc_algorithm`.
    PqcAlgorithm,
    /// `ed25519_public_key`.
    Ed25519PublicKey,
    /// `canonical_hash_raw`.
    CanonicalHashRaw,
}

impl TranscriptField {
    /// The field's name as written in [`RecordTranscriptInputs`] and the shared vectors.
    pub fn name(self) -> &'static str {
        match self {
            Self::CdpVersion => "cdp_version",
            Self::SigningMode => "signing_mode",
            Self::CapsuleId => "capsule_id",
            Self::KeyId => "key_id",
            Self::SignatureAlgorithm => "signature_algorithm",
            Self::PqcAlgorithm => "pqc_algorithm",
            Self::Ed25519PublicKey => "ed25519_public_key",
            Self::CanonicalHashRaw => "canonical_hash_raw",
        }
    }
}

impl std::fmt::Display for TranscriptField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Why [`record_transcript`] refused its inputs. Each value names the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TranscriptError {
    /// A text field holds a 0x00 byte (H3).
    #[error("{0} holds a 0x00 byte")]
    NulByte(TranscriptField),
    /// A text field holds a byte above 0x7F (H3: every field is ASCII).
    #[error("{0} holds a byte that is not ASCII")]
    NonAsciiByte(TranscriptField),
    /// `cdp_version` is not `2.1` or `2.2`; H3 gives no other version a last field.
    #[error("cdp_version must be 2.1 or 2.2")]
    CdpVersionUnsupported,
    /// `signing_mode` is not `nanorix_only` or `customer_only`; H3 gives no other mode a last field.
    #[error("signing_mode must be nanorix_only or customer_only")]
    SigningModeUnsupported,
    /// `capsule_id` is empty.
    #[error("capsule_id is empty")]
    CapsuleIdEmpty,
    /// `key_id` is empty.
    #[error("key_id is empty")]
    KeyIdEmpty,
    /// `signature_algorithm` is not `Ed25519`.
    #[error("signature_algorithm must be Ed25519")]
    SignatureAlgorithmUnsupported,
    /// `pqc_algorithm` is not `ML-DSA-65`.
    #[error("pqc_algorithm must be ML-DSA-65")]
    PqcAlgorithmUnsupported,
    /// `ed25519_public_key` is not `base64:` and the canonical standard padded base64 of 32 bytes.
    #[error("ed25519_public_key must be base64: and the padded standard base64 of 32 bytes")]
    Ed25519PublicKeyMalformed,
    /// The ML-DSA-65 public key is not 1952 bytes long; carries the length given.
    #[error("the ML-DSA-65 public key must be 1952 bytes, not {0}")]
    PqcPublicKeyLength(usize),
    /// `canonical_hash_raw` is not exactly 128 lowercase hex characters.
    #[error("canonical_hash_raw must be 128 lowercase hex characters")]
    CanonicalHashMalformed,
}

/// Builds the record transcript (as amended by H3, with the field forms of the hub's
/// 2026-11-18 amendment), or refuses the inputs.
///
/// Every text field is checked first for 0x00 and for bytes above 0x7F, then each field's form.
/// The fingerprint field is `sha256:` and the lowercase hex SHA-256 of `pqc_public_key`.
///
/// ```
/// use nanorix_verify::pqc_transcript::{record_transcript, RecordTranscriptInputs, TranscriptError};
///
/// let inputs = RecordTranscriptInputs {
///     cdp_version: "2.2",
///     signing_mode: "customer_only",
///     capsule_id: "cap_7be2915c0d3a4e6f8a1b2c3d4e5f6071",
///     key_id: "nrx-kms-v2",
///     signature_algorithm: "Ed25519",
///     pqc_algorithm: "ML-DSA-65",
///     ed25519_public_key: "base64:GVHak/xHE0xBsS1K/zXf3f5XTSdINLQ568meFsvQvCw=",
///     pqc_public_key: &[7u8; 1952],
///     canonical_hash_raw: &"ab".repeat(64),
/// };
/// let transcript = record_transcript(&inputs).expect("valid inputs");
/// assert!(transcript.as_bytes().starts_with(b"nanorix-pqc-v1\x002.2\x00cap_"));
///
/// let v1 = RecordTranscriptInputs { cdp_version: "1.0", ..inputs };
/// assert_eq!(record_transcript(&v1), Err(TranscriptError::CdpVersionUnsupported));
/// ```
pub fn record_transcript(
    inputs: &RecordTranscriptInputs<'_>,
) -> Result<RecordTranscript, TranscriptError> {
    let text = [
        (TranscriptField::CdpVersion, inputs.cdp_version),
        (TranscriptField::SigningMode, inputs.signing_mode),
        (TranscriptField::CapsuleId, inputs.capsule_id),
        (TranscriptField::KeyId, inputs.key_id),
        (
            TranscriptField::SignatureAlgorithm,
            inputs.signature_algorithm,
        ),
        (TranscriptField::PqcAlgorithm, inputs.pqc_algorithm),
        (TranscriptField::Ed25519PublicKey, inputs.ed25519_public_key),
        (TranscriptField::CanonicalHashRaw, inputs.canonical_hash_raw),
    ];
    for (field, value) in text {
        if value.as_bytes().contains(&0x00) {
            return Err(TranscriptError::NulByte(field));
        }
        if !value.is_ascii() {
            return Err(TranscriptError::NonAsciiByte(field));
        }
    }
    if !matches!(inputs.cdp_version, "2.1" | "2.2") {
        return Err(TranscriptError::CdpVersionUnsupported);
    }
    if !matches!(inputs.signing_mode, "nanorix_only" | "customer_only") {
        return Err(TranscriptError::SigningModeUnsupported);
    }
    if inputs.capsule_id.is_empty() {
        return Err(TranscriptError::CapsuleIdEmpty);
    }
    if inputs.key_id.is_empty() {
        return Err(TranscriptError::KeyIdEmpty);
    }
    if inputs.signature_algorithm != "Ed25519" {
        return Err(TranscriptError::SignatureAlgorithmUnsupported);
    }
    if inputs.pqc_algorithm != "ML-DSA-65" {
        return Err(TranscriptError::PqcAlgorithmUnsupported);
    }
    if !ed25519_public_key_is_canonical(inputs.ed25519_public_key) {
        return Err(TranscriptError::Ed25519PublicKeyMalformed);
    }
    if inputs.pqc_public_key.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        return Err(TranscriptError::PqcPublicKeyLength(
            inputs.pqc_public_key.len(),
        ));
    }
    let hash = inputs.canonical_hash_raw.as_bytes();
    if hash.len() != 128 || !hash.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(TranscriptError::CanonicalHashMalformed);
    }

    let fingerprint = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(inputs.pqc_public_key))
    );
    let fields = [
        RECORD_TRANSCRIPT_TAG,
        inputs.cdp_version,
        inputs.capsule_id,
        inputs.key_id,
        inputs.signature_algorithm,
        inputs.pqc_algorithm,
        inputs.ed25519_public_key,
        fingerprint.as_str(),
        inputs.canonical_hash_raw,
    ];
    Ok(RecordTranscript(fields.join("\0").into_bytes()))
}

/// `base64:` followed by the standard padded base64 of exactly 32 bytes, re-encoding to the same
/// text: no URL-safe alphabet, no missing padding, no non-zero padding bits.
///
/// The decode accepts any padding and non-zero padding bits on purpose, so the re-encode
/// comparison is the one rule that makes the text canonical, as the field forms state it.
fn ed25519_public_key_is_canonical(text: &str) -> bool {
    use base64::engine::{
        general_purpose, DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig,
    };
    let Some(body) = text.strip_prefix("base64:") else {
        return false;
    };
    let lenient = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    match lenient.decode(body) {
        Ok(raw) => raw.len() == 32 && general_purpose::STANDARD.encode(&raw) == body,
        Err(_) => false,
    }
}
