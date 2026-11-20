//! Population tick: canonical bytes, both signed messages, the seal,
//! the salt, the log key pin, the form check and the signature check
//! (Amendment 2026-11-16, A4 and A5; the format is Appendix A.2.1, "Tick").
//!
//! ```text
//! canonical_bytes    = JCS(tick without signature and pqc_signature)   RFC 8785
//! signed_message     = "nanorix-population-tick-v1:" ‖ hex(SHA-512(canonical_bytes))
//! pqc_signed_message = "nanorix-population-tick-pqc-v1" ‖ 0x00 ‖ signed_message
//! salt(n)            = HMAC-SHA-512(salt_key, "nanorix-tick-salt-v1" ‖ 0x00 ‖ decimal(n))
//! sealed_fingerprint = "sha512:" ‖ hex(SHA-512("nanorix-tick-seal-v1" ‖ 0x00 ‖ salt(n) ‖ 0x00 ‖ head_hash))
//! log_key_pin        = "log1-sha256:" ‖ hex(SHA-256("nanorix-log-hybrid-v1" ‖ 0x00 ‖ "Ed25519" ‖ 0x00 ‖
//!                      ed25519_key ‖ 0x00 ‖ "ML-DSA-65" ‖ 0x00 ‖ ml_dsa_65_key))
//! ```
//!
//! Ed25519 signs `signed_message`; ML-DSA-65, pure with an empty context, signs
//! `pqc_signed_message`. Both are required. `head_hash` is the latest head's
//! hash exactly as the head appendix writes it, `sha512:` included, or the
//! genesis value before the first head. Opening a seal needs only that tick's
//! salt, so an offline bundle can carry one salt and never the salt key.
//!
//! The checks that read ticks from a chain's box, (d) and (e), are not here.

use aws_lc_rs::hmac;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use crate::checkpoint::{self, Digest64};
use crate::ed25519_strict::VerifyCanonicalStrict;
use crate::mldsa::{verify_ml_dsa, MlDsaParameterSet};
use crate::trust_chain::repeated_member;

pub use nanorix_verify_types::population_tick::*;

/// Length of an Ed25519 public key in a log key pin.
const ED25519_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature.
const ED25519_SIGNATURE_LEN: usize = 64;

/// The members outside the signed bytes.
const SIGNATURE_MEMBERS: [&str; 2] = ["signature", "pqc_signature"];

/// The tick's RFC 8785 canonical bytes, without its two signatures. `None`
/// only if serialization fails, which a tick of strings and integers does not
/// do.
pub fn canonical_bytes(tick: &PopulationTick) -> Option<Vec<u8>> {
    let mut value = serde_json::to_value(tick).ok()?;
    let object = value.as_object_mut()?;
    for member in SIGNATURE_MEMBERS {
        object.remove(member);
    }
    serde_jcs::to_vec(&value).ok()
}

fn tick_digest(tick: &PopulationTick) -> Option<Digest64> {
    canonical_bytes(tick).map(|b| Sha512::digest(&b).into())
}

/// The ASCII text the tick's Ed25519 signature covers:
/// `nanorix-population-tick-v1:` and the hex SHA-512 of the canonical bytes.
/// `None` for a tick of any other type, whose tag this format does not know.
pub fn signed_message(tick: &PopulationTick) -> Option<String> {
    if tick.tick_type != POPULATION_TICK_TYPE_V1 {
        return None;
    }
    tick_digest(tick).map(|d| format!("{POPULATION_TICK_TYPE_V1}:{}", checkpoint::hex(&d)))
}

/// The bytes the tick's ML-DSA-65 signature covers: the PQC tag, a 0x00 byte
/// and [`signed_message`].
pub fn pqc_signed_message(tick: &PopulationTick) -> Option<Vec<u8>> {
    let text = signed_message(tick)?;
    let mut message = Vec::with_capacity(POPULATION_TICK_PQC_TAG_V1.len() + 1 + text.len());
    message.extend_from_slice(POPULATION_TICK_PQC_TAG_V1.as_bytes());
    message.push(0x00);
    message.extend_from_slice(text.as_bytes());
    Some(message)
}

/// The log key pin of one log key version, from its 32 Ed25519 bytes and its
/// 1952 ML-DSA-65 bytes. `None` when either key has another length.
pub fn log_key_pin(ed25519_key: &[u8], ml_dsa_65_key: &[u8]) -> Option<String> {
    if ed25519_key.len() != ED25519_KEY_LEN
        || ml_dsa_65_key.len() != MlDsaParameterSet::MlDsa65.public_key_len()
    {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(LOG_KEY_PIN_TAG_V1.as_bytes());
    hasher.update([0x00]);
    hasher.update(b"Ed25519");
    hasher.update([0x00]);
    hasher.update(ed25519_key);
    hasher.update([0x00]);
    hasher.update(b"ML-DSA-65");
    hasher.update([0x00]);
    hasher.update(ml_dsa_65_key);
    Some(format!(
        "{LOG_KEY_PIN_PREFIX}{}",
        hex::encode(hasher.finalize())
    ))
}

/// One tick's salt: HMAC-SHA-512 under the chain's salt key over the salt tag,
/// a 0x00 byte and the tick number in decimal.
pub fn tick_salt(salt_key: &[u8; TICK_SALT_KEY_LEN], sequence: u64) -> [u8; TICK_SALT_LEN] {
    let key = hmac::Key::new(hmac::HMAC_SHA512, salt_key);
    let mut message = Vec::with_capacity(TICK_SALT_TAG_V1.len() + 21);
    message.extend_from_slice(TICK_SALT_TAG_V1.as_bytes());
    message.push(0x00);
    message.extend_from_slice(sequence.to_string().as_bytes());
    let tag = hmac::sign(&key, &message);
    let mut salt = [0u8; TICK_SALT_LEN];
    salt.copy_from_slice(tag.as_ref());
    salt
}

/// The sealed fingerprint of `head_hash` under one tick's salt.
pub fn sealed_fingerprint(salt: &[u8; TICK_SALT_LEN], head_hash: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(TICK_SEAL_TAG_V1.as_bytes());
    hasher.update([0x00]);
    hasher.update(salt);
    hasher.update([0x00]);
    hasher.update(head_hash.as_bytes());
    let digest: Digest64 = hasher.finalize().into();
    format!("sha512:{}", checkpoint::hex(&digest))
}

/// True when the tick's seal opens, under this one salt, to `head_hash`.
pub fn seal_opens(tick: &PopulationTick, salt: &[u8; TICK_SALT_LEN], head_hash: &str) -> bool {
    sealed_fingerprint(salt, head_hash) == tick.sealed_fingerprint
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_sha512_ref(s: &str) -> bool {
    s.strip_prefix("sha512:")
        .is_some_and(|h| is_lower_hex(h, 128))
}

/// The bytes of a `base64:` value: standard padded base64 with no stray bits.
fn prefixed_base64(s: &str) -> Option<Vec<u8>> {
    let body = s.strip_prefix("base64:")?;
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

fn in_sequence_range(n: u64) -> bool {
    (1..=MAX_TICK_SEQUENCE).contains(&n)
}

/// The first member that breaks the tick format, as its path and what the
/// format expects. An emitter runs this before signing, so it cannot sign a
/// tick a verifier refuses.
pub fn validate_tick(tick: &PopulationTick) -> Result<(), (String, String)> {
    let bad = |field: &str, expected: &str| Err((field.to_string(), expected.to_string()));
    if tick.tick_type != POPULATION_TICK_TYPE_V1 {
        return bad("tick.type", "expected nanorix-population-tick-v1");
    }
    let pin_hex = tick.log_key_pin.strip_prefix(LOG_KEY_PIN_PREFIX);
    if !pin_hex.is_some_and(|h| is_lower_hex(h, 64)) {
        return bad(
            "tick.log_key_pin",
            "expected log1-sha256: + 64 lowercase hex",
        );
    }
    if !in_sequence_range(tick.sequence) {
        return bad("tick.sequence", "expected an integer from 1 to 2^53 - 1");
    }
    if !is_sha512_ref(&tick.sealed_fingerprint) {
        return bad(
            "tick.sealed_fingerprint",
            "expected sha512: + 128 lowercase hex",
        );
    }
    if let Some(entries) = &tick.key_list_fingerprints {
        if entries.is_empty() {
            return bad("tick.key_list_fingerprints", "expected at least one entry");
        }
        let mut previous = 0;
        for (i, entry) in entries.iter().enumerate() {
            if !in_sequence_range(entry.list_version) || entry.list_version <= previous {
                return bad(
                    &format!("tick.key_list_fingerprints[{i}].list_version"),
                    "expected an integer from 1 to 2^53 - 1, above the entry before",
                );
            }
            if !is_sha512_ref(&entry.fingerprint) {
                return bad(
                    &format!("tick.key_list_fingerprints[{i}].fingerprint"),
                    "expected sha512: + 128 lowercase hex",
                );
            }
            previous = entry.list_version;
        }
    }
    if let Some(tokens) = &tick.timestamp_tokens {
        if tokens.is_empty() {
            return bad("tick.timestamp_tokens", "expected at least one entry");
        }
        let mut previous = 0;
        for (i, token) in tokens.iter().enumerate() {
            if token.sequence == 0 || token.sequence >= tick.sequence || token.sequence <= previous
            {
                return bad(
                    &format!("tick.timestamp_tokens[{i}].sequence"),
                    "expected an earlier tick's sequence, above the entry before",
                );
            }
            if !prefixed_base64(&token.token).is_some_and(|b| !b.is_empty()) {
                return bad(
                    &format!("tick.timestamp_tokens[{i}].token"),
                    "expected base64: + the token's DER bytes",
                );
            }
            previous = token.sequence;
        }
    }
    if tick.final_tick.is_some_and(|f| !f) {
        return bad("tick.final", "expected true, or the member absent");
    }
    if !prefixed_base64(&tick.signature).is_some_and(|b| b.len() == ED25519_SIGNATURE_LEN) {
        return bad("tick.signature", "expected base64: + 64 signature bytes");
    }
    let pqc_len = MlDsaParameterSet::MlDsa65.signature_len();
    if !prefixed_base64(&tick.pqc_signature).is_some_and(|b| b.len() == pqc_len) {
        return bad(
            "tick.pqc_signature",
            "expected base64: + 3309 ML-DSA-65 signature bytes",
        );
    }
    Ok(())
}

/// Why a tick's text was refused before any check reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TickParseError {
    /// The bytes are not JSON.
    NotJson,
    /// The bytes are JSON but not its RFC 8785 form (other whitespace, member
    /// order or escapes): a timestamp token's imprint is over a tick's bytes
    /// as stored, so a reader that re-canonicalizes and one that hashes the
    /// stored bytes could read two ticks.
    NotCanonical,
    /// A member name is written twice in one object, named as an RFC 6901
    /// JSON Pointer: a parser keeps one copy, so two readers could read two
    /// ticks.
    MemberWrittenTwice(String),
    /// The JSON does not have the tick's shape: a missing or unknown member,
    /// or a value of the wrong JSON type.
    Shape(String),
    /// A value of the right type outside the format, as [`validate_tick`]
    /// names it.
    Field {
        /// The member's path.
        field: String,
        /// What the format expects there.
        expected: String,
    },
}

/// The path of the first member, at the top level or in an entry of
/// `key_list_fingerprints` or `timestamp_tokens`, whose value is `null`. The
/// parsed tick reads `null` as absent and writes it back left out, so the
/// signatures would still verify over a member the stored object holds.
fn null_member(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    for (name, member) in object {
        if member.is_null() {
            return Some(format!("tick.{name}"));
        }
    }
    for list in ["key_list_fingerprints", "timestamp_tokens"] {
        let Some(entries) = object.get(list).and_then(Value::as_array) else {
            continue;
        };
        for (i, entry) in entries.iter().enumerate() {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            if let Some((name, _)) = entry.iter().find(|(_, v)| v.is_null()) {
                return Some(format!("tick.{list}[{i}].{name}"));
            }
        }
    }
    None
}

/// Reads one tick from its bytes: refuses a member written twice, bytes that
/// are not their own RFC 8785 form, a member written `null`, then any member
/// outside the format, then any value outside it.
pub fn parse_tick(bytes: &[u8]) -> Result<PopulationTick, TickParseError> {
    match repeated_member(bytes) {
        Err(_) => return Err(TickParseError::NotJson),
        Ok(Some(pointer)) => return Err(TickParseError::MemberWrittenTwice(pointer)),
        Ok(None) => {}
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| TickParseError::NotJson)?;
    if serde_jcs::to_vec(&value).ok().as_deref() != Some(bytes) {
        return Err(TickParseError::NotCanonical);
    }
    if let Some(field) = null_member(&value) {
        return Err(TickParseError::Field {
            field,
            expected: "expected a value; an absent member is left out, never null".to_string(),
        });
    }
    let tick: PopulationTick =
        serde_json::from_value(value).map_err(|e| TickParseError::Shape(e.to_string()))?;
    validate_tick(&tick).map_err(|(field, expected)| TickParseError::Field { field, expected })?;
    Ok(tick)
}

/// Which check of a tick's signatures failed, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickSignatureError {
    /// The tick has no canonical encoding.
    NoCanonicalEncoding,
    /// The keys are not one log key version's pair of the right lengths, or
    /// their pin is not the tick's `log_key_pin`.
    LogKeyPinMismatch,
    /// The Ed25519 signature is not 64 `base64:` bytes, or does not verify
    /// strictly under the Ed25519 key.
    Ed25519DoesNotVerify,
    /// The ML-DSA-65 signature does not verify under the ML-DSA-65 key.
    MlDsa65DoesNotVerify,
}

/// Checks a tick against one log key version: its pin names these keys, its
/// Ed25519 signature verifies strictly, and its ML-DSA-65 signature verifies.
/// Both halves are required. Run [`validate_tick`] first.
pub fn verify_tick_signatures(
    tick: &PopulationTick,
    ed25519_key: &[u8],
    ml_dsa_65_key: &[u8],
) -> Result<(), TickSignatureError> {
    let (Some(message), Some(pqc_message)) = (signed_message(tick), pqc_signed_message(tick))
    else {
        return Err(TickSignatureError::NoCanonicalEncoding);
    };
    if log_key_pin(ed25519_key, ml_dsa_65_key).as_deref() != Some(tick.log_key_pin.as_str()) {
        return Err(TickSignatureError::LogKeyPinMismatch);
    }
    let ed25519_ok = <[u8; ED25519_KEY_LEN]>::try_from(ed25519_key)
        .ok()
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .zip(
            prefixed_base64(&tick.signature)
                .and_then(|s| <[u8; ED25519_SIGNATURE_LEN]>::try_from(s).ok()),
        )
        .is_some_and(|(key, signature)| {
            key.verify_canonical_strict(message.as_bytes(), &Signature::from_bytes(&signature))
                .is_ok()
        });
    if !ed25519_ok {
        return Err(TickSignatureError::Ed25519DoesNotVerify);
    }
    let pqc_signature =
        prefixed_base64(&tick.pqc_signature).ok_or(TickSignatureError::MlDsa65DoesNotVerify)?;
    verify_ml_dsa(
        MlDsaParameterSet::MlDsa65,
        ml_dsa_65_key,
        &pqc_message,
        &pqc_signature,
    )
    .map_err(|_| TickSignatureError::MlDsa65DoesNotVerify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_signed_message_is_built_for_another_tick_type() {
        let mut tick = PopulationTick {
            tick_type: POPULATION_TICK_TYPE_V1.to_string(),
            log_key_pin: format!("{LOG_KEY_PIN_PREFIX}{}", "0".repeat(64)),
            sequence: 1,
            sealed_fingerprint: format!("sha512:{}", "0".repeat(128)),
            key_list_fingerprints: None,
            timestamp_tokens: None,
            final_tick: None,
            signature: String::new(),
            pqc_signature: String::new(),
        };
        assert!(signed_message(&tick)
            .unwrap()
            .starts_with("nanorix-population-tick-v1:"));
        tick.tick_type = "nanorix-population-tick-v2".to_string();
        assert_eq!(signed_message(&tick), None);
        assert_eq!(pqc_signed_message(&tick), None);
    }
}
