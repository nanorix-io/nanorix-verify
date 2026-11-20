//! Population tick wire form (Amendment 2026-11-16, A4 and A5).
//!
//! A tick is a separate signed primitive: it witnesses a
//! customer's head chain from write-once storage and changes no AuditProof
//! and no head. The byte rules (canonical bytes, signed messages, seal, salt
//! and log key pin) live in `nanorix-verify`'s `population_tick` module.

use serde::{Deserialize, Serialize};

/// The `type` of a version-1 tick. It is inside the tick's canonical bytes
/// and it prefixes the Ed25519 signed message.
pub const POPULATION_TICK_TYPE_V1: &str = "nanorix-population-tick-v1";

/// The tag in front of the ML-DSA-65 signed message, followed by a 0x00 byte
/// and the Ed25519 signed message.
pub const POPULATION_TICK_PQC_TAG_V1: &str = "nanorix-population-tick-pqc-v1";

/// The domain tag of a tick's sealed fingerprint.
pub const TICK_SEAL_TAG_V1: &str = "nanorix-tick-seal-v1";

/// The domain tag of a tick's salt, derived from the salt key.
pub const TICK_SALT_TAG_V1: &str = "nanorix-tick-salt-v1";

/// The domain tag of the log key pin.
pub const LOG_KEY_PIN_TAG_V1: &str = "nanorix-log-hybrid-v1";

/// The text in front of the log key pin's hex digest.
pub const LOG_KEY_PIN_PREFIX: &str = "log1-sha256:";

/// Length in bytes of the salt key a chain's tick salts are derived from.
pub const TICK_SALT_KEY_LEN: usize = 32;

/// Length in bytes of one tick's salt (HMAC-SHA-512 output).
pub const TICK_SALT_LEN: usize = 64;

/// Largest `sequence`, `list_version` or token `sequence` a tick may carry:
/// 2^53 − 1, so RFC 8785 writes each one exactly.
pub const MAX_TICK_SEQUENCE: u64 = 9_007_199_254_740_991;

/// One tick: exactly the members of the specification, and nothing else.
///
/// The three optional members are absent unless they carry something, so a
/// tick without them has the same canonical bytes as one that never knew
/// them. `final` is present only as `true`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PopulationTick {
    /// Tick format tag; `type` on the wire.
    #[serde(rename = "type")]
    pub tick_type: String,
    /// `log1-sha256:` and the lowercase hex SHA-256 of the log key's pin
    /// input: the chain's log key version, both halves.
    pub log_key_pin: String,
    /// The tick number, from 1, contiguous per chain across log key versions.
    pub sequence: u64,
    /// `sha512:` and the lowercase hex seal over this tick's salt and the
    /// chain's latest `head_hash` at the tick's time.
    pub sealed_fingerprint: String,
    /// In the first tick after each new key-list version: one entry per
    /// version made since the tick before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_list_fingerprints: Option<Vec<KeyListFingerprint>>,
    /// When timestamps are on: tokens that each cover an earlier tick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_tokens: Option<Vec<TimestampToken>>,
    /// Present, as `true`, only in the chain's final tick.
    #[serde(rename = "final", default, skip_serializing_if = "Option::is_none")]
    pub final_tick: Option<bool>,
    /// `base64:` Ed25519 signature over the tick's signed message.
    pub signature: String,
    /// `base64:` ML-DSA-65 signature, pure, empty context, over the tag, a
    /// 0x00 byte and the Ed25519 signed message.
    pub pqc_signature: String,
}

/// A key-list version's fingerprint as a tick carries it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyListFingerprint {
    /// The key list's version number, from 1.
    pub list_version: u64,
    /// `sha512:` and the lowercase hex SHA-512 of the list's bytes as handed.
    pub fingerprint: String,
}

/// An RFC 3161 token a tick carries for an earlier tick. Only its form is
/// read here; checking the token itself is outside this format's checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimestampToken {
    /// The `sequence` of the earlier tick the token's message imprint covers.
    pub sequence: u64,
    /// `base64:` and the token's DER bytes.
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_members_stay_off_the_wire() {
        let tick = PopulationTick {
            tick_type: POPULATION_TICK_TYPE_V1.to_string(),
            log_key_pin: String::new(),
            sequence: 1,
            sealed_fingerprint: String::new(),
            key_list_fingerprints: None,
            timestamp_tokens: None,
            final_tick: None,
            signature: String::new(),
            pqc_signature: String::new(),
        };
        let text = serde_json::to_string(&tick).unwrap();
        assert!(!text.contains("final"));
        assert!(!text.contains("key_list_fingerprints"));
        assert!(!text.contains("timestamp_tokens"));
        assert!(text.contains("\"type\":\"nanorix-population-tick-v1\""));
    }

    #[test]
    fn an_unknown_member_is_refused() {
        let text = r#"{"type":"nanorix-population-tick-v1","log_key_pin":"","sequence":1,
            "sealed_fingerprint":"","signature":"","pqc_signature":"","random":"00"}"#;
        assert!(serde_json::from_str::<PopulationTick>(text).is_err());
    }

    #[test]
    fn final_is_read_by_its_wire_name() {
        let text = r#"{"type":"nanorix-population-tick-v1","log_key_pin":"","sequence":1,
            "sealed_fingerprint":"","final":true,"signature":"","pqc_signature":""}"#;
        let tick: PopulationTick = serde_json::from_str(text).unwrap();
        assert_eq!(tick.final_tick, Some(true));
    }
}
