//! Strict Ed25519 verification.
//!
//! `VerifyingKey::verify_strict` rejects a small-order public key and a
//! small-order or non-canonical `R`. It still accepts a public key whose
//! encoding is non-canonical (y >= p). The extension method below rejects that
//! too, so every verifier agrees on the same set of acceptable keys.

use ed25519_dalek::{Signature, SignatureError, VerifyingKey};

/// Strict verification that also rejects a non-canonically encoded public key.
pub trait VerifyCanonicalStrict {
    /// Returns an error unless the key is canonically encoded and the
    /// signature passes `verify_strict`.
    fn verify_canonical_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError>;
}

/// True when the key's bytes are the canonical (y < p) encoding of its point.
pub(crate) fn is_canonical_key(key: &VerifyingKey) -> bool {
    key.to_edwards().compress().to_bytes() == key.to_bytes()
}

impl VerifyCanonicalStrict for VerifyingKey {
    fn verify_canonical_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        if !is_canonical_key(self) {
            return Err(SignatureError::new());
        }
        self.verify_strict(message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn unhex(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    #[test]
    fn canonical_predicate_refuses_all_20_non_canonical_encodings_and_accepts_a_genuine_key() {
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/ed25519_strict_negative.json"
        ))
        .unwrap();
        let encs = doc["non_canonical_point_encodings_hex"].as_array().unwrap();
        assert_eq!(encs.len(), 20);
        for h in encs {
            let key = VerifyingKey::from_bytes(&unhex(h.as_str().unwrap())).unwrap();
            assert!(!is_canonical_key(&key), "{h}");
        }
        let genuine = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(is_canonical_key(&genuine));
    }
}
