//! ML-DSA (FIPS 204) signature verification, the primitive only.
//!
//! [`verify_ml_dsa`] checks one signature over one message with one public key,
//! for ML-DSA-65 or ML-DSA-87. It is pure ML-DSA (not HashML-DSA) with an empty
//! context string, the external `ML-DSA.Verify` of FIPS 204 Algorithm 3.
//!
//! A success says only that the signature is valid for that key and message. It
//! says nothing about a record, a key list, a checkpoint, or whether the key is
//! anchored to any authority: the caller decides what the key and the message
//! are and what a valid signature means for them.
//!
//! Decoding is strict. The public key and the signature must be raw FIPS 204
//! encodings of exactly the parameter set's length, checked here before the
//! library is called, so a DER `SubjectPublicKeyInfo` given as the key is
//! refused by that length check. The library reads a key as DER first and
//! falls back to raw only when that parse fails, without checking that the DER
//! parse used every byte (aws-lc-rs 1.18.1 `src/pqdsa.rs:83-93`,
//! `src/evp_pkey.rs:212-226`), so a raw key whose first bytes happen to form a
//! smaller parameter set's `SubjectPublicKeyInfo` would be read as that smaller
//! key. This module therefore wraps every raw key in the asked parameter set's
//! own `SubjectPublicKeyInfo` before the library sees it, and the library
//! always reads exactly the given key bytes as the asked parameter set.
//! The library refuses a signature whose hint section is not the canonical
//! encoding (repeated or out-of-order indices, a count above omega or
//! decreasing, non-zero padding: aws-lc-sys 0.45.0
//! `aws-lc/crypto/fipsmodule/ml_dsa/mldsa/packing.c:157-195`) and one whose `z`
//! is out of range (`mldsa/sign.c:1231`), and it reports those the same way as a
//! signature that does not verify, so this module does too
//! ([`MlDsaError::SignatureInvalid`]). The vectors under `fixtures/mldsa/` hold
//! a refused case for each of those classes; `fixtures/mldsa/README.md` says
//! which cases isolate their check.

use std::fmt;

use aws_lc_rs::signature::{ParsedPublicKey, ML_DSA_65, ML_DSA_87};

/// An ML-DSA parameter set this module verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-65 (FIPS 204 Table 1, security category 3).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204 Table 1, security category 5).
    MlDsa87,
}

impl MlDsaParameterSet {
    /// Length in bytes of an encoded public key (FIPS 204 Table 2).
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Length in bytes of an encoded signature (FIPS 204 Table 2).
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// The parameter set's name as FIPS 204 writes it, `ML-DSA-65` or `ML-DSA-87`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// DER `SubjectPublicKeyInfo` header that precedes the raw key: an outer
    /// SEQUENCE, the AlgorithmIdentifier with the NIST OID for the parameter
    /// set (2.16.840.1.101.3.4.3.18 or .19) and no parameters, and a BIT STRING
    /// header with zero unused bits.
    const fn spki_prefix(self) -> &'static [u8; 22] {
        match self {
            Self::MlDsa65 => &[
                0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
            ],
            Self::MlDsa87 => &[
                0x30, 0x82, 0x0a, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                0x04, 0x03, 0x13, 0x03, 0x82, 0x0a, 0x21, 0x00,
            ],
        }
    }

    fn algorithm(self) -> &'static aws_lc_rs::signature::PqdsaVerificationAlgorithm {
        match self {
            Self::MlDsa65 => &ML_DSA_65,
            Self::MlDsa87 => &ML_DSA_87,
        }
    }
}

impl fmt::Display for MlDsaParameterSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why [`verify_ml_dsa`] refused a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MlDsaError {
    /// The public key is not exactly the parameter set's raw encoded length.
    #[error("{parameter_set} public key must be {expected} bytes, got {actual}")]
    PublicKeyLength {
        /// The parameter set the caller asked for.
        parameter_set: MlDsaParameterSet,
        /// The required length.
        expected: usize,
        /// The length given.
        actual: usize,
    },
    /// The signature is not exactly the parameter set's encoded length.
    #[error("{parameter_set} signature must be {expected} bytes, got {actual}")]
    SignatureLength {
        /// The parameter set the caller asked for.
        parameter_set: MlDsaParameterSet,
        /// The required length.
        expected: usize,
        /// The length given.
        actual: usize,
    },
    /// The library refused to decode the public key. Every key of the right
    /// length is handed to the library inside the parameter set's own
    /// `SubjectPublicKeyInfo`, which it is expected to take, so input of the
    /// right length is not expected to reach this; it is kept so that an
    /// unexpected refusal by the library is reported as a key refusal.
    #[error("{parameter_set} public key was refused by the decoder")]
    PublicKeyRejected {
        /// The parameter set the caller asked for.
        parameter_set: MlDsaParameterSet,
    },
    /// The signature does not verify for this key and message, or its encoding
    /// is not canonical.
    #[error("{parameter_set} signature does not verify")]
    SignatureInvalid {
        /// The parameter set the caller asked for.
        parameter_set: MlDsaParameterSet,
    },
}

/// Verifies an ML-DSA `signature` over `message` with `public_key`, pure
/// ML-DSA with an empty context.
///
/// `Ok(())` means the signature is valid for this key and message under
/// `parameter_set`, and nothing more: it is a primitive check that says nothing
/// about a record, a key list, or whether the key is anchored.
///
/// # Errors
///
/// [`MlDsaError::PublicKeyLength`] or [`MlDsaError::SignatureLength`] when an
/// input is not exactly the parameter set's length (checked first, key before
/// signature); [`MlDsaError::SignatureInvalid`] when the signature does not
/// verify or is not canonically encoded; [`MlDsaError::PublicKeyRejected`] only
/// if the library refuses the wrapped key, which input of the right length is
/// not expected to cause.
pub fn verify_ml_dsa(
    parameter_set: MlDsaParameterSet,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), MlDsaError> {
    if public_key.len() != parameter_set.public_key_len() {
        return Err(MlDsaError::PublicKeyLength {
            parameter_set,
            expected: parameter_set.public_key_len(),
            actual: public_key.len(),
        });
    }
    if signature.len() != parameter_set.signature_len() {
        return Err(MlDsaError::SignatureLength {
            parameter_set,
            expected: parameter_set.signature_len(),
            actual: signature.len(),
        });
    }
    let mut spki = Vec::with_capacity(22 + public_key.len());
    spki.extend_from_slice(parameter_set.spki_prefix());
    spki.extend_from_slice(public_key);
    let key = ParsedPublicKey::new(parameter_set.algorithm(), &spki)
        .map_err(|_| MlDsaError::PublicKeyRejected { parameter_set })?;
    key.verify_sig(message, signature)
        .map_err(|_| MlDsaError::SignatureInvalid { parameter_set })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::signature::{
        KeyPair, PqdsaKeyPair, PqdsaSigningAlgorithm, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING,
        ML_DSA_87_SIGNING,
    };

    const SETS: [(MlDsaParameterSet, &PqdsaSigningAlgorithm); 2] = [
        (MlDsaParameterSet::MlDsa65, &ML_DSA_65_SIGNING),
        (MlDsaParameterSet::MlDsa87, &ML_DSA_87_SIGNING),
    ];

    fn sign(alg: &'static PqdsaSigningAlgorithm, message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pair = PqdsaKeyPair::from_seed(alg, &[7u8; 32]).unwrap();
        let mut sig = vec![0u8; alg.signature_len()];
        let n = pair.sign(message, &mut sig).unwrap();
        assert_eq!(n, sig.len());
        (pair.public_key().as_ref().to_vec(), sig)
    }

    #[test]
    fn lengths_match_the_library_constants() {
        for (set, alg) in SETS {
            assert_eq!(set.public_key_len(), alg.public_key_len(), "{set}");
            assert_eq!(set.signature_len(), alg.signature_len(), "{set}");
        }
    }

    #[test]
    fn a_fresh_signature_verifies_and_a_changed_message_does_not() {
        for (set, alg) in SETS {
            let (pk, sig) = sign(alg, b"nanorix");
            assert_eq!(verify_ml_dsa(set, &pk, b"nanorix", &sig), Ok(()));
            assert_eq!(
                verify_ml_dsa(set, &pk, b"nanoriy", &sig),
                Err(MlDsaError::SignatureInvalid { parameter_set: set })
            );
        }
    }

    #[test]
    fn a_der_public_key_is_refused_by_length() {
        for (set, alg) in SETS {
            let pair = PqdsaKeyPair::from_seed(alg, &[7u8; 32]).unwrap();
            let der = pair.public_key().as_der().unwrap();
            let (_, sig) = sign(alg, b"m");
            assert_eq!(
                verify_ml_dsa(set, der.as_ref(), b"m", &sig),
                Err(MlDsaError::PublicKeyLength {
                    parameter_set: set,
                    expected: set.public_key_len(),
                    actual: der.as_ref().len(),
                })
            );
        }
    }

    #[test]
    fn the_spki_prefix_matches_the_library_encoder() {
        for (set, alg) in SETS {
            let pair = PqdsaKeyPair::from_seed(alg, &[7u8; 32]).unwrap();
            let der = pair.public_key().as_der().unwrap();
            let mut want = set.spki_prefix().to_vec();
            want.extend_from_slice(pair.public_key().as_ref());
            assert_eq!(der.as_ref(), want.as_slice(), "{set}");
        }
    }

    // Unwrapped, the library would read these buffers as the smaller key and
    // refuse them as a key; wrapped, they are read whole as the asked set's raw
    // key, so the only refusal left is the signature's.
    #[test]
    fn a_right_length_key_starting_with_a_smaller_set_spki_is_read_as_a_raw_key() {
        let smaller: [(&'static PqdsaSigningAlgorithm, &[MlDsaParameterSet]); 2] = [
            (
                &ML_DSA_44_SIGNING,
                &[MlDsaParameterSet::MlDsa65, MlDsaParameterSet::MlDsa87],
            ),
            (&ML_DSA_65_SIGNING, &[MlDsaParameterSet::MlDsa87]),
        ];
        for (small, sets) in smaller {
            let pair = PqdsaKeyPair::from_seed(small, &[7u8; 32]).unwrap();
            let der = pair.public_key().as_der().unwrap();
            for &set in sets {
                let alg = SETS.iter().find(|(s, _)| *s == set).unwrap().1;
                let mut key = der.as_ref().to_vec();
                assert!(key.len() < set.public_key_len());
                key.resize(set.public_key_len(), 0);
                let (_, sig) = sign(alg, b"m");
                assert_eq!(
                    verify_ml_dsa(set, &key, b"m", &sig),
                    Err(MlDsaError::SignatureInvalid { parameter_set: set }),
                    "{set}"
                );
            }
        }
    }

    #[test]
    fn errors_name_the_parameter_set_and_lengths() {
        let e = verify_ml_dsa(MlDsaParameterSet::MlDsa87, &[0u8; 3], b"", &[]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "ML-DSA-87 public key must be 2592 bytes, got 3"
        );
        let e =
            verify_ml_dsa(MlDsaParameterSet::MlDsa65, &[0u8; 1952], b"", &[0u8; 5]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "ML-DSA-65 signature must be 3309 bytes, got 5"
        );
        assert_eq!(
            MlDsaError::PublicKeyRejected {
                parameter_set: MlDsaParameterSet::MlDsa65
            }
            .to_string(),
            "ML-DSA-65 public key was refused by the decoder"
        );
        assert_eq!(
            MlDsaError::SignatureInvalid {
                parameter_set: MlDsaParameterSet::MlDsa87
            }
            .to_string(),
            "ML-DSA-87 signature does not verify"
        );
    }
}
