//! The strict Ed25519 wrapper must accept every genuine signature.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nanorix_verify::ed25519_strict::VerifyCanonicalStrict;
use sha2::{Digest, Sha512};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ten_thousand_distinct_keys_and_messages_all_pass_the_strict_check() {
    for i in 0..10_000u32 {
        let digest = Sha512::digest(format!("nanorix-verify strict positive seed {i}"));
        let seed: [u8; 32] = digest[..32].try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let msg = digest[32..32 + (i as usize % 32)].to_vec();
        let sig = sk.sign(&msg);
        assert!(
            sk.verifying_key()
                .verify_canonical_strict(&msg, &sig)
                .is_ok(),
            "genuine signature {i} refused"
        );
    }
}

#[test]
fn every_genuine_positive_vector_passes_the_strict_check() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/ed25519_strict_positive.json"
    ))
    .unwrap();
    let vs = doc["vectors"].as_array().unwrap();
    assert_eq!(vs.len(), 64);
    for v in vs {
        let pk: [u8; 32] = unhex(v["public_key_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let sig: [u8; 64] = unhex(v["signature_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let msg = unhex(v["message_hex"].as_str().unwrap());
        assert!(VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify_canonical_strict(&msg, &Signature::from_bytes(&sig))
            .is_ok());
    }
}
