//! Version 2 population heads in check (f).
//!
//! A BYOC chain carries `nanorix-population-head-v2`, signed by the record key
//! with both halves: Ed25519 over `nanorix-population-head-v2:` and the hex
//! SHA-512 of the head's JCS bytes, and the key's ML-DSA-65 partner over
//! `nanorix-population-head-pqc-v2`, a 0x00 byte, then that same text. Under
//! a hybrid pin (f) refuses a version 1 head and a version 2 head missing
//! either half; under a classical pin it refuses a version 2 head.
//!
//! Every key comes from a fixed, public, test-only seed. Each byte string a
//! head is signed over is written out here from its tags, not taken from the
//! library, and every expected result is the wire JSON, so the file states
//! the format by itself.

use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::population_head::{tip_proof_hash, verify_population, PopulationResult};
use nanorix_verify::pqc_transcript::RECORD_TRANSCRIPT_TAG;
use nanorix_verify::trust_chain::{
    hybrid_pin, AuthorityRecord, TrustChainManifest, VerifiedManifest, KEY_LIST_PQC_TAG,
};
use nanorix_verify_types::signed_tags::SIGNED_MESSAGE_TAGS;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::path::Path;

const SEED_ED_IDENTITY: [u8; 32] = [0x51; 32];
const SEED_ML_IDENTITY: [u8; 32] = [0x52; 32];
const SEED_ED_RECORD: [u8; 32] = [0x61; 32];
const SEED_ML_PARTNER: [u8; 32] = [0x71; 32];
const SEED_ML_OTHER: [u8; 32] = [0x72; 32];

const GENESIS: &str = "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
const ISSUED_AT: &str = "2026-11-02T00:00:00Z";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(text.strip_prefix("base64:").unwrap_or(text))
        .expect("base64")
}

fn ed_public(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn ml65(seed: [u8; 32]) -> PqdsaKeyPair {
    PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed).expect("ML-DSA-65 key from seed")
}

fn ml_sign(pair: &PqdsaKeyPair, len: usize, message: &[u8]) -> Vec<u8> {
    let mut sig = vec![0u8; len];
    let n = pair.sign(message, &mut sig).expect("ML-DSA signs");
    sig.truncate(n);
    sig
}

fn record(version: &str, key: &[u8], algorithm: Option<&str>, partner: Option<&str>) -> Value {
    let mut rec = json!({
        "signing_key_version": version,
        "public_key_b64": b64(key),
        "public_key_fingerprint": format!("sha256:{}", hex::encode(Sha256::digest(key))),
        "effective_from": "2026-11-01T00:00:00Z",
    });
    if let Some(a) = algorithm {
        rec["algorithm"] = json!(a);
    }
    if let Some(p) = partner {
        rec["pqc_partner_version"] = json!(p);
    }
    rec
}

fn marked_authority(active: Vec<Value>) -> Value {
    json!({
        "display_name": "Acme Health signing authority",
        "active_versions": active,
        "archived_versions": [],
        "revoked": false,
        "emits_population_heads": true,
    })
}

/// One BYOC authority marked for heads: Ed25519 version 1 with its ML-DSA-65
/// partner 2, and an unrelated ML-DSA-65 record 3, signed by both identity
/// keys under the install's hybrid pin.
fn hybrid_list() -> (String, VerifiedManifest) {
    let ed = ed_public(SEED_ED_IDENTITY);
    let ml_pair = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &SEED_ML_IDENTITY).unwrap();
    let ml = ml_pair.public_key().as_ref().to_vec();
    let pin = hybrid_pin(&ed, &ml);
    let id = format!(
        "us-customer-kms-acme-hybrid1.{}-v1",
        &pin["hybrid1-sha256:".len()..]
    );
    let records = vec![
        record("1", &ed_public(SEED_ED_RECORD), None, Some("2")),
        record(
            "2",
            ml65(SEED_ML_PARTNER).public_key().as_ref(),
            Some("ML-DSA-65"),
            None,
        ),
        record(
            "3",
            ml65(SEED_ML_OTHER).public_key().as_ref(),
            Some("ML-DSA-65"),
            None,
        ),
    ];
    let authorities: HashMap<String, AuthorityRecord> =
        serde_json::from_value(json!({ id.clone(): marked_authority(records) })).unwrap();
    let m = TrustChainManifest::build_unsigned_hybrid(
        "1",
        "2026-11-01T00:00:00Z",
        authorities,
        &ed,
        &ml,
    );
    let ed_sig = SigningKey::from_bytes(&SEED_ED_IDENTITY)
        .sign(&m.signed_payload().unwrap())
        .to_bytes();
    let ml_sig = ml_sign(
        &ml_pair,
        ML_DSA_87_SIGNING.signature_len(),
        &m.pqc_signed_message().unwrap(),
    );
    (
        id,
        m.attach(&ed_sig, &ml_sig)
            .expect("the hybrid list verifies under its pin"),
    )
}

/// A classical list marking the same Ed25519 record key for heads.
fn classical_list() -> (String, VerifiedManifest) {
    let id = "us-customer-kms-acme-v1".to_string();
    let identity = SigningKey::from_bytes(&SEED_ED_IDENTITY);
    let pin = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(identity.verifying_key().to_bytes()))
    );
    let authorities: HashMap<String, AuthorityRecord> = serde_json::from_value(
        json!({ id.clone(): marked_authority(vec![record("1", &ed_public(SEED_ED_RECORD), None, None)]) }),
    )
    .unwrap();
    let verified =
        TrustChainManifest::build_and_sign("1", "2026-11-01T00:00:00Z", authorities, &identity)
            .into_verified(&pin)
            .expect("the classical list verifies under its pin");
    (id, verified)
}

fn tip(n: u8) -> String {
    format!("sha512:{}", hex::encode([n; 64]))
}

fn head(head_type: &str, authority: &str, sequence: u64, prev: &str, tip: &str) -> Value {
    json!({
        "type": head_type,
        "authority_id": authority,
        "proof_sequence": sequence,
        "prev_head_hash": prev,
        "tip_proof_hash": tip,
        "issued_at": ISSUED_AT,
    })
}

fn digest_hex(head: &Value) -> String {
    hex::encode(Sha512::digest(serde_jcs::to_vec(head).expect("JCS")))
}

fn head_hash(head: &Value) -> String {
    format!("sha512:{}", digest_hex(head))
}

/// The Ed25519 message: the head's type, `:` and the hex SHA-512 of its JCS
/// bytes.
fn ed_message(head: &Value) -> String {
    format!("{}:{}", head["type"].as_str().unwrap(), digest_hex(head))
}

/// The ML-DSA-65 message: the tag, a 0x00 byte, then the Ed25519 message.
fn pqc_message(head: &Value) -> Vec<u8> {
    let mut out = b"nanorix-population-head-pqc-v2".to_vec();
    out.push(0x00);
    out.extend_from_slice(ed_message(head).as_bytes());
    out
}

fn ed_sign(message: &[u8]) -> String {
    format!(
        "base64:{}",
        b64(&SigningKey::from_bytes(&SEED_ED_RECORD)
            .sign(message)
            .to_bytes())
    )
}

fn pqc_sign(seed: [u8; 32], message: &[u8]) -> String {
    format!(
        "base64:{}",
        b64(&ml_sign(
            &ml65(seed),
            ML_DSA_65_SIGNING.signature_len(),
            message
        ))
    )
}

/// A head signed with both halves under version 1 and its partner 2.
fn v2(head: Value) -> Value {
    json!({
        "head": head,
        "signing_key_version": "1",
        "signature": ed_sign(ed_message(&head).as_bytes()),
        "pqc_signing_key_version": "2",
        "pqc_signature": pqc_sign(SEED_ML_PARTNER, &pqc_message(&head)),
    })
}

/// A head with the Ed25519 half only.
fn v1(head: Value) -> Value {
    json!({
        "head": head,
        "signing_key_version": "1",
        "signature": ed_sign(ed_message(&head).as_bytes()),
    })
}

/// A chain of `n` heads of `head_type` under `authority`, each naming its own
/// tip, linked from genesis.
fn chain(head_type: &str, authority: &str, n: u64) -> Vec<Value> {
    let mut prev = GENESIS.to_string();
    (1..=n)
        .map(|sequence| {
            let h = head(head_type, authority, sequence, &prev, &tip(sequence as u8));
            prev = head_hash(&h);
            h
        })
        .collect()
}

fn run(heads: &[Value], list: &VerifiedManifest) -> PopulationResult {
    verify_population(&[], heads, Some(list))
}

fn f_of(result: &PopulationResult) -> Value {
    serde_json::to_value(&result.checks.f_head_signatures).unwrap()
}

fn a_of(result: &PopulationResult) -> Value {
    serde_json::to_value(&result.checks.a_chain_links).unwrap()
}

fn not_handed() -> Value {
    json!({"outcome": "not_checked", "reason": "a named proof was not handed"})
}

fn f_failed(reason: Value) -> Value {
    json!({"outcome": "failed", "reason": reason})
}

fn pqc_invalid(sequence: u64, version: &str, reason: &str) -> Value {
    f_failed(json!({
        "type": "head_pqc_signature_invalid",
        "proof_sequence": sequence,
        "pqc_signing_key_version": version,
        "reason": reason,
    }))
}

fn malformed_at(field: &str) -> impl Fn(&Value) -> bool + '_ {
    move |a: &Value| {
        a["outcome"] == "failed"
            && a["reason"]["type"] == "head_malformed"
            && a["reason"]["field"] == field
    }
}

const V1: &str = "nanorix-population-head-v1";
const V2: &str = "nanorix-population-head-v2";

#[test]
fn a_version_2_chain_with_both_halves_passes_f_to_the_unhanded_proof() {
    let (id, list) = hybrid_list();
    for n in [1, 3] {
        let heads: Vec<Value> = chain(V2, &id, n).into_iter().map(v2).collect();
        let result = run(&heads, &list);
        assert_eq!(a_of(&result), json!({"outcome": "ok"}), "{n} heads");
        assert_eq!(f_of(&result), not_handed(), "{n} heads");
    }
}

#[test]
fn the_ed25519_message_of_a_version_2_head_is_155_bytes_under_its_own_tag() {
    let (id, list) = hybrid_list();
    let h = chain(V2, &id, 1).remove(0);
    let message = ed_message(&h);
    assert_eq!(message.len(), 155);
    assert!(message.starts_with("nanorix-population-head-v2:"));
    // The same head signed over the version 1 tag's text fails the Ed25519 half.
    let mut signed = v2(h.clone());
    let v1_text = format!("{V1}:{}", digest_hex(&h));
    signed["signature"] = json!(ed_sign(v1_text.as_bytes()));
    assert_eq!(
        f_of(&run(&[signed], &list)),
        f_failed(
            json!({"type": "head_signature_mismatch", "proof_sequence": 1, "reason": "does_not_verify"})
        )
    );
}

#[test]
fn a_flipped_bit_in_either_half_fails_f() {
    let (id, list) = hybrid_list();
    let good = v2(chain(V2, &id, 1).remove(0));
    for member in ["signature", "pqc_signature"] {
        for byte in [0, 31, 63] {
            let mut doc = good.clone();
            let mut bytes = unb64(doc[member].as_str().unwrap());
            bytes[byte] ^= 0x01;
            doc[member] = json!(format!("base64:{}", b64(&bytes)));
            let expected = if member == "signature" {
                f_failed(
                    json!({"type": "head_signature_mismatch", "proof_sequence": 1, "reason": "does_not_verify"}),
                )
            } else {
                pqc_invalid(1, "2", "does_not_verify")
            };
            assert_eq!(f_of(&run(&[doc], &list)), expected, "{member} byte {byte}");
        }
    }
}

#[test]
fn the_ml_dsa_half_signs_the_tag_the_separator_and_the_text() {
    let (id, list) = hybrid_list();
    let h = chain(V2, &id, 1).remove(0);
    let text = ed_message(&h).into_bytes();
    let joined = |tag: &[u8], sep: &[u8]| [tag, sep, &text[..]].concat();
    let wrong_messages: Vec<(&str, Vec<u8>)> = vec![
        ("the text alone", text.clone()),
        ("no 0x00", joined(b"nanorix-population-head-pqc-v2", b"")),
        (
            "0x01 for 0x00",
            joined(b"nanorix-population-head-pqc-v2", b"\x01"),
        ),
        (
            "the version 1 tag",
            joined(b"nanorix-population-head-pqc-v1", b"\x00"),
        ),
        (
            "the tick's tag",
            joined(b"nanorix-population-tick-pqc-v1", b"\x00"),
        ),
        (
            "the key list's tag",
            joined(b"nanorix-key-list-pqc-v1", b"\x00"),
        ),
    ];
    for (name, message) in wrong_messages {
        let mut doc = v2(h.clone());
        doc["pqc_signature"] = json!(pqc_sign(SEED_ML_PARTNER, &message));
        assert_eq!(
            f_of(&run(&[doc], &list)),
            pqc_invalid(1, "2", "does_not_verify"),
            "{name}"
        );
    }
}

#[test]
fn the_ml_dsa_half_verifies_only_under_the_partner() {
    let (id, list) = hybrid_list();
    let h = chain(V2, &id, 1).remove(0);

    let mut other_key = v2(h.clone());
    other_key["pqc_signature"] = json!(pqc_sign(SEED_ML_OTHER, &pqc_message(&h)));
    assert_eq!(
        f_of(&run(&[other_key], &list)),
        pqc_invalid(1, "2", "does_not_verify")
    );

    // Version 3 is an ML-DSA-65 record of the authority, but not version 1's
    // partner, even with a signature its own key makes.
    for (version, seed) in [
        ("3", SEED_ML_OTHER),
        ("1", SEED_ML_PARTNER),
        ("9", SEED_ML_PARTNER),
    ] {
        let mut doc = v2(h.clone());
        doc["pqc_signing_key_version"] = json!(version);
        doc["pqc_signature"] = json!(pqc_sign(seed, &pqc_message(&h)));
        assert_eq!(
            f_of(&run(&[doc], &list)),
            f_failed(json!({
                "type": "head_signing_key_unknown",
                "proof_sequence": 1,
                "authority_id": id,
                "signing_key_version": version,
            })),
            "pqc version {version}"
        );
    }
}

#[test]
fn a_short_or_long_ml_dsa_signature_is_malformed() {
    let (id, list) = hybrid_list();
    let good = v2(chain(V2, &id, 1).remove(0));
    let sig = unb64(good["pqc_signature"].as_str().unwrap());
    for bytes in [
        sig[..3308].to_vec(),
        [&sig[..], &[0u8][..]].concat(),
        Vec::new(),
    ] {
        let mut doc = good.clone();
        doc["pqc_signature"] = json!(format!("base64:{}", b64(&bytes)));
        assert_eq!(
            f_of(&run(&[doc], &list)),
            pqc_invalid(1, "2", "malformed"),
            "{} bytes",
            bytes.len()
        );
    }
}

#[test]
fn a_version_2_head_missing_either_half_is_refused() {
    let (id, list) = hybrid_list();
    let good = v2(chain(V2, &id, 1).remove(0));
    for member in ["pqc_signature", "pqc_signing_key_version", "signature"] {
        let mut doc = good.clone();
        doc.as_object_mut().unwrap().remove(member);
        let result = run(&[doc], &list);
        let a = a_of(&result);
        let at = if member == "signature" { "" } else { member };
        assert!(malformed_at(at)(&a), "{member}: (a) is {a}");
        assert_eq!(
            f_of(&result),
            json!({"outcome": "not_checked", "reason": "a handed head is malformed"}),
            "{member}"
        );
        assert_eq!(
            serde_json::to_value(result.verdict).unwrap(),
            json!("failed")
        );
    }
    for (member, value) in [
        (
            "pqc_signature",
            json!(good["pqc_signature"]
                .as_str()
                .unwrap()
                .trim_start_matches("base64:")),
        ),
        ("pqc_signing_key_version", json!("")),
        ("pqc_signing_key_version", json!("V2")),
    ] {
        let mut doc = good.clone();
        doc[member] = value;
        assert!(malformed_at(member)(&a_of(&run(&[doc], &list))), "{member}");
    }
}

#[test]
fn a_version_1_head_carries_no_ml_dsa_member() {
    let (id, list) = classical_list();
    let h = chain(V1, &id, 1).remove(0);
    for member in ["pqc_signing_key_version", "pqc_signature"] {
        let mut doc = v1(h.clone());
        doc[member] = json!(if member == "pqc_signature" {
            "base64:AA=="
        } else {
            "2"
        });
        assert!(malformed_at(member)(&a_of(&run(&[doc], &list))), "{member}");
    }
}

#[test]
fn a_version_1_head_with_a_null_ml_dsa_member_is_refused() {
    let (id, list) = classical_list();
    let h = chain(V1, &id, 1).remove(0);
    for member in ["pqc_signing_key_version", "pqc_signature"] {
        let mut doc = v1(h.clone());
        doc[member] = Value::Null;
        let result = run(&[doc], &list);
        assert!(
            malformed_at(member)(&a_of(&result)),
            "{member}: (a) is {}",
            a_of(&result)
        );
        assert_eq!(
            f_of(&result),
            json!({"outcome": "not_checked", "reason": "a handed head is malformed"}),
            "{member}"
        );
    }
}

#[test]
fn the_registered_tags_and_the_record_and_key_list_pqc_tags_prefix_no_other() {
    let mut tags: Vec<&str> = SIGNED_MESSAGE_TAGS.to_vec();
    tags.push(RECORD_TRANSCRIPT_TAG);
    tags.push(KEY_LIST_PQC_TAG);
    for (i, a) in tags.iter().enumerate() {
        for (j, b) in tags.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
                assert!(!b.starts_with(a), "{a} prefixes {b}");
            }
        }
    }
}

#[test]
fn under_a_hybrid_pin_the_first_version_1_head_is_refused() {
    let (id, list) = hybrid_list();
    let refusal = |sequence: u64| {
        f_failed(json!({
            "type": "head_algorithm_unsupported",
            "proof_sequence": sequence,
            "found": "Ed25519 (hybrid pin)",
        }))
    };
    let all_v1: Vec<Value> = chain(V1, &id, 2).into_iter().map(v1).collect();
    assert_eq!(f_of(&run(&all_v1, &list)), refusal(1));

    // Version 2 at sequence 1, version 1 at sequence 2, linked.
    let first = head(V2, &id, 1, GENESIS, &tip(1));
    let second = head(V1, &id, 2, &head_hash(&first), &tip(2));
    let mixed = vec![v2(first), v1(second)];
    let result = run(&mixed, &list);
    assert_eq!(a_of(&result), json!({"outcome": "ok"}));
    assert_eq!(f_of(&result), refusal(2));
}

#[test]
fn under_a_classical_pin_a_version_2_head_is_refused() {
    let (id, list) = classical_list();
    let control: Vec<Value> = chain(V1, &id, 1).into_iter().map(v1).collect();
    assert_eq!(f_of(&run(&control, &list)), not_handed());
    let heads: Vec<Value> = chain(V2, &id, 1).into_iter().map(v2).collect();
    assert_eq!(
        f_of(&run(&heads, &list)),
        f_failed(json!({
            "type": "head_algorithm_unsupported",
            "proof_sequence": 1,
            "found": "nanorix-population-head-v2 (classical pin)",
        }))
    );
}

#[test]
fn a_version_2_head_naming_a_record_with_pqc_attestation_matches_no_proof() {
    let (id, list) = hybrid_list();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json");
    let mut proof: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    proof["authority_id"] = json!(id);
    proof["signing_key_version"] = json!("1");
    let key = SigningKey::from_bytes(&SEED_ED_RECORD);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    proof["attestation"]["public_key"] =
        json!(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = json!(format!("base64:{}", b64(&sig.to_bytes())));
    // The head names the record by its leaf without the ML-DSA half, the only
    // leaf this verifier reads; the record carries `pqc_attestation`, so it
    // has no leaf here and (c) matches no proof.
    let named = tip_proof_hash(&proof).expect("the leaf without pqc_attestation");
    proof["pqc_attestation"] = json!({
        "algorithm": "ML-DSA-65",
        "key_id": "nrx-pqc-v2",
        "public_key": "base64:CCCC",
        "signature": "base64:DDDD",
    });
    let h = head(V2, &id, 1, GENESIS, &named);
    let result = verify_population(&[proof], &[v2(h)], Some(&list));
    assert_eq!(
        serde_json::to_value(&result.checks.c_tips_match_proofs).unwrap(),
        json!({
            "outcome": "failed",
            "reason": {"type": "tip_matches_no_proof", "proof_sequence": 1, "tip_proof_hash": named},
        })
    );
    assert_eq!(f_of(&result), not_handed());
}
