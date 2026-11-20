//! Properties of the hybrid key list, each over at least 10,000 seeded cases.
//!
//! - Under a hybrid pin no record, version 1 population head or boundary
//!   attestation is reported a success, signed or not, with or without the
//!   pin or the key list, because none of them carries an ML-DSA half this
//!   build checks. (f) checks a version 2 head's two halves
//!   (`tests/population_head_v2.rs`).
//! - The hybrid pin's pre-image encoding is injective: it decodes back to the
//!   one key pair it was made from.
//! - Any one-bit change to either identity key, a partner member, any other
//!   signed member or either list signature makes the list fail to load.
//! - A list built with `build_unsigned_hybrid` and `attach` verifies under
//!   its own pin.
//! - `attach` refuses a truncated, lengthened or altered signature, or one
//!   made over another list.
//!
//! The cases come from a fixed-seed generator, so every run sees the same
//! ones. Each loop prints its case count and time (`--nocapture`).

// These tests read the wire field `valid`, which is deprecated for callers.
#![allow(deprecated)]

use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::population_head::{
    genesis_prev_head_hash, signed_message, tip_proof_hash, verify_population, PopulationCheck,
    PopulationFailureReason, PopulationHead, HYBRID_HEAD_CHECK_MISSING, POPULATION_HEAD_TYPE_V1,
};
use nanorix_verify::trust_chain::{
    hybrid_pin, AuthorityRecord, TrustChainManifest, VerifiedManifest,
};
use nanorix_verify::{
    verify_auditproof, verify_boundary_attestation, verify_boundary_chain, VerifierPolicy,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

const CASES: usize = 10_000;
const SEED: u64 = 0x5184_1a1b_2026_1116;

const SEED_ED_IDENTITY: [u8; 32] = [0x51; 32];
const SEED_ML_IDENTITY: [u8; 32] = [0x52; 32];
const SEED_ED_1: [u8; 32] = [0x61; 32];
const SEED_ML_2: [u8; 32] = [0x71; 32];

/// SplitMix64: a small fixed-seed generator, so no new dependency is needed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
        out
    }

    fn fill(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn report(name: &str, cases: usize, start: Instant) {
    eprintln!(
        "property {name}: {cases} cases in {:.2}s (seed {SEED:#x})",
        start.elapsed().as_secs_f64()
    );
}

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

fn ml87(seed: [u8; 32]) -> PqdsaKeyPair {
    PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &seed).expect("ML-DSA-87 key from seed")
}

fn ml87_sign(pair: &PqdsaKeyPair, message: &[u8]) -> Vec<u8> {
    let mut sig = vec![0u8; ML_DSA_87_SIGNING.signature_len()];
    let n = pair.sign(message, &mut sig).expect("ML-DSA-87 signs");
    sig.truncate(n);
    sig
}

fn ml65_public(seed: [u8; 32]) -> Vec<u8> {
    PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed)
        .expect("ML-DSA-65 key from seed")
        .public_key()
        .as_ref()
        .to_vec()
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

fn authority(active: Vec<Value>) -> Value {
    json!({
        "display_name": "Acme Health signing authority",
        "active_versions": active,
        "archived_versions": [],
        "revoked": false,
    })
}

fn byoc_id(base: &str, pin: &str) -> String {
    format!("{base}-hybrid1.{}-v1", &pin["hybrid1-sha256:".len()..])
}

fn unsigned(authorities: Value, ed: &[u8; 32], ml: &[u8]) -> TrustChainManifest {
    let map: HashMap<String, AuthorityRecord> =
        serde_json::from_value(authorities).expect("authorities parse");
    TrustChainManifest::build_unsigned_hybrid("1", "2026-11-01T00:00:00Z", map, ed, ml)
}

/// The shared vectors' base list: one BYOC authority, Ed25519 version 1 with
/// its ML-DSA-65 partner 2, signed by both identity keys through `attach`.
struct Base {
    pin: String,
    id: String,
    unsigned: TrustChainManifest,
    verified: VerifiedManifest,
}

fn base() -> Base {
    let ed = ed_public(SEED_ED_IDENTITY);
    let ml_pair = ml87(SEED_ML_IDENTITY);
    let ml = ml_pair.public_key().as_ref().to_vec();
    let pin = hybrid_pin(&ed, &ml);
    let id = byoc_id("us-customer-kms-acme", &pin);
    let records = vec![
        record("1", &ed_public(SEED_ED_1), None, Some("2")),
        record("2", &ml65_public(SEED_ML_2), Some("ML-DSA-65"), None),
    ];
    let m = unsigned(json!({ id.clone(): authority(records) }), &ed, &ml);
    let ed_sig = SigningKey::from_bytes(&SEED_ED_IDENTITY)
        .sign(&m.signed_payload().unwrap())
        .to_bytes();
    let ml_sig = ml87_sign(&ml_pair, &m.pqc_signed_message().unwrap());
    let verified = m
        .clone()
        .attach(&ed_sig, &ml_sig)
        .expect("the base list verifies under its own pin");
    Base {
        pin,
        id,
        unsigned: m,
        verified,
    }
}

fn corpus_proof() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json");
    serde_json::from_slice(&std::fs::read(path).expect("read corpus fixture")).expect("parse")
}

fn sign_proof(mut proof: Value, authority: &str, version: &str, key: &SigningKey) -> Value {
    proof["authority_id"] = json!(authority);
    proof["signing_key_version"] = json!(version);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    proof["attestation"]["public_key"] =
        json!(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = json!(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

/// Every string or boolean leaf of `v`, as a JSON pointer, skipping `skip`.
fn leaves(v: &Value, at: String, skip: &[&str], out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if at.is_empty() && skip.contains(&k.as_str()) {
                    continue;
                }
                let key = k.replace('~', "~0").replace('/', "~1");
                leaves(child, format!("{at}/{key}"), skip, out);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                leaves(child, format!("{at}/{i}"), skip, out);
            }
        }
        Value::String(_) | Value::Bool(_) => out.push(at),
        _ => {}
    }
}

/// Flip one bit of the leaf at `pointer`: a low bit of one byte of a string,
/// which keeps it ASCII, or a boolean's value.
fn flip_leaf(doc: &mut Value, pointer: &str, rng: &mut Rng) {
    let leaf = doc.pointer_mut(pointer).expect("leaf");
    match leaf {
        Value::Bool(b) => *b = !*b,
        Value::String(s) if !s.is_empty() && s.is_ascii() => {
            let mut bytes = s.clone().into_bytes();
            let i = rng.below(bytes.len());
            bytes[i] ^= 1 << rng.below(7);
            *s = String::from_utf8(bytes).expect("ASCII stays UTF-8");
        }
        Value::String(s) => s.push('x'),
        _ => unreachable!("only string and boolean leaves are picked"),
    }
}

/// Flip one bit of the decoded bytes of a base64 member and re-encode it,
/// keeping its `base64:` prefix if it had one.
fn flip_decoded(doc: &mut Value, pointer: &str, rng: &mut Rng) {
    let text = doc
        .pointer(pointer)
        .and_then(Value::as_str)
        .expect("member");
    let prefixed = text.starts_with("base64:");
    let mut bytes = unb64(text);
    let i = rng.below(bytes.len());
    bytes[i] ^= 1 << rng.below(8);
    let encoded = if prefixed {
        format!("base64:{}", b64(&bytes))
    } else {
        b64(&bytes)
    };
    *doc.pointer_mut(pointer).unwrap() = json!(encoded);
}

fn loads(doc: &Value, pin: &str) -> bool {
    serde_json::from_value::<TrustChainManifest>(doc.clone())
        .is_ok_and(|m| m.verify_signature(pin).is_ok())
}

#[test]
fn under_a_hybrid_pin_no_record_is_a_success() {
    let base = base();
    let manifest = base.verified.manifest().clone();
    let proof = corpus_proof();
    let listed = SigningKey::from_bytes(&SEED_ED_1);
    let policies = [
        VerifierPolicy {
            trust_chain: Some(manifest.clone()),
            pinned_identity_fingerprint: Some(base.pin.clone()),
            ..Default::default()
        },
        VerifierPolicy {
            trust_chain: Some(manifest),
            ..Default::default()
        },
        VerifierPolicy {
            pinned_identity_fingerprint: Some(base.pin.clone()),
            ..Default::default()
        },
    ];
    // The same records do succeed without the pin and the list, so the loop
    // is not refusing them for another reason.
    let genuine = sign_proof(proof.clone(), &base.id, "1", &listed);
    assert!(verify_auditproof(&genuine, &[], &VerifierPolicy::default()).valid);

    let mut rng = Rng(SEED);
    let start = Instant::now();
    for case in 0..CASES {
        let key = if rng.below(4) == 0 {
            SigningKey::from_bytes(&rng.bytes())
        } else {
            listed.clone()
        };
        let version = ["1", "2", "9"][rng.below(3)];
        let authority = if rng.below(8) == 0 {
            "us-kms-nanorix-v1"
        } else {
            base.id.as_str()
        };
        let mut doc = sign_proof(proof.clone(), authority, version, &key);
        match rng.below(4) {
            0 => {
                for member in ["signature", "public_key"] {
                    doc["attestation"].as_object_mut().unwrap().remove(member);
                }
            }
            1 => {
                let member = ["signature", "public_key"][rng.below(2)];
                doc["attestation"].as_object_mut().unwrap().remove(member);
            }
            _ => {}
        }
        let policy = &policies[rng.below(policies.len())];
        let result = verify_auditproof(&doc, &[], policy);
        assert!(
            !result.valid,
            "case {case}: a record ended valid under a hybrid pin"
        );
    }
    report("record_never_valid_under_a_hybrid_pin", CASES, start);
}

/// One case's head chain under `authority`: `tip` in every head, each head
/// signed with the listed key or the case's stranger key at a version, as
/// `picks` says (`true` for the listed key).
fn heads(
    authority: &str,
    tip: &str,
    picks: &[(bool, &str)],
    listed: &SigningKey,
    stranger: &SigningKey,
) -> Vec<Value> {
    let mut prev = genesis_prev_head_hash();
    let mut out = Vec::with_capacity(picks.len());
    for (sequence, (by_listed, version)) in (1..).zip(picks) {
        let head = PopulationHead {
            head_type: POPULATION_HEAD_TYPE_V1.to_string(),
            authority_id: authority.to_string(),
            proof_sequence: sequence,
            prev_head_hash: prev.clone(),
            tip_proof_hash: tip.to_string(),
            issued_at: "2026-11-01T00:00:00Z".to_string(),
        };
        let key = if *by_listed { listed } else { stranger };
        let message = signed_message(&head).expect("head message");
        prev = nanorix_verify::population_head::head_hash(&head).expect("head hash");
        out.push(json!({
            "head": head,
            "signing_key_version": version,
            "signature": format!("base64:{}", b64(&key.sign(message.as_bytes()).to_bytes())),
        }));
    }
    out
}

#[test]
fn under_a_hybrid_pin_no_version_1_population_head_signature_is_accepted() {
    let base = base();
    let listed = SigningKey::from_bytes(&SEED_ED_1);
    let proof = corpus_proof();

    // The control: the same heads under a classical list whose authority is
    // marked for heads, with their proof handed, end (f) Ok exactly when every
    // head is by the listed key at its version. So the hybrid refusal below is
    // the gate, not some other check.
    let classical_id = "us-customer-kms-acme-v1";
    let mut marked = authority(vec![record("1", &ed_public(SEED_ED_1), None, None)]);
    marked["emits_population_heads"] = json!(true);
    let identity = SigningKey::from_bytes(&SEED_ED_IDENTITY);
    let classical_pin = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(identity.verifying_key().to_bytes()))
    );
    let classical: VerifiedManifest = TrustChainManifest::build_and_sign(
        "1",
        "2026-11-01T00:00:00Z",
        serde_json::from_value(json!({ classical_id: marked })).unwrap(),
        &identity,
    )
    .into_verified(&classical_pin)
    .expect("the marked classical list verifies under its pin");
    let hybrid_proof = sign_proof(proof.clone(), &base.id, "1", &listed);
    let classical_proof = sign_proof(proof, classical_id, "1", &listed);
    let hybrid_tip = tip_proof_hash(&hybrid_proof).expect("tip");
    let classical_tip = tip_proof_hash(&classical_proof).expect("tip");

    let gate = PopulationCheck::Failed {
        reason: PopulationFailureReason::HeadAlgorithmUnsupported {
            proof_sequence: 1,
            found: HYBRID_HEAD_CHECK_MISSING.to_string(),
        },
    };
    let mut rng = Rng(SEED ^ 1);
    let start = Instant::now();
    let mut control_ok = 0;
    for case in 0..CASES {
        let stranger = SigningKey::from_bytes(&rng.bytes());
        let picks: Vec<(bool, &str)> = (0..1 + rng.below(3))
            .map(|_| (rng.below(4) != 0, ["1", "2"][rng.below(2)]))
            .collect();

        let hybrid_heads = heads(&base.id, &hybrid_tip, &picks, &listed, &stranger);
        let result = verify_population(
            std::slice::from_ref(&hybrid_proof),
            &hybrid_heads,
            Some(&base.verified),
        );
        assert_eq!(
            result.checks.f_head_signatures, gate,
            "case {case}: (f) under a hybrid pin is not the typed refusal"
        );

        let classical_heads = heads(classical_id, &classical_tip, &picks, &listed, &stranger);
        let control = verify_population(
            std::slice::from_ref(&classical_proof),
            &classical_heads,
            Some(&classical),
        );
        let all_listed = picks.iter().all(|&(by_listed, v)| by_listed && v == "1");
        assert_eq!(
            control.checks.f_head_signatures == PopulationCheck::Ok,
            all_listed,
            "case {case}: the classical control gave {:?}",
            control.checks.f_head_signatures
        );
        control_ok += usize::from(all_listed);
    }
    eprintln!("  control cases with (f) Ok under the marked classical list: {control_ok}");
    report(
        "version_1_population_head_never_accepted_under_a_hybrid_pin",
        CASES,
        start,
    );
}

#[test]
fn under_a_hybrid_pin_no_boundary_attestation_is_valid() {
    let base = base();
    let manifest = base.verified.manifest().clone();
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/boundary/0001_single_signed.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(verify_boundary_attestation(&fixture, &VerifierPolicy::default()).valid);
    let policies = [
        VerifierPolicy {
            trust_chain: Some(manifest.clone()),
            pinned_identity_fingerprint: Some(base.pin.clone()),
            ..Default::default()
        },
        VerifierPolicy {
            trust_chain: Some(manifest),
            ..Default::default()
        },
        VerifierPolicy {
            pinned_identity_fingerprint: Some(base.pin.clone()),
            ..Default::default()
        },
    ];
    let mut fields = Vec::new();
    leaves(&fixture, String::new(), &[], &mut fields);
    let mut rng = Rng(SEED ^ 2);
    let start = Instant::now();
    for case in 0..CASES {
        let mut doc = fixture.clone();
        match rng.below(4) {
            0 => {
                for member in ["signature", "public_key"] {
                    doc["attestation"].as_object_mut().unwrap().remove(member);
                }
            }
            1 => {
                let member = ["signature", "public_key"][rng.below(2)];
                doc["attestation"].as_object_mut().unwrap().remove(member);
            }
            2 => {
                let field = fields[rng.below(fields.len())].clone();
                flip_leaf(&mut doc, &field, &mut rng);
            }
            _ => {}
        }
        let policy = &policies[rng.below(policies.len())];
        let one = verify_boundary_attestation(&doc, policy);
        assert!(
            !one.valid && !one.trust_anchored,
            "case {case}: a boundary attestation ended valid under a hybrid pin"
        );
        let chain = verify_boundary_chain(&[doc], policy);
        assert!(
            !chain.valid,
            "case {case}: a chain ended valid under a hybrid pin"
        );
    }
    report(
        "boundary_attestation_never_valid_under_a_hybrid_pin",
        CASES,
        start,
    );
}

/// The pre-image the hybrid pin hashes, as the amendment writes it.
fn preimage(ed: &[u8], ml: &[u8]) -> Vec<u8> {
    let mut pre = b"nanorix-identity-hybrid-v1\x00Ed25519\x00".to_vec();
    pre.extend_from_slice(ed);
    pre.extend_from_slice(b"\x00ML-DSA-87\x00");
    pre.extend_from_slice(ml);
    pre
}

/// Read a pre-image back into its two keys, refusing anything not of the
/// encoding's exact shape.
fn decode_preimage(pre: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let head = b"nanorix-identity-hybrid-v1\x00Ed25519\x00";
    let middle = b"\x00ML-DSA-87\x00";
    let rest = pre.strip_prefix(&head[..])?;
    let (ed, rest) = rest.split_at_checked(32)?;
    let ml = rest.strip_prefix(&middle[..])?;
    (ml.len() == 2592).then(|| (ed.try_into().unwrap(), ml.to_vec()))
}

#[test]
fn the_pin_preimage_decodes_back_to_its_one_key_pair() {
    let mut rng = Rng(SEED ^ 3);
    let start = Instant::now();
    for case in 0..CASES {
        let ed: [u8; 32] = rng.bytes();
        let ml = rng.fill(2592);
        let pre = preimage(&ed, &ml);
        assert_eq!(
            hybrid_pin(&ed, &ml),
            format!("hybrid1-sha256:{}", hex::encode(Sha256::digest(&pre))),
            "case {case}: the library hashes another encoding"
        );
        assert_eq!(
            decode_preimage(&pre),
            Some((ed, ml.clone())),
            "case {case}: the pre-image does not decode to the pair it came from"
        );
        // A different pair: one bit of either key, so a different pre-image.
        let (mut ed2, mut ml2) = (ed, ml.clone());
        if rng.below(2) == 0 {
            ed2[rng.below(32)] ^= 1 << rng.below(8);
        } else {
            ml2[rng.below(2592)] ^= 1 << rng.below(8);
        }
        assert_ne!(
            pre,
            preimage(&ed2, &ml2),
            "case {case}: two pairs share a pre-image"
        );
    }
    report("pin_preimage_injective", CASES, start);
}

#[test]
fn any_one_bit_change_to_a_signed_or_identity_member_or_a_signature_fails() {
    let base = base();
    let list = serde_json::to_value(base.verified.manifest()).unwrap();
    assert!(loads(&list, &base.pin), "the unchanged list loads");
    let mut signed = Vec::new();
    leaves(
        &list,
        String::new(),
        &["manifest_signature", "pqc_manifest_signature"],
        &mut signed,
    );
    let partner = format!(
        "/authorities/{}/active_versions/0/pqc_partner_version",
        base.id
    );
    assert!(signed.contains(&partner));
    let mut rng = Rng(SEED ^ 4);
    let start = Instant::now();
    let mut kinds = [0usize; 5];
    for case in 0..CASES {
        let mut doc = list.clone();
        let kind = rng.below(5);
        kinds[kind] += 1;
        match kind {
            0 => flip_decoded(&mut doc, "/identity_public_key_b64", &mut rng),
            1 => flip_decoded(&mut doc, "/pqc_identity_public_key_b64", &mut rng),
            2 => flip_leaf(&mut doc, &partner, &mut rng),
            3 => {
                let field = signed[rng.below(signed.len())].clone();
                flip_leaf(&mut doc, &field, &mut rng);
            }
            _ => {
                let member = ["/manifest_signature", "/pqc_manifest_signature"][rng.below(2)];
                flip_decoded(&mut doc, member, &mut rng);
            }
        }
        assert!(
            !loads(&doc, &base.pin),
            "case {case} (kind {kind}): a list with one bit changed still loads"
        );
    }
    eprintln!(
        "  identity Ed25519 {}, identity ML-DSA-87 {}, partner {}, other signed member {}, signature {}",
        kinds[0], kinds[1], kinds[2], kinds[3], kinds[4]
    );
    report("one_bit_change_fails", CASES, start);
}

/// Pools of keys made once, so each case only signs and checks.
struct Pools {
    ml87: Vec<PqdsaKeyPair>,
    ml65: Vec<Vec<u8>>,
}

fn pools(rng: &mut Rng) -> Pools {
    Pools {
        ml87: (0..16).map(|_| ml87(rng.bytes())).collect(),
        ml65: (0..16).map(|_| ml65_public(rng.bytes())).collect(),
    }
}

#[test]
fn a_list_built_and_attached_verifies_under_its_own_pin() {
    let mut rng = Rng(SEED ^ 5);
    let pools = pools(&mut rng);
    let start = Instant::now();
    for case in 0..CASES {
        let ed_seed: [u8; 32] = rng.bytes();
        let ed = ed_public(ed_seed);
        let ml_pair = &pools.ml87[rng.below(pools.ml87.len())];
        let ml = ml_pair.public_key().as_ref().to_vec();
        let pin = hybrid_pin(&ed, &ml);
        let mut ml65: Vec<usize> = (0..pools.ml65.len()).collect();
        let mut authorities = serde_json::Map::new();
        for base_name in ["us-customer-kms-acme", "eu-customer-kms-acme"]
            .iter()
            .take(1 + rng.below(2))
        {
            let mut records = Vec::new();
            for pair in 0..1 + rng.below(3) {
                let ed_version = (2 * pair + 1).to_string();
                let ml_version = (2 * pair + 2).to_string();
                let ml_key = &pools.ml65[ml65.swap_remove(rng.below(ml65.len()))];
                records.push(record(
                    &ed_version,
                    &ed_public(rng.bytes()),
                    None,
                    Some(&ml_version),
                ));
                records.push(record(&ml_version, ml_key, Some("ML-DSA-65"), None));
            }
            authorities.insert(byoc_id(base_name, &pin), authority(records));
        }
        let m = unsigned(Value::Object(authorities), &ed, &ml);
        let ed_sig = SigningKey::from_bytes(&ed_seed)
            .sign(&m.signed_payload().unwrap())
            .to_bytes();
        let ml_sig = ml87_sign(ml_pair, &m.pqc_signed_message().unwrap());
        let verified = m
            .attach(&ed_sig, &ml_sig)
            .unwrap_or_else(|e| panic!("case {case}: attach refused a list it built: {e:?}"));
        let written = serde_json::to_vec(verified.manifest()).unwrap();
        let read: TrustChainManifest = serde_json::from_slice(&written).unwrap();
        assert_eq!(
            read.verify_signature(&pin),
            Ok(()),
            "case {case}: the written list does not verify under its own pin"
        );
    }
    report("build_and_attach_round_trip", CASES, start);
}

#[test]
fn attach_refuses_a_wrong_length_altered_or_foreign_signature() {
    let base = base();
    let ml_pair = ml87(SEED_ML_IDENTITY);
    let ed_key = SigningKey::from_bytes(&SEED_ED_IDENTITY);
    let m = base.unsigned.clone();
    let ed_sig = ed_key.sign(&m.signed_payload().unwrap()).to_bytes();
    let ml_sig = ml87_sign(&ml_pair, &m.pqc_signed_message().unwrap());
    // Another list from the same identity: the same authority with one more
    // version pair.
    let mut other_records = vec![
        record("1", &ed_public(SEED_ED_1), None, Some("2")),
        record("2", &ml65_public(SEED_ML_2), Some("ML-DSA-65"), None),
    ];
    other_records.push(record("3", &ed_public([0x63; 32]), None, Some("4")));
    other_records.push(record(
        "4",
        &ml65_public([0x72; 32]),
        Some("ML-DSA-65"),
        None,
    ));
    let other = unsigned(
        json!({ base.id.clone(): authority(other_records) }),
        &ed_public(SEED_ED_IDENTITY),
        ml_pair.public_key().as_ref(),
    );
    let other_ed = ed_key.sign(&other.signed_payload().unwrap()).to_bytes();
    let other_ml = ml87_sign(&ml_pair, &other.pqc_signed_message().unwrap());
    assert!(m.clone().attach(&ed_sig, &ml_sig).is_ok());
    assert!(other.clone().attach(&other_ed, &other_ml).is_ok());

    // `attach` takes the Ed25519 signature as exactly 64 bytes, so only the
    // ML-DSA-87 signature can have a wrong length.
    let mut rng = Rng(SEED ^ 6);
    let start = Instant::now();
    let mut kinds = [0usize; 6];
    for case in 0..CASES {
        let kind = rng.below(6);
        kinds[kind] += 1;
        let (ed, ml): ([u8; 64], Vec<u8>) = match kind {
            0 => (ed_sig, ml_sig[..rng.below(ml_sig.len())].to_vec()),
            1 => {
                let mut longer = ml_sig.clone();
                let extra = 1 + rng.below(64);
                longer.extend(rng.fill(extra));
                (ed_sig, longer)
            }
            2 => {
                let mut flipped = ml_sig.clone();
                let at = rng.below(flipped.len());
                flipped[at] ^= 1 << rng.below(8);
                (ed_sig, flipped)
            }
            3 => {
                let mut flipped = ed_sig;
                flipped[rng.below(64)] ^= 1 << rng.below(8);
                (flipped, ml_sig.clone())
            }
            4 => {
                if rng.below(2) == 0 {
                    (other_ed, ml_sig.clone())
                } else {
                    (ed_sig, other_ml.clone())
                }
            }
            _ => (rng.bytes(), rng.fill(ml_sig.len())),
        };
        assert!(
            m.clone().attach(&ed, &ml).is_err(),
            "case {case} (kind {kind}): attach took a signature it must refuse"
        );
    }
    eprintln!(
        "  truncated {}, lengthened {}, ML-DSA bit {}, Ed25519 bit {}, other list's {}, random {}",
        kinds[0], kinds[1], kinds[2], kinds[3], kinds[4], kinds[5]
    );
    report("attach_fault_injection", CASES, start);
}
