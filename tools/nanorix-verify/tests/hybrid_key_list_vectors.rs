//! Hybrid key-list vectors shared by every verifier (
//! H5's Key-list row, H7.2 to H7.5).
//!
//! The Rust library is the reference. This test builds each key list in
//! memory from fixed seeds, runs the reference on every case, and compares the
//! result with the files committed under `fixtures/trust_chain_hybrid/`. Go,
//! Python, TypeScript and the browser page replay the same files.
//!
//! ML-DSA signing in aws-lc-rs 1.18.1 is hedged and takes no randomness
//! option, so a regenerated `pqc_manifest_signature` differs from the
//! committed one on every run. The comparison therefore masks that one member
//! in every key list, and the reference is also run on every committed file,
//! so a committed signature that does not verify cannot pass as one that does.
//! The fixture README says so.
//!
//! Two signatures cannot be made here: one with the tag given as the FIPS 204
//! context, and a HashML-DSA one. They come from
//! `scripts/gen_hybrid_foreign_signatures.py` into `foreign_signatures.json`,
//! which records the SHA-512 of the payload it signed, checked below.
//!
//! To rewrite the committed files after an intended change, run the test with
//! `NANORIX_REGEN_HYBRID_KEY_LIST_VECTORS=1`.

// These tests pin the wire field `valid`, which is deprecated for callers.
#![allow(deprecated)]

use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::trust_chain::{
    compare_partners, hybrid_pin, AuthorityRecord, TrustChainManifest, KEY_LIST_PQC_TAG,
};
use nanorix_verify::{verify_auditproof, VerifierPolicy};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const BASE: &str = "us-customer-kms-acme";
const CLASSICAL_ID: &str = "us-customer-kms-acme-v1";

const SEED_ED_IDENTITY: [u8; 32] = [0x51; 32];
const SEED_ML_IDENTITY: [u8; 32] = [0x52; 32];
const SEED_OTHER_ED_IDENTITY: [u8; 32] = [0x53; 32];
const SEED_OTHER_ML_IDENTITY: [u8; 32] = [0x54; 32];
const SEED_ED_1: [u8; 32] = [0x61; 32];
const SEED_ED_3: [u8; 32] = [0x63; 32];
const SEED_ED_STRANGER: [u8; 32] = [0x65; 32];
const SEED_ML_2: [u8; 32] = [0x71; 32];
const SEED_ML_4: [u8; 32] = [0x72; 32];
const SEED_ML_STRANGER: [u8; 32] = [0x73; 32];

const MASK: &str = "<regenerated each run: ML-DSA signing is hedged>";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn ed_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn ed_public(seed: [u8; 32]) -> [u8; 32] {
    ed_key(seed).verifying_key().to_bytes()
}

fn ml87(seed: [u8; 32]) -> PqdsaKeyPair {
    PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, &seed).expect("ML-DSA-87 key from seed")
}

fn ml65_public(seed: [u8; 32]) -> Vec<u8> {
    PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed)
        .expect("ML-DSA-65 key from seed")
        .public_key()
        .as_ref()
        .to_vec()
}

fn ml87_public(seed: [u8; 32]) -> Vec<u8> {
    ml87(seed).public_key().as_ref().to_vec()
}

fn ml87_sign(seed: [u8; 32], message: &[u8]) -> Vec<u8> {
    let pair = ml87(seed);
    let mut sig = vec![0u8; ML_DSA_87_SIGNING.signature_len()];
    let n = pair.sign(message, &mut sig).expect("ML-DSA-87 signs");
    sig.truncate(n);
    sig
}

fn sha256_fp(key: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(key)))
}

fn pin_of(ed: [u8; 32], ml: [u8; 32]) -> String {
    hybrid_pin(&ed_public(ed), &ml87_public(ml))
}

fn pin_hex(pin: &str) -> &str {
    pin.strip_prefix("hybrid1-sha256:").expect("hybrid pin")
}

fn byoc_id(pin: &str) -> String {
    format!("{BASE}-hybrid1.{}-v1", pin_hex(pin))
}

fn record(version: &str, key: &[u8], algorithm: Option<&str>, partner: Option<&str>) -> Value {
    let mut rec = json!({
        "signing_key_version": version,
        "public_key_b64": b64(key),
        "public_key_fingerprint": sha256_fp(key),
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

fn ed_record(version: &str, seed: [u8; 32], partner: Option<&str>) -> Value {
    record(version, &ed_public(seed), None, partner)
}

fn ml_record(version: &str, seed: [u8; 32]) -> Value {
    record(version, &ml65_public(seed), Some("ML-DSA-65"), None)
}

fn archived(mut rec: Value) -> Value {
    rec["archived_at"] = json!("2026-12-01T00:00:00Z");
    rec
}

fn authority(active: Vec<Value>, archived: Vec<Value>) -> Value {
    json!({
        "display_name": "Acme Health signing authority",
        "active_versions": active,
        "archived_versions": archived,
        "revoked": false,
    })
}

/// The partner pair of the base list: Ed25519 version 1, ML-DSA-65 version 2.
fn base_records() -> Vec<Value> {
    vec![
        ed_record("1", SEED_ED_1, Some("2")),
        ml_record("2", SEED_ML_2),
    ]
}

/// An unsigned hybrid list for `authorities`, with both identity keys.
fn unsigned(authorities: Value, ed: [u8; 32], ml: [u8; 32]) -> TrustChainManifest {
    let map: HashMap<String, AuthorityRecord> =
        serde_json::from_value(authorities).expect("authorities parse");
    TrustChainManifest::build_unsigned_hybrid(
        "1",
        "2026-11-01T00:00:00Z",
        map,
        &ed_public(ed),
        &ml87_public(ml),
    )
}

/// Sign both halves as given, without checking the result, so that lists the
/// reference must refuse can be built.
fn sign_both(mut m: TrustChainManifest, ed: [u8; 32], ml: [u8; 32]) -> Value {
    let payload = m.signed_payload().expect("payload");
    let message = m.pqc_signed_message().expect("message");
    m.manifest_signature = format!("base64:{}", b64(&ed_key(ed).sign(&payload).to_bytes()));
    m.pqc_manifest_signature = Some(format!("base64:{}", b64(&ml87_sign(ml, &message))));
    serde_json::to_value(m).expect("serializes")
}

/// Re-sign a list value after an edit, both halves, under the given seeds.
fn resign(list: &Value, ed: [u8; 32], ml: [u8; 32]) -> Value {
    let m: TrustChainManifest = serde_json::from_value(list.clone()).expect("list parses");
    sign_both(m, ed, ml)
}

fn signed_hybrid(authorities: Value) -> Value {
    sign_both(
        unsigned(authorities, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
        SEED_ED_IDENTITY,
        SEED_ML_IDENTITY,
    )
}

fn signed_classical(authorities: Value, ed: [u8; 32]) -> Value {
    let map: HashMap<String, AuthorityRecord> =
        serde_json::from_value(authorities).expect("authorities parse");
    serde_json::to_value(TrustChainManifest::build_and_sign(
        "1",
        "2026-11-01T00:00:00Z",
        map,
        &ed_key(ed),
    ))
    .expect("serializes")
}

/// Re-sign the Ed25519 half only of a classical list after an edit.
fn resign_classical(list: &Value, ed: [u8; 32]) -> Value {
    let mut m: TrustChainManifest = serde_json::from_value(list.clone()).expect("list parses");
    let payload = m.signed_payload().expect("payload");
    m.manifest_signature = format!("base64:{}", b64(&ed_key(ed).sign(&payload).to_bytes()));
    serde_json::to_value(m).expect("serializes")
}

fn proof(authority: &str, key_version: &str, seed: [u8; 32]) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json");
    let mut proof: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read corpus fixture")).expect("parse");
    assert_eq!(proof["cdp_version"], "2.1");
    proof["authority_id"] = json!(authority);
    proof["signing_key_version"] = json!(key_version);
    let key = ed_key(seed);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    proof["attestation"]["public_key"] =
        json!(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = json!(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

/// The corpus's signed 1.0 proof, labelled with `authority` and `key_version`
/// and its `final_hash` signed with `seed`. A 1.0 signature covers that hash
/// alone, so neither label is covered.
fn proof_v1_0(authority: &str, key_version: &str, seed: [u8; 32]) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/12_failure_diagnostic_refused/0001_v1_0_signed.json");
    let mut proof: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read corpus fixture")).expect("parse");
    assert_eq!(proof["cdp_version"], "1.0");
    proof["authority_id"] = json!(authority);
    proof["signing_key_version"] = json!(key_version);
    let final_hash = proof["final_hash"].as_str().expect("final_hash");
    let message = final_hash.strip_prefix("sha512:").unwrap_or(final_hash);
    let key = ed_key(seed);
    let sig = key.sign(message.as_bytes());
    proof["attestation"]["public_key"] =
        json!(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = json!(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), sorted(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn file_bytes(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(&sorted(v)).expect("serialize");
    s.push('\n');
    s.into_bytes()
}

fn load(bytes: &[u8]) -> Result<TrustChainManifest, Value> {
    serde_json::from_slice(bytes).map_err(|_| json!({ "refusal": "load_failed" }))
}

/// The Ed25519 version to partner version map of a loaded list, per authority.
fn partners(m: &TrustChainManifest) -> Value {
    let mut out = BTreeMap::new();
    for (id, a) in &m.authorities {
        let mut map = BTreeMap::new();
        for r in a.active_versions.iter().chain(&a.archived_versions) {
            if let Some(p) = m.hybrid_partner(id, &r.signing_key_version) {
                map.insert(r.signing_key_version.clone(), json!(p.version));
            }
        }
        out.insert(id.clone(), json!(map));
    }
    json!(out)
}

/// What the reference does with a key list under a pin.
fn reference_list(bytes: &[u8], pin: &str) -> Value {
    let m = match load(bytes) {
        Ok(m) => m,
        Err(r) => return r,
    };
    match m.verify_signature(pin) {
        Err(e) => json!({ "refusal": e.kind() }),
        Ok(()) => json!({ "loaded": true, "partners": partners(&m) }),
    }
}

/// What the reference does with a proof checked against a key list.
fn reference_record(bytes: &[u8], proof: &Value, pin: &str) -> Value {
    let m = match load(bytes) {
        Ok(m) => m,
        Err(r) => return r,
    };
    if let Err(e) = m.verify_signature(pin) {
        return json!({ "refusal": e.kind() });
    }
    let policy = VerifierPolicy {
        trust_chain: Some(m),
        pinned_identity_fingerprint: Some(pin.to_string()),
        ..Default::default()
    };
    let result = verify_auditproof(proof, &[], &policy);
    json!({
        "valid": result.valid,
        "stage_reached": result.stage_reached,
        "status": result.status(),
        "failure_reason": result.failure_reason.map(|r| serde_json::to_value(r).expect("reason serializes")),
    })
}

/// What the reference does with two lists from one identity.
fn reference_two(earlier: &[u8], later: &[u8], pin: &str) -> Value {
    let verified = |bytes: &[u8]| -> Result<_, Value> {
        let m = load(bytes)?;
        m.into_verified(pin)
            .map_err(|e| json!({ "refusal": e.kind() }))
    };
    let (earlier, later) = match (verified(earlier), verified(later)) {
        (Ok(e), Ok(l)) => (e, l),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    match compare_partners(&earlier, &later) {
        Ok(()) => json!({ "same_partners": true }),
        Err(e) => json!({ "refusal": e.kind() }),
    }
}

/// The result a verifier without an ML-DSA check gives: every hybrid pin is
/// refused up front.
fn without_ml_dsa(pin: &str, expected: &Value) -> Value {
    if pin.starts_with("hybrid1-sha256:") {
        json!({ "refusal": "hybrid_check_unavailable" })
    } else {
        expected.clone()
    }
}

enum Kind {
    List {
        list: &'static str,
    },
    Record {
        list: &'static str,
        proof: &'static str,
    },
    TwoLists {
        earlier: &'static str,
        later: &'static str,
    },
}

struct Case {
    name: &'static str,
    note: &'static str,
    kind: Kind,
    pin: String,
    intent: Value,
}

fn loaded(partners: Value) -> Value {
    json!({ "loaded": true, "partners": partners })
}

fn refused(kind: &str) -> Value {
    json!({ "refusal": kind })
}

/// Set the trailing bits of a padded base64 text's last data character, so
/// the text decodes to the same bytes under a lenient decoder and is refused
/// by a strict one.
fn set_trailing_bits(text: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body = text.trim_end_matches('=');
    let pad = text.len() - body.len();
    assert!(pad > 0, "only padded text has trailing bits");
    let last = *body.as_bytes().last().unwrap();
    let index = ALPHABET.iter().position(|&c| c == last).unwrap();
    let bit = if pad == 2 { 0b1111 } else { 0b11 };
    assert_eq!(
        index & bit,
        0,
        "a canonical encoder leaves the trailing bits clear"
    );
    let mut out = body[..body.len() - 1].to_string();
    out.push(ALPHABET[index | 1] as char);
    out.push_str(&"=".repeat(pad));
    out
}

struct Built {
    files: BTreeMap<String, Vec<u8>>,
}

fn foreign_path() -> PathBuf {
    vectors_dir().join("foreign_signatures.json")
}

fn build() -> Built {
    let pin = pin_of(SEED_ED_IDENTITY, SEED_ML_IDENTITY);
    let other_pin = pin_of(SEED_OTHER_ED_IDENTITY, SEED_OTHER_ML_IDENTITY);
    let id = byoc_id(&pin);
    let classical_pin = sha256_fp(&ed_public(SEED_ED_IDENTITY));

    let mut lists: BTreeMap<&'static str, Value> = BTreeMap::new();
    let mut raw: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    let mut proofs: BTreeMap<&'static str, Value> = BTreeMap::new();

    let one = |records: Vec<Value>| json!({ id.clone(): authority(records, vec![]) });

    // The genuine list, built through `attach`, which checks it under its own
    // pin, so the base every case edits is one the signer path would write.
    let base_unsigned = unsigned(one(base_records()), SEED_ED_IDENTITY, SEED_ML_IDENTITY);
    let ed_sig = ed_key(SEED_ED_IDENTITY)
        .sign(&base_unsigned.signed_payload().unwrap())
        .to_bytes();
    let ml_sig = ml87_sign(
        SEED_ML_IDENTITY,
        &base_unsigned.pqc_signed_message().unwrap(),
    );
    let verified = base_unsigned
        .clone()
        .attach(&ed_sig, &ml_sig)
        .expect("the base list verifies under its own pin");
    let base = serde_json::to_value(verified.manifest()).unwrap();
    lists.insert("hybrid_v1", base.clone());

    lists.insert(
        "hybrid_rotated",
        signed_hybrid(json!({ id.clone(): authority(
            vec![ed_record("3", SEED_ED_3, Some("4")), ml_record("4", SEED_ML_4)],
            vec![archived(ed_record("1", SEED_ED_1, Some("2"))), archived(ml_record("2", SEED_ML_2))],
        ) })),
    );

    // Signatures and identity members.
    let mut no_pqc_sig = base.clone();
    no_pqc_sig
        .as_object_mut()
        .unwrap()
        .remove("pqc_manifest_signature");
    lists.insert("hybrid_v1_missing_pqc_signature", no_pqc_sig);

    let mut empty_ed_sig = base.clone();
    empty_ed_sig["manifest_signature"] = json!("");
    lists.insert("hybrid_v1_empty_ed25519_signature", empty_ed_sig);

    let mut no_ed_sig = base.clone();
    no_ed_sig
        .as_object_mut()
        .unwrap()
        .remove("manifest_signature");
    lists.insert("hybrid_v1_missing_ed25519_signature", no_ed_sig);

    // A well-formed Ed25519 signature by the identity key, over other bytes:
    // only the verify call itself refuses it.
    let mut other_bytes = base_unsigned.signed_payload().unwrap();
    other_bytes.push(b'\n');
    let mut ed_over_other = base.clone();
    ed_over_other["manifest_signature"] = json!(format!(
        "base64:{}",
        b64(&ed_key(SEED_ED_IDENTITY).sign(&other_bytes).to_bytes())
    ));
    lists.insert(
        "hybrid_v1_ed25519_signature_over_other_bytes",
        ed_over_other,
    );

    let mut no_ml_key = base.clone();
    no_ml_key
        .as_object_mut()
        .unwrap()
        .remove("pqc_identity_public_key_b64");
    lists.insert("hybrid_v1_missing_pqc_identity_key", no_ml_key);

    let mut no_ml_algorithm = base.clone();
    no_ml_algorithm
        .as_object_mut()
        .unwrap()
        .remove("pqc_identity_algorithm");
    lists.insert("hybrid_v1_missing_pqc_identity_algorithm", no_ml_algorithm);

    let mut no_ed_key = base.clone();
    no_ed_key
        .as_object_mut()
        .unwrap()
        .remove("identity_public_key_b64");
    lists.insert("hybrid_v1_missing_ed25519_identity_key", no_ed_key);

    let mut swapped = base.clone();
    swapped["pqc_identity_public_key_b64"] = json!(b64(&ml87_public(SEED_OTHER_ML_IDENTITY)));
    lists.insert("hybrid_v1_swapped_mldsa_key", swapped);

    // A forger holding the Ed25519 identity key swaps in an ML-DSA key of its
    // own and signs both halves: the list is self-consistent, its pin is not
    // the relying party's.
    let mut forged = unsigned(
        one(base_records()),
        SEED_ED_IDENTITY,
        SEED_OTHER_ML_IDENTITY,
    );
    forged.identity_fingerprint = hybrid_pin(
        &ed_public(SEED_ED_IDENTITY),
        &ml87_public(SEED_OTHER_ML_IDENTITY),
    );
    lists.insert(
        "hybrid_v1_swapped_mldsa_key_resigned",
        sign_both(forged, SEED_ED_IDENTITY, SEED_OTHER_ML_IDENTITY),
    );

    let base_m: TrustChainManifest = serde_json::from_value(base.clone()).unwrap();
    let payload = base_m.signed_payload().unwrap();
    let message = base_m.pqc_signed_message().unwrap();
    let with_pqc_sig = |sig: &[u8]| {
        let mut v = base.clone();
        v["pqc_manifest_signature"] = json!(format!("base64:{}", b64(sig)));
        v
    };
    let mut flipped = ml87_sign(SEED_ML_IDENTITY, &message);
    flipped[100] ^= 0x01;
    lists.insert("hybrid_v1_bad_pqc_signature", with_pqc_sig(&flipped));
    let mut wrong_tag_message = b"nanorix-population-head-pqc-v2\x00".to_vec();
    wrong_tag_message.extend_from_slice(&payload);
    lists.insert(
        "hybrid_v1_wrong_tag",
        with_pqc_sig(&ml87_sign(SEED_ML_IDENTITY, &wrong_tag_message)),
    );
    lists.insert(
        "hybrid_v1_no_tag",
        with_pqc_sig(&ml87_sign(SEED_ML_IDENTITY, &payload)),
    );
    let truncated = ml87_sign(SEED_ML_IDENTITY, &message)[..4626].to_vec();
    lists.insert(
        "hybrid_v1_truncated_pqc_signature",
        with_pqc_sig(&truncated),
    );
    lists.insert(
        "hybrid_v1_ed25519_signature_as_pqc",
        with_pqc_sig(&ed_key(SEED_ED_IDENTITY).sign(&payload).to_bytes()),
    );

    // A first regeneration has no foreign file for the new base list yet: it
    // writes a placeholder, the script then signs the committed base list, and
    // a second regeneration writes the real signatures.
    let foreign: Value = std::fs::read(foreign_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    let fresh = foreign["payload_sha512"] == json!(hex::encode(Sha512::digest(&payload)));
    assert!(
        fresh || regenerating(),
        "foreign_signatures.json is missing or was made over another payload: regenerate, run \
         scripts/gen_hybrid_foreign_signatures.py, and regenerate again"
    );
    let foreign_sig = |name: &str| {
        if !fresh {
            eprintln!(
                "foreign_signatures.json is stale: {name} is a placeholder until the script runs"
            );
            return vec![0u8; 4627];
        }
        base64::engine::general_purpose::STANDARD
            .decode(foreign[name].as_str().expect("foreign signature"))
            .expect("foreign signature decodes")
    };
    lists.insert(
        "hybrid_v1_tag_as_context",
        with_pqc_sig(&foreign_sig("tag_as_context")),
    );
    lists.insert(
        "hybrid_v1_hash_mldsa_signature",
        with_pqc_sig(&foreign_sig("hash_ml_dsa_sha512")),
    );

    let mut slh = base.clone();
    slh["pqc_identity_algorithm"] = json!("SLH-DSA-SHA2-256s");
    lists.insert(
        "hybrid_v1_slh_dsa_algorithm",
        resign(&slh, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
    );

    // Encodings.
    let mut noncanonical_sig = base.clone();
    let sig_text = base["pqc_manifest_signature"].as_str().unwrap();
    noncanonical_sig["pqc_manifest_signature"] = json!(format!(
        "base64:{}",
        set_trailing_bits(sig_text.strip_prefix("base64:").unwrap())
    ));
    lists.insert(
        "hybrid_v1_noncanonical_pqc_signature_base64",
        noncanonical_sig,
    );

    let mut noncanonical_ed_sig = base.clone();
    let ed_sig_text = base["manifest_signature"].as_str().unwrap();
    noncanonical_ed_sig["manifest_signature"] = json!(format!(
        "base64:{}",
        set_trailing_bits(ed_sig_text.strip_prefix("base64:").unwrap())
    ));
    lists.insert(
        "hybrid_v1_noncanonical_ed25519_signature_base64",
        noncanonical_ed_sig,
    );

    // The two key members below are signed text, so both halves sign the
    // edited text: a lenient decoder reads the same key and loads the list.
    let mut noncanonical_identity = base.clone();
    let identity_text = base["identity_public_key_b64"].as_str().unwrap();
    noncanonical_identity["identity_public_key_b64"] = json!(set_trailing_bits(
        identity_text
            .strip_prefix("base64:")
            .unwrap_or(identity_text)
    ));
    lists.insert(
        "hybrid_v1_noncanonical_ed25519_identity_key_base64",
        resign(&noncanonical_identity, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
    );

    let mut noncanonical_ed_record = base.clone();
    let ed_record_text = base["authorities"][&id]["active_versions"][0]["public_key_b64"]
        .as_str()
        .unwrap()
        .to_string();
    noncanonical_ed_record["authorities"][&id]["active_versions"][0]["public_key_b64"] =
        json!(set_trailing_bits(&ed_record_text));
    lists.insert(
        "hybrid_v1_noncanonical_ed25519_record_key_base64",
        resign(&noncanonical_ed_record, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
    );

    // An Ed25519 identity key that is not a curve point, with the list's
    // identity_fingerprint and the case's pin both the hybrid pin over it, so
    // each verifier reaches its own check of the key.
    let non_point: [u8; 32] = (0u8..=255)
        .map(|n| {
            let mut b = [0u8; 32];
            b[0] = n;
            b
        })
        .find(|b| VerifyingKey::from_bytes(b).is_err())
        .expect("a 32-byte string that is not an Ed25519 point");
    let non_point_pin = hybrid_pin(&non_point, &ml87_public(SEED_ML_IDENTITY));
    let mut non_point_list = base.clone();
    non_point_list["identity_public_key_b64"] = json!(b64(&non_point));
    non_point_list["identity_fingerprint"] = json!(non_point_pin.clone());
    lists.insert(
        "hybrid_v1_ed25519_identity_key_not_a_point",
        resign(&non_point_list, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
    );

    let mut noncanonical_partner = base.clone();
    let key_text = noncanonical_partner["authorities"][&id]["active_versions"][1]["public_key_b64"]
        .as_str()
        .unwrap()
        .to_string();
    noncanonical_partner["authorities"][&id]["active_versions"][1]["public_key_b64"] =
        json!(set_trailing_bits(&key_text));
    lists.insert(
        "hybrid_v1_noncanonical_partner_key_base64",
        resign(&noncanonical_partner, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
    );

    // The identity key written twice: a parser keeps one copy, and no
    // signature covers the other.
    let base_text = String::from_utf8(file_bytes(&base)).unwrap();
    let ml_member = format!(
        "\"pqc_identity_public_key_b64\": \"{}\",",
        base["pqc_identity_public_key_b64"].as_str().unwrap()
    );
    let twice = base_text.replacen(
        &ml_member,
        &format!(
            "\"pqc_identity_public_key_b64\": \"{}\",\n  {ml_member}",
            b64(&ml87_public(SEED_OTHER_ML_IDENTITY))
        ),
        1,
    );
    assert_ne!(twice, base_text, "the member was written twice");
    raw.insert("hybrid_v1_repeated_pqc_identity_key", twice.into_bytes());

    let mut classical_fp = base.clone();
    classical_fp["identity_fingerprint"] = json!(classical_pin);
    lists.insert(
        "hybrid_v1_classical_identity_fingerprint",
        resign(&classical_fp, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
    );

    // Classical pins.
    let classical_byoc = signed_classical(
        json!({ id.clone(): authority(vec![ed_record("1", SEED_ED_1, None)], vec![]) }),
        SEED_ED_IDENTITY,
    );
    lists.insert("classical_list_with_byoc_ids", classical_byoc);
    let classical_plain = signed_classical(
        json!({ CLASSICAL_ID: authority(vec![ed_record("1", SEED_ED_1, None)], vec![]) }),
        SEED_ED_IDENTITY,
    );
    lists.insert("classical_list", classical_plain.clone());
    let mut with_members = classical_plain.clone();
    with_members["pqc_identity_algorithm"] = json!("ML-DSA-87");
    with_members["pqc_identity_public_key_b64"] = json!(b64(&ml87_public(SEED_ML_IDENTITY)));
    lists.insert(
        "classical_list_with_pqc_identity_members_appended",
        with_members.clone(),
    );
    lists.insert(
        "classical_list_with_pqc_identity_members_signed",
        resign_classical(&with_members, SEED_ED_IDENTITY),
    );
    lists.insert(
        "hybrid_list_id_outside_alphabet",
        signed_hybrid(json!({ "us-Customer-kms-acme-v1": authority(base_records(), vec![]) })),
    );

    // Authority ids under a hybrid pin.
    lists.insert(
        "hybrid_list_with_plain_id",
        signed_hybrid(json!({ CLASSICAL_ID: authority(base_records(), vec![]) })),
    );
    lists.insert(
        "hybrid_list_with_other_pin_id",
        signed_hybrid(json!({ byoc_id(&other_pin): authority(base_records(), vec![]) })),
    );
    lists.insert(
        "hybrid_list_with_malformed_byoc_id",
        signed_hybrid(json!({ format!("{BASE}-hybrid1.{}-v01", pin_hex(&pin)): authority(base_records(), vec![]) })),
    );
    lists.insert(
        "hybrid_list_with_hybrid1_in_base",
        signed_hybrid(json!({ format!("us-hybrid1-acme-hybrid1.{}-v1", pin_hex(&pin)): authority(base_records(), vec![]) })),
    );

    // Record and role rules.
    let rules: Vec<(&'static str, Vec<Value>, Vec<Value>)> = vec![
        (
            "hybrid_v1_label_ed25519_lowercase",
            vec![
                record("1", &ed_public(SEED_ED_1), Some("ed25519"), Some("2")),
                ml_record("2", SEED_ML_2),
            ],
            vec![],
        ),
        (
            "hybrid_v1_label_ml_dsa_87_record",
            vec![
                ed_record("1", SEED_ED_1, Some("2")),
                record("2", &ml87_public(SEED_ML_STRANGER), Some("ML-DSA-87"), None),
            ],
            vec![],
        ),
        (
            "hybrid_v1_version_repeated_text",
            vec![
                ed_record("1", SEED_ED_1, Some("2")),
                ml_record("2", SEED_ML_2),
            ],
            vec![archived(ml_record("2", SEED_ML_STRANGER))],
        ),
        (
            "hybrid_v1_version_repeated_integer",
            vec![
                ed_record("1", SEED_ED_1, Some("2")),
                ml_record("2", SEED_ML_2),
            ],
            vec![archived(ml_record("02", SEED_ML_STRANGER))],
        ),
        (
            "hybrid_v1_identity_key_reused_as_record_key",
            vec![
                ed_record("1", SEED_ED_IDENTITY, Some("2")),
                ml_record("2", SEED_ML_2),
            ],
            vec![],
        ),
        (
            "hybrid_v1_partner_missing",
            vec![ed_record("1", SEED_ED_1, None), ml_record("2", SEED_ML_2)],
            vec![],
        ),
        (
            "hybrid_v1_partner_not_mldsa65",
            vec![
                ed_record("1", SEED_ED_1, Some("3")),
                ml_record("2", SEED_ML_2),
                ed_record("3", SEED_ED_3, Some("2")),
            ],
            vec![],
        ),
        (
            "hybrid_v1_partner_not_on_list",
            vec![
                ed_record("1", SEED_ED_1, Some("9")),
                ml_record("2", SEED_ML_2),
            ],
            vec![],
        ),
        (
            "hybrid_v1_partner_shared_by_two_versions",
            vec![
                ed_record("1", SEED_ED_1, Some("2")),
                ml_record("2", SEED_ML_2),
                ed_record("3", SEED_ED_3, Some("2")),
            ],
            vec![],
        ),
        (
            "hybrid_v1_partner_version_on_mldsa_record",
            vec![
                ed_record("1", SEED_ED_1, Some("2")),
                record("2", &ml65_public(SEED_ML_2), Some("ML-DSA-65"), Some("1")),
            ],
            vec![],
        ),
        (
            "hybrid_v1_key_in_two_roles",
            vec![
                ed_record("1", SEED_ED_1, Some("2")),
                ml_record("2", SEED_ML_2),
                ed_record("3", SEED_ED_1, Some("4")),
                ml_record("4", SEED_ML_4),
            ],
            vec![],
        ),
        (
            "hybrid_v1_archived_partner_missing",
            vec![
                ed_record("3", SEED_ED_3, Some("4")),
                ml_record("4", SEED_ML_4),
            ],
            vec![
                archived(ed_record("1", SEED_ED_1, None)),
                archived(ml_record("2", SEED_ML_2)),
            ],
        ),
        (
            "hybrid_v1_record_key_wrong_length",
            vec![
                ed_record("1", SEED_ED_1, Some("2")),
                record(
                    "2",
                    &ml65_public(SEED_ML_2)[..1951],
                    Some("ML-DSA-65"),
                    None,
                ),
            ],
            vec![],
        ),
    ];
    for (name, active, archived_records) in rules {
        lists.insert(
            name,
            signed_hybrid(json!({ id.clone(): authority(active, archived_records) })),
        );
    }
    let mut fp_not_of_key = base.clone();
    fp_not_of_key["authorities"][&id]["active_versions"][1]["public_key_fingerprint"] =
        json!(sha256_fp(&ml65_public(SEED_ML_STRANGER)));
    lists.insert(
        "hybrid_v1_fingerprint_not_of_key",
        resign(&fp_not_of_key, SEED_ED_IDENTITY, SEED_ML_IDENTITY),
    );
    let partner_elsewhere = signed_hybrid(json!({
        id.clone(): authority(vec![ed_record("1", SEED_ED_1, Some("2"))], vec![]),
        format!("eu-customer-kms-acme-hybrid1.{}-v1", pin_hex(&pin)): authority(vec![ml_record("2", SEED_ML_2)], vec![]),
    }));
    lists.insert("hybrid_v1_partner_other_authority", partner_elsewhere);

    // Two lists.
    lists.insert(
        "hybrid_v1_partner_key_changed",
        signed_hybrid(one(vec![
            ed_record("1", SEED_ED_1, Some("2")),
            ml_record("2", SEED_ML_STRANGER),
        ])),
    );
    lists.insert(
        "hybrid_v1_ed25519_key_changed",
        signed_hybrid(one(vec![
            ed_record("1", SEED_ED_STRANGER, Some("2")),
            ml_record("2", SEED_ML_2),
        ])),
    );
    // Version 1 points at a new partner, version 5; version 2 stays with its
    // key, named by no Ed25519 version. Every record of the earlier list is
    // unchanged in the later one, so only the partner comparison refuses.
    lists.insert(
        "hybrid_v1_partner_repointed",
        signed_hybrid(one(vec![
            ed_record("1", SEED_ED_1, Some("5")),
            ml_record("2", SEED_ML_2),
            ml_record("5", SEED_ML_4),
        ])),
    );
    lists.insert(
        "hybrid_v3_only",
        signed_hybrid(one(vec![
            ed_record("3", SEED_ED_3, Some("4")),
            ml_record("4", SEED_ML_4),
        ])),
    );

    // Records under a hybrid pin.
    let signed_v1 = proof(&id, "1", SEED_ED_1);
    let mut unsigned_v1 = signed_v1.clone();
    for member in ["signature", "public_key"] {
        unsigned_v1["attestation"]
            .as_object_mut()
            .unwrap()
            .remove(member);
    }
    proofs.insert("ed25519_only_v1", signed_v1);
    proofs.insert("ed25519_only_v1_unsigned", unsigned_v1);
    proofs.insert("v1_0_ed25519_v1", proof_v1_0(&id, "1", SEED_ED_1));

    let partners_v1 = json!({ id.clone(): { "1": "2" } });
    let partners_rotated = json!({ id.clone(): { "1": "2", "3": "4" } });
    let list = |list| Kind::List { list };
    let two = |earlier, later| Kind::TwoLists { earlier, later };
    let gate = json!({
        "valid": false,
        "stage_reached": 8,
        "status": "not_verified",
        "failure_reason": { "type": "algorithm_unsupported", "found": nanorix_verify::HYBRID_RECORD_CHECK_MISSING },
    });
    let v1_0_gate = json!({
        "valid": false,
        "stage_reached": 7,
        "status": "not_verified",
        "failure_reason": { "type": "algorithm_unsupported", "found": nanorix_verify::HYBRID_RECORD_CHECK_MISSING },
    });
    let unsigned_gate = json!({
        "valid": false,
        "stage_reached": 4,
        "status": "not_verified",
        "failure_reason": { "type": "algorithm_unsupported", "found": nanorix_verify::HYBRID_RECORD_CHECK_MISSING },
    });
    let cases = vec![
        Case { name: "hybrid_list_verifies_under_hybrid_pin", note: "A BYOC list signed by both identity keys, checked under the hybrid pin recomputed from both. It loads, and its one Ed25519 version names its ML-DSA-65 partner.", kind: list("hybrid_v1"), pin: pin.clone(), intent: loaded(partners_v1.clone()) },
        Case { name: "hybrid_rotated_list_verifies", note: "After a rotation the archived Ed25519 version keeps its partner.", kind: list("hybrid_rotated"), pin: pin.clone(), intent: loaded(partners_rotated) },
        Case { name: "missing_pqc_signature", note: "The ML-DSA-87 list signature was removed.", kind: list("hybrid_v1_missing_pqc_signature"), pin: pin.clone(), intent: refused("pqc_signature_missing") },
        Case { name: "empty_ed25519_signature", note: "The Ed25519 list signature is empty.", kind: list("hybrid_v1_empty_ed25519_signature"), pin: pin.clone(), intent: refused("signature_invalid") },
        Case { name: "missing_ed25519_signature", note: "The Ed25519 list signature member was removed.", kind: list("hybrid_v1_missing_ed25519_signature"), pin: pin.clone(), intent: refused("load_failed") },
        Case { name: "ed25519_signature_over_other_bytes", note: "The Ed25519 list signature is a well-formed signature by the identity key over other bytes; the ML-DSA-87 signature is genuine.", kind: list("hybrid_v1_ed25519_signature_over_other_bytes"), pin: pin.clone(), intent: refused("signature_invalid") },
        Case { name: "ed25519_identity_key_not_a_point", note: "The Ed25519 identity key is 32 bytes that are not a curve point; the list's identity_fingerprint and the pin are the hybrid pin over it. Verifiers refuse it with different kinds today (expected_by_verifier).", kind: list("hybrid_v1_ed25519_identity_key_not_a_point"), pin: non_point_pin.clone(), intent: refused("malformed") },
        Case { name: "missing_pqc_identity_key", note: "The ML-DSA-87 identity key was removed.", kind: list("hybrid_v1_missing_pqc_identity_key"), pin: pin.clone(), intent: refused("pqc_identity_missing") },
        Case { name: "missing_pqc_identity_algorithm", note: "The identity algorithm member was removed.", kind: list("hybrid_v1_missing_pqc_identity_algorithm"), pin: pin.clone(), intent: refused("pqc_identity_missing") },
        Case { name: "missing_ed25519_identity_key", note: "The Ed25519 identity key was removed.", kind: list("hybrid_v1_missing_ed25519_identity_key"), pin: pin.clone(), intent: refused("malformed") },
        Case { name: "swapped_mldsa_key", note: "The ML-DSA-87 identity key was replaced after signing. The recomputed pin differs.", kind: list("hybrid_v1_swapped_mldsa_key"), pin: pin.clone(), intent: refused("fingerprint_mismatch") },
        Case { name: "swapped_mldsa_key_resigned", note: "A forger holding the Ed25519 identity key put in its own ML-DSA-87 key and signed both halves. The list is self-consistent; its pin is not the given one.", kind: list("hybrid_v1_swapped_mldsa_key_resigned"), pin: pin.clone(), intent: refused("fingerprint_mismatch") },
        Case { name: "bad_pqc_signature", note: "One bit of the ML-DSA-87 signature was flipped.", kind: list("hybrid_v1_bad_pqc_signature"), pin: pin.clone(), intent: refused("pqc_signature_invalid") },
        Case { name: "wrong_tag", note: "The ML-DSA-87 signature covers the payload behind another H5 tag.", kind: list("hybrid_v1_wrong_tag"), pin: pin.clone(), intent: refused("pqc_signature_invalid") },
        Case { name: "no_tag", note: "The ML-DSA-87 signature covers the payload with no tag.", kind: list("hybrid_v1_no_tag"), pin: pin.clone(), intent: refused("pqc_signature_invalid") },
        Case { name: "tag_as_context", note: "The ML-DSA-87 signature covers the payload with the tag given as the FIPS 204 context instead of in the message. foreign_signatures.json holds it.", kind: list("hybrid_v1_tag_as_context"), pin: pin.clone(), intent: refused("pqc_signature_invalid") },
        Case { name: "hash_mldsa_signature", note: "A HashML-DSA (SHA-512) signature over the tagged payload, not pure ML-DSA. foreign_signatures.json holds it.", kind: list("hybrid_v1_hash_mldsa_signature"), pin: pin.clone(), intent: refused("pqc_signature_invalid") },
        Case { name: "truncated_pqc_signature", note: "The ML-DSA-87 signature is one byte short.", kind: list("hybrid_v1_truncated_pqc_signature"), pin: pin.clone(), intent: refused("pqc_signature_invalid") },
        Case { name: "ed25519_signature_as_pqc", note: "The post-quantum slot holds the Ed25519 signature.", kind: list("hybrid_v1_ed25519_signature_as_pqc"), pin: pin.clone(), intent: refused("pqc_signature_invalid") },
        Case { name: "slh_dsa_algorithm", note: "The list names SLH-DSA-SHA2-256s as its identity algorithm, signed. H2 opens ML-DSA-87 only for a BYOC list.", kind: list("hybrid_v1_slh_dsa_algorithm"), pin: pin.clone(), intent: refused("pqc_algorithm_unsupported") },
        Case { name: "noncanonical_pqc_signature_base64", note: "The ML-DSA-87 signature's base64 has its trailing bits set: the same bytes under a lenient decoder.", kind: list("hybrid_v1_noncanonical_pqc_signature_base64"), pin: pin.clone(), intent: refused("non_canonical_encoding") },
        Case { name: "noncanonical_ed25519_signature_base64", note: "The Ed25519 list signature's base64 has its trailing bits set: the same bytes under a lenient decoder.", kind: list("hybrid_v1_noncanonical_ed25519_signature_base64"), pin: pin.clone(), intent: refused("signature_invalid") },
        Case { name: "noncanonical_ed25519_identity_key_base64", note: "The Ed25519 identity key's base64 has its trailing bits set, and both halves signed that text.", kind: list("hybrid_v1_noncanonical_ed25519_identity_key_base64"), pin: pin.clone(), intent: refused("malformed") },
        Case { name: "noncanonical_ed25519_record_key_base64", note: "An Ed25519 record key's base64 has its trailing bits set, and both halves signed that text.", kind: list("hybrid_v1_noncanonical_ed25519_record_key_base64"), pin: pin.clone(), intent: refused("non_canonical_encoding") },
        Case { name: "noncanonical_partner_key_base64", note: "The partner key's base64 has its trailing bits set, and both halves signed that text.", kind: list("hybrid_v1_noncanonical_partner_key_base64"), pin: pin.clone(), intent: refused("non_canonical_encoding") },
        Case { name: "repeated_pqc_identity_key", note: "The ML-DSA-87 identity key member is written twice, another key first. A parser keeps one; no signature covers the other.", kind: list("hybrid_v1_repeated_pqc_identity_key"), pin: pin.clone(), intent: refused("load_failed") },
        Case { name: "classical_identity_fingerprint_given_hybrid_pin", note: "The list's identity_fingerprint is the sha256: value of its Ed25519 key, signed by both halves.", kind: list("hybrid_v1_classical_identity_fingerprint"), pin: pin.clone(), intent: refused("fingerprint_mismatch") },
        Case { name: "hybrid_pin_uppercase", note: "The pin is written in uppercase.", kind: list("hybrid_v1"), pin: pin.to_uppercase(), intent: refused("fingerprint_mismatch") },
        Case { name: "hybrid_pin_uppercase_hex", note: "The pin's prefix is lowercase, its hex uppercase.", kind: list("hybrid_v1"), pin: format!("hybrid1-sha256:{}", pin_hex(&pin).to_uppercase()), intent: refused("fingerprint_mismatch") },
        Case { name: "hybrid_pin_inner_whitespace", note: "The pin has a space after its prefix.", kind: list("hybrid_v1"), pin: format!("hybrid1-sha256: {}", pin_hex(&pin)), intent: refused("fingerprint_mismatch") },
        Case { name: "hybrid_pin_outer_whitespace", note: "The pin has surrounding whitespace. The library does not trim; a caller that trims gives it the pin without.", kind: list("hybrid_v1"), pin: format!(" {pin}\n"), intent: refused("fingerprint_mismatch") },
        Case { name: "hybrid_list_under_classical_pin", note: "A genuine BYOC list under the sha256: value of its own Ed25519 identity key.", kind: list("hybrid_v1"), pin: classical_pin.clone(), intent: refused("fingerprint_mismatch") },
        Case { name: "classical_list_with_pqc_identity_members_signed", note: "A classical list whose Ed25519 signature covers post-quantum identity members, under a classical pin.", kind: list("classical_list_with_pqc_identity_members_signed"), pin: classical_pin.clone(), intent: refused("pqc_identity_under_classical_pin") },
        Case { name: "classical_list_with_pqc_identity_members_appended", note: "The same members appended to a classical list after signing. The signed payload now holds them, so the Ed25519 signature fails.", kind: list("classical_list_with_pqc_identity_members_appended"), pin: classical_pin.clone(), intent: refused("signature_invalid") },
        Case { name: "classical_list_loads", note: "A classical list with a plain authority id loads under its sha256: pin, as before.", kind: list("classical_list"), pin: classical_pin.clone(), intent: loaded(json!({ CLASSICAL_ID: {} })) },
        Case { name: "classical_pin_list_with_byoc_ids", note: "A classical list carrying an authority id of BYOC form, under a classical pin (H4.8).", kind: list("classical_list_with_byoc_ids"), pin: classical_pin.clone(), intent: refused("byoc_authority_needs_hybrid_pin") },
        Case { name: "list_id_outside_alphabet", note: "A BYOC list whose authority id holds an uppercase letter, outside the id alphabet (H4.8). Under a classical pin the alphabet is left to population check (f), as before.", kind: list("hybrid_list_id_outside_alphabet"), pin: pin.clone(), intent: refused("authority_id_malformed") },
        Case { name: "hybrid_pin_list_with_plain_id", note: "A BYOC list whose authority id is not of BYOC form.", kind: list("hybrid_list_with_plain_id"), pin: pin.clone(), intent: refused("byoc_authority_pin_mismatch") },
        Case { name: "hybrid_pin_list_with_other_pin_id", note: "A BYOC list whose authority id carries another install's pin.", kind: list("hybrid_list_with_other_pin_id"), pin: pin.clone(), intent: refused("byoc_authority_pin_mismatch") },
        Case { name: "hybrid_pin_list_with_malformed_byoc_id", note: "An authority id of BYOC form whose version has a leading zero (-v01).", kind: list("hybrid_list_with_malformed_byoc_id"), pin: pin.clone(), intent: refused("byoc_authority_id_malformed") },
        Case { name: "hybrid_pin_list_with_hybrid1_in_base", note: "An authority id holding hybrid1 twice, once in its base.", kind: list("hybrid_list_with_hybrid1_in_base"), pin: pin.clone(), intent: refused("byoc_authority_id_malformed") },
        Case { name: "label_ed25519_lowercase", note: "A record labelled ed25519 in lowercase.", kind: list("hybrid_v1_label_ed25519_lowercase"), pin: pin.clone(), intent: refused("key_label_unknown") },
        Case { name: "label_ml_dsa_87_record", note: "A record labelled ML-DSA-87, which is the identity's algorithm, not a record's.", kind: list("hybrid_v1_label_ml_dsa_87_record"), pin: pin.clone(), intent: refused("key_label_unknown") },
        Case { name: "version_repeated_text", note: "One authority holds version 2 twice, active and archived.", kind: list("hybrid_v1_version_repeated_text"), pin: pin.clone(), intent: refused("version_repeated") },
        Case { name: "version_repeated_integer", note: "One authority holds versions 2 and 02.", kind: list("hybrid_v1_version_repeated_integer"), pin: pin.clone(), intent: refused("version_repeated") },
        Case { name: "fingerprint_not_of_key", note: "The partner record's fingerprint is another key's.", kind: list("hybrid_v1_fingerprint_not_of_key"), pin: pin.clone(), intent: refused("fingerprint_not_of_key") },
        Case { name: "identity_key_reused_as_record_key", note: "The Ed25519 identity key is also a record key.", kind: list("hybrid_v1_identity_key_reused_as_record_key"), pin: pin.clone(), intent: refused("key_in_two_roles") },
        Case { name: "partner_missing", note: "The Ed25519 version names no partner.", kind: list("hybrid_v1_partner_missing"), pin: pin.clone(), intent: refused("partner_missing") },
        Case { name: "archived_partner_missing", note: "An archived Ed25519 version names no partner.", kind: list("hybrid_v1_archived_partner_missing"), pin: pin.clone(), intent: refused("partner_missing") },
        Case { name: "partner_not_mldsa65", note: "The Ed25519 version names an Ed25519 version as its partner.", kind: list("hybrid_v1_partner_not_mldsa65"), pin: pin.clone(), intent: refused("partner_invalid") },
        Case { name: "partner_not_on_list", note: "The Ed25519 version names a version the authority does not hold.", kind: list("hybrid_v1_partner_not_on_list"), pin: pin.clone(), intent: refused("partner_invalid") },
        Case { name: "partner_other_authority", note: "The named partner is a record of another authority.", kind: list("hybrid_v1_partner_other_authority"), pin: pin.clone(), intent: refused("partner_invalid") },
        Case { name: "partner_shared_by_two_versions", note: "Two Ed25519 versions name one partner.", kind: list("hybrid_v1_partner_shared_by_two_versions"), pin: pin.clone(), intent: refused("partner_shared") },
        Case { name: "partner_version_on_mldsa_record", note: "An ML-DSA-65 record names a partner of its own.", kind: list("hybrid_v1_partner_version_on_mldsa_record"), pin: pin.clone(), intent: refused("partner_invalid") },
        Case { name: "key_in_two_roles", note: "One Ed25519 key under two versions.", kind: list("hybrid_v1_key_in_two_roles"), pin: pin.clone(), intent: refused("key_in_two_roles") },
        Case { name: "record_key_wrong_length", note: "The partner's key is one byte short of ML-DSA-65's 1952.", kind: list("hybrid_v1_record_key_wrong_length"), pin: pin.clone(), intent: refused("record_key_length") },
        Case { name: "two_lists_same_partners", note: "An earlier list and a later rotated one that keeps version 1 and its partner in the archive.", kind: two("hybrid_v1", "hybrid_rotated"), pin: pin.clone(), intent: json!({ "same_partners": true }) },
        Case { name: "two_lists_partner_changed_same_version_string", note: "The later list keeps version 2 but with another ML-DSA-65 key.", kind: two("hybrid_v1", "hybrid_v1_partner_key_changed"), pin: pin.clone(), intent: refused("partner_changed") },
        Case { name: "two_lists_ed25519_key_changed", note: "The later list keeps version 1 but with another Ed25519 key.", kind: two("hybrid_v1", "hybrid_v1_ed25519_key_changed"), pin: pin.clone(), intent: refused("partner_changed") },
        Case { name: "two_lists_partner_repointed", note: "The later list keeps every record of the earlier one, unchanged, but points version 1 at another ML-DSA-65 version.", kind: two("hybrid_v1", "hybrid_v1_partner_repointed"), pin: pin.clone(), intent: refused("partner_changed") },
        Case { name: "two_lists_version_dropped", note: "The later list drops versions 1 and 2.", kind: two("hybrid_v1", "hybrid_v3_only"), pin: pin.clone(), intent: refused("partner_changed") },
        Case { name: "ed25519_only_record_under_hybrid_pin", note: "An Ed25519-only record under the BYOC authority, whose key and version resolve in the list. Under a hybrid pin this build refuses it at stage 8: it does not check the record's ML-DSA-65 half yet.", kind: Kind::Record { list: "hybrid_v1", proof: "ed25519_only_v1" }, pin: pin.clone(), intent: gate },
        Case { name: "v1_0_record_under_hybrid_pin", note: "A genuine 1.0 record labelled with the BYOC authority and version 1, its final_hash signed by that version's Ed25519 key. It runs the key lookup, the re-verify against the listed key and the revocation check, and is refused at stage 7, where a 1.0 record ends: under a hybrid pin no record is anchored on its Ed25519 half alone.", kind: Kind::Record { list: "hybrid_v1", proof: "v1_0_ed25519_v1" }, pin: pin.clone(), intent: v1_0_gate },
        Case { name: "unsigned_record_under_hybrid_pin", note: "The same record with its signature and public key removed. Without a pin it ends valid at stage 4, signature not checked; under a hybrid pin it is refused there.", kind: Kind::Record { list: "hybrid_v1", proof: "ed25519_only_v1_unsigned" }, pin: pin.clone(), intent: unsigned_gate },
    ];

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, v) in &lists {
        files.insert(format!("key_lists/{name}.json"), file_bytes(v));
    }
    for (name, bytes) in &raw {
        files.insert(format!("key_lists/{name}.json"), bytes.clone());
    }
    for (name, v) in &proofs {
        files.insert(format!("proofs/{name}.json"), file_bytes(v));
    }
    let list_file = |name: &str| format!("key_lists/{name}.json");
    // Where another verifier gives a different refusal kind from the
    // reference today, the kind it gives, so its replay holds it to that.
    let by_verifier: BTreeMap<&str, Value> = BTreeMap::from([(
        "ed25519_identity_key_not_a_point",
        json!({
            "go": refused("signature_invalid"),
            "python": refused("signature_invalid"),
            "typescript": refused("signature_invalid"),
        }),
    )]);
    let mut index = Vec::new();
    for c in &cases {
        let (computed, entry) = match &c.kind {
            Kind::List { list } => (
                reference_list(&files[&list_file(list)], &c.pin),
                json!({ "kind": "key_list", "key_list": list_file(list) }),
            ),
            Kind::Record { list, proof } => (
                reference_record(&files[&list_file(list)], &proofs[proof], &c.pin),
                json!({ "kind": "record", "key_list": list_file(list), "proof": format!("proofs/{proof}.json") }),
            ),
            Kind::TwoLists { earlier, later } => (
                reference_two(
                    &files[&list_file(earlier)],
                    &files[&list_file(later)],
                    &c.pin,
                ),
                json!({ "kind": "two_lists", "earlier": list_file(earlier), "later": list_file(later) }),
            ),
        };
        assert_eq!(
            computed, c.intent,
            "case {}: the reference disagrees with what the case was written to show",
            c.name
        );
        let mut entry = entry;
        entry["name"] = json!(c.name);
        entry["note"] = json!(c.note);
        entry["pin"] = json!(c.pin);
        entry["expected_without_ml_dsa"] = without_ml_dsa(&c.pin, &computed);
        if let Some(kinds) = by_verifier.get(c.name) {
            entry["expected_by_verifier"] = kinds.clone();
        }
        entry["expected"] = computed;
        index.push(entry);
    }
    files.insert(
        "cases.json".to_string(),
        file_bytes(&json!({
            "about": "Hybrid key-list vectors. Each case: a kind (key_list, record or two_lists), its files, the pin, the result the Rust reference gives (expected), and the result a verifier without an ML-DSA check gives (expected_without_ml_dsa). Regenerated and compared by tools/nanorix-verify/tests/hybrid_key_list_vectors.rs; see README.md.",
            "key_list_pqc_tag": KEY_LIST_PQC_TAG,
            "cases": index,
        })),
    );
    Built { files }
}

fn regenerating() -> bool {
    std::env::var("NANORIX_REGEN_HYBRID_KEY_LIST_VECTORS").as_deref() == Ok("1")
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/trust_chain_hybrid")
}

fn committed_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for sub in ["", "key_lists", "proofs"] {
        let Ok(rd) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for entry in rd {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !path.is_file()
                || path.extension().and_then(|e| e.to_str()) != Some("json")
                || name == "foreign_signatures.json"
            {
                continue;
            }
            let rel = if sub.is_empty() {
                name
            } else {
                format!("{sub}/{name}")
            };
            out.insert(rel, std::fs::read(&path).expect("read committed vector"));
        }
    }
    out
}

/// A key list's text with its `pqc_manifest_signature` value replaced by
/// [`MASK`], every copy of the member.
fn masked(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut rest: &str = &text;
    let needle = "\"pqc_manifest_signature\": \"";
    while let Some(at) = rest.find(needle) {
        let start = at + needle.len();
        out.push_str(&rest[..start]);
        let end = rest[start..].find('"').expect("closing quote") + start;
        out.push_str(MASK);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out.into_bytes()
}

#[test]
fn committed_hybrid_key_list_vectors_match_the_reference() {
    let built = build();
    let dir = vectors_dir();

    if regenerating() {
        for stale in committed_files(&dir).keys() {
            std::fs::remove_file(dir.join(stale)).expect("remove stale vector");
        }
        for (rel, bytes) in &built.files {
            let path = dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
            std::fs::write(&path, bytes).expect("write vector");
        }
        return;
    }

    let committed = committed_files(&dir);
    assert_eq!(
        built.files.keys().collect::<Vec<_>>(),
        committed.keys().collect::<Vec<_>>(),
        "the committed hybrid vector files and the regenerated set differ in which files exist; \
         rerun with NANORIX_REGEN_HYBRID_KEY_LIST_VECTORS=1 if the change is intended"
    );
    for (rel, bytes) in &built.files {
        assert!(
            masked(&committed[rel]) == masked(bytes),
            "{rel} differs from what the reference regenerates (pqc_manifest_signature masked); \
             rerun with NANORIX_REGEN_HYBRID_KEY_LIST_VECTORS=1 if the change is intended"
        );
    }

    // The masked comparison cannot tell a placeholder from a real foreign
    // signature, so the two foreign cases must carry the script's bytes.
    let foreign: Value =
        serde_json::from_slice(&std::fs::read(foreign_path()).expect("read foreign signatures"))
            .expect("foreign signatures parse");
    for (list, member) in [
        ("hybrid_v1_tag_as_context", "tag_as_context"),
        ("hybrid_v1_hash_mldsa_signature", "hash_ml_dsa_sha512"),
    ] {
        let committed_list: Value =
            serde_json::from_slice(&committed[&format!("key_lists/{list}.json")]).unwrap();
        assert_eq!(
            committed_list["pqc_manifest_signature"],
            json!(format!(
                "base64:{}",
                foreign[member].as_str().expect("foreign signature")
            )),
            "{list} does not carry foreign_signatures.json's {member}: run \
             scripts/gen_hybrid_foreign_signatures.py and regenerate"
        );
    }

    // The committed signatures are the ones every other verifier reads, so the
    // reference runs on the committed files too.
    let cases: Value = serde_json::from_slice(&committed["cases.json"]).unwrap();
    for case in cases["cases"].as_array().unwrap() {
        let file = |member: &str| committed[case[member].as_str().unwrap()].clone();
        let pin = case["pin"].as_str().unwrap();
        let got = match case["kind"].as_str().unwrap() {
            "key_list" => reference_list(&file("key_list"), pin),
            "record" => {
                let proof: Value = serde_json::from_slice(&file("proof")).unwrap();
                reference_record(&file("key_list"), &proof, pin)
            }
            "two_lists" => reference_two(&file("earlier"), &file("later"), pin),
            other => panic!("unknown kind {other}"),
        };
        assert_eq!(got, case["expected"], "committed case {}", case["name"]);
    }
}

#[test]
fn the_hybrid_pin_preimage_is_the_amendment_encoding() {
    let ed = ed_public(SEED_ED_IDENTITY);
    let ml = ml87_public(SEED_ML_IDENTITY);
    assert_eq!(ml.len(), 2592);
    let mut pre = b"nanorix-identity-hybrid-v1\x00Ed25519\x00".to_vec();
    pre.extend_from_slice(&ed);
    pre.extend_from_slice(b"\x00ML-DSA-87\x00");
    pre.extend_from_slice(&ml);
    assert_eq!(
        hybrid_pin(&ed, &ml),
        format!("hybrid1-sha256:{}", hex::encode(Sha256::digest(&pre)))
    );
}

#[test]
fn the_pqc_message_is_the_tag_a_zero_byte_and_the_payload() {
    let m: TrustChainManifest = serde_json::from_value(signed_hybrid(json!({
        byoc_id(&pin_of(SEED_ED_IDENTITY, SEED_ML_IDENTITY)): authority(base_records(), vec![])
    })))
    .unwrap();
    let mut expected = b"nanorix-key-list-pqc-v1\x00".to_vec();
    expected.extend_from_slice(&m.signed_payload().unwrap());
    assert_eq!(m.pqc_signed_message().unwrap(), expected);
}

#[test]
fn attach_refuses_a_signature_over_other_bytes() {
    let pin = pin_of(SEED_ED_IDENTITY, SEED_ML_IDENTITY);
    let m = unsigned(
        json!({ byoc_id(&pin): authority(base_records(), vec![]) }),
        SEED_ED_IDENTITY,
        SEED_ML_IDENTITY,
    );
    let ed_sig = ed_key(SEED_ED_IDENTITY)
        .sign(&m.signed_payload().unwrap())
        .to_bytes();
    let wrong = ml87_sign(SEED_ML_IDENTITY, &m.signed_payload().unwrap());
    assert_eq!(
        m.clone().attach(&ed_sig, &wrong).unwrap_err().kind(),
        "pqc_signature_invalid"
    );
    let right = ml87_sign(SEED_ML_IDENTITY, &m.pqc_signed_message().unwrap());
    let other_ed = ed_key(SEED_OTHER_ED_IDENTITY)
        .sign(&m.signed_payload().unwrap())
        .to_bytes();
    assert_eq!(
        m.clone().attach(&other_ed, &right).unwrap_err().kind(),
        "signature_invalid"
    );
    assert!(m.attach(&ed_sig, &right).is_ok());
}

#[test]
fn the_hosted_list_keeps_its_signed_bytes_and_still_loads() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../static/.well-known/trust-chain.json");
    let bytes = std::fs::read(&path).expect("read the hosted list");
    let m: TrustChainManifest = serde_json::from_slice(&bytes).expect("the hosted list parses");
    let mut written: Value = serde_json::from_slice(&bytes).unwrap();
    for member in ["manifest_signature", "pqc_manifest_signature"] {
        written.as_object_mut().unwrap().remove(member);
    }
    assert_eq!(
        m.signed_payload().unwrap(),
        serde_jcs::to_vec(&written).unwrap(),
        "the new members change no byte the hosted list's signature covers"
    );
    assert_eq!(m.member_not_signed(&bytes).unwrap(), None);
    let reserialized: Value = serde_json::to_value(&m).unwrap();
    let original: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        reserialized, original,
        "re-serialized through the new structs, the hosted list is the same JSON"
    );
    let pin = m.identity_fingerprint.clone();
    assert!(pin.starts_with("sha256:"));
    assert_eq!(
        m.verify_signature(&pin),
        Ok(()),
        "the hosted list still verifies under its pin"
    );
}
