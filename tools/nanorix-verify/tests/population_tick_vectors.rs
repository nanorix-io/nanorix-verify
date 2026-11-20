//! Population tick vectors (the format is the evidence specification's
//! Appendix A.2.1, "Tick"), shared by every verifier that reads ticks.
//!
//! The committed file `fixtures/population_tick/population_tick_vectors.json`
//! holds test-only keys from fixed seeds, three signed ticks with every byte
//! string a tick is built from, and cases with the result a reader must give.
//! This test recomputes each byte string from the primitives with the tags and
//! separators written out here, not taken from the library, and requires both
//! that and the library to give the committed value. It then runs the library
//! on every case.
//!
//! ML-DSA signing in aws-lc-rs is hedged, so a rebuilt file differs in its
//! ML-DSA signatures on every run; the committed signatures are checked by
//! verifying them. To rewrite the file after an intended change, run this test
//! with `NANORIX_REGEN_POPULATION_TICK_VECTORS=1`.

use aws_lc_rs::hmac;
use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_65_SIGNING};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::population_tick::{
    canonical_bytes, log_key_pin, parse_tick, pqc_signed_message, seal_opens, sealed_fingerprint,
    signed_message, tick_salt, verify_tick_signatures, PopulationTick, TickParseError,
    TickSignatureError,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::path::PathBuf;

const SEED_LOG_ED: [u8; 32] = [0x81; 32];
const SEED_LOG_ML: [u8; 32] = [0x82; 32];
const SEED_OTHER_ED: [u8; 32] = [0x83; 32];
const SEED_OTHER_ML: [u8; 32] = [0x84; 32];
const SALT_KEY: [u8; 32] = [0x91; 32];

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/population_tick/population_tick_vectors.json")
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    let body = text.strip_prefix("base64:").unwrap_or(text);
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("fixture base64")
}

fn sha512_hex(data: &[u8]) -> String {
    hex::encode(Sha512::digest(data))
}

fn ed_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn ml_pair(seed: [u8; 32]) -> PqdsaKeyPair {
    PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, &seed).expect("ML-DSA-65 key from seed")
}

fn ml_sign(seed: [u8; 32], message: &[u8]) -> Vec<u8> {
    let pair = ml_pair(seed);
    let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let n = pair.sign(message, &mut signature).expect("ML-DSA-65 signs");
    signature.truncate(n);
    signature
}

// ---- The byte rules, written out from the primitives ----------------------

fn canonical_of(tick: &Value) -> Vec<u8> {
    let mut unsigned = tick.clone();
    let object = unsigned.as_object_mut().unwrap();
    object.remove("signature");
    object.remove("pqc_signature");
    serde_jcs::to_vec(&unsigned).unwrap()
}

fn message_of(tick: &Value) -> String {
    format!(
        "nanorix-population-tick-v1:{}",
        sha512_hex(&canonical_of(tick))
    )
}

fn pqc_message_of(tick: &Value) -> Vec<u8> {
    let mut m = b"nanorix-population-tick-pqc-v1\x00".to_vec();
    m.extend_from_slice(message_of(tick).as_bytes());
    m
}

fn pin_of(ed: &[u8], ml: &[u8]) -> String {
    let mut input = b"nanorix-log-hybrid-v1\x00Ed25519\x00".to_vec();
    input.extend_from_slice(ed);
    input.extend_from_slice(b"\x00ML-DSA-65\x00");
    input.extend_from_slice(ml);
    format!("log1-sha256:{}", hex::encode(Sha256::digest(&input)))
}

fn salt_of(salt_key: &[u8], sequence: u64) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA512, salt_key);
    let message = format!("nanorix-tick-salt-v1\x00{sequence}");
    hmac::sign(&key, message.as_bytes()).as_ref().to_vec()
}

/// The Ed25519 group order L, little-endian. A signature whose S is not below
/// L is refused (RFC 8032, section 5.1.7).
const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn add_order_to_s(signature: &mut [u8]) {
    let mut carry = 0u16;
    for (i, l) in ED25519_ORDER_LE.iter().enumerate() {
        let sum = u16::from(signature[32 + i]) + u16::from(*l) + carry;
        signature[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
}

fn seal_of(salt: &[u8], head_hash: &str) -> String {
    let mut input = b"nanorix-tick-seal-v1\x00".to_vec();
    input.extend_from_slice(salt);
    input.push(0x00);
    input.extend_from_slice(head_hash.as_bytes());
    format!("sha512:{}", sha512_hex(&input))
}

// ---- Building the file -----------------------------------------------------

fn genesis() -> String {
    format!("sha512:{}", sha512_hex(b""))
}

fn head_hash_two() -> String {
    format!("sha512:{}", sha512_hex(b"a head at sequence 7, test-only"))
}

fn list_fingerprint(version: u64) -> String {
    format!(
        "sha512:{}",
        sha512_hex(format!("key list version {version} as handed, test-only").as_bytes())
    )
}

/// An unsigned tick: the members the tick format lists, with empty signatures.
fn unsigned(sequence: u64, head_hash: &str, extra: Value) -> Value {
    let mut tick = json!({
        "type": "nanorix-population-tick-v1",
        "log_key_pin": pin_of(
            &ed_key(SEED_LOG_ED).verifying_key().to_bytes(),
            ml_pair(SEED_LOG_ML).public_key().as_ref(),
        ),
        "sequence": sequence,
        "sealed_fingerprint": seal_of(&salt_of(&SALT_KEY, sequence), head_hash),
        "signature": "",
        "pqc_signature": "",
    });
    for (k, v) in extra.as_object().unwrap() {
        tick[k] = v.clone();
    }
    tick
}

fn signed(mut tick: Value) -> Value {
    let ed = ed_key(SEED_LOG_ED).sign(message_of(&tick).as_bytes());
    let ml = ml_sign(SEED_LOG_ML, &pqc_message_of(&tick));
    tick["signature"] = json!(format!("base64:{}", b64(&ed.to_bytes())));
    tick["pqc_signature"] = json!(format!("base64:{}", b64(&ml)));
    tick
}

fn good_ticks() -> Vec<(&'static str, &'static str, String, Value)> {
    vec![
        (
            "first_tick",
            "Tick 1, before the first head: it seals the genesis value and carries the first \
             key-list version's fingerprint.",
            genesis(),
            signed(unsigned(
                1,
                &genesis(),
                json!({"key_list_fingerprints": [
                    {"list_version": 1, "fingerprint": list_fingerprint(1)}
                ]}),
            )),
        ),
        (
            "tick_with_a_token",
            "Tick 2 seals a head and carries a timestamp token for tick 1. The token bytes \
             are a test-only placeholder: only the token's form is read here.",
            head_hash_two(),
            signed(unsigned(
                2,
                &head_hash_two(),
                json!({"timestamp_tokens": [
                    {"sequence": 1, "token": format!("base64:{}", b64(b"placeholder, not an RFC 3161 token"))}
                ]}),
            )),
        ),
        (
            "final_tick",
            "Tick 3 seals the same head as tick 2 under its own salt, carries the archiving \
             key-list version's fingerprint and is the chain's final tick.",
            head_hash_two(),
            signed(unsigned(
                3,
                &head_hash_two(),
                json!({
                    "key_list_fingerprints": [
                        {"list_version": 2, "fingerprint": list_fingerprint(2)}
                    ],
                    "final": true
                }),
            )),
        ),
    ]
}

fn text(tick: &Value) -> String {
    serde_json::to_string(tick).unwrap()
}

fn build() -> Value {
    let goods = good_ticks();
    let ed = ed_key(SEED_LOG_ED).verifying_key().to_bytes();
    let ml = ml_pair(SEED_LOG_ML).public_key().as_ref().to_vec();
    let encoding: Vec<Value> = goods
        .iter()
        .map(|(name, description, head_hash, tick)| {
            let sequence = tick["sequence"].as_u64().unwrap();
            json!({
                "name": name,
                "description": description,
                "tick": tick,
                "canonical_bytes": String::from_utf8(canonical_of(tick)).unwrap(),
                "signed_message": message_of(tick),
                "pqc_signed_message_hex": hex::encode(pqc_message_of(tick)),
                "head_hash": head_hash,
                "salt_hex": hex::encode(salt_of(&SALT_KEY, sequence)),
                "sealed_fingerprint": tick["sealed_fingerprint"],
                "log_key_pin": tick["log_key_pin"],
            })
        })
        .collect();

    let base = goods[1].3.clone();
    let mut cases = Vec::new();
    let mut add = |name: &str, description: &str, text: String, keys: &str, expected: Value| {
        cases.push(json!({
            "name": name,
            "description": description,
            "text": text,
            "keys": keys,
            "expected": expected,
        }));
    };
    let ok = json!({"parse": "ok", "signatures": "ok"});
    for (name, description, _, tick) in &goods {
        add(name, description, text(tick), "log", ok.clone());
    }
    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut tick = base.clone();
        edit(&mut tick);
        text(&tick)
    };
    let field = |path: &str| json!({"parse": {"field": path}});
    let shape = json!({"parse": "shape"});

    add(
        "unknown_member",
        "A member the tick format does not list, beside the others.",
        edited(&|t| t["random"] = json!("00")),
        "log",
        shape.clone(),
    );
    add(
        "member_missing",
        "No pqc_signature: both signatures are required.",
        edited(&|t| {
            t.as_object_mut().unwrap().remove("pqc_signature");
        }),
        "log",
        shape.clone(),
    );
    add(
        "sequence_as_text",
        "sequence written as the text \"2\".",
        edited(&|t| t["sequence"] = json!("2")),
        "log",
        shape,
    );
    add(
        "type_v2",
        "A later tick type.",
        edited(&|t| t["type"] = json!("nanorix-population-tick-v2")),
        "log",
        field("tick.type"),
    );
    add(
        "log_key_pin_upper_case",
        "The pin's hex in upper case.",
        edited(&|t| {
            let p = t["log_key_pin"]
                .as_str()
                .unwrap()
                .to_uppercase()
                .replace("LOG1-SHA256:", "log1-sha256:");
            t["log_key_pin"] = json!(p);
        }),
        "log",
        field("tick.log_key_pin"),
    );
    add(
        "sequence_0",
        "sequence 0: ticks count from 1.",
        edited(&|t| t["sequence"] = json!(0)),
        "log",
        field("tick.sequence"),
    );
    add(
        "sequence_2_to_the_53",
        "sequence 2^53, above the exact range of RFC 8785 numbers.",
        edited(&|t| t["sequence"] = json!(9_007_199_254_740_992u64)),
        "log",
        field("tick.sequence"),
    );
    add(
        "sealed_fingerprint_without_prefix",
        "The seal without its sha512: prefix.",
        edited(&|t| {
            let s = t["sealed_fingerprint"].as_str().unwrap()[7..].to_string();
            t["sealed_fingerprint"] = json!(s);
        }),
        "log",
        field("tick.sealed_fingerprint"),
    );
    add(
        "key_list_fingerprints_empty",
        "key_list_fingerprints present and empty.",
        edited(&|t| t["key_list_fingerprints"] = json!([])),
        "log",
        field("tick.key_list_fingerprints"),
    );
    add(
        "key_list_versions_out_of_order",
        "Two fingerprints, the second for an earlier list version.",
        edited(&|t| {
            t["key_list_fingerprints"] = json!([
                {"list_version": 3, "fingerprint": list_fingerprint(3)},
                {"list_version": 2, "fingerprint": list_fingerprint(2)}
            ])
        }),
        "log",
        field("tick.key_list_fingerprints[1].list_version"),
    );
    add(
        "token_covers_its_own_tick",
        "A token naming the tick that carries it.",
        edited(&|t| t["timestamp_tokens"][0]["sequence"] = json!(2)),
        "log",
        field("tick.timestamp_tokens[0].sequence"),
    );
    add(
        "token_without_prefix",
        "A token without its base64: prefix.",
        edited(&|t| t["timestamp_tokens"][0]["token"] = json!(b64(b"placeholder"))),
        "log",
        field("tick.timestamp_tokens[0].token"),
    );
    add(
        "final_false",
        "final written as false: the member is present only as true.",
        edited(&|t| t["final"] = json!(false)),
        "log",
        field("tick.final"),
    );
    add(
        "signature_without_prefix",
        "The Ed25519 signature without its base64: prefix.",
        edited(&|t| {
            let s = t["signature"].as_str().unwrap()[7..].to_string();
            t["signature"] = json!(s);
        }),
        "log",
        field("tick.signature"),
    );
    add(
        "pqc_signature_one_byte_short",
        "An ML-DSA-65 signature of 3308 bytes.",
        edited(&|t| {
            let s = unb64(t["pqc_signature"].as_str().unwrap());
            t["pqc_signature"] = json!(format!("base64:{}", b64(&s[..s.len() - 1])));
        }),
        "log",
        field("tick.pqc_signature"),
    );
    add(
        "pqc_signature_without_prefix",
        "The ML-DSA-65 signature without its base64: prefix.",
        edited(&|t| {
            let s = t["pqc_signature"].as_str().unwrap()[7..].to_string();
            t["pqc_signature"] = json!(s);
        }),
        "log",
        field("tick.pqc_signature"),
    );
    add(
        "signature_63_bytes",
        "An Ed25519 signature of 63 bytes.",
        edited(&|t| {
            let s = unb64(t["signature"].as_str().unwrap());
            t["signature"] = json!(format!("base64:{}", b64(&s[..63])));
        }),
        "log",
        field("tick.signature"),
    );
    add(
        "key_list_fingerprint_without_prefix",
        "A key-list fingerprint without its sha512: prefix.",
        edited(&|t| {
            t["key_list_fingerprints"] =
                json!([{"list_version": 1, "fingerprint": list_fingerprint(1)[7..].to_string()}])
        }),
        "log",
        field("tick.key_list_fingerprints[0].fingerprint"),
    );
    add(
        "key_list_version_0",
        "A key-list fingerprint for list version 0: versions count from 1.",
        edited(&|t| {
            t["key_list_fingerprints"] =
                json!([{"list_version": 0, "fingerprint": list_fingerprint(0)}])
        }),
        "log",
        field("tick.key_list_fingerprints[0].list_version"),
    );
    add(
        "key_list_version_2_to_the_53",
        "A key-list fingerprint for list version 2^53.",
        edited(&|t| {
            t["key_list_fingerprints"] = json!([
                {"list_version": 9_007_199_254_740_992u64, "fingerprint": list_fingerprint(1)}
            ])
        }),
        "log",
        field("tick.key_list_fingerprints[0].list_version"),
    );
    add(
        "key_list_version_repeated",
        "Two fingerprints for one list version.",
        edited(&|t| {
            t["key_list_fingerprints"] = json!([
                {"list_version": 2, "fingerprint": list_fingerprint(2)},
                {"list_version": 2, "fingerprint": list_fingerprint(3)}
            ])
        }),
        "log",
        field("tick.key_list_fingerprints[1].list_version"),
    );
    add(
        "timestamp_tokens_empty",
        "timestamp_tokens present and empty.",
        edited(&|t| t["timestamp_tokens"] = json!([])),
        "log",
        field("tick.timestamp_tokens"),
    );
    let token = |sequence: u64| json!({"sequence": sequence, "token": format!("base64:{}", b64(b"placeholder"))});
    add(
        "tokens_out_of_order",
        "Tick 5 with tokens for ticks 3 then 2.",
        edited(&|t| {
            t["sequence"] = json!(5);
            t["timestamp_tokens"] = json!([token(3), token(2)]);
        }),
        "log",
        field("tick.timestamp_tokens[1].sequence"),
    );
    add(
        "token_repeated",
        "Tick 5 with two tokens for tick 3.",
        edited(&|t| {
            t["sequence"] = json!(5);
            t["timestamp_tokens"] = json!([token(3), token(3)]);
        }),
        "log",
        field("tick.timestamp_tokens[1].sequence"),
    );
    add(
        "token_empty",
        "A token written base64: with nothing after it.",
        edited(&|t| t["timestamp_tokens"][0]["token"] = json!("base64:")),
        "log",
        field("tick.timestamp_tokens[0].token"),
    );
    add(
        "final_null",
        "final written as null: an absent member is left out.",
        edited(&|t| t["final"] = Value::Null),
        "log",
        field("tick.final"),
    );
    add(
        "key_list_fingerprints_null",
        "key_list_fingerprints written as null.",
        edited(&|t| t["key_list_fingerprints"] = Value::Null),
        "log",
        field("tick.key_list_fingerprints"),
    );
    add(
        "timestamp_tokens_null",
        "timestamp_tokens written as null.",
        edited(&|t| t["timestamp_tokens"] = Value::Null),
        "log",
        field("tick.timestamp_tokens"),
    );
    let tick_text = text(&base);
    let spaced = tick_text.replacen("\"sequence\":2,", "\"sequence\": 2,", 1);
    assert_ne!(spaced, tick_text);
    add(
        "extra_whitespace",
        "The tick with a space after one colon: not its RFC 8785 bytes.",
        spaced,
        "log",
        json!({"parse": "not_canonical"}),
    );
    let type_member = "\"type\":\"nanorix-population-tick-v1\"";
    let without_type = tick_text.replacen(&format!(",{type_member}}}"), "}", 1);
    assert_ne!(without_type, tick_text);
    let reordered = format!("{{{type_member},{}", &without_type[1..]);
    add(
        "members_reordered",
        "The tick with type written first: not its RFC 8785 member order.",
        reordered,
        "log",
        json!({"parse": "not_canonical"}),
    );
    let twice = tick_text.replacen("\"sequence\":2,", "\"sequence\":2,\"sequence\":2,", 1);
    assert_ne!(twice, tick_text);
    add(
        "sequence_written_twice",
        "The member sequence written twice in the tick.",
        twice,
        "log",
        json!({"parse": {"member_written_twice": "/sequence"}}),
    );
    add(
        "not_json",
        "Bytes that are not JSON.",
        "{\"type\":".to_string(),
        "log",
        json!({"parse": "not_json"}),
    );

    let sig_case = |half: &str| json!({"parse": "ok", "signatures": half});
    add(
        "ed25519_signature_flipped",
        "One bit of the Ed25519 signature flipped.",
        edited(&|t| {
            let mut s = unb64(t["signature"].as_str().unwrap());
            s[0] ^= 1;
            t["signature"] = json!(format!("base64:{}", b64(&s)));
        }),
        "log",
        sig_case("ed25519_does_not_verify"),
    );
    add(
        "ed25519_s_not_reduced",
        "The Ed25519 signature with the group order added to S, so S is not \
        below the group order.",
        edited(&|t| {
            let mut s = unb64(t["signature"].as_str().unwrap());
            add_order_to_s(&mut s);
            t["signature"] = json!(format!("base64:{}", b64(&s)));
        }),
        "log",
        sig_case("ed25519_does_not_verify"),
    );
    add(
        "ml_dsa_signature_flipped",
        "One bit of the ML-DSA-65 signature flipped.",
        edited(&|t| {
            let mut s = unb64(t["pqc_signature"].as_str().unwrap());
            s[100] ^= 1;
            t["pqc_signature"] = json!(format!("base64:{}", b64(&s)));
        }),
        "log",
        sig_case("ml_dsa_65_does_not_verify"),
    );
    add(
        "checked_under_another_log_key",
        "A good tick checked against another log key version: \
        its pin names the first.",
        text(&base),
        "other",
        sig_case("log_key_pin_mismatch"),
    );
    add(
        "ml_dsa_over_the_message_without_its_tag",
        "The ML-DSA-65 half signs the Ed25519 \
        message alone.",
        edited(&|t| {
            let s = ml_sign(SEED_LOG_ML, message_of(t).as_bytes());
            t["pqc_signature"] = json!(format!("base64:{}", b64(&s)));
        }),
        "log",
        sig_case("ml_dsa_65_does_not_verify"),
    );
    add(
        "ml_dsa_without_the_separator",
        "The ML-DSA-65 half signs the tag and the message with \
        no 0x00 between them.",
        edited(&|t| {
            let mut m = b"nanorix-population-tick-pqc-v1".to_vec();
            m.extend_from_slice(message_of(t).as_bytes());
            let s = ml_sign(SEED_LOG_ML, &m);
            t["pqc_signature"] = json!(format!("base64:{}", b64(&s)));
        }),
        "log",
        sig_case("ml_dsa_65_does_not_verify"),
    );
    add(
        "ed25519_over_the_canonical_bytes",
        "The Ed25519 half signs the canonical bytes, not the \
        tagged digest.",
        edited(&|t| {
            let s = ed_key(SEED_LOG_ED).sign(&canonical_of(t));
            t["signature"] = json!(format!("base64:{}", b64(&s.to_bytes())));
        }),
        "log",
        sig_case("ed25519_does_not_verify"),
    );
    add(
        "ed25519_over_the_pqc_message",
        "The Ed25519 half signs the ML-DSA message.",
        edited(&|t| {
            let s = ed_key(SEED_LOG_ED).sign(&pqc_message_of(t));
            t["signature"] = json!(format!("base64:{}", b64(&s.to_bytes())));
        }),
        "log",
        sig_case("ed25519_does_not_verify"),
    );

    let other_ed = ed_key(SEED_OTHER_ED).verifying_key().to_bytes();
    let other_ml = ml_pair(SEED_OTHER_ML).public_key().as_ref().to_vec();
    json!({
        "description": "Population tick vectors. Test-only keys from fixed seeds; \
            never a production or ceremony key. Each case gives a tick's text, the log key \
            version to check it under and the result a reader must give.",
        "keys": {
            "log": {"ed25519": format!("base64:{}", b64(&ed)), "ml_dsa_65": format!("base64:{}", b64(&ml))},
            "other": {"ed25519": format!("base64:{}", b64(&other_ed)), "ml_dsa_65": format!("base64:{}", b64(&other_ml))}
        },
        "salt_key_hex": hex::encode(SALT_KEY),
        "encoding": encoding,
        "cases": cases,
    })
}

fn committed() -> Value {
    if std::env::var("NANORIX_REGEN_POPULATION_TICK_VECTORS").as_deref() == Ok("1") {
        let rendered = serde_json::to_string_pretty(&build()).unwrap() + "\n";
        std::fs::write(fixture_path(), rendered).expect("write the vectors");
    }
    let bytes = std::fs::read(fixture_path()).expect("the committed tick vectors");
    serde_json::from_slice(&bytes).expect("the committed tick vectors are JSON")
}

fn keys(doc: &Value, which: &str) -> (Vec<u8>, Vec<u8>) {
    let k = &doc["keys"][which];
    (
        unb64(k["ed25519"].as_str().unwrap()),
        unb64(k["ml_dsa_65"].as_str().unwrap()),
    )
}

fn salt_key(doc: &Value) -> [u8; 32] {
    hex::decode(doc["salt_key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn the_keys_are_the_seeded_test_keys() {
    let doc = committed();
    let (ed, ml) = keys(&doc, "log");
    assert_eq!(ed, ed_key(SEED_LOG_ED).verifying_key().to_bytes());
    assert_eq!(ml, ml_pair(SEED_LOG_ML).public_key().as_ref());
    assert_eq!(salt_key(&doc), SALT_KEY);
}

#[test]
fn every_byte_string_recomputes_from_the_primitives_and_the_library() {
    let doc = committed();
    let (ed, ml) = keys(&doc, "log");
    let salt_key = salt_key(&doc);
    let entries = doc["encoding"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let value = &entry["tick"];
        let tick: PopulationTick = serde_json::from_value(value.clone()).unwrap();
        let sequence = tick.sequence;
        let head_hash = entry["head_hash"].as_str().unwrap();

        let canonical = entry["canonical_bytes"].as_str().unwrap().as_bytes();
        assert_eq!(canonical_of(value), canonical, "{name}: canonical bytes");
        assert_eq!(
            canonical_bytes(&tick).unwrap(),
            canonical,
            "{name}: library canonical bytes"
        );

        let message = entry["signed_message"].as_str().unwrap();
        assert_eq!(message_of(value), message, "{name}: signed message");
        assert_eq!(
            signed_message(&tick).unwrap(),
            message,
            "{name}: library signed message"
        );

        let pqc = hex::decode(entry["pqc_signed_message_hex"].as_str().unwrap()).unwrap();
        assert_eq!(pqc_message_of(value), pqc, "{name}: pqc message");
        assert_eq!(
            pqc_signed_message(&tick).unwrap(),
            pqc,
            "{name}: library pqc message"
        );

        let pin = entry["log_key_pin"].as_str().unwrap();
        assert_eq!(pin_of(&ed, &ml), pin, "{name}: pin");
        assert_eq!(log_key_pin(&ed, &ml).unwrap(), pin, "{name}: library pin");

        let salt = hex::decode(entry["salt_hex"].as_str().unwrap()).unwrap();
        assert_eq!(salt_of(&salt_key, sequence), salt, "{name}: salt");
        let library_salt = tick_salt(&salt_key, sequence);
        assert_eq!(
            library_salt.as_slice(),
            salt.as_slice(),
            "{name}: library salt"
        );

        let seal = entry["sealed_fingerprint"].as_str().unwrap();
        assert_eq!(seal_of(&salt, head_hash), seal, "{name}: seal");
        assert_eq!(
            sealed_fingerprint(&library_salt, head_hash),
            seal,
            "{name}: library seal"
        );
        assert!(
            seal_opens(&tick, &library_salt, head_hash),
            "{name}: seal opens"
        );
        assert!(!seal_opens(
            &tick,
            &library_salt,
            &genesis().replace('c', "d")
        ));
        assert!(
            !seal_opens(&tick, &tick_salt(&salt_key, sequence + 1), head_hash),
            "{name}: another tick's salt does not open the seal"
        );

        let ed_signature = ed_key(SEED_LOG_ED).sign(message.as_bytes());
        assert_eq!(
            value["signature"].as_str().unwrap(),
            format!("base64:{}", b64(&ed_signature.to_bytes())),
            "{name}: Ed25519 is deterministic"
        );
    }
}

#[test]
fn two_idle_ticks_over_one_head_differ() {
    let doc = committed();
    let entries = doc["encoding"].as_array().unwrap();
    assert_eq!(entries[1]["head_hash"], entries[2]["head_hash"]);
    assert_ne!(
        entries[1]["sealed_fingerprint"],
        entries[2]["sealed_fingerprint"]
    );
}

fn parse_outcome(result: &Result<PopulationTick, TickParseError>) -> Value {
    match result {
        Ok(_) => json!("ok"),
        Err(TickParseError::NotJson) => json!("not_json"),
        Err(TickParseError::NotCanonical) => json!("not_canonical"),
        Err(TickParseError::Shape(_)) => json!("shape"),
        Err(TickParseError::MemberWrittenTwice(p)) => json!({"member_written_twice": p}),
        Err(TickParseError::Field { field, .. }) => json!({"field": field}),
    }
}

fn signature_outcome(result: Result<(), TickSignatureError>) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(TickSignatureError::NoCanonicalEncoding) => "no_canonical_encoding",
        Err(TickSignatureError::LogKeyPinMismatch) => "log_key_pin_mismatch",
        Err(TickSignatureError::Ed25519DoesNotVerify) => "ed25519_does_not_verify",
        Err(TickSignatureError::MlDsa65DoesNotVerify) => "ml_dsa_65_does_not_verify",
    }
}

#[test]
fn every_case_reports_its_expected_result() {
    let doc = committed();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 43);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let parsed = parse_tick(case["text"].as_str().unwrap().as_bytes());
        let mut got = json!({"parse": parse_outcome(&parsed)});
        if let Ok(tick) = &parsed {
            let (ed, ml) = keys(&doc, case["keys"].as_str().unwrap());
            got["signatures"] = json!(signature_outcome(verify_tick_signatures(tick, &ed, &ml)));
        }
        assert_eq!(got, case["expected"], "{name}");
    }
}
