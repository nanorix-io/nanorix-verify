//! Stage 8 vectors shared by every verifier.
//!
//! The Rust library is the reference. This test builds each key list and proof
//! in memory from fixed seeds, runs the reference on every case to get the
//! verdict, and compares the result byte for byte with the files committed
//! under `fixtures/trust_chain/`. Go, Python and TypeScript replay the same
//! files, so a verdict can change in one place only: here.
//!
//! Every case also carries the outcome it was written to show. The test fails
//! if the reference disagrees with that intent, so a changed reference cannot
//! quietly rewrite what a case means.
//!
//! To rewrite the committed files after an intended change, run the test with
//! `NANORIX_REGEN_TRUST_CHAIN_VECTORS=1`.

// These tests pin the wire field `valid`, which is deprecated for callers.
#![allow(deprecated)]

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use nanorix_verify::trust_chain::{AuthorityRecord, TrustChainManifest};
use nanorix_verify::{verify_auditproof, VerifierPolicy};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const CUSTOMER: &str = "us-customer-kms-acme-v1";
const DEFAULT_AUTHORITY: &str = "us-kms-nanorix-v1";

const SEED_KEY_1: [u8; 32] = [0x41; 32];
const SEED_IDENTITY: [u8; 32] = [0x42; 32];
const SEED_OTHER_IDENTITY: [u8; 32] = [0x43; 32];
const SEED_DEFAULT_KEY: [u8; 32] = [0x44; 32];
const SEED_KEY_2: [u8; 32] = [0x45; 32];
const SEED_STRANGER_KEY: [u8; 32] = [0x47; 32];
/// The identity of the key list published for the customer authority that
/// signed `13_customer_only/0000` in the corpus. A test seed, never a real key.
const SEED_CUSTOMER_ONLY_IDENTITY: [u8; 32] = [0x48; 32];
/// The corpus's own fixed test signing seed (`FIXTURE_SIGNING_SEED` in
/// `fixtures/generator.rs`), which signed every corpus proof.
const CORPUS_FIXTURE_SIGNING_SEED: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
];

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn signing_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn public(seed: [u8; 32]) -> [u8; 32] {
    signing_key(seed).verifying_key().to_bytes()
}

fn fingerprint(pubkey: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(pubkey)))
}

fn pin_of(seed: [u8; 32]) -> String {
    fingerprint(&public(seed))
}

fn key_record(version: &str, seed: [u8; 32], archived_at: Option<&str>) -> Value {
    let mut rec = json!({
        "signing_key_version": version,
        "public_key_b64": b64(&public(seed)),
        "public_key_fingerprint": fingerprint(&public(seed)),
        "effective_from": "2026-11-01T00:00:00Z",
    });
    if let Some(at) = archived_at {
        rec["archived_at"] = json!(at);
    }
    rec
}

fn authority(name: &str, active: Vec<Value>, archived: Vec<Value>, revoked: bool) -> Value {
    json!({
        "display_name": name,
        "active_versions": active,
        "archived_versions": archived,
        "revoked": revoked,
    })
}

/// Sign `authorities` under `identity` with the reference, and return the list
/// as the JSON a publisher would host.
fn signed_list(authorities: Value, identity: [u8; 32]) -> Value {
    let map: HashMap<String, AuthorityRecord> =
        serde_json::from_value(authorities).expect("authorities parse");
    let manifest = TrustChainManifest::build_and_sign(
        "1",
        "2026-11-01T00:00:00Z",
        map,
        &signing_key(identity),
    );
    serde_json::to_value(manifest).expect("manifest serializes")
}

fn customer_authorities(active: Vec<Value>, archived: Vec<Value>, revoked: bool) -> Value {
    json!({ CUSTOMER: authority("Acme Health signing authority", active, archived, revoked) })
}

/// A genuine 2.1 proof from the corpus, relabelled to `authority` and
/// `key_version` (either may be absent) and signed over its recomputed
/// canonical hash with `seed`. 2.1 signs both fields.
fn proof(authority: Option<&str>, key_version: &str, seed: [u8; 32]) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json");
    let mut proof: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read corpus fixture")).expect("parse");
    assert_eq!(proof["cdp_version"], "2.1");
    match authority {
        Some(a) => proof["authority_id"] = json!(a),
        None => {
            proof.as_object_mut().unwrap().remove("authority_id");
        }
    }
    proof["signing_key_version"] = json!(key_version);
    let key = signing_key(seed);
    let sig = key.sign(recompute_canonical_hash(&proof).as_bytes());
    proof["attestation"]["public_key"] =
        json!(format!("base64:{}", b64(&key.verifying_key().to_bytes())));
    proof["attestation"]["signature"] = json!(format!("base64:{}", b64(&sig.to_bytes())));
    proof
}

/// The corpus's signed 1.0 proof, given the top-level `signing_key_version`
/// the issuer writes on 1.0 and a `capsule_started` event naming a region, and
/// its `final_hash` signed with `seed`. A 1.0 signature covers that hash alone,
/// so none of these changes is covered, and a verifier must name neither the
/// capsule nor the region.
fn proof_v1_0(key_version: &str, seed: [u8; 32]) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/12_failure_diagnostic_refused/0001_v1_0_signed.json");
    let mut proof: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read corpus fixture")).expect("parse");
    assert_eq!(proof["cdp_version"], "1.0");
    assert!(proof.get("authority_id").is_none());
    proof["signing_key_version"] = json!(key_version);
    proof["activity"] = json!([{ "event": "capsule_started", "region": "us-central1" }]);
    let final_hash = proof["final_hash"].as_str().expect("final_hash");
    let message = final_hash.strip_prefix("sha512:").unwrap_or(final_hash);
    let key = signing_key(seed);
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

/// What the reference does with one case: a refusal before any proof is read,
/// or the verdict. The list is parsed from its file's bytes, as
/// `trust_chain::load_from_file` does.
fn reference(key_list: &[u8], proof: &Value, pin: &str, required: Option<&str>) -> Value {
    let manifest: TrustChainManifest = match serde_json::from_slice(key_list) {
        Ok(m) => m,
        Err(_) => return json!({ "refusal": "load_failed" }),
    };
    if let Err(e) = manifest.verify_signature(pin) {
        return json!({ "refusal": e.kind() });
    }
    let policy = VerifierPolicy {
        required_authority_id: required.map(String::from),
        trust_chain: Some(manifest),
        pinned_identity_fingerprint: Some(pin.to_string()),
        ..Default::default()
    };
    let result = verify_auditproof(proof, &[], &policy);
    assert_eq!(
        result.ok(),
        result.status() == "verified",
        "ok() is true only for verified"
    );
    if proof["cdp_version"] == "1.0" {
        assert_eq!(
            result.metadata.capsule_id, None,
            "a 1.0 result names no capsule"
        );
        assert_eq!(result.metadata.region, None, "a 1.0 result names no region");
    }
    json!({
        "valid": result.valid,
        "stage_reached": result.stage_reached,
        "status": result.status(),
        "failure_reason": result.failure_reason.map(|r| serde_json::to_value(r).expect("reason serializes")),
    })
}

fn verdict(valid: bool, stage: u8, status: &str, reason: Value) -> Value {
    json!({ "valid": valid, "stage_reached": stage, "status": status, "failure_reason": reason })
}

fn ok8() -> Value {
    verdict(true, 8, "verified", Value::Null)
}

fn refusal(kind: &str) -> Value {
    json!({ "refusal": kind })
}

struct Case {
    name: &'static str,
    note: &'static str,
    key_list: &'static str,
    proof: &'static str,
    pin: String,
    required_authority_id: Option<&'static str>,
    intent: Value,
}

struct Built {
    files: BTreeMap<String, Vec<u8>>,
}

fn build() -> Built {
    let pin = pin_of(SEED_IDENTITY);

    let mut lists: BTreeMap<&'static str, Value> = BTreeMap::new();
    let mut proofs: BTreeMap<&'static str, Value> = BTreeMap::new();

    // Key lists.
    let customer = customer_authorities(vec![key_record("1", SEED_KEY_1, None)], vec![], false);
    lists.insert("customer_v1", signed_list(customer.clone(), SEED_IDENTITY));

    let rotated = customer_authorities(
        vec![key_record("2", SEED_KEY_2, None)],
        vec![key_record("1", SEED_KEY_1, Some("2026-12-01T00:00:00Z"))],
        false,
    );
    lists.insert(
        "customer_rotated",
        signed_list(rotated.clone(), SEED_IDENTITY),
    );

    let mut archive_row_removed = lists["customer_rotated"].clone();
    archive_row_removed["authorities"][CUSTOMER]["archived_versions"] = json!([]);
    lists.insert("customer_rotated_archive_row_removed", archive_row_removed);

    let mut key_swapped = lists["customer_v1"].clone();
    key_swapped["authorities"][CUSTOMER]["active_versions"][0]["public_key_b64"] =
        json!(b64(&public(SEED_STRANGER_KEY)));
    lists.insert("customer_v1_key_swapped_after_signing", key_swapped);

    lists.insert(
        "customer_v1_other_identity",
        signed_list(customer.clone(), SEED_OTHER_IDENTITY),
    );

    // Signed by the other identity, but relabelled to claim the pinned one:
    // both the fingerprint and the inline key are the customer's, the
    // signature is not.
    let mut forged = lists["customer_v1_other_identity"].clone();
    forged["identity_fingerprint"] = json!(pin_of(SEED_IDENTITY));
    forged["identity_public_key_b64"] = json!(b64(&public(SEED_IDENTITY)));
    lists.insert("customer_v1_other_identity_claiming_pin", forged);

    // Same, but only the fingerprint field is relabelled; the inline key stays
    // the other identity's, so the fingerprint no longer matches its key.
    let mut claim_only = lists["customer_v1_other_identity"].clone();
    claim_only["identity_fingerprint"] = json!(pin_of(SEED_IDENTITY));
    lists.insert(
        "customer_v1_other_identity_fingerprint_relabelled",
        claim_only,
    );

    lists.insert(
        "customer_revoked",
        signed_list(
            customer_authorities(vec![key_record("1", SEED_KEY_1, None)], vec![], true),
            SEED_IDENTITY,
        ),
    );

    // One version name in both lists, holding different keys. The active row
    // is the one a proof resolves to.
    lists.insert(
        "customer_active_shadows_archived",
        signed_list(
            customer_authorities(
                vec![key_record("1", SEED_KEY_1, None)],
                vec![key_record("1", SEED_KEY_2, Some("2026-12-01T00:00:00Z"))],
                false,
            ),
            SEED_IDENTITY,
        ),
    );

    // Nanorix's default authority alone, marked revoked.
    lists.insert(
        "default_revoked",
        signed_list(
            json!({
                DEFAULT_AUTHORITY: authority("Nanorix default authority", vec![key_record("1", SEED_DEFAULT_KEY, None)], vec![], true),
            }),
            SEED_IDENTITY,
        ),
    );

    // Two authorities: the signature covers both.
    lists.insert(
        "customer_and_default",
        signed_list(
            json!({
                CUSTOMER: authority("Acme Health signing authority", vec![key_record("1", SEED_KEY_1, None)], vec![], false),
                DEFAULT_AUTHORITY: authority("Nanorix default authority", vec![key_record("1", SEED_DEFAULT_KEY, None)], vec![], false),
            }),
            SEED_IDENTITY,
        ),
    );

    // The signature covers the list as the reference re-serializes it:
    // `archived_versions` and `revoked` default in before signing.
    let mut defaults_omitted = lists["customer_v1"].clone();
    defaults_omitted["authorities"][CUSTOMER]
        .as_object_mut()
        .unwrap()
        .remove("archived_versions");
    defaults_omitted["authorities"][CUSTOMER]
        .as_object_mut()
        .unwrap()
        .remove("revoked");
    lists.insert("customer_v1_defaults_omitted", defaults_omitted);

    // Fields the reference does not read are not covered by the signature.
    let mut extra_fields = lists["customer_v1"].clone();
    extra_fields["note"] = json!("added after signing");
    extra_fields["authorities"][CUSTOMER]["active_versions"][0]["comment"] =
        json!("added after signing");
    lists.insert("customer_v1_unknown_fields_added", extra_fields);

    // The post-quantum slot is outside the signed bytes.
    let mut pqc = lists["customer_v1"].clone();
    pqc["pqc_manifest_signature"] = json!("base64:AAAA");
    lists.insert("customer_v1_pqc_slot_populated", pqc);

    // The signature is read with or without its `base64:` prefix.
    let mut bare_sig = lists["customer_v1"].clone();
    let sig = bare_sig["manifest_signature"]
        .as_str()
        .unwrap()
        .trim_start_matches("base64:")
        .to_string();
    bare_sig["manifest_signature"] = json!(sig);
    lists.insert("customer_v1_signature_without_prefix", bare_sig);

    let mut missing_field = lists["customer_v1"].clone();
    missing_field["authorities"][CUSTOMER]
        .as_object_mut()
        .unwrap()
        .remove("display_name");
    lists.insert("customer_v1_display_name_missing", missing_field);

    // The marker that an authority emits population heads is signed when it
    // is true, and when false is the same signed bytes as its absence.
    let mut marked = customer.clone();
    marked[CUSTOMER]["emits_population_heads"] = json!(true);
    lists.insert("customer_marked", signed_list(marked, SEED_IDENTITY));

    let mut marker_removed = lists["customer_marked"].clone();
    marker_removed["authorities"][CUSTOMER]
        .as_object_mut()
        .unwrap()
        .remove("emits_population_heads");
    lists.insert("customer_marked_marker_removed", marker_removed);

    let mut marker_added = lists["customer_v1"].clone();
    marker_added["authorities"][CUSTOMER]["emits_population_heads"] = json!(true);
    lists.insert("customer_v1_marker_added_after_signing", marker_added);

    let mut marker_false = lists["customer_v1"].clone();
    marker_false["authorities"][CUSTOMER]["emits_population_heads"] = json!(false);
    lists.insert("customer_v1_marker_false", marker_false);

    let mut marker_text = lists["customer_v1"].clone();
    marker_text["authorities"][CUSTOMER]["emits_population_heads"] = json!("true");
    lists.insert("customer_v1_marker_not_boolean", marker_text);

    let mut no_identity_key = lists["customer_v1"].clone();
    no_identity_key["identity_public_key_b64"] = json!("");
    lists.insert("customer_v1_identity_key_empty", no_identity_key);

    // A signature only a non-strict Ed25519 check accepts: the identity key is
    // the small-order identity point and the signature is R = identity, S = 0,
    // which verifies for every message under the cofactorless equation.
    let weak_key = {
        let mut k = [0u8; 32];
        k[0] = 1;
        k
    };
    let weak_pin = fingerprint(&weak_key);
    let mut weak = lists["customer_v1"].clone();
    weak["identity_public_key_b64"] = json!(b64(&weak_key));
    weak["identity_fingerprint"] = json!(weak_pin);
    let mut weak_sig = [0u8; 64];
    weak_sig[0] = 1;
    weak["manifest_signature"] = json!(format!("base64:{}", b64(&weak_sig)));
    {
        let mut payload = weak.clone();
        let obj = payload.as_object_mut().unwrap();
        obj.remove("manifest_signature");
        obj.remove("pqc_manifest_signature");
        let bytes = serde_jcs::to_vec(&payload).expect("jcs");
        let vk = VerifyingKey::from_bytes(&weak_key).expect("identity point decodes");
        let sig = ed25519_dalek::Signature::from_bytes(&weak_sig);
        assert!(
            vk.verify(&bytes, &sig).is_ok(),
            "non-strict check must accept the weak signature"
        );
        assert!(
            vk.verify_strict(&bytes, &sig).is_err(),
            "strict check must refuse it"
        );
    }
    lists.insert("customer_v1_non_strict_signature_only", weak);

    // Proofs.
    proofs.insert("customer_v1", proof(Some(CUSTOMER), "1", SEED_KEY_1));
    proofs.insert("customer_v2", proof(Some(CUSTOMER), "2", SEED_KEY_2));
    proofs.insert(
        "customer_v2_signed_by_key_1",
        proof(Some(CUSTOMER), "2", SEED_KEY_1),
    );
    proofs.insert(
        "customer_v1_signed_by_stranger_key",
        proof(Some(CUSTOMER), "1", SEED_STRANGER_KEY),
    );
    proofs.insert(
        "customer_v1_signed_by_key_2",
        proof(Some(CUSTOMER), "1", SEED_KEY_2),
    );
    proofs.insert(
        "default_authority_v1",
        proof(Some(DEFAULT_AUTHORITY), "1", SEED_KEY_1),
    );
    proofs.insert(
        "default_authority_v1_own_key",
        proof(Some(DEFAULT_AUTHORITY), "1", SEED_DEFAULT_KEY),
    );
    proofs.insert("no_authority_field_v1", proof(None, "1", SEED_DEFAULT_KEY));
    proofs.insert("v1_0_default_authority", proof_v1_0("1", SEED_DEFAULT_KEY));
    proofs.insert(
        "v1_0_default_authority_signed_by_stranger_key",
        proof_v1_0("1", SEED_STRANGER_KEY),
    );
    // The corpus's signed customer_only proof, as committed, and a key list
    // published for the customer authority its signed labels name.
    let customer_only_corpus: Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/corpus/13_customer_only/0000_v2_1_customer_only_signed.json"),
        )
        .expect("read corpus fixture"),
    )
    .expect("parse");
    assert_eq!(customer_only_corpus["signing_mode"], "customer_only");
    assert_eq!(customer_only_corpus["authority_id"], CUSTOMER);
    proofs.insert("customer_only_corpus_0000", customer_only_corpus);
    lists.insert(
        "customer_only_authority",
        signed_list(
            customer_authorities(
                vec![key_record("1", CORPUS_FIXTURE_SIGNING_SEED, None)],
                vec![],
                false,
            ),
            SEED_CUSTOMER_ONLY_IDENTITY,
        ),
    );

    let mut with_algorithm = key_record("1", SEED_KEY_1, None);
    with_algorithm["algorithm"] = json!("Ed25519");
    let customer_with_algorithm = customer_authorities(vec![with_algorithm], vec![], false);
    lists.insert(
        "customer_v1_algorithm",
        signed_list(customer_with_algorithm, SEED_IDENTITY),
    );
    let mut algorithm_edited = lists["customer_v1_algorithm"].clone();
    algorithm_edited["authorities"][CUSTOMER]["active_versions"][0]["algorithm"] =
        json!("ML-DSA-65");
    lists.insert(
        "customer_v1_algorithm_edited_after_signing",
        algorithm_edited,
    );
    let mut algorithm_number = lists["customer_v1"].clone();
    algorithm_number["authorities"][CUSTOMER]["active_versions"][0]["algorithm"] = json!(7);
    lists.insert("customer_v1_algorithm_not_a_string", algorithm_number);

    // Lists only the file's bytes can carry. Each is `customer_v1`, which
    // verifies, in another encoding or with one member the reference does not
    // read, holding a constant that is not JSON. serde_json refuses each one,
    // and a parser that skips a byte order mark, guesses the encoding or reads
    // NaN would load it.
    let base = file_bytes(&lists["customer_v1"]);
    let base_text = String::from_utf8(base.clone()).expect("customer_v1 is UTF-8");
    assert_eq!(base.first(), Some(&b'{'), "customer_v1 is a JSON object");
    let with_unread_member = |raw: &[u8]| -> Vec<u8> {
        let mut out = b"{\n  \"x_unread\": ".to_vec();
        out.extend_from_slice(raw);
        out.push(b',');
        out.extend_from_slice(&base[1..]);
        out
    };
    let mut raw_lists: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(&base);
    raw_lists.insert("customer_v1_utf8_bom", bom);
    let mut utf16 = vec![0xFF, 0xFE];
    for unit in base_text.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    raw_lists.insert("customer_v1_utf16le", utf16);
    let mut utf32 = vec![0xFF, 0xFE, 0x00, 0x00];
    for c in base_text.chars() {
        utf32.extend_from_slice(&u32::from(c).to_le_bytes());
    }
    raw_lists.insert("customer_v1_utf32le", utf32);
    raw_lists.insert("customer_v1_nan_member", with_unread_member(b"NaN"));
    raw_lists.insert(
        "customer_v1_infinity_member",
        with_unread_member(b"-Infinity"),
    );
    // With a JSON value in the unread member the list still verifies, so each
    // refusal below is the reference refusing that one value or encoding.
    let customer_proof = &proofs["customer_v1"];
    for raw in [&b"null"[..], &b"\"NaN\""[..]] {
        assert_eq!(
            reference(&with_unread_member(raw), customer_proof, &pin, None),
            ok8(),
            "customer_v1 with an unread member holding {}",
            String::from_utf8_lossy(raw)
        );
    }
    for name in raw_lists.keys() {
        assert!(
            !lists.contains_key(name),
            "{name} is both a raw and a JSON list"
        );
    }

    let cases = vec![
        Case { name: "active_version_resolves", note: "The pinned identity signed the list; the proof's authority and key version are in it. Stage 8.", key_list: "customer_v1", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "required_authority_matches", note: "As above, with a required authority id equal to the proof's.", key_list: "customer_v1", proof: "customer_v1", pin: pin.clone(), required_authority_id: Some(CUSTOMER), intent: ok8() },
        Case { name: "archived_version_resolves", note: "The proof's key version was archived by a rotation; the list still holds it, so it resolves.", key_list: "customer_rotated", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "rotated_active_version_resolves", note: "After the rotation, a proof under the new active version resolves.", key_list: "customer_rotated", proof: "customer_v2", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "wrong_pin_refused", note: "The pin names another identity than the one that signed the list. Refused before any proof is checked.", key_list: "customer_v1", proof: "customer_v1", pin: pin_of(SEED_OTHER_IDENTITY), required_authority_id: None, intent: refusal("fingerprint_mismatch") },
        Case { name: "list_signed_by_other_identity_refused", note: "A well-formed list signed by, and naming, another identity, checked under the customer's pin.", key_list: "customer_v1_other_identity", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("fingerprint_mismatch") },
        Case { name: "list_claiming_pinned_fingerprint_with_other_key_refused", note: "Another identity's list whose fingerprint field is relabelled to the pin; the inline key still hashes to the other identity.", key_list: "customer_v1_other_identity_fingerprint_relabelled", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("fingerprint_mismatch") },
        Case { name: "list_claiming_pinned_identity_fully_refused", note: "Another identity's list relabelled with the pinned fingerprint and the pinned public key; only the signature is not the pinned identity's.", key_list: "customer_v1_other_identity_claiming_pin", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("signature_invalid") },
        Case { name: "authority_key_edited_after_signing_refused", note: "An authority's public key was replaced after the list was signed.", key_list: "customer_v1_key_swapped_after_signing", proof: "customer_v1_signed_by_stranger_key", pin: pin.clone(), required_authority_id: None, intent: refusal("signature_invalid") },
        Case { name: "archived_row_removed_after_signing_refused", note: "The archived row was deleted after signing; a proof under it would otherwise be lost.", key_list: "customer_rotated_archive_row_removed", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("signature_invalid") },
        Case { name: "non_strict_only_signature_refused", note: "A small-order identity key and a signature that a non-strict Ed25519 check accepts for any message. The pin is that key's own fingerprint.", key_list: "customer_v1_non_strict_signature_only", proof: "customer_v1", pin: weak_pin, required_authority_id: None, intent: refusal("signature_invalid") },
        Case { name: "key_version_not_in_list", note: "The proof names version 2; the list holds only version 1. Stage 6.", key_list: "customer_v1", proof: "customer_v2_signed_by_key_1", pin: pin.clone(), required_authority_id: None, intent: verdict(false, 6, "not_verified", json!({ "type": "signing_key_version_unknown", "version": "2" })) },
        Case { name: "authority_not_in_list", note: "A proof naming Nanorix's default authority, checked against the customer's list. The list does not hold that authority. Stage 6.", key_list: "customer_v1", proof: "default_authority_v1", pin: pin.clone(), required_authority_id: None, intent: verdict(false, 6, "not_verified", json!({ "type": "signing_key_version_unknown", "version": "1" })) },
        Case { name: "required_authority_mismatch", note: "The customer's proof under a required authority id naming Nanorix's default authority. Refused at stage 2 by the policy pin, before the list is read.", key_list: "customer_v1", proof: "customer_v1", pin: pin.clone(), required_authority_id: Some(DEFAULT_AUTHORITY), intent: verdict(false, 2, "not_verified", json!({ "type": "authority_id_mismatch", "claimed_authority_id": CUSTOMER, "expected_authority_id": DEFAULT_AUTHORITY, "reason": "verifier_policy_authority_id_mismatch" })) },
        Case { name: "required_authority_absent_from_proof", note: "A proof with no authority_id under a required authority id other than the default.", key_list: "customer_and_default", proof: "no_authority_field_v1", pin: pin.clone(), required_authority_id: Some(CUSTOMER), intent: verdict(false, 2, "not_verified", json!({ "type": "authority_id_mismatch", "claimed_authority_id": null, "expected_authority_id": CUSTOMER, "reason": "verifier_policy_demands_customer_hsm_audit_proof_has_none" })) },
        Case { name: "different_key_under_listed_version", note: "The proof's embedded key verifies its own signature but is not the key the list holds under that version. Stage 7.", key_list: "customer_v1", proof: "customer_v1_signed_by_stranger_key", pin: pin.clone(), required_authority_id: None, intent: verdict(false, 7, "not_verified", json!({ "type": "signature_mismatch", "reason": "does_not_verify" })) },
        Case { name: "absent_authority_field_means_default", note: "A proof with no authority_id is read as Nanorix's default authority and resolved in a list that holds it.", key_list: "customer_and_default", proof: "no_authority_field_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "default_authority_in_list_resolves", note: "Both authorities in one signed list; the proof under Nanorix's default authority resolves to its own key.", key_list: "customer_and_default", proof: "default_authority_v1_own_key", pin: pin.clone(), required_authority_id: Some(DEFAULT_AUTHORITY), intent: ok8() },
        Case { name: "revoked_authority", note: "The list marks the authority revoked. Stage 8 is reached and the proof is not valid.", key_list: "customer_revoked", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: verdict(false, 8, "not_verified", json!({ "type": "authority_revoked" })) },
        Case { name: "active_row_wins_over_archived_row", note: "One version name in both lists with different keys. A proof signed by the active key resolves.", key_list: "customer_active_shadows_archived", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "archived_row_never_used_when_active_has_name", note: "Same list; a proof signed by the archived row's key is checked against the active key. Stage 7.", key_list: "customer_active_shadows_archived", proof: "customer_v1_signed_by_key_2", pin: pin.clone(), required_authority_id: None, intent: verdict(false, 7, "not_verified", json!({ "type": "signature_mismatch", "reason": "does_not_verify" })) },
        Case { name: "defaults_omitted_in_published_list", note: "The published list leaves out archived_versions and revoked; the signature was made over the list with both filled in.", key_list: "customer_v1_defaults_omitted", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "unknown_fields_are_not_covered", note: "Fields the reference does not read were added after signing. The reference ignores them and the list verifies.", key_list: "customer_v1_unknown_fields_added", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "pqc_slot_is_not_covered", note: "The reserved post-quantum signature slot is populated with a value. It is outside the signed bytes.", key_list: "customer_v1_pqc_slot_populated", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "signature_without_base64_prefix", note: "The manifest signature is given without its base64: prefix.", key_list: "customer_v1_signature_without_prefix", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "list_missing_required_field", note: "An authority record without display_name does not parse as a key list.", key_list: "customer_v1_display_name_missing", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
        Case { name: "key_record_algorithm_is_signed", note: "The key record carries algorithm, as every hosted key record does. It is in the signed bytes.", key_list: "customer_v1_algorithm", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "algorithm_edited_after_signing_refused", note: "The key record's algorithm was changed after signing.", key_list: "customer_v1_algorithm_edited_after_signing", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("signature_invalid") },
        Case { name: "algorithm_not_a_string", note: "A key record's algorithm that is not a string does not parse as a key list.", key_list: "customer_v1_algorithm_not_a_string", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
        Case { name: "marked_authority_resolves", note: "The list marks the authority as emitting population heads. The marker is in the signed bytes.", key_list: "customer_marked", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "marker_removed_after_signing_refused", note: "The marker was removed after signing, which would hide that the authority emits heads.", key_list: "customer_marked_marker_removed", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("signature_invalid") },
        Case { name: "marker_added_after_signing_refused", note: "The marker was added to a list signed without it.", key_list: "customer_v1_marker_added_after_signing", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("signature_invalid") },
        Case { name: "marker_false_signs_as_absent", note: "A marker of false is not in the signed bytes, the same as no marker.", key_list: "customer_v1_marker_false", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: ok8() },
        Case { name: "marker_not_boolean", note: "A marker that is not a boolean does not parse as a key list.", key_list: "customer_v1_marker_not_boolean", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
        Case { name: "identity_key_empty", note: "A list that carries no identity public key cannot be checked against a pin.", key_list: "customer_v1_identity_key_empty", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("malformed") },
        Case { name: "utf8_bom_refused", note: "customer_v1 with a UTF-8 byte order mark in front. serde_json refuses it; a parser that skips the mark would load the list.", key_list: "customer_v1_utf8_bom", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
        Case { name: "utf16_refused", note: "customer_v1 written as UTF-16 with its byte order mark. The reference reads UTF-8 only.", key_list: "customer_v1_utf16le", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
        Case { name: "utf32_refused", note: "customer_v1 written as UTF-32 with its byte order mark. The reference reads UTF-8 only.", key_list: "customer_v1_utf32le", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
        Case { name: "nan_refused", note: "customer_v1 with one member the reference does not read, whose value is NaN, which is not JSON.", key_list: "customer_v1_nan_member", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
        Case { name: "customer_only_corpus_proof_resolves", note: "The corpus's signed customer_only proof (13_customer_only/0000), whose signed labels name the customer authority, resolves in the key list published for that authority under that list's own pin. Stage 8, the same as nanorix_only.", key_list: "customer_only_authority", proof: "customer_only_corpus_0000", pin: pin_of(SEED_CUSTOMER_ONLY_IDENTITY), required_authority_id: None, intent: ok8() },
        Case { name: "v1_0_proof_never_anchors", note: "A genuine 1.0 proof whose final_hash is signed by the key the list holds for Nanorix's default authority under version 1, checked against that list under its pin. A 1.0 signature covers final_hash alone, which binds destroyed_at and the two optional Merkle roots. It does not bind the capsule_id itself (only through record receipts, which a holder can remove), the region or the key id, so a 1.0 proof is never anchored: stage 7, not stage 8. The proof's capsule_started event names a region, which no verifier may report.", key_list: "customer_and_default", proof: "v1_0_default_authority", pin: pin.clone(), required_authority_id: None, intent: verdict(true, 7, "not_anchored", Value::Null) },
        Case { name: "v1_0_revoked_authority", note: "The same 1.0 proof under a list that marks Nanorix's default authority revoked. A 1.0 proof runs the revocation check as 2.x does, so it is refused at stage 8 like a 2.x proof.", key_list: "default_revoked", proof: "v1_0_default_authority", pin: pin.clone(), required_authority_id: None, intent: verdict(false, 8, "not_verified", json!({ "type": "authority_revoked" })) },
        Case { name: "v1_0_forgery_under_list", note: "A 1.0 proof self-signed with a key of its own, naming version 1 of Nanorix's default authority. Its signature verifies on the key it carries and not on the listed key, so it is refused at stage 7, as a 2.x forgery is.", key_list: "customer_and_default", proof: "v1_0_default_authority_signed_by_stranger_key", pin: pin.clone(), required_authority_id: None, intent: verdict(false, 7, "not_verified", json!({ "type": "signature_mismatch", "reason": "does_not_verify" })) },
        Case { name: "infinity_refused", note: "customer_v1 with one member the reference does not read, whose value is -Infinity, which is not JSON.", key_list: "customer_v1_infinity_member", proof: "customer_v1", pin: pin.clone(), required_authority_id: None, intent: refusal("load_failed") },
    ];

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, v) in &lists {
        files.insert(format!("key_lists/{name}.json"), file_bytes(v));
    }
    for (name, bytes) in &raw_lists {
        files.insert(format!("key_lists/{name}.json"), bytes.clone());
    }
    for (name, v) in &proofs {
        files.insert(format!("proofs/{name}.json"), file_bytes(v));
    }

    let mut index = Vec::new();
    for c in &cases {
        let list_bytes = match raw_lists.get(c.key_list) {
            Some(bytes) => bytes.clone(),
            None => file_bytes(&lists[c.key_list]),
        };
        let computed = reference(
            &list_bytes,
            &proofs[c.proof],
            &c.pin,
            c.required_authority_id,
        );
        assert_eq!(
            computed, c.intent,
            "case {}: the reference disagrees with what the case was written to show",
            c.name
        );
        index.push(json!({
            "name": c.name,
            "note": c.note,
            "key_list": format!("key_lists/{}.json", c.key_list),
            "proof": format!("proofs/{}.json", c.proof),
            "pin": c.pin,
            "required_authority_id": c.required_authority_id,
            "expected": computed,
        }));
    }
    files.insert(
        "cases.json".to_string(),
        file_bytes(&json!({
            "about": "Stage 8 vectors. Each case: a signed key list, a proof, the pinned identity fingerprint, an optional required authority id, and the verdict or refusal the Rust reference gives. Regenerated and compared by tools/nanorix-verify/tests/trust_chain_vectors.rs.",
            "cases": index,
        })),
    );

    Built { files }
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/trust_chain")
}

fn committed_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for sub in ["", "key_lists", "proofs"] {
        let d = dir.join(sub);
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in rd {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let rel = if sub.is_empty() {
                entry.file_name().to_string_lossy().to_string()
            } else {
                format!("{sub}/{}", entry.file_name().to_string_lossy())
            };
            out.insert(rel, std::fs::read(&path).expect("read committed vector"));
        }
    }
    out
}

#[test]
fn committed_stage8_vectors_match_the_reference() {
    let built = build();
    let dir = vectors_dir();

    if std::env::var("NANORIX_REGEN_TRUST_CHAIN_VECTORS").as_deref() == Ok("1") {
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
    let built_names: Vec<&String> = built.files.keys().collect();
    let committed_names: Vec<&String> = committed.keys().collect();
    assert_eq!(
        built_names, committed_names,
        "the committed vector files and the regenerated set differ in which files exist; \
         rerun with NANORIX_REGEN_TRUST_CHAIN_VECTORS=1 if the change is intended"
    );
    for (rel, bytes) in &built.files {
        assert!(
            committed[rel] == *bytes,
            "{rel} differs from what the reference regenerates; rerun with \
             NANORIX_REGEN_TRUST_CHAIN_VECTORS=1 if the change is intended"
        );
    }
}
