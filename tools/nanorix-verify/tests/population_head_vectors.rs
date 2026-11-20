//! Population head vectors, generated independently by
//! `fixtures/population_head/generate_population_head_vectors.py`.
//!
//! Each case hands `verify_population` the named pool proofs and the heads,
//! with or without the signed key list, and compares the whole reported result with
//! the generator's expected JSON: the verdict, the label, every check's
//! outcome and reason, and the unwitnessed proofs. A `head_malformed`
//! reason's `detail` is free text for a human reader, so it is checked to be
//! present and then left out of the comparison.

// These tests pin the wire field `valid`, which is deprecated for callers.
#![allow(deprecated)]

use nanorix_verify::population_head::{
    canonical_bytes, genesis_prev_head_hash, head_hash, signed_message, tip_proof_hash,
    verify_population, PopulationHead,
};
use nanorix_verify::trust_chain::{
    repeated_member, MemberNotCarried, TrustChainManifest, VerifiedManifest,
};
use nanorix_verify::{verify_auditproof, VerifierPolicy};
use serde_json::Value;
use std::collections::BTreeSet;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../fixtures/population_head/population_head_vectors.json"
    ))
    .expect("vectors parse")
}

fn verified(doc: &Value, list: &Value) -> VerifiedManifest {
    let list: TrustChainManifest = serde_json::from_value(list.clone()).expect("key list parses");
    list.into_verified(doc["key_list_identity_fingerprint"].as_str().unwrap())
        .expect("key list verifies against its pin")
}

fn key_list(doc: &Value) -> VerifiedManifest {
    verified(doc, &doc["key_list"])
}

#[test]
fn pool_proofs_verify_to_their_recorded_stage() {
    let doc = vectors();
    let manifest = key_list(&doc);
    let anchored = VerifierPolicy {
        trust_chain: Some(manifest.manifest().clone()),
        pinned_identity_fingerprint: Some(manifest.manifest().identity_fingerprint.clone()),
        ..Default::default()
    };
    let pool = doc["proof_pool"].as_object().unwrap();
    let stages = doc["proof_stages"].as_object().unwrap();
    let failures = doc["proof_failures"].as_object().unwrap();
    let recorded: BTreeSet<&String> = stages.keys().chain(failures.keys()).collect();
    assert_eq!(recorded.len(), stages.len() + failures.len());
    assert_eq!(recorded, pool.keys().collect::<BTreeSet<_>>());
    for (name, stage) in stages {
        let stage = stage.as_u64().unwrap();
        let policy = if stage == 8 {
            anchored.clone()
        } else {
            VerifierPolicy::default()
        };
        let r = verify_auditproof(&pool[name], &[], &policy);
        assert!(r.valid, "{name}: {:?}", r.failure_reason);
        assert_eq!(u64::from(r.stage_reached), stage, "{name}");
    }
    for (name, failure) in failures {
        let r = verify_auditproof(&pool[name], &[], &VerifierPolicy::default());
        assert!(!r.valid, "{name}");
        assert_eq!(
            u64::from(r.stage_reached),
            failure["stage_reached"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            serde_json::to_value(&r.failure_reason).unwrap(),
            failure["failure_reason"],
            "{name}"
        );
    }
}

/// Drops each `head_malformed` reason's `detail` after checking it is
/// non-empty text.
fn without_malformed_detail(mut result: Value) -> Value {
    for check in result["checks"].as_object_mut().unwrap().values_mut() {
        if let Some(reason) = check.get_mut("reason").and_then(Value::as_object_mut) {
            if reason.get("type").and_then(Value::as_str) == Some("head_malformed") {
                let detail = reason.remove("detail");
                assert!(detail
                    .as_ref()
                    .and_then(Value::as_str)
                    .is_some_and(|d| !d.is_empty()));
            }
        }
    }
    result
}

#[test]
fn leaves_match_the_independent_generator() {
    let doc = vectors();
    for (name, proof) in doc["proof_pool"].as_object().unwrap() {
        assert_eq!(
            tip_proof_hash(proof).as_deref(),
            doc["leaves"][name].as_str(),
            "{name}"
        );
    }
}

#[test]
fn encoding_matches_the_independent_generator() {
    let doc = vectors();
    assert_eq!(
        doc["genesis_link"].as_str().unwrap(),
        genesis_prev_head_hash()
    );
    for v in doc["encoding"].as_array().unwrap() {
        let h: PopulationHead = serde_json::from_value(v["head"].clone()).unwrap();
        let bytes = String::from_utf8(canonical_bytes(&h).unwrap()).unwrap();
        assert_eq!(bytes, v["canonical_bytes"].as_str().unwrap());
        assert_eq!(head_hash(&h).unwrap(), v["head_hash"].as_str().unwrap());
        assert_eq!(
            signed_message(&h).unwrap(),
            v["signed_message"].as_str().unwrap()
        );
    }
}

/// The case count Appendix A.5 states, read from the Appendix, so the sentence
/// cannot drift from the vectors.
fn appendix_case_count() -> usize {
    let appendix = include_str!("../../../docs/signed-containment-evidence.md");
    let text = appendix.split_whitespace().collect::<Vec<_>>().join(" ");
    let (_, after) = text
        .split_once("encoding vectors and ")
        .expect("Appendix A.5 states the case count");
    after
        .split(' ')
        .next()
        .and_then(|count| count.parse().ok())
        .expect("Appendix A.5 states the case count in digits")
}

#[test]
fn every_case_reports_the_expected_result() {
    let doc = vectors();
    let manifest = key_list(&doc);
    let pool = doc["proof_pool"].as_object().unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), appendix_case_count());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let proofs: Vec<Value> = case["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| pool[id.as_str().unwrap()].clone())
            .collect();
        let heads = case["heads"].as_array().unwrap();
        let supplied = case["key_list_supplied"].as_bool().unwrap();
        let variant = case["list_variant"]
            .as_str()
            .map(|v| verified(&doc, &doc["key_list_variants"][v]));
        let list = variant.as_ref().unwrap_or(&manifest);
        let result = verify_population(&proofs, heads, supplied.then_some(list));
        let got = without_malformed_detail(serde_json::to_value(&result).unwrap());
        assert_eq!(got, case["expected"], "case {name}");
    }
}

#[test]
fn each_key_list_text_reports_its_first_member_outside_the_signature() {
    let doc = vectors();
    let texts = doc["key_list_texts"].as_array().unwrap();
    assert!(!texts.is_empty());
    for text in texts {
        let name = text["name"].as_str().unwrap();
        let bytes = text["text"].as_str().unwrap().as_bytes();
        let list: TrustChainManifest = serde_json::from_slice(bytes).expect("text parses");
        let list = list
            .into_verified(doc["key_list_identity_fingerprint"].as_str().unwrap())
            .unwrap_or_else(|e| panic!("{name}: the text is signed: {e}"));
        let found = match list.manifest().member_not_signed(bytes).unwrap() {
            None => Value::Null,
            Some(MemberNotCarried::Repeated(pointer)) => {
                serde_json::json!({"kind": "repeated", "pointer": pointer})
            }
            Some(MemberNotCarried::NotCarried(pointer)) => {
                serde_json::json!({"kind": "not_carried", "pointer": pointer})
            }
        };
        assert_eq!(found, text["member"], "text {name}");
    }
}

#[test]
fn each_head_text_reports_its_first_member_written_twice() {
    let doc = vectors();
    let texts = doc["head_texts"].as_array().unwrap();
    assert!(!texts.is_empty());
    let genuine = &doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "good_chain")
        .unwrap()["heads"];
    for text in texts {
        let name = text["name"].as_str().unwrap();
        let bytes = text["text"].as_str().unwrap().as_bytes();
        // The checks would read the good chain's signed heads in every text.
        let read: Value = serde_json::from_slice(bytes).expect("text parses");
        assert_eq!(&read, genuine, "text {name}");
        let found = match repeated_member(bytes).unwrap() {
            None => Value::Null,
            Some(pointer) => serde_json::json!({"kind": "repeated", "pointer": pointer}),
        };
        assert_eq!(found, text["member"], "text {name}");
    }
}

#[test]
fn checks_d_and_e_are_never_ok_in_any_case() {
    let doc = vectors();
    let manifest = key_list(&doc);
    let pool = doc["proof_pool"].as_object().unwrap();
    for case in doc["cases"].as_array().unwrap() {
        let proofs: Vec<Value> = case["proofs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| pool[id.as_str().unwrap()].clone())
            .collect();
        let r = verify_population(&proofs, case["heads"].as_array().unwrap(), Some(&manifest));
        assert!(!r.checks.d_log_inclusion.is_ok());
        assert!(!r.checks.e_log_population.is_ok());
        assert!(r.honesty_label.is_some());
    }
}
