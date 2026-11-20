//! Mutation sweep — every field a forger would reach for.
//!
//! The fixture corpus covers four tamper families (`09_tamper_patterns`):
//! byte flip, reordering, version downgrade, signature substitution. Those are
//! generated artifacts and are checked byte-for-byte by `corpus_sweep.rs`,
//! which is why new cases cannot simply be dropped into the corpus directory —
//! a hand-added fixture would fail the regeneration check by design.
//!
//! Six mutation classes were not covered anywhere. They were run by hand
//! against the live `/v1/verify` endpoint on 2026-08-22 and all six were
//! correctly rejected — but a hand-run check that lives in a scratchpad is a
//! result, not a guarantee. This file makes them a guarantee.
//!
//! Each case takes a corpus success fixture, changes exactly one thing, and
//! asserts the verdict flips. **A mutation that does not change the document
//! is a silent pass** — the same hand run initially reported a clean verdict
//! on a mutation that had altered nothing, because the field being edited did
//! not exist. Every case here proves the document changed before it asserts
//! anything about the verdict.

// These tests pin the wire field `valid`, which is deprecated for callers.
#![allow(deprecated)]

use nanorix_verify::{verify_auditproof, VerifierPolicy};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("corpus")
}

/// A known-good fixture. Everything here is a single-field delta from this.
fn baseline() -> Value {
    let dir = corpus_root().join("01_single_capsule_success");
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension().and_then(|s| s.to_str()) == Some("json")
                && !p.to_string_lossy().ends_with(".expected.json")
        })
        .collect();
    fixtures.sort();
    let path = fixtures
        .first()
        .unwrap_or_else(|| panic!("no success fixture in {}", dir.display()));
    let raw = std::fs::read_to_string(path).expect("read fixture");
    serde_json::from_str(&raw).expect("parse fixture")
}

/// Assert the baseline still verifies. Without this the whole file could pass
/// against a corpus that stopped verifying for unrelated reasons.
#[test]
fn baseline_verifies() {
    let proof = baseline();
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(
        result.valid,
        "baseline success fixture must verify, else every mutation below is \
         vacuous: {:?}",
        result.failure_reason
    );
}

/// Apply `mutate`, prove it actually changed the document, then require
/// rejection.
fn assert_rejected(name: &str, mutate: impl Fn(&mut Value)) {
    let original = baseline();
    let mut mutated = original.clone();
    mutate(&mut mutated);

    assert_ne!(
        original, mutated,
        "{name}: mutation was a no-op — the field it targets does not exist, \
         so a passing verdict here would prove nothing"
    );

    let result = verify_auditproof(&mutated, &[], &VerifierPolicy::default());
    assert!(
        !result.valid,
        "{name}: mutated proof verified as valid — a forger can change this \
         field without detection"
    );
}

#[test]
fn backdated_timestamps_are_rejected() {
    assert_rejected("backdate", |v| {
        fn back(v: &mut Value) {
            match v {
                Value::Object(m) => {
                    for (_, val) in m.iter_mut() {
                        if let Value::String(s) = val {
                            if s.len() > 4 && s.starts_with("202") && s.contains('T') {
                                *s = format!("2019{}", &s[4..]);
                            }
                        } else {
                            back(val);
                        }
                    }
                }
                Value::Array(a) => a.iter_mut().for_each(back),
                _ => {}
            }
        }
        back(v);
    });
}

#[test]
fn truncated_chain_is_rejected() {
    assert_rejected("truncate", |v| {
        if let Some(Value::Array(chain)) = v.get_mut("chain") {
            chain.pop();
        }
    });
}

#[test]
fn mutated_step_operation_is_rejected() {
    assert_rejected("operation", |v| {
        if let Some(Value::Array(chain)) = v.get_mut("chain") {
            if let Some(Value::Object(step)) = chain.get_mut(2) {
                step.insert("operation".into(), Value::String("preserve".into()));
            }
        }
    });
}

#[test]
fn mutated_step_subsystem_is_rejected() {
    assert_rejected("subsystem", |v| {
        if let Some(Value::Array(chain)) = v.get_mut("chain") {
            if let Some(Value::Object(step)) = chain.get_mut(2) {
                step.insert("subsystem".into(), Value::String("eee_nothing".into()));
            }
        }
    });
}

#[test]
fn mutated_evidence_hash_is_rejected() {
    assert_rejected("evidence_hash", |v| {
        if let Some(Value::Array(chain)) = v.get_mut("chain") {
            if let Some(Value::Object(step)) = chain.get_mut(2) {
                // The baseline fixture's evidence hashes are all-zero
                // placeholders, so an all-zero "mutation" is a no-op and the
                // guard above rightly rejects it (caught 2026-08-23). Use a
                // value that cannot equal any placeholder or real digest.
                step.insert(
                    "evidence_hash".into(),
                    Value::String(format!("sha512:{}", "ab".repeat(64))),
                );
            }
        }
    });
}

/// The destruction outcome is the load-bearing claim. If `complete` can be
/// swapped for `partial` — or the reverse — without detection, the proof does
/// not actually attest to what happened.
#[test]
fn flipped_destruction_state_is_rejected() {
    assert_rejected("destruction_state", |v| {
        if let Some(obj) = v.as_object_mut() {
            let flipped = match obj.get("destruction_state").and_then(|s| s.as_str()) {
                Some("complete") => "partial",
                _ => "complete",
            };
            obj.insert("destruction_state".into(), Value::String(flipped.into()));
        }
    });
}

/// Substitution: present a legitimately-signed proof as evidence for a
/// different capsule. The eight-step chain preimage carries no capsule
/// identity — this is only caught because v2.1 signs a canonical view of the
/// whole document. If the signed message ever narrows back to the chain tip,
/// this test is what fails.
#[test]
fn substituted_capsule_id_is_rejected() {
    assert_rejected("capsule_id substitution", |v| {
        if let Some(obj) = v.as_object_mut() {
            obj.insert(
                "capsule_id".into(),
                Value::String("00000000-dead-beef-0000-000000000000".into()),
            );
        }
    });
}
