//! the receipt pipeline (the per-record receipt specification + the receipt-batching specification) fixture corpus extension tests.
//!
//! Synthesizes 10 NEW fixtures spanning receipt set sizes + parent-proof
//! depths + cyclic-rejection + missing-signature variants. Each fixture
//! is verified against the extended `verify_auditproof` pipeline; the
//! happy-path fixtures verify cleanly through Stage 3 (chain
//! reproducibility + Merkle root binding + per-receipt chain hash
//! roundtrip), the failure-mode fixtures fail at the expected stage.
//!
//! The 100-fixture pre-the receipt pipeline corpus baseline is verified separately
//! (`tests/integration_tests.rs`) — this file ADDS to that surface
//! WITHOUT mutating it.

use nanorix_verify::{
    compute_step_8_amended_verifier, compute_step_hash, lookup_method, verifier_merkle_root,
    verify_auditproof, VerifierPolicy, NANORIX_GENESIS_HASH,
};
use sha2::{Digest, Sha512};

const TIMESTAMP: &str = "2026-05-12T00:00:00Z";
const CAPSULE_ID: &str = "cap_wave_n_fixture";

/// Compute the per-record activity root using genesis fallback (matches
/// service-side compute_activity_root when trail is None/empty).
fn genesis_activity_root() -> String {
    NANORIX_GENESIS_HASH.to_string()
}

fn compute_record_chain_hash_local(
    capsule_id: &str,
    record_index: u32,
    record_id: &str,
    in_h: &str,
    out_h: &str,
    activity_root: &str,
    pattern_tag_wire: Option<&str>,
) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(capsule_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(record_index.to_string().as_bytes());
    data.push(0x00);
    data.extend_from_slice(record_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(in_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(out_h.as_bytes());
    data.push(0x00);
    data.extend_from_slice(activity_root.as_bytes());
    // the per-record receipt specification conformance (2026-08-08): a declared pattern_tag is bound into
    // the chain hash — the fixture mirror must match the production formula
    // or every tagged fixture verifies against the wrong hash.
    if let Some(tag) = pattern_tag_wire {
        data.push(0x00);
        data.extend_from_slice(tag.as_bytes());
    }
    hex::encode(Sha512::digest(&data))
}

fn fixture_pattern_tag(idx: u32) -> &'static str {
    match idx % 4 {
        0 => "pa",
        1 => "rcm_claim",
        2 => "dicom_study",
        _ => "agent_step",
    }
}

fn build_receipt(idx: u32) -> serde_json::Value {
    let in_h = hex::encode(Sha512::digest(format!("in_{idx}").as_bytes()));
    let out_h = hex::encode(Sha512::digest(format!("out_{idx}").as_bytes()));
    let activity_root = genesis_activity_root();
    let chain_h = compute_record_chain_hash_local(
        CAPSULE_ID,
        idx,
        &format!("rec_{idx:05}"),
        &in_h,
        &out_h,
        &activity_root,
        Some(fixture_pattern_tag(idx)),
    );
    serde_json::json!({
        "record_index": idx,
        "record_id": format!("rec_{idx:05}"),
        "record_input_hash": format!("sha512:{in_h}"),
        "record_output_hash": format!("sha512:{out_h}"),
        "record_chain_hash": format!("sha512:{chain_h}"),
        "pattern_tag": fixture_pattern_tag(idx),
        "merkle_inclusion_proof": [],
    })
}

fn build_parent(seed: u32, role: &str, org: &str) -> serde_json::Value {
    let chain_h = hex::encode(Sha512::digest(format!("parent_{seed}").as_bytes()));
    let sig = hex::encode(Sha512::digest(format!("sig_{seed}").as_bytes()));
    serde_json::json!({
        "parent_chain_hash": format!("sha512:{chain_h}"),
        "parent_key_id": format!("cust-auth-{role}-{seed}"),
        "parent_signature": format!("base64:{sig}"),
        "parent_role": role,
        "parent_jurisdiction": "US",
        "parent_organization_tag": format!("vendor:{org}"),
    })
}

/// Synthesize a receipt pipeline AuditProof with N receipts and M parent links.
/// `parent_chain_hashes` field is the Merkle root computed over receipts/
/// parents; Step 8 is amended via the combined the per-record receipt specification+041 formula.
fn synthesize_wave_n_proof(
    n_receipts: u32,
    parent_seeds: &[(&'static str, &'static str)],
) -> serde_json::Value {
    let subsystems = [
        "eee_namespace",
        "eee_tmpfs",
        "eee_memory",
        "dire_keys",
        "dire_identity",
        "fgx_forensic",
        "rzl_audit",
        "capsule_destroy",
    ];

    // Build receipts + compute Merkle root.
    let receipts: Vec<serde_json::Value> = (0..n_receipts).map(build_receipt).collect();
    let leaves: Vec<String> = receipts
        .iter()
        .map(|r| {
            r.get("record_chain_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();
    let rrmr_opt = verifier_merkle_root(&leaves);

    // Build parents + compute Merkle root.
    let parents: Vec<serde_json::Value> = parent_seeds
        .iter()
        .enumerate()
        .map(|(i, (role, org))| build_parent(i as u32, role, org))
        .collect();
    let parent_leaves: Vec<String> = parents
        .iter()
        .map(|p| {
            p.get("parent_chain_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect();
    let ppmr_opt = verifier_merkle_root(&parent_leaves);

    // Build chain steps 1-7 with legacy formula; step 8 with amended.
    let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
    let mut chain = Vec::new();
    for (i, subsystem) in subsystems.iter().enumerate() {
        let method = lookup_method(subsystem);
        let chain_hash = if i == 7 {
            compute_step_8_amended_verifier(
                &prev_hash,
                TIMESTAMP,
                rrmr_opt.as_deref(),
                ppmr_opt.as_deref(),
            )
        } else {
            compute_step_hash(&prev_hash, subsystem, "destroy", method, TIMESTAMP)
        };
        chain.push(serde_json::json!({
            "subsystem": subsystem,
            "method": method,
            "chain_hash": chain_hash.clone(),
        }));
        prev_hash = chain_hash;
    }
    let final_hash = chain[7]["chain_hash"].as_str().unwrap().to_string();

    let mut proof = serde_json::json!({
        "cdp_version": "1.0",
        "capsule_id": CAPSULE_ID,
        "destroyed_at": TIMESTAMP,
        "chain": chain,
        "final_hash": final_hash,
        "attestation": {
            "algorithm": "Ed25519",
            "signing_key_version": "1",
        },
    });

    if n_receipts > 0 {
        proof["record_receipts"] = serde_json::Value::Array(receipts);
        if let Some(rrmr) = rrmr_opt {
            proof["record_receipts_merkle_root"] =
                serde_json::Value::String(format!("sha512:{rrmr}"));
        }
    }
    if !parent_seeds.is_empty() {
        proof["parent_proof_hashes"] = serde_json::Value::Array(parents);
        if let Some(ppmr) = ppmr_opt {
            proof["parent_proofs_merkle_root"] =
                serde_json::Value::String(format!("sha512:{ppmr}"));
        }
    }

    proof
}

// ── Fixture 1: N=0 (no receipts, no parents — Forever-Standard) ──

#[test]
fn fixture_01_n0_no_receipts_no_parents_byte_equivalent_baseline() {
    let proof = synthesize_wave_n_proof(0, &[]);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(
        result.valid,
        "N=0 (pre-the receipt pipeline) MUST verify cleanly; got {result:?}"
    );
    assert!(proof.get("record_receipts").is_none());
    assert!(proof.get("parent_proof_hashes").is_none());
}

// ── Fixture 2: N=1 (single receipt; root = leaf) ──

#[test]
fn fixture_02_n1_single_receipt() {
    let proof = synthesize_wave_n_proof(1, &[]);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(result.valid, "N=1 receipt MUST verify; got {result:?}");
}

// ── Fixture 3: N=2 (binary tree, single pair) ──

#[test]
fn fixture_03_n2_two_receipts() {
    let proof = synthesize_wave_n_proof(2, &[]);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(result.valid, "N=2 receipts MUST verify; got {result:?}");
}

// ── Fixture 4: N=10 (multi-level binary tree) ──

#[test]
fn fixture_04_n10_ten_receipts() {
    let proof = synthesize_wave_n_proof(10, &[]);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(result.valid, "N=10 receipts MUST verify; got {result:?}");
}

// ── Fixture 5: N=100 ──

#[test]
fn fixture_05_n100_hundred_receipts() {
    let proof = synthesize_wave_n_proof(100, &[]);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(result.valid, "N=100 receipts MUST verify; got {result:?}");
}

// ── Fixture 6: N=1000 (large set, deep tree) ──

#[test]
fn fixture_06_n1000_thousand_receipts() {
    let proof = synthesize_wave_n_proof(1000, &[]);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(result.valid, "N=1000 receipts MUST verify; got {result:?}");
}

// ── Fixture 7: depth-1 parent ──

#[test]
fn fixture_07_parent_depth_1() {
    let proof = synthesize_wave_n_proof(1, &[("input-data", "banjo")]);
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(result.valid, "depth-1 parent MUST verify; got {result:?}");
}

// ── Fixture 8: depth-4 parents ──

#[test]
fn fixture_08_parent_depth_4() {
    let proof = synthesize_wave_n_proof(
        2,
        &[
            ("input-data", "banjo"),
            ("rag-retrieval", "llamaindex"),
            ("safety-review", "guardrails"),
            ("output-validation", "anterior"),
        ],
    );
    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(result.valid, "depth-4 parents MUST verify; got {result:?}");
}

// ── Fixture 9: cyclic parent (FAILURE expected) ──

#[test]
fn fixture_09_cyclic_parent_rejected() {
    // Build a happy-path proof first to get its step_8 chain hash, then
    // inject a parent that references that exact hash. The verifier
    // re-computes the receipts Merkle root + step 8 amendment; the
    // cycle is detected at the chain-walk level when the parent set's
    // Merkle root binds into Step 8 — recomputed Step 8 differs from
    // the claimed hash because the parent set has a different root.
    //
    // For Wave A this fixture is constructed as a *structural-anomaly*
    // proof; verify_auditproof returns invalid at stage 3 because the
    // proof's claimed parent_proofs_merkle_root doesn't match the
    // recomputed root over the cyclic parent set.
    // Construct a receipt pipeline proof WITH parents declared. Then mutate the
    // single parent to be a self-cycle referencing this proof's own
    // Step 8. Crucially, we update the claimed `parent_proofs_merkle_root`
    // to match the cycle (N=1 root = leaf), so the parent Merkle-root
    // check at stage 3 passes. The verifier then re-derives Step 8 from
    // prev_hash + the NEW parent Merkle root (cycle leaf) — which DIFFERS
    // from the Step 8 chain hash stamped under the ORIGINAL parent set.
    // Chain-walk detects the mismatch at step 8 and rejects.
    let mut proof = synthesize_wave_n_proof(1, &[("input-data", "banjo")]);
    let step_8_hash = proof["chain"][7]["chain_hash"]
        .as_str()
        .unwrap()
        .to_string();

    // Inject a cyclic parent referencing this proof's own Step 8.
    let cyclic_parent = serde_json::json!({
        "parent_chain_hash": format!("sha512:{step_8_hash}"),
        "parent_key_id": "cust-auth-self-cycle",
        "parent_signature": "base64:malicious",
        "parent_role": "self-loop",
        "parent_jurisdiction": "US",
        "parent_organization_tag": "vendor:cyclic",
    });
    proof["parent_proof_hashes"] = serde_json::json!([cyclic_parent]);
    // Match claimed Merkle root to cycle parent's hash (N=1 → root = leaf).
    proof["parent_proofs_merkle_root"] = serde_json::Value::String(format!("sha512:{step_8_hash}"));

    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(
        !result.valid,
        "Cyclic parent fixture MUST be rejected; got {result:?}"
    );
}

// ── Fixture 10: missing-signature parent (declared but signature empty) ──

#[test]
fn fixture_10_missing_signature_parent() {
    // The verifier accepts parent_proof_hashes WITHOUT per-link signature
    // verification at Wave A (that's a Wave B Portable Pubkey Bundle
    // surface). The verifier DOES check the Merkle root binding, which
    // is independent of the signature presence. So this fixture verifies
    // structurally (Merkle root matches claimed) but a Wave-B-aware
    // verifier would flag the empty signature.
    let proof = synthesize_wave_n_proof(1, &[("input-data", "banjo")]);
    // Mutate the parent's signature to empty string in-place.
    let mut proof = proof;
    if let Some(parents) = proof["parent_proof_hashes"].as_array_mut() {
        if let Some(p) = parents.get_mut(0) {
            if let Some(obj) = p.as_object_mut() {
                obj.insert(
                    "parent_signature".into(),
                    serde_json::Value::String(String::new()),
                );
            }
        }
    }

    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    // Structural verification passes (Merkle root + chain hash both
    // intact; per-link signature not checked at Wave A). Wave B will
    // surface a per-link signature failure here.
    assert!(
        result.valid,
        "missing-signature parent fixture verifies structurally at Wave A; got {result:?}"
    );
}

// ── Additional regression: tampered Merkle root MUST be rejected ──

#[test]
fn regression_tampered_record_merkle_root_rejected() {
    let mut proof = synthesize_wave_n_proof(5, &[]);
    proof["record_receipts_merkle_root"] =
        serde_json::Value::String(format!("sha512:{}", "f".repeat(128)));

    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(!result.valid, "Tampered Merkle root MUST be rejected");
}

#[test]
fn regression_tampered_receipt_chain_hash_rejected() {
    let mut proof = synthesize_wave_n_proof(3, &[]);
    proof["record_receipts"][1]["record_chain_hash"] =
        serde_json::Value::String(format!("sha512:{}", "f".repeat(128)));

    let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
    assert!(
        !result.valid,
        "Tampered receipt chain hash MUST be rejected"
    );
}

// ── Forever-Standard byte-equivalence regression ──

#[test]
fn forever_standard_pre_wave_n_proof_byte_identical() {
    // A pre-the receipt pipeline proof (no record_receipts, no parent_proof_hashes
    // fields) MUST produce the EXACT same Step 8 hash as a receipt pipeline
    // verifier walking it. This is the load-bearing test for the
    // 100-fixture corpus baseline preservation guarantee.
    let subsystems = [
        "eee_namespace",
        "eee_tmpfs",
        "eee_memory",
        "dire_keys",
        "dire_identity",
        "fgx_forensic",
        "rzl_audit",
        "capsule_destroy",
    ];

    let mut prev_hash = NANORIX_GENESIS_HASH.to_string();
    let mut chain = Vec::new();
    for subsystem in subsystems {
        let method = lookup_method(subsystem);
        let chain_hash = compute_step_hash(&prev_hash, subsystem, "destroy", method, TIMESTAMP);
        chain.push(serde_json::json!({
            "subsystem": subsystem,
            "method": method,
            "chain_hash": chain_hash.clone(),
        }));
        prev_hash = chain_hash;
    }
    let final_hash = chain[7]["chain_hash"].as_str().unwrap().to_string();

    let pre_wave_n_proof = serde_json::json!({
        "cdp_version": "1.0",
        "capsule_id": CAPSULE_ID,
        "destroyed_at": TIMESTAMP,
        "chain": chain,
        "final_hash": final_hash,
    });

    let result = verify_auditproof(&pre_wave_n_proof, &[], &VerifierPolicy::default());
    assert!(
        result.valid,
        "Pre-the receipt pipeline proof MUST verify byte-identically post-amendment; got {result:?}"
    );
    assert_eq!(result.stage_reached, 4);
}
