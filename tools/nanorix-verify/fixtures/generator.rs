//! Fixture corpus generator for AuditProof verifier cross-implementation
//! byte-equivalence proof.
//!
//! ## Purpose
//!
//! This generator produces a deterministic corpus of 100+ AuditProof JSON
//! documents covering:
//!
//! - Single-capsule successful destroy (10 fixtures)
//! - Multi-step pipeline with parent-linkage chain (10 fixtures)
//! - Failure modes — chain mismatch, signature invalid, region mismatch,
//!   authority unknown, version unsupported, canonical-hash drift
//!   (10 each = 60 fixtures)
//! - Tamper patterns — byte-flip, re-order, version downgrade, signature
//!   substitution (5 each = 20 fixtures)
//!
//! Each fixture is written as `corpus/<category>/<NNNN>_<descriptor>.json`
//! plus a sibling `<NNNN>_<descriptor>.expected.json` describing the expected
//! verifier verdict (success or specific FailureReason variant).
//!
//! ## Expected-verdict file schema
//!
//! ```json
//! {
//!   "valid":         true | false,
//!   "failure_reason": null | { "type": "<snake_case_variant>", ... },
//!   "stage_reached":  1..=8,
//!   "policy":         { "required_region": "...",
//!                       "required_authority_id": "..." },   // optional
//!   "note":           "..."                                  // optional
//! }
//! ```
//!
//! `policy` is what makes a fixture self-describing: the `05_*` and `06_*`
//! verdicts are only reachable when the verifier is configured with that pin,
//! so the pin travels with the fixture instead of living in a harness the
//! other implementations cannot see. Absent `policy` means
//! `VerifierPolicy::default()`.
//!
//! ## The signed message (why every v2.1 fixture must carry canonical fields)
//!
//! A v2.1 `nanorix_only` AuditProof is NOT signed over `final_hash` — that is
//! the v1.0 message. It is signed over the ADR-011 Part-3 canonical-view hash:
//! `hex(sha512(serde_jcs(canonical_view)))`, built by
//! `services/api/src/cdp_document.rs::FullCdp::canonical_view()` and mirrored
//! for the offline verifier in `canonical_recompute::recompute_canonical_hash`.
//! The generator signs with that same mirrored function rather than a third
//! private copy, so the corpus cannot drift away from the verifier; the
//! verifier in turn cannot drift away from the server because
//! `canonical_recompute_matches_server_golden` pins it to the server's golden
//! digest. Corpus → verifier → server is therefore one unbroken chain.
//!
//! A consequence worth stating: every canonical-bound field must be present
//! BEFORE signing. `parent_audit_proof_id` is canonical-bound, so the
//! multi-step fixtures set it first and sign second.
//!
//! ## Cross-implementation byte-equivalence anchor
//!
//! The fixtures are the public commitment for cross-implementation parity:
//! Rust + Go + Python + TypeScript verifiers must all produce byte-identical
//! verdicts on every fixture. The generator is run once; the corpus is
//! committed to source control. Fixtures are pinned reference inputs.
//!
//! ## Invocation
//!
//! ```bash
//! cargo run --bin nanorix-verify-fixtures-gen           # write the corpus in-place
//! cargo run --bin nanorix-verify-fixtures-gen -- <dir>  # write to <dir> instead
//! ```
//!
//! Generated files land at `tools/nanorix-verify/fixtures/corpus/`. The
//! generator is idempotent: running it twice produces byte-identical output
//! (deterministic timestamp, deterministic capsule_id sequence, deterministic
//! key derivation from a fixed seed). `tests/corpus_sweep.rs` regenerates into
//! a tempdir and diffs against the committed corpus, so the committed bytes
//! can never drift away from this file.
//!
//! ## Forever-Standard discipline
//!
//! The corpus is locked once published. Fixture additions are additive
//! (new files, new categories) and never break existing fixture numbers.
//! Cross-implementation parity tests reference fixtures by relative path;
//! renaming a fixture is a breaking change to consumer test suites.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};
use nanorix_verify::canonical_recompute::recompute_canonical_hash;
use serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::fs;
use std::path::{Path, PathBuf};

// ── Constants ────────────────────────────────────────────────────────

/// Genesis hash — SHA-512 of the empty input. Forever-stable cryptographic
/// anchor; the value is duplicated here (rather than imported from the
/// verifier crate) to keep the generator self-contained for cross-impl
/// byte-equivalence anchoring. If this value drifted, the entire corpus
/// would invalidate.
const GENESIS_HASH: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/// The 8 destruction subsystems in canonical order. Forever-stable per the
/// AuditProof Forever-Standard discipline.
const SUBSYSTEMS: [(&str, &str); 8] = [
    ("eee_namespace", "procfs_verification"),
    ("eee_tmpfs", "mountinfo_verification"),
    ("eee_memory", "dod_5220_multipass_wipe"),
    ("dire_keys", "ed25519_key_destruction"),
    ("dire_identity", "credential_incineration"),
    ("fgx_forensic", "merkle_tree_verification"),
    ("rzl_audit", "hash_chain_validation"),
    ("capsule_destroy", "capsule_lifecycle_verification"),
];

/// Deterministic Ed25519 seed. Using a fixed seed keeps the corpus
/// byte-identical across regenerations — every fixture's signature is
/// identical on every machine, every time.
const FIXTURE_SIGNING_SEED: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
];

/// Deterministic timestamp anchor — every fixture uses this timestamp as the
/// destroy moment. Constant timestamp keeps chain hashes deterministic.
const FIXTURE_TIMESTAMP: &str = "2026-05-08T00:00:00Z";

// ── Builder ──────────────────────────────────────────────────────────

struct FixtureBuilder {
    signing_key: SigningKey,
    public_key_b64: String,
}

impl FixtureBuilder {
    fn new() -> Self {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let signing_key = SigningKey::from_bytes(&FIXTURE_SIGNING_SEED);
        let public_key_b64 = B64.encode(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            public_key_b64,
        }
    }

    /// Compute one chain step's hash per the Forever-Standard format:
    /// SHA-512(prev_hash || \x00 || subsystem || \x00 || "destroy" || \x00
    ///         || method || \x00 || timestamp).
    fn compute_step_hash(
        &self,
        prev_hash: &str,
        subsystem: &str,
        method: &str,
        timestamp: &str,
    ) -> String {
        let mut hasher = Sha512::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(b"\x00");
        hasher.update(subsystem.as_bytes());
        hasher.update(b"\x00");
        hasher.update(b"destroy");
        hasher.update(b"\x00");
        hasher.update(method.as_bytes());
        hasher.update(b"\x00");
        hasher.update(timestamp.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Build a successful 8-step chain anchored at GENESIS.
    fn build_chain(&self, timestamp: &str) -> (Vec<Value>, String) {
        let mut chain = Vec::with_capacity(8);
        let mut prev_hash = GENESIS_HASH.to_string();

        for (idx, (subsystem, method)) in SUBSYSTEMS.iter().enumerate() {
            let chain_hash = self.compute_step_hash(&prev_hash, subsystem, method, timestamp);
            chain.push(json!({
                "step": idx + 1,
                "subsystem": subsystem,
                "operation": format!("{}_op", subsystem),
                "evidence_hash": format!("sha512:{}", "0".repeat(128)),
                "chain_hash": format!("sha512:{}", chain_hash),
            }));
            prev_hash = chain_hash;
        }

        (chain, prev_hash)
    }

    /// Build a deterministic capsule_id from an integer index. Pattern matches
    /// the production `^cap_[0-9a-f]{32}$` shape; predictable for cross-impl
    /// reference tests.
    fn capsule_id(&self, idx: usize) -> String {
        let suffix = format!("{:032x}", idx as u128);
        format!("cap_{}", suffix)
    }

    /// Build a minimal AuditProof v1.0 fixture (no canonical-hash binding;
    /// chain + final_hash only). Suitable for stage 1-4 verification tests.
    ///
    /// Currently unused — the corpus ships v2.1 fixtures only. Retained as a
    /// reference helper for the next corpus expansion that adds v1.0 backward-
    /// compatibility fixtures (Forever-Standard requirement: a verifier built
    /// today must verify a v1.0 AuditProof issued years ago).
    #[allow(dead_code)]
    fn build_v1_minimal(&self, capsule_idx: usize) -> Value {
        let capsule_id = self.capsule_id(capsule_idx);
        let (chain, last_hash) = self.build_chain(FIXTURE_TIMESTAMP);

        json!({
            "cdp_version": "1.0",
            "capsule_id": capsule_id,
            "destroyed_at": FIXTURE_TIMESTAMP,
            "chain": chain,
            "final_hash": format!("sha512:{}", last_hash),
        })
    }

    /// Build an UNSIGNED v2.1 AuditProof carrying every canonical-view field a
    /// production `nanorix_only` proof carries. Signing is a separate step
    /// because the signature covers these fields — see `sign_in_place`.
    fn build_v2_1_unsigned(&self, capsule_idx: usize, region: &str) -> Value {
        let capsule_id = self.capsule_id(capsule_idx);
        let (chain, last_hash) = self.build_chain(FIXTURE_TIMESTAMP);

        json!({
            "cdp_version": "2.1",
            "capsule_id": capsule_id,
            // Canonical view parses this to i64 (unparseable -> 0); production
            // emits a numeric string, so the corpus does too.
            "signing_key_version": "1",
            "org_id": "00000000-0000-0000-0000-000000000001",
            "signing_mode": "nanorix_only",
            "jurisdiction": "us",
            "authority_id": "us-kms-nanorix-v1",
            "destruction_state": "complete",
            "hash_algorithm": "SHA-512",
            "signature_algorithm": "Ed25519",
            // Region lives on the `capsule_started` event, NOT at top level.
            // `activity` is inside `CanonicalCdpView`, so a region carried here
            // is covered by the signature; a top-level `region` is not, and a
            // corpus that put it there could never exercise the residency pin's
            // real path. Production emits region the same way (EO-03 G1).
            "activity": [{
                "event": "capsule_started",
                "encryption": "aes-256-gcm",
                "network": "sealed",
                "region": region,
            }],
            "destroyed_at": FIXTURE_TIMESTAMP,
            "chain": chain,
            "final_hash": format!("sha512:{}", last_hash),
        })
    }

    /// Sign a built document over its ADR-011 Part-3 canonical hash and attach
    /// the attestation block. Must run AFTER every canonical-bound field is
    /// set; tamper fixtures mutate only after this returns.
    fn sign_in_place(&self, proof: &mut Value) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let canonical_hash = recompute_canonical_hash(proof);
        // Ed25519 over the canonical hash's ASCII hex characters (128 bytes),
        // not its 64 raw digest bytes — Forever-Standard per ADR-006.
        let signature_b64 = B64.encode(self.signing_key.sign(canonical_hash.as_bytes()).to_bytes());

        let capsule_id = proof["capsule_id"].as_str().unwrap_or_default().to_string();
        let destroyed_at = proof["destroyed_at"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        proof["attestation"] = json!({
            "algorithm": "Ed25519",
            "public_key": format!("base64:{}", self.public_key_b64),
            "signature": format!("base64:{}", signature_b64),
            // Mirrors governance/rzl/src/cdp.rs: the timestamp's ':' separators
            // are replaced with '-', and the suffix is the capsule_id's FIRST 8
            // characters.
            "key_id": format!(
                "nrx-verify-{}-{}",
                destroyed_at.replace(':', "-"),
                &capsule_id[..8.min(capsule_id.len())]
            ),
        });
    }

    /// Build a signed v2.1 AuditProof.
    fn build_v2_1_signed(&self, capsule_idx: usize, region: &str) -> Value {
        let mut proof = self.build_v2_1_unsigned(capsule_idx, region);
        self.sign_in_place(&mut proof);
        proof
    }

    /// Build a v2.1 AuditProof carrying a parent_audit_proof_id linkage.
    /// `parent_audit_proof_id` is canonical-bound, so it is set BEFORE signing.
    fn build_v2_1_with_parent(&self, capsule_idx: usize, parent_capsule_idx: usize) -> Value {
        let mut proof = self.build_v2_1_unsigned(capsule_idx, "us-central1");
        proof["parent_audit_proof_id"] = Value::String(self.capsule_id(parent_capsule_idx));
        self.sign_in_place(&mut proof);
        proof
    }
}

// ── Expected verdict shape ───────────────────────────────────────────

/// Expected verifier verdict per fixture. Cross-impl tests assert that the
/// verifier produces this exact shape (success or specific failure reason).
///
/// Every field here is authored from the AuditProof specification, never
/// captured from a verifier run — a corpus whose expectations are recorded
/// from the implementation under test proves nothing.
///
/// Stage 7 is the success stage without a trust-chain manifest: sub-A proves
/// integrity against the embedded key. Stage 8 needs `--trust-chain`, which
/// the corpus deliberately does not pin (the manifest is an operator artifact,
/// not a fixture).
fn expected_success() -> Value {
    json!({
        "valid": true,
        "failure_reason": null,
        "stage_reached": 7,
    })
}

fn expected_failure(reason_type: &str, extras: Value, stage_reached: u8) -> Value {
    let mut failure = json!({ "type": reason_type });
    if let Value::Object(map) = extras {
        if let Value::Object(failure_map) = &mut failure {
            for (k, v) in map {
                failure_map.insert(k, v);
            }
        }
    }
    json!({
        "valid": false,
        "failure_reason": failure,
        "stage_reached": stage_reached,
    })
}

/// Attach the verifier policy a fixture's verdict depends on. Without this the
/// `05_*` / `06_*` verdicts are unreachable and the fixture silently "passes"
/// as valid.
fn with_policy(mut expected: Value, policy: Value) -> Value {
    expected["policy"] = policy;
    expected
}

/// Attach a human-readable note explaining a verdict that is not the one a
/// reader would first guess from the category name.
fn with_note(mut expected: Value, note: &str) -> Value {
    expected["note"] = Value::String(note.to_string());
    expected
}

// ── Category writers ─────────────────────────────────────────────────

fn write_fixture(out_dir: &Path, name: &str, proof: &Value, expected: &Value) {
    fs::create_dir_all(out_dir).expect("create category dir");
    let proof_path = out_dir.join(format!("{}.json", name));
    let expected_path = out_dir.join(format!("{}.expected.json", name));

    let proof_bytes = serde_json::to_vec_pretty(proof).expect("serialize proof");
    let expected_bytes = serde_json::to_vec_pretty(expected).expect("serialize expected");

    fs::write(&proof_path, &proof_bytes).expect("write proof file");
    fs::write(&expected_path, &expected_bytes).expect("write expected file");
}

/// Category 1 — single-capsule successful destroy (10 fixtures).
fn generate_single_capsule_success(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("01_single_capsule_success");
    let mut count = 0;
    for i in 0..10 {
        let proof = builder.build_v2_1_signed(i, "us-central1");
        let expected = expected_success();
        write_fixture(&dir, &format!("{:04}_v2_1_signed", i), &proof, &expected);
        count += 1;
    }
    count
}

/// Category 2 — multi-step pipeline with parent_audit_proof_id chain
/// (10 fixtures). Builds a 5-deep linear chain from genesis-cap_0 →
/// cap_1 → cap_2 → cap_3 → cap_4, then 5 additional leaves at
/// varying depths. Each leaf is fixture-emitted; verifier chain-walk
/// against the corpus exercises depth limits and parent reachability.
fn generate_multi_step_pipeline(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("02_multi_step_pipeline");
    let mut count = 0;

    // 5-deep linear chain: cap_10 (root) ← cap_11 ← cap_12 ← cap_13 ← cap_14
    let root_proof = builder.build_v2_1_signed(10, "us-central1");
    write_fixture(&dir, "0000_root", &root_proof, &expected_success());
    count += 1;

    for depth in 1..5 {
        let parent_idx = 10 + depth - 1;
        let leaf_idx = 10 + depth;
        let proof = builder.build_v2_1_with_parent(leaf_idx, parent_idx);
        write_fixture(
            &dir,
            &format!("{:04}_depth_{}", depth, depth),
            &proof,
            &expected_success(),
        );
        count += 1;
    }

    // 5 additional leaves at varying depths pointing back into the same chain.
    for branch in 0..5 {
        let parent_idx = 10 + (branch % 4);
        let leaf_idx = 100 + branch;
        let proof = builder.build_v2_1_with_parent(leaf_idx, parent_idx);
        write_fixture(
            &dir,
            &format!("{:04}_branch_{}", 5 + branch, branch),
            &proof,
            &expected_success(),
        );
        count += 1;
    }

    count
}

/// Category 3a — chain mismatch failures (10 fixtures). Tampers chain hash at
/// step indexes 0..7 plus two additional "wholesale wrong" patterns.
fn generate_chain_mismatch_failures(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("03_failure_chain_mismatch");
    let mut count = 0;

    for step_idx in 0..8 {
        let mut proof = builder.build_v2_1_signed(200 + step_idx, "us-central1");
        proof["chain"][step_idx]["chain_hash"] =
            Value::String(format!("sha512:{}", "0".repeat(128)));

        let subsystem = SUBSYSTEMS[step_idx].0;
        let expected = expected_failure(
            "step_hash_mismatch",
            json!({ "step_idx": step_idx, "subsystem": subsystem }),
            3,
        );

        write_fixture(
            &dir,
            &format!("{:04}_step_{}_tampered", step_idx, step_idx),
            &proof,
            &expected,
        );
        count += 1;
    }

    // Two wholesale-mismatch fixtures (chain truncated, chain extended).
    let mut truncated = builder.build_v2_1_signed(210, "us-central1");
    if let Value::Array(arr) = &mut truncated["chain"] {
        arr.truncate(7);
    }
    let expected = expected_failure(
        "step_count_invalid",
        json!({ "expected": 8, "found": 7 }),
        3,
    );
    write_fixture(&dir, "0008_chain_truncated_to_7", &truncated, &expected);
    count += 1;

    let mut extended = builder.build_v2_1_signed(211, "us-central1");
    if let Value::Array(arr) = &mut extended["chain"] {
        let extra = arr[7].clone();
        arr.push(extra);
    }
    let expected = expected_failure(
        "step_count_invalid",
        json!({ "expected": 8, "found": 9 }),
        3,
    );
    write_fixture(&dir, "0009_chain_extended_to_9", &extended, &expected);
    count += 1;

    count
}

/// Category 3b — signature invalid failures (10 fixtures). Constructs proofs
/// where the attestation signature fails Ed25519 verification.
fn generate_signature_invalid_failures(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("04_failure_signature_invalid");
    let mut count = 0;

    // 5 fixtures: signature byte-flipped at various positions.
    for i in 0..5 {
        let mut proof = builder.build_v2_1_signed(300 + i, "us-central1");
        // Substitute a deterministic-but-invalid signature.
        let bad_sig = format!("base64:{}", "A".repeat(86) + "==");
        proof["attestation"]["signature"] = Value::String(bad_sig);
        let expected = expected_failure(
            "signature_mismatch",
            json!({ "reason": "does_not_verify" }),
            7,
        );
        write_fixture(
            &dir,
            &format!("{:04}_sig_byteflip_{}", i, i),
            &proof,
            &expected,
        );
        count += 1;
    }

    // 3 fixtures: malformed signature (wrong length, invalid base64).
    for (i, malformed) in ["base64:short", "base64:!!!notbase64!!!", "base64:"]
        .iter()
        .enumerate()
    {
        let mut proof = builder.build_v2_1_signed(310 + i, "us-central1");
        proof["attestation"]["signature"] = Value::String(malformed.to_string());
        let expected = expected_failure("signature_mismatch", json!({ "reason": "malformed" }), 7);
        write_fixture(
            &dir,
            &format!("{:04}_sig_malformed_{}", 5 + i, i),
            &proof,
            &expected,
        );
        count += 1;
    }

    // 2 fixtures: malformed public key.
    for i in 0..2 {
        let mut proof = builder.build_v2_1_signed(320 + i, "us-central1");
        proof["attestation"]["public_key"] = Value::String(format!(
            "base64:{}",
            if i == 0 { "tooShort" } else { "AAAA" }
        ));
        let expected = expected_failure(
            "signature_mismatch",
            json!({ "reason": "public_key_malformed" }),
            7,
        );
        write_fixture(
            &dir,
            &format!("{:04}_pubkey_malformed_{}", 8 + i, i),
            &proof,
            &expected,
        );
        count += 1;
    }

    count
}

/// Category 3c — region mismatch failures (10 fixtures). Each fixture
/// declares a region and expects rejection against a different policy region.
fn generate_region_mismatch_failures(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("05_failure_region_mismatch");
    let mut count = 0;

    let regions = [
        ("us-central1", "europe-west1"),
        ("europe-west1", "us-central1"),
        ("asia-east1", "us-central1"),
        ("us-east4", "europe-west1"),
        ("europe-west4", "asia-east1"),
        ("us-central1", "asia-southeast1"),
        ("asia-northeast1", "europe-west1"),
        ("us-west1", "europe-north1"),
        ("europe-west1", "asia-east1"),
        ("asia-southeast1", "us-central1"),
    ];

    for (i, (proof_region, policy_required)) in regions.iter().enumerate() {
        let proof = builder.build_v2_1_signed(400 + i, proof_region);
        let expected = with_policy(
            expected_failure(
                "region_mismatch",
                json!({ "required": policy_required, "actual": proof_region }),
                2,
            ),
            json!({ "required_region": policy_required }),
        );
        write_fixture(
            &dir,
            &format!("{:04}_{}_to_{}", i, proof_region, policy_required),
            &proof,
            &expected,
        );
        count += 1;
    }

    count
}

/// Category 3d — authority unknown failures (10 fixtures). Proofs reference
/// authority IDs not in the trust chain.
fn generate_authority_unknown_failures(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("06_failure_authority_unknown");
    let mut count = 0;

    let unknown_authorities = [
        "phantom-kms-v1",
        "ghost-authority-v9",
        "nonexistent-region-kms",
        "customer-hsm-not-registered-v1",
        "us-kms-typo-1",
        "eu-kms-typo-1",
        "asia-kms-not-yet-launched-v1",
        "abandoned-authority-v0",
        "test-authority-do-not-use",
        "deprecated-authority-2024",
    ];

    for (i, authority_id) in unknown_authorities.iter().enumerate() {
        let mut proof = builder.build_v2_1_signed(500 + i, "us-central1");
        proof["signing_authority"] = json!({ "authority_id": authority_id });
        let expected = with_policy(
            expected_failure(
                "authority_id_mismatch",
                json!({
                    "claimed_authority_id": authority_id,
                    "expected_authority_id": "us-kms-nanorix-v1",
                    "reason": "verifier_policy_authority_id_mismatch",
                }),
                2,
            ),
            json!({ "required_authority_id": "us-kms-nanorix-v1" }),
        );
        write_fixture(&dir, &format!("{:04}_unknown_{}", i, i), &proof, &expected);
        count += 1;
    }

    count
}

/// Category 3e — cdp_version unsupported failures (10 fixtures). Each fixture
/// declares a future or invalid version.
fn generate_version_unsupported_failures(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("07_failure_version_unsupported");
    let mut count = 0;

    let bad_versions = [
        "0.9", "3.0", "99.0", "2.99", "v2.1", "2.1.0", "two.one", "", "null", "1",
    ];

    for (i, bad_version) in bad_versions.iter().enumerate() {
        let mut proof = builder.build_v2_1_signed(600 + i, "us-central1");
        proof["cdp_version"] = Value::String(bad_version.to_string());
        let expected = expected_failure(
            "cdp_version_unsupported",
            json!({ "found": bad_version }),
            2,
        );
        write_fixture(&dir, &format!("{:04}_version_{}", i, i), &proof, &expected);
        count += 1;
    }

    count
}

/// The verdict for a canonical-view field mutated after signing.
///
/// There is no `canonical_hash_mismatch` variant in the Forever-Standard
/// `FailureReason` enum (`governance/verify-types/src/lib.rs`) and there never
/// was one. Canonical drift is *detected* by the signature check: the verifier
/// recomputes the canonical hash from the document in front of it, and the
/// signature — made over the pre-mutation hash — no longer verifies. So the
/// honest expected verdict for drift is a signature failure at stage 7.
fn expected_canonical_drift() -> Value {
    with_note(
        expected_failure(
            "signature_mismatch",
            json!({ "reason": "does_not_verify" }),
            7,
        ),
        "Canonical-view drift is detected as a signature failure over the \
         recomputed canonical hash; the FailureReason enum has no separate \
         canonical_hash_mismatch variant.",
    )
}

/// Category 3f — canonical hash drift failures (10 fixtures). Each fixture is
/// signed as a well-formed v2.1 document, then one canonical-view field is
/// mutated afterwards. Two of the ten are deliberately NOT plain signature
/// failures — see their notes; they document where drift is caught earlier or
/// not caught at all.
fn generate_canonical_hash_drift_failures(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("08_failure_canonical_hash_drift");
    let mut count = 0;

    type Mutator = fn(&mut Value);
    let mutations: Vec<(&str, Mutator, Value)> = vec![
        (
            "flip_jurisdiction",
            |p| p["jurisdiction"] = json!("eu"),
            expected_canonical_drift(),
        ),
        (
            "flip_authority_id",
            |p| p["authority_id"] = json!("eu-kms-nanorix-v1"),
            expected_canonical_drift(),
        ),
        (
            // Downgrading the signing mode moves the proof into a mode this
            // verifier cannot check a signature for, so it reports "chain
            // Closed 2026-08-11: an unrecognised signing_mode is now rejected
            // rather than reported as "chain verified, signature NOT checked".
            // The field is inside the canonical hash and attacker-controllable,
            // so a partial-success verdict was a downgrade oracle.
            "flip_signing_mode",
            |p| p["signing_mode"] = json!("dual_signature"),
            with_note(
                json!({
                    "valid": false,
                    "failure_reason": {
                        "type": "algorithm_unsupported",
                        "found": "signing_mode=dual_signature"
                    },
                    "stage_reached": 4
                }),
                "CLOSED 2026-08-11. Flipping signing_mode to a mode this build \
                 cannot verify is a REJECTION, not 'chain verified, signature NOT \
                 checked'. signing_mode is inside the canonical hash and is \
                 attacker-controllable, so an unrecognised mode yielding a partial \
                 success was a downgrade oracle: flip the field, turn a rejection \
                 into reassurance. 'I have no signature to check' and 'I cannot \
                 perform the verification this document requires' are different \
                 conditions and get different verdicts. Reported as the existing \
                 Forever-Standard algorithm_unsupported rather than a new variant \
                 — the resolution (upgrade the verifier) is identical.",
            ),
        ),
        (
            "flip_capsule_id",
            |p| p["capsule_id"] = json!("cap_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            expected_canonical_drift(),
        ),
        (
            // destroyed_at is the chain timestamp as well as a wire field, so
            // this drift is caught by the chain walk before the signature stage
            // is ever reached — a strictly earlier, cheaper rejection.
            "flip_destroyed_at",
            |p| p["destroyed_at"] = json!("2026-01-01T00:00:00Z"),
            with_note(
                expected_failure(
                    "step_hash_mismatch",
                    json!({ "step_idx": 0, "subsystem": "eee_namespace" }),
                    3,
                ),
                "destroyed_at is the chain timestamp, so this drift is caught at \
                 stage 3 by the chain walk — earlier than the signature stage.",
            ),
        ),
        (
            "flip_destruction_state",
            |p| p["destruction_state"] = json!("aborted"),
            expected_canonical_drift(),
        ),
        (
            "flip_hash_algorithm",
            |p| p["hash_algorithm"] = json!("SHA-256"),
            expected_canonical_drift(),
        ),
        (
            "flip_signature_algorithm",
            |p| p["signature_algorithm"] = json!("RSA-PSS"),
            // ADR-051 C.1: algorithm dispatch precedes byte-shape checks — a
            // document declaring a non-Ed25519 algorithm fails typed at stage
            // 4 (this build cannot evaluate what the document declares), not
            // as a presumed-Ed25519 mismatch at stage 7. Same path is the
            // graceful degradation an old verifier applies to a genuine
            // future-algorithm proof.
            with_note(
                expected_failure("algorithm_unsupported", json!({ "found": "RSA-PSS" }), 4),
                "ADR-051 C.1: algorithm dispatch precedes byte-shape checks. A \
                 document declaring a non-Ed25519 signature algorithm fails \
                 typed as algorithm_unsupported at stage 4 — this build cannot \
                 evaluate what the document declares, so presuming Ed25519 \
                 semantics and reporting a mismatch would be dishonest.",
            ),
        ),
        (
            "inject_runtime_attestation",
            |p| {
                p["runtime_attestation"] = json!({
                    "algorithm": "Ed25519",
                    "public_key": "base64:AAAA",
                    "signature": "base64:AAAA",
                })
            },
            expected_canonical_drift(),
        ),
        (
            "flip_org_id",
            |p| p["org_id"] = json!("11111111-1111-1111-1111-111111111111"),
            expected_canonical_drift(),
        ),
    ];

    for (i, (descriptor, mutator, expected)) in mutations.iter().enumerate() {
        // Signed first with every canonical field in place, mutated second —
        // that ordering is the whole point of the category.
        let mut proof = builder.build_v2_1_signed(700 + i, "us-central1");
        mutator(&mut proof);
        write_fixture(&dir, &format!("{:04}_{}", i, descriptor), &proof, expected);
        count += 1;
    }

    count
}

/// Category 4 — tamper patterns. Four sub-categories of 5 fixtures each:
/// byte-flip, re-order, version downgrade, signature substitution.
fn generate_tamper_patterns(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir_root = root.join("09_tamper_patterns");
    let mut count = 0;

    // 4a — byte-flip: 5 fixtures with a single character flipped in
    // various canonical fields.
    let dir = dir_root.join("a_byte_flip");
    for i in 0..5 {
        let mut proof = builder.build_v2_1_signed(800 + i, "us-central1");
        let last = proof["final_hash"].as_str().unwrap().to_string();
        let mut flipped: Vec<char> = last.chars().collect();
        let pos = 8 + i; // "sha512:" prefix has length 7
        if pos < flipped.len() {
            flipped[pos] = if flipped[pos] == '0' { '1' } else { '0' };
        }
        let flipped: String = flipped.into_iter().collect();
        proof["final_hash"] = Value::String(flipped.clone());
        // final_hash is not canonical-bound, so this is caught at stage 4 by
        // the final_hash↔last-chain-hash binding, before the signature stage.
        let expected = expected_failure(
            "final_hash_mismatch",
            json!({
                "claimed": flipped,
                "computed": proof["chain"][7]["chain_hash"].as_str().unwrap_or_default(),
            }),
            4,
        );
        write_fixture(
            &dir,
            &format!("{:04}_byte_flip_{}", i, i),
            &proof,
            &expected,
        );
        count += 1;
    }

    // 4b — re-order: 5 fixtures where chain steps are permuted.
    let dir = dir_root.join("b_re_order");
    for i in 0..5 {
        let mut proof = builder.build_v2_1_signed(810 + i, "us-central1");
        let chain = proof["chain"].as_array_mut().unwrap();
        let swap_a = i % chain.len();
        let swap_b = (i + 3) % chain.len();
        chain.swap(swap_a, swap_b);
        // The walk fails at the FIRST disturbed index, and the subsystem it
        // reports is the one now sitting there — i.e. the step swapped IN, not
        // the step that used to occupy the slot.
        let first_disturbed = swap_a.min(swap_b);
        let occupant_after_swap = SUBSYSTEMS[swap_a.max(swap_b)].0;
        let expected = expected_failure(
            "step_hash_mismatch",
            json!({ "step_idx": first_disturbed, "subsystem": occupant_after_swap }),
            3,
        );
        write_fixture(
            &dir,
            &format!("{:04}_swap_{}_{}", i, swap_a, swap_b),
            &proof,
            &expected,
        );
        count += 1;
    }

    // 4c — version downgrade: every fixture starts life as a genuine signed
    // v2.1 document and is then re-stamped with a lower `cdp_version`.
    //
    // The first two targets are the interesting attack: 2.0 and 1.0 are
    // *supported* versions, so the version gate lets them through and the
    // rejection has to come from the signature stage. It does, because the
    // signed message is version-dependent — v1.0 signs `final_hash`, v2.0 signs
    // `document_hash`, v2.1 signs the canonical hash — so a downgraded document
    // is checked against a message its signature was never made over. The
    // remaining three targets are unsupported versions, rejected two stages
    // earlier at the version gate.
    let dir = dir_root.join("c_version_downgrade");
    let downgrades = ["2.0", "1.0", "0.9", "1", "two.one"];
    for (i, to) in downgrades.iter().enumerate() {
        let mut proof = builder.build_v2_1_signed(820 + i, "us-central1");
        proof["cdp_version"] = Value::String(to.to_string());
        let expected = if matches!(*to, "2.0" | "1.0") {
            with_note(
                expected_failure(
                    "signature_mismatch",
                    json!({ "reason": "does_not_verify" }),
                    7,
                ),
                "Supported version, so the version gate passes; the downgrade is \
                 caught at the signature stage because the signed message differs \
                 per version.",
            )
        } else {
            expected_failure("cdp_version_unsupported", json!({ "found": to }), 2)
        };
        write_fixture(
            &dir,
            &format!("{:04}_downgrade_2.1_to_{}", i, to),
            &proof,
            &expected,
        );
        count += 1;
    }

    // 4d — signature substitution: 5 fixtures where the signature comes
    // from a different (valid) AuditProof.
    let dir = dir_root.join("d_signature_substitution");
    for i in 0..5 {
        let proof_a = builder.build_v2_1_signed(830 + i, "us-central1");
        let proof_b = builder.build_v2_1_signed(840 + i, "us-central1");
        let mut substituted = proof_a.clone();
        substituted["attestation"]["signature"] = proof_b["attestation"]["signature"].clone();
        let expected = with_note(
            expected_failure(
                "signature_mismatch",
                json!({ "reason": "does_not_verify" }),
                7,
            ),
            "Signature lifted verbatim from a different, genuinely signed AuditProof.",
        );
        write_fixture(
            &dir,
            &format!("{:04}_substitute_{}", i, i),
            &substituted,
            &expected,
        );
        count += 1;
    }

    count
}

// ── Index manifest ───────────────────────────────────────────────────

/// Write a top-level index.json describing every fixture in the corpus,
/// for cross-impl test harnesses to discover fixtures without filesystem
/// crawling.
fn write_index(root: &Path, total: usize) {
    let categories = [
        ("01_single_capsule_success", 10),
        ("02_multi_step_pipeline", 10),
        ("03_failure_chain_mismatch", 10),
        ("04_failure_signature_invalid", 10),
        ("05_failure_region_mismatch", 10),
        ("06_failure_authority_unknown", 10),
        ("07_failure_version_unsupported", 10),
        ("08_failure_canonical_hash_drift", 10),
        ("09_tamper_patterns/a_byte_flip", 5),
        ("09_tamper_patterns/b_re_order", 5),
        ("09_tamper_patterns/c_version_downgrade", 5),
        ("09_tamper_patterns/d_signature_substitution", 5),
    ];

    let categories_json: Vec<Value> = categories
        .iter()
        .map(|(path, count)| {
            json!({
                "path": path,
                "fixture_count": count,
            })
        })
        .collect();

    let index = json!({
        "schema_version": "2",
        "total_fixtures": total,
        "generator": "tools/nanorix-verify/fixtures/generator.rs",
        "expected_verdict_schema": {
            "valid": "bool — the verifier's accept/reject decision",
            "failure_reason": "null on success; otherwise the FailureReason wire object, tag key `type`",
            "stage_reached": "1..=8; 7 is the success stage without a trust-chain manifest",
            "policy": "optional — VerifierPolicy pins REQUIRED to reach this verdict; absent means defaults",
            "note": "optional — prose for verdicts that are not the obvious guess from the category name",
        },
        "signed_message": "v1.0 signs final_hash; v2.0 signs document_hash; v2.1 nanorix_only signs the ADR-011 Part-3 canonical-view hash (hex(sha512(jcs(view))))",
        "anchor_timestamp": FIXTURE_TIMESTAMP,
        "anchor_signing_seed_sha256": {
            "_note": "Public anchor for cross-impl reproducibility. The seed itself is constant in source.",
            "value": format!("{:x}", Sha512::digest(FIXTURE_SIGNING_SEED)),
        },
        "categories": categories_json,
        "purpose": "Cross-implementation byte-equivalence corpus for the nanorix-verify reference verifier.",
    });

    let path = root.join("index.json");
    let bytes = serde_json::to_vec_pretty(&index).expect("serialize index");
    fs::write(&path, &bytes).expect("write index.json");
}

// ── Entrypoint ───────────────────────────────────────────────────────

fn main() {
    // Optional argv[1] output directory. `tests/corpus_sweep.rs` uses it to
    // regenerate into a tempdir and diff against the committed corpus, which is
    // what keeps the committed bytes from drifting away from this generator.
    let root = match std::env::args().nth(1) {
        Some(dir) => PathBuf::from(dir),
        None => {
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("fixtures");
            p.push("corpus");
            p
        }
    };

    fs::create_dir_all(&root).expect("create corpus root");

    let builder = FixtureBuilder::new();
    let mut total = 0;

    println!("Generating AuditProof fixture corpus at {:?}", root);

    total += generate_single_capsule_success(&builder, &root);
    total += generate_multi_step_pipeline(&builder, &root);
    total += generate_chain_mismatch_failures(&builder, &root);
    total += generate_signature_invalid_failures(&builder, &root);
    total += generate_region_mismatch_failures(&builder, &root);
    total += generate_authority_unknown_failures(&builder, &root);
    total += generate_version_unsupported_failures(&builder, &root);
    total += generate_canonical_hash_drift_failures(&builder, &root);
    total += generate_tamper_patterns(&builder, &root);

    write_index(&root, total);

    println!("Generated {} fixtures.", total);
    println!("Index manifest at {:?}", root.join("index.json"));
}
