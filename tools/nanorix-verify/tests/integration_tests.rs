//! End-to-end integration tests for `nanorix-verify` CLI binary.
//!
//! Synthesizes valid + tampered AuditProofs in a tempdir, invokes the CLI
//! binary against them, and verifies stdout / stderr / exit code shape.
//!
//! These tests validate the customer-facing artifact end-to-end — a clean
//! machine with the binary should successfully process a real-shape
//! AuditProof and produce auditor-actionable output.

use nanorix_verify::{compute_step_hash, lookup_method, NANORIX_GENESIS_HASH};
use std::process::Command;

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");

fn synthesize_valid_proof(capsule_id: &str, timestamp: &str) -> serde_json::Value {
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
        let chain_hash = compute_step_hash(&prev_hash, subsystem, "destroy", method, timestamp);
        chain.push(serde_json::json!({
            "subsystem": subsystem,
            "method": method,
            "chain_hash": chain_hash.clone(),
        }));
        prev_hash = chain_hash;
    }

    let final_hash = chain
        .last()
        .and_then(|s| s.get("chain_hash"))
        .and_then(|v| v.as_str())
        .unwrap()
        .to_string();

    serde_json::json!({
        "cdp_version": "1.0",
        "capsule_id": capsule_id,
        "destroyed_at": timestamp,
        "chain": chain,
        "final_hash": final_hash,
        "environment": {
            "region": "us-central1",
        },
        "attestation": {
            "algorithm": "Ed25519",
            "signing_key_version": "7",
        }
    })
}

fn write_proof(json: &serde_json::Value) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    serde_json::to_writer_pretty(&mut file, json).expect("write json");
    file
}

#[test]
fn cli_verifies_valid_v1_proof_with_zero_exit() {
    let proof = synthesize_valid_proof("cap_integration_test", "2026-05-06T12:00:00Z");
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .output()
        .expect("spawn nanorix-verify");

    // This fixture is deliberately UNSIGNED (see the stdout assertion below), so
    // the honest exit code is 3 — "chain verified, signature NOT checked" — not 0.
    // Exiting 0 here would let an automated `verify && accept` gate accept a
    // proof carrying no signature at all. When signature verification is wired
    // on this path, the fixture gains a real signature and this becomes 0.
    assert_eq!(
        output.status.code(),
        Some(3),
        "expected exit 3 (chain verified, signature not checked); got {output:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // INTERIM (pre-embedded-key verification): this build reproduces the 8-step chain but does
    // NOT yet verify the Ed25519 signature on the single-proof path, so the CLI
    // now fails honest — "Chain verified · signature NOT checked" instead of an
    // unqualified green "Verified" (which would mislead an auditor into trusting
    // an unauthenticated, potentially forged proof). When sub-A wires signature
    // verification, tighten this to assert a full stage-8 "Verified" verdict.
    assert!(
        stdout.contains("Chain verified") && stdout.contains("signature NOT checked"),
        "expected honest chain-verified verdict in stdout, got: {stdout}"
    );
    assert!(
        stdout.contains("cap_integration_test"),
        "expected capsule id in stdout, got: {stdout}"
    );
    assert!(
        stdout.contains("us-central1"),
        "expected region in stdout, got: {stdout}"
    );
}

#[test]
fn cli_json_mode_returns_structured_output_on_valid_proof() {
    let proof = synthesize_valid_proof("cap_json_test", "2026-05-06T12:00:00Z");
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .arg("--json")
        .output()
        .expect("spawn nanorix-verify --json");

    // Same unsigned fixture as above: exit 3, not 0. The JSON body still reports
    // valid=true because the chain genuinely reproduces — the exit code is what
    // carries "the signature was never checked" to an automated caller.
    assert_eq!(
        output.status.code(),
        Some(3),
        "expected exit 3 (chain verified, signature not checked); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");

    assert_eq!(parsed["valid"], true);
    assert!(parsed["failure_reason"].is_null());
    assert_eq!(parsed["metadata"]["cdp_version"], "1.0");
    assert_eq!(parsed["metadata"]["capsule_id"], "cap_json_test");
    assert_eq!(parsed["metadata"]["region"], "us-central1");
    assert_eq!(parsed["metadata"]["signing_key_version"], "7");
    assert_eq!(parsed["metadata"]["algorithm"], "Ed25519");
    assert_eq!(parsed["metadata"]["step_count"], 8);
}

#[test]
fn cli_fails_with_exit_1_on_tampered_step() {
    let mut proof = synthesize_valid_proof("cap_tamper_test", "2026-05-06T12:00:00Z");
    proof["chain"][3]["chain_hash"] = serde_json::Value::String("0".repeat(128));
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .output()
        .expect("spawn nanorix-verify");

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1 on tampered proof; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("FAILED"),
        "expected 'FAILED' in stdout, got: {stdout}"
    );
    assert!(
        stdout.contains("step_hash_mismatch"),
        "expected failure reason name, got: {stdout}"
    );
    assert!(
        stdout.contains("step 3"),
        "expected step idx in failure detail, got: {stdout}"
    );
}

#[test]
fn cli_json_mode_returns_typed_failure_reason_on_tampered_proof() {
    let mut proof = synthesize_valid_proof("cap_tamper_json", "2026-05-06T12:00:00Z");
    // Tamper the final_hash binding (stage 4 failure)
    proof["final_hash"] = serde_json::Value::String("0".repeat(128));
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .arg("--json")
        .output()
        .expect("spawn nanorix-verify --json");

    assert_eq!(output.status.code(), Some(1), "expected exit 1");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");

    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["failure_reason"]["type"], "final_hash_mismatch");
    assert_eq!(parsed["stage_reached"], 4);
}

#[test]
fn cli_fails_on_unsupported_cdp_version() {
    let proof = serde_json::json!({"cdp_version": "99.99"});
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .output()
        .expect("spawn nanorix-verify");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cdp_version_unsupported"),
        "expected cdp_version_unsupported, got: {stdout}"
    );
}

#[test]
fn cli_fails_on_missing_chain_field() {
    let proof = serde_json::json!({"cdp_version": "1.0", "capsule_id": "cap_missing_chain"});
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .output()
        .expect("spawn nanorix-verify");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("required_field_missing"),
        "expected required_field_missing, got: {stdout}"
    );
    assert!(
        stdout.contains("chain"),
        "expected 'chain' in failure detail, got: {stdout}"
    );
}

#[test]
fn cli_print_trust_chain_succeeds_with_zero_exit() {
    let output = Command::new(BIN_PATH)
        .arg("print-trust-chain")
        .output()
        .expect("spawn nanorix-verify print-trust-chain");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Trust-chain manifest"),
        "expected header, got: {stdout}"
    );
    assert!(
        stdout.contains("Archive-forever"),
        "expected archive-forever discipline doc, got: {stdout}"
    );
    assert!(
        stdout.contains("archived_versions"),
        "expected schema field reference, got: {stdout}"
    );
}

#[test]
fn cli_help_lists_subcommands_and_flags() {
    let output = Command::new(BIN_PATH)
        .arg("--help")
        .output()
        .expect("spawn --help");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("verify"),
        "expected 'verify' subcommand in help"
    );
    assert!(
        stdout.contains("print-trust-chain"),
        "expected 'print-trust-chain' subcommand in help"
    );
    assert!(stdout.contains("--json"), "expected --json flag in help");
    assert!(
        stdout.contains("--reject-diagnostic"),
        "expected --reject-diagnostic flag in help"
    );
    assert!(
        stdout.contains("--required-region"),
        "expected --required-region flag in help"
    );
}

#[test]
fn cli_version_prints_package_version() {
    let output = Command::new(BIN_PATH)
        .arg("--version")
        .output()
        .expect("spawn --version");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("nanorix-verify"),
        "expected binary name in version output"
    );
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        stdout.contains(version),
        "expected version {version}, got: {stdout}"
    );
}

#[test]
fn cli_exit_2_on_no_args() {
    let output = Command::new(BIN_PATH).output().expect("spawn no-args");

    // Help printed, exit 2 (CLI usage error per cli code path)
    assert_eq!(output.status.code(), Some(2));
}

// ── an earlier release-7 / : Bulk verification --batch ─────────────────────

/// Helper: write a valid proof JSON into the given directory under the
/// given filename, using a synthesized timestamp.
fn write_valid_proof_into(
    dir: &std::path::Path,
    filename: &str,
    capsule_id: &str,
) -> std::path::PathBuf {
    let proof = synthesize_valid_proof(capsule_id, "2026-05-11T00:00:00Z");
    let path = dir.join(filename);
    let f = std::fs::File::create(&path).expect("create proof file");
    serde_json::to_writer_pretty(f, &proof).expect("write proof");
    path
}

/// Helper: write a tampered (step_hash mismatch) proof into the given
/// directory under the given filename.
fn write_tampered_proof_into(
    dir: &std::path::Path,
    filename: &str,
    capsule_id: &str,
) -> std::path::PathBuf {
    let mut proof = synthesize_valid_proof(capsule_id, "2026-05-11T00:00:00Z");
    proof["chain"][2]["chain_hash"] = serde_json::Value::String("0".repeat(128));
    let path = dir.join(filename);
    let f = std::fs::File::create(&path).expect("create tampered file");
    serde_json::to_writer_pretty(f, &proof).expect("write tampered");
    path
}

#[test]
fn cli_batch_all_pass_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "p1.json", "cap_batch_001");
    write_valid_proof_into(tmp.path(), "p2.json", "cap_batch_002");
    write_valid_proof_into(tmp.path(), "p3.json", "cap_batch_003");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    assert!(
        output.status.success(),
        "expected exit 0 when all proofs pass; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS"), "expected PASS lines: {stdout}");
    assert!(
        stdout.contains("3 / 3 passed"),
        "expected '3 / 3 passed' summary: {stdout}"
    );
}

#[test]
fn cli_batch_with_failure_exits_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "good1.json", "cap_good_001");
    write_tampered_proof_into(tmp.path(), "bad.json", "cap_bad_001");
    write_valid_proof_into(tmp.path(), "good2.json", "cap_good_002");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1 when any proof fails; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FAIL"), "expected FAIL line: {stdout}");
    assert!(
        stdout.contains("2 passed"),
        "expected '2 passed' in summary: {stdout}"
    );
    assert!(
        stdout.contains("1 failed"),
        "expected '1 failed' in summary: {stdout}"
    );
}

#[test]
fn cli_batch_recursive_walks_subdirectories() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sub1 = tmp.path().join("sub1");
    let sub2 = tmp.path().join("sub2");
    let nested = sub1.join("deep");
    std::fs::create_dir_all(&nested).expect("mkdir nested");
    std::fs::create_dir_all(&sub2).expect("mkdir sub2");

    write_valid_proof_into(tmp.path(), "root.json", "cap_root");
    write_valid_proof_into(&sub1, "child1.json", "cap_child1");
    write_valid_proof_into(&nested, "grandchild.json", "cap_grand");
    write_valid_proof_into(&sub2, "child2.json", "cap_child2");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    assert!(
        output.status.success(),
        "expected exit 0 on all-valid recursive walk; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("4 / 4 passed"),
        "expected '4 / 4 passed' across 4 nested files; got: {stdout}"
    );
}

#[test]
fn cli_batch_skips_non_json_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "real.json", "cap_real");
    // Irrelevant file in mixed-content directory
    std::fs::write(tmp.path().join("README.md"), "noise").expect("write noise");
    std::fs::write(tmp.path().join("notes.txt"), "more noise").expect("write txt");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    assert!(output.status.success(), "exit 0 expected on single pass");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 / 1 passed"),
        "expected '1 / 1 passed' — non-json files skipped; got: {stdout}"
    );
}

#[test]
fn cli_batch_empty_directory_exits_zero_with_zero_files() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    // Empty corpus is NOT a failure — auditor distinguishes empty by the
    // summary numbers, not by the exit code.
    assert!(
        output.status.success(),
        "empty directory should exit 0; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No AuditProof files matching"),
        "expected empty-directory note: {stdout}"
    );
}

#[test]
fn cli_batch_json_mode_emits_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "p1.json", "cap_json_001");
    write_tampered_proof_into(tmp.path(), "p2.json", "cap_json_002");

    let output = Command::new(BIN_PATH)
        .args(["--json", "batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify --json batch");

    // Exit 1 because one entry fails
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON envelope");

    assert_eq!(parsed["summary"]["total"], 2);
    assert_eq!(parsed["summary"]["passed"], 1);
    assert_eq!(parsed["summary"]["failed"], 1);
    assert!(parsed["files"].is_array());
    assert_eq!(parsed["files"].as_array().unwrap().len(), 2);
}

#[test]
fn cli_batch_handles_invalid_json_per_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "good.json", "cap_good");
    std::fs::write(tmp.path().join("bad.json"), "{this is not json").expect("write malformed file");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    // Invalid JSON counts as a per-file failure; batch keeps walking.
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("invalid_json"),
        "expected invalid_json reason: {stdout}"
    );
    assert!(stdout.contains("1 passed"));
    assert!(stdout.contains("1 failed"));
}

#[test]
fn cli_batch_deterministic_ordering() {
    // Two runs against the same corpus must produce byte-identical
    // PASS/FAIL line ordering — auditors diff this output.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "zeta.json", "cap_zeta");
    write_valid_proof_into(tmp.path(), "alpha.json", "cap_alpha");
    write_valid_proof_into(tmp.path(), "mu.json", "cap_mu");

    let out1 = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn run 1");
    let out2 = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn run 2");

    assert_eq!(
        out1.stdout, out2.stdout,
        "batch output must be byte-identical across runs (deterministic ordering)"
    );

    // Alphabetic order: alpha < mu < zeta
    let stdout = String::from_utf8_lossy(&out1.stdout);
    let alpha_idx = stdout.find("alpha.json").expect("alpha line present");
    let mu_idx = stdout.find("mu.json").expect("mu line present");
    let zeta_idx = stdout.find("zeta.json").expect("zeta line present");
    assert!(
        alpha_idx < mu_idx && mu_idx < zeta_idx,
        "expected lexicographic ordering of file paths"
    );
}

#[test]
fn cli_batch_directory_does_not_exist_aborts() {
    let output = Command::new(BIN_PATH)
        .args(["batch", "/nonexistent/path/that/does/not/exist"])
        .output()
        .expect("spawn nanorix-verify batch");

    assert!(
        !output.status.success(),
        "non-existent directory should abort with non-zero exit"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("is not a directory"),
        "expected directory error in stderr: {stderr}"
    );
}

#[test]
fn cli_batch_mixed_corpus_with_ten_files() {
    // Mixed 7 valid + 3 tampered → summary 7/10, exit 1.
    let tmp = tempfile::tempdir().expect("tempdir");
    for i in 0..7 {
        write_valid_proof_into(tmp.path(), &format!("good_{i}.json"), &format!("cap_g_{i}"));
    }
    for i in 0..3 {
        write_tampered_proof_into(tmp.path(), &format!("bad_{i}.json"), &format!("cap_b_{i}"));
    }

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("7 passed"),
        "expected '7 passed' in 10-file mixed corpus: {stdout}"
    );
    assert!(
        stdout.contains("3 failed"),
        "expected '3 failed' in 10-file mixed corpus: {stdout}"
    );
}

// ── the chain-timestamp recovery rule D4 — captured-document regression guard ──────────────────────────
//
// Every other fixture in this file is synthesized by `synthesize_valid_proof`.
// That is precisely how the v2.1 defect survived to production: the verifier was
// only ever fed documents this test file built, never one the API emitted. A
// hand-authored proof carries whatever fields the test author remembered, so an
// omission in the real serialization is structurally invisible here.
//
// The fixture below is a captured API v2.1 document from a real capsule
// (2026-07-30). Before the chain-timestamp recovery rule restored `destroyed_at`, this exact document
// failed `step_hash_mismatch` at step 0 — an authentic proof the reference
// verifier rejected.

const CAPTURED_V2_1: &str = include_str!("captured/api-v2_1-real-capsule.json");

#[test]
fn captured_api_v2_1_document_carries_the_chain_timestamp() {
    let proof: serde_json::Value = serde_json::from_str(CAPTURED_V2_1).expect("fixture parses");
    let ts = proof
        .get("destroyed_at")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !ts.is_empty(),
        "captured v2.1 document lost `destroyed_at` — every chain step hashes it, \
         so a verifier holding only this document cannot recompute step 0 (the chain-timestamp recovery rule)"
    );
    assert_eq!(
        proof.get("chain").and_then(|c| c.as_array()).map(Vec::len),
        Some(8),
        "Forever-Standard chain is exactly 8 steps (the Forever-Standard wire discipline)"
    );
}

#[test]
fn cli_walks_the_full_chain_of_a_captured_api_document() {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    std::io::Write::write_all(&mut file, CAPTURED_V2_1.as_bytes()).expect("write fixture");

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .output()
        .expect("spawn nanorix-verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The pre-the chain-timestamp recovery rule failure mode, named exactly so a regression is unambiguous.
    assert!(
        !stdout.contains("step_hash_mismatch"),
        "captured document failed chain recomputation — the the chain-timestamp recovery rule regression is back.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("8 / 8"),
        "expected all 8 chain steps to verify on a captured document.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}
