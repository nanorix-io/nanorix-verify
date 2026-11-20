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
        // Region is read from the signed `capsule_started` event, never from
        // `environment` — that projection is outside the canonical hash and
        // its struct has no region field at all.
        "activity": [{
            "event": "capsule_started",
            "encryption": "aes-256-gcm",
            "network": "sealed",
            "region": "us-central1",
        }],
        "attestation": {
            "algorithm": "Ed25519",
            "signing_key_version": "7",
        }
    })
}

/// `synthesize_valid_proof` plus a real Ed25519 signature over `final_hash`
/// (v1.0 signs the ASCII hex of the final chain hash), so the verifier
/// reaches the signature stage.
fn synthesize_signed_proof(capsule_id: &str, timestamp: &str) -> serde_json::Value {
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    let b64 = base64::engine::general_purpose::STANDARD;
    let key = SigningKey::from_bytes(&[0x42u8; 32]);
    let mut proof = synthesize_valid_proof(capsule_id, timestamp);
    let final_hash = proof["final_hash"].as_str().unwrap().to_string();
    let sig = key.sign(final_hash.as_bytes());
    proof["attestation"]["public_key"] = serde_json::Value::String(format!(
        "base64:{}",
        b64.encode(key.verifying_key().to_bytes())
    ));
    proof["attestation"]["signature"] =
        serde_json::Value::String(format!("base64:{}", b64.encode(sig.to_bytes())));
    proof
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
    // A 1.0 signature covers final_hash alone, so the verdict names neither
    // the capsule id nor the region the document states.
    assert!(
        !stdout.contains("cap_integration_test") && !stdout.contains("us-central1"),
        "a 1.0 verdict must not name the capsule or the region, got: {stdout}"
    );
    assert!(
        stdout.contains("capsule not named (a 1.0 signature does not cover it)"),
        "expected the 1.0 capsule label in stdout, got: {stdout}"
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
    // 1.0 signs final_hash alone: no capsule id or region is reported.
    assert!(parsed["metadata"]["capsule_id"].is_null(), "{parsed}");
    assert!(parsed["metadata"]["region"].is_null(), "{parsed}");
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
    // chain[3] is step 4 (dire_keys): the label is the step's own 1-based
    // number, never the 0-based wire index. This assertion previously pinned
    // "step 3" — the off-by-one itself.
    assert!(
        stdout.contains("step 4") && stdout.contains("dire_keys"),
        "expected 1-based step label with its subsystem, got: {stdout}"
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
    // A label names an authority; it never says who holds the key (
    // Part A).
    for custody in ["customer's key", "customer-held"] {
        assert!(
            !stdout.contains(custody),
            "--help reads a label as key custody ({custody}): {stdout}"
        );
    }
    assert!(
        stdout.contains("the fingerprint published for that authority"),
        "expected the --identity-fingerprint doc to name the authority's published fingerprint: {stdout}"
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

// ── Bulk verification --batch ─────────────────────────────────────────────

/// Helper: write a valid proof JSON into the given directory under the
/// given filename, using a synthesized timestamp.
fn write_valid_proof_into(
    dir: &std::path::Path,
    filename: &str,
    capsule_id: &str,
) -> std::path::PathBuf {
    let proof = synthesize_signed_proof(capsule_id, "2026-05-11T00:00:00Z");
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
    let mut proof = synthesize_signed_proof(capsule_id, "2026-05-11T00:00:00Z");
    proof["chain"][2]["chain_hash"] = serde_json::Value::String("0".repeat(128));
    let path = dir.join(filename);
    let f = std::fs::File::create(&path).expect("create tampered file");
    serde_json::to_writer_pretty(f, &proof).expect("write tampered");
    path
}

/// Helper: a chain that reproduces but carries no signature anyone checked.
fn write_unsigned_proof_into(
    dir: &std::path::Path,
    filename: &str,
    capsule_id: &str,
) -> std::path::PathBuf {
    let proof = synthesize_valid_proof(capsule_id, "2026-05-11T00:00:00Z");
    let path = dir.join(filename);
    let f = std::fs::File::create(&path).expect("create unsigned file");
    serde_json::to_writer_pretty(f, &proof).expect("write unsigned");
    path
}

#[test]
fn cli_batch_unsigned_proof_is_not_verified_and_does_not_exit_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "signed.json", "cap_signed");
    write_unsigned_proof_into(tmp.path(), "unsigned.json", "cap_unsigned");

    let output = Command::new(BIN_PATH)
        .args(["--json", "batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    assert_eq!(
        output.status.code(),
        Some(1),
        "a batch holding a proof with no checked signature must not exit 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    // Without --trust-chain a checked signature is only "not anchored".
    assert_eq!(parsed["summary"]["verified"], 0);
    assert_eq!(parsed["summary"]["not_anchored"], 1);
    assert_eq!(parsed["summary"]["not_verified"], 1);
    let files = parsed["files"].as_array().unwrap();
    let unsigned = files
        .iter()
        .find(|f| f["path"].as_str().unwrap().ends_with("unsigned.json"))
        .unwrap();
    assert_eq!(unsigned["status"], "not_verified");
    assert!(
        unsigned["reason"]
            .as_str()
            .unwrap()
            .contains("no_signature_checked"),
        "{unsigned}"
    );
}

#[test]
fn cli_batch_all_signed_without_trust_chain_is_not_anchored_and_exits_four() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "p1.json", "cap_batch_001");
    write_valid_proof_into(tmp.path(), "p2.json", "cap_batch_002");
    write_valid_proof_into(tmp.path(), "p3.json", "cap_batch_003");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    assert_eq!(
        output.status.code(),
        Some(4),
        "expected exit 4 when every signature checks only against the key the file carries \
         (single-file mode exits 4 at stage 7); stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| l.contains("· capsule")).collect();
    assert_eq!(lines.len(), 3, "expected 3 per-file lines: {stdout}");
    assert!(
        lines.iter().all(|l| l.starts_with("not anchored ")),
        "expected every per-file line to start with 'not anchored ': {stdout}"
    );
    assert!(
        stdout.contains("0 verified, 3 not anchored"),
        "expected '0 verified, 3 not anchored' summary: {stdout}"
    );
}

#[test]
fn cli_stage_7_verdict_names_the_signed_view() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/corpus");
    let nanorix = corpus.join("01_single_capsule_success/0000_v2_1_signed.json");
    let customer_only = corpus.join("13_customer_only/0000_v2_1_customer_only_signed.json");

    for (path, branch_header) in [
        (nanorix, "key NOT anchored to Nanorix trust root"),
        (customer_only, "key NOT anchored to a published key list"),
    ] {
        let output = Command::new(BIN_PATH)
            .arg(&path)
            .output()
            .expect("spawn nanorix-verify");

        assert_eq!(
            output.status.code(),
            Some(4),
            "stage 7 exits 4; stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(branch_header),
            "expected the {branch_header:?} branch: {stdout}"
        );
        assert!(
            stdout.contains("no signed byte changed since signing")
                && stdout.contains("outside the signed view"),
            "the stage 7 verdict must say what the signature covers: {stdout}"
        );
        assert!(
            !stdout.contains("not tampered since signing"),
            "the stage 7 verdict must not claim the whole proof is untouched: {stdout}"
        );
    }

    // A 1.0 proof gets its own stage 7 line: its signature covers final_hash alone.
    let v1_0 = write_proof(&synthesize_signed_proof(
        "cap_stage7_wording",
        "2026-05-06T12:00:00Z",
    ));
    let output = Command::new(BIN_PATH)
        .arg(v1_0.path())
        .output()
        .expect("spawn nanorix-verify");
    assert_eq!(output.status.code(), Some(4));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("AuditProof 1.0 binds its time and two Merkle roots only"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("key NOT anchored to Nanorix trust root"),
        "{stdout}"
    );
}

/// The shared 1.0 vector under the key list that holds its key, with that
/// list's pin: the CLI exits 4 and says that no key list changes this, in the
/// single-file note, the key-version line and the batch lines and summary.
#[test]
fn cli_v1_0_under_its_key_list_names_no_key_list_as_a_remedy() {
    let vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/trust_chain");
    let cases: serde_json::Value =
        serde_json::from_slice(&std::fs::read(vectors.join("cases.json")).unwrap()).unwrap();
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "v1_0_proof_never_anchors")
        .expect("the shared 1.0 case")
        .clone();
    let key_list = vectors.join(case["key_list"].as_str().unwrap());
    let proof = vectors.join(case["proof"].as_str().unwrap());
    let pin = case["pin"].as_str().unwrap();
    let list_args = [
        "--trust-chain",
        key_list.to_str().unwrap(),
        "--identity-fingerprint",
        pin,
    ];

    let output = Command::new(BIN_PATH)
        .arg(&proof)
        .args(list_args)
        .output()
        .expect("spawn nanorix-verify");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{stdout}{stderr}");
    assert!(
        stderr.contains("a 1.0 proof is never anchored; no key list changes this"),
        "{stderr}"
    );
    assert!(!stderr.contains("--trust-chain"), "{stderr}");
    assert!(
        !stderr.contains("no trust chain resolved that key"),
        "{stderr}"
    );
    assert!(
        stdout.contains("Signing key version (not covered by a 1.0 signature): "),
        "{stdout}"
    );

    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(&proof, dir.path().join("v1_0.json")).unwrap();
    let output = Command::new(BIN_PATH)
        .args(list_args)
        .args(["batch", dir.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(4), "{stdout}");
    assert!(!stdout.contains("--trust-chain"), "{stdout}");
    assert!(!stdout.contains("capsule (unknown)"), "{stdout}");
    assert!(
        stdout.contains("capsule not named (a 1.0 signature does not cover it)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("a 1.0 proof is never anchored; no key list changes this"),
        "{stdout}"
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
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("not verified ") && l.contains("bad.json")),
        "expected a 'not verified' line for bad.json: {stdout}"
    );
    assert!(
        stdout.contains("2 not anchored"),
        "expected '2 not anchored' in summary: {stdout}"
    );
    assert!(
        stdout.contains("1 not verified"),
        "expected '1 not verified' in summary: {stdout}"
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

    assert_eq!(
        output.status.code(),
        Some(4),
        "expected exit 4 on an all-signed, not anchored recursive walk; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0 verified, 4 not anchored (total 4)"),
        "expected 4 not anchored across 4 nested files; got: {stdout}"
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

    assert_eq!(
        output.status.code(),
        Some(4),
        "exit 4 expected: the one file is not anchored"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0 verified, 1 not anchored (total 1)"),
        "expected one file counted — non-json files skipped; got: {stdout}"
    );
}

#[test]
fn cli_batch_empty_directory_exits_two_with_zero_files() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let output = Command::new(BIN_PATH)
        .args(["batch", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn nanorix-verify batch");

    // Nothing was verified, so the exit that means "every file is verified"
    // must not be given: a CI glob that matched nothing does not pass.
    assert_eq!(
        output.status.code(),
        Some(2),
        "empty directory should exit 2; stdout: {}",
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
    assert_eq!(parsed["summary"]["verified"], 0);
    assert_eq!(parsed["summary"]["not_anchored"], 1);
    assert_eq!(parsed["summary"]["not_verified"], 1);
    // Per-file verdict values are verified / not_anchored / not_verified.
    let statuses: Vec<&str> = parsed["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, vec!["not_anchored", "not_verified"]);
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
    assert!(stdout.contains("1 not anchored"));
    assert!(stdout.contains("1 not verified"));
}

#[test]
fn cli_batch_deterministic_ordering() {
    // Two runs against the same corpus must produce byte-identical
    // verified / not verified line ordering — auditors diff this output.
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
        stdout.contains("7 not anchored"),
        "expected '7 not anchored' in 10-file mixed corpus: {stdout}"
    );
    assert!(
        stdout.contains("3 not verified"),
        "expected '3 not verified' in 10-file mixed corpus: {stdout}"
    );
}

// ── the chain-timestamp recovery rule — captured-document regression guard ──────────────────────────
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
         so a verifier holding only this document cannot recompute step 0"
    );
    assert_eq!(
        proof.get("chain").and_then(|c| c.as_array()).map(Vec::len),
        Some(8),
        "Forever-Standard chain is exactly 8 steps"
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

    // The earlier failure mode, named exactly so a regression is unambiguous.
    assert!(
        !stdout.contains("step_hash_mismatch"),
        "captured document failed chain recomputation — the missing-destroyed_at regression is back.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("8 / 8"),
        "expected all 8 chain steps to verify on a captured document.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
}

// ── Step labels are 1-based and name the step's own subsystem ──────────────
//
// The wire `step_idx` is 0-based (Forever-Standard); the human label must be
// the step's own 1-based `step` number (1..=8) beside its subsystem. Until
// 2026-08-23 the CLI printed the raw index: a tamper in chain[2] (step 3,
// eee_memory) read "step 2, subsystem: eee_memory" — a label naming a step
// the subsystem does not belong to.

#[test]
fn cli_step_hash_mismatch_labels_chain_index_2_as_step_3() {
    let mut proof = synthesize_valid_proof("cap_step_label_3", "2026-05-06T12:00:00Z");
    proof["chain"][2]["chain_hash"] = serde_json::Value::String("0".repeat(128));
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .output()
        .expect("spawn nanorix-verify");
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("step 3") && stdout.contains("eee_memory"),
        "expected 'step 3' beside 'eee_memory', got: {stdout}"
    );
    assert!(
        !stdout.contains("step 2,"),
        "0-based index leaked into the 1-based step label: {stdout}"
    );
}

#[test]
fn cli_step_hash_mismatch_labels_chain_index_0_as_step_1() {
    let mut proof = synthesize_valid_proof("cap_step_label_1", "2026-05-06T12:00:00Z");
    proof["chain"][0]["chain_hash"] = serde_json::Value::String("0".repeat(128));
    let file = write_proof(&proof);

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .output()
        .expect("spawn nanorix-verify");
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("step 1") && stdout.contains("eee_namespace"),
        "expected 'step 1' beside 'eee_namespace', got: {stdout}"
    );
    assert!(
        !stdout.contains("step 0"),
        "0-based index leaked into the 1-based step label: {stdout}"
    );
}

// ── Foreign authority under the published manifest (BYOC disclosure) ───────
//
// The outside-key reference sample names authority `customer-kms-example-health-v1`,
// which the published Nanorix manifest does not carry. The verdict class is
// unchanged (`signing_key_version_unknown`, stage 6, exit 1 — an unanchorable
// proof must not pass an automated gate under an explicitly supplied
// manifest), but the text must disclose what the hosted /v1/verify already
// does: the manifest does not name this authority; integrity and the
// embedded-key signature held; anchoring is not established here.

const CUSTOMER_SIGNED_SAMPLE: &str =
    include_str!("captured/reference-sample-outside-key.auditproof.json");

#[test]
fn cli_foreign_authority_reports_manifest_does_not_name_authority() {
    let proof: serde_json::Value =
        serde_json::from_str(CUSTOMER_SIGNED_SAMPLE).expect("sample parses");
    let file = write_proof(&proof);

    let static_root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../static/.well-known");
    let pin = std::fs::read_to_string(format!("{static_root}/identity.txt"))
        .expect("read published identity pin")
        .trim()
        .to_string();

    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .arg("--trust-chain")
        .arg(format!("{static_root}/trust-chain.json"))
        .arg("--identity-fingerprint")
        .arg(&pin)
        .output()
        .expect("spawn nanorix-verify");

    assert_eq!(
        output.status.code(),
        Some(1),
        "foreign-authority proof under an explicit manifest must still exit 1; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("signing_key_version_unknown"),
        "wire reason name must be unchanged, got: {stdout}"
    );
    assert!(
        stdout.contains("does not name signing authority \"customer-kms-example-health-v1\""),
        "expected the unnamed-authority disclosure, got: {stdout}"
    );
    assert!(
        stdout.contains("anchoring is not established under this manifest"),
        "expected the anchoring-scope disclosure, got: {stdout}"
    );
    assert!(
        stdout.contains("signature verified against the public key embedded in the document"),
        "expected the integrity-held disclosure, got: {stdout}"
    );
    assert!(
        !stdout.contains("isn't in this verifier's trust chain"),
        "the generic broken-trust-chain hint is the misleading text this replaces: {stdout}"
    );
}

fn run_with_pin(proof: &serde_json::Value, pin: &str) -> (Option<i32>, String) {
    let file = write_proof(proof);
    let output = Command::new(BIN_PATH)
        .arg(file.path())
        .arg("--required-authority-id")
        .arg(pin)
        .output()
        .expect("spawn nanorix-verify");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// A genuine 1.0 proof naming the default authority, checked against a
/// customer pin, is a policy mismatch: nothing about it was altered.
#[test]
fn cli_default_authority_v1_proof_under_customer_pin_gets_the_policy_hint() {
    let mut proof = synthesize_valid_proof("cap_pin_default", "2026-05-06T12:00:00Z");
    proof["authority_id"] = serde_json::json!("us-kms-nanorix-v1");
    let (code, stdout) = run_with_pin(&proof, "customer-hsm-example-org-v1");

    assert_eq!(code, Some(1), "stdout: {stdout}");
    assert!(
        stdout.contains("claimed: us-kms-nanorix-v1")
            && stdout.contains("reason: verifier_policy_authority_id_mismatch"),
        "wire fields unchanged, got: {stdout}"
    );
    assert!(
        stdout.contains("operational misconfiguration"),
        "expected the policy hint, got: {stdout}"
    );
    assert!(
        !stdout.contains("not covered by its signature")
            && !stdout.contains("altered after signing"),
        "a default authority on 1.0 is not tampering: {stdout}"
    );
}

/// The same 1.0 proof relabelled to the pin is refused with the
/// unsigned-on-this-version hint, never the policy one.
#[test]
fn cli_relabelled_v1_proof_under_its_pin_gets_the_unsigned_hint() {
    let mut proof = synthesize_valid_proof("cap_pin_relabel", "2026-05-06T12:00:00Z");
    proof["authority_id"] = serde_json::json!("customer-hsm-example-org-v1");
    let (code, stdout) = run_with_pin(&proof, "customer-hsm-example-org-v1");

    assert_eq!(code, Some(1), "stdout: {stdout}");
    assert!(
        stdout.contains("claimed: customer-hsm-example-org-v1")
            && stdout.contains("reason: verifier_policy_authority_id_mismatch"),
        "wire fields unchanged, got: {stdout}"
    );
    assert!(
        stdout.contains("not covered by its signature"),
        "expected the unsigned-on-this-version hint, got: {stdout}"
    );
    assert!(
        !stdout.contains("operational misconfiguration"),
        "a relabelled 1.0 proof is not a policy mismatch: {stdout}"
    );
}

/// An unlabelled proof under a customer pin: the hint prints before any
/// signature check, so it may only say which authority the proof names.
#[test]
fn cli_unlabelled_proof_under_customer_pin_says_it_names_no_authority() {
    let proof = synthesize_valid_proof("cap_pin_none", "2026-05-06T12:00:00Z");
    let (code, stdout) = run_with_pin(&proof, "customer-hsm-example-org-v1");

    assert_eq!(code, Some(1), "stdout: {stdout}");
    assert!(
        stdout.contains("reason: verifier_policy_demands_customer_hsm_audit_proof_has_none"),
        "wire reason unchanged, got: {stdout}"
    );
    assert!(
        stdout.contains("names no authority_id, so the Nanorix default authority"),
        "expected the has-none hint, got: {stdout}"
    );
    assert!(
        !stdout.contains("was signed under"),
        "the hint prints before any signature check: {stdout}"
    );
}

/// cdp_version 2.0 is refused at the version gate; a pin cannot reopen it.
#[test]
fn cli_v2_0_proof_under_a_pin_is_refused_at_the_version_gate() {
    let mut proof = synthesize_valid_proof("cap_pin_v2_0", "2026-05-06T12:00:00Z");
    proof["cdp_version"] = serde_json::json!("2.0");
    for pin in ["us-kms-nanorix-v1", "customer-hsm-example-org-v1"] {
        let (code, stdout) = run_with_pin(&proof, pin);
        assert_eq!(code, Some(1), "pin {pin}, stdout: {stdout}");
        assert!(
            stdout.contains("cdp_version_unsupported (found: 2.0)")
                && !stdout.contains("authority_id_mismatch"),
            "pin {pin}: expected the version refusal, got: {stdout}"
        );
    }
}

/// A pin with no key list checks nothing, so it is refused with exit 2 before
/// any proof is read, in single-file and batch mode alike.
#[test]
fn cli_identity_fingerprint_without_trust_chain_exits_two() {
    let file = write_proof(&synthesize_signed_proof(
        "cap_pin_alone",
        "2026-05-06T12:00:00Z",
    ));
    let tmp = tempfile::tempdir().expect("tempdir");
    write_valid_proof_into(tmp.path(), "p1.json", "cap_pin_alone_batch");
    for args in [
        vec![
            "--identity-fingerprint",
            "sha256:00",
            file.path().to_str().unwrap(),
        ],
        vec![
            "--identity-fingerprint",
            "sha256:00",
            "batch",
            tmp.path().to_str().unwrap(),
        ],
    ] {
        let output = Command::new(BIN_PATH)
            .args(&args)
            .output()
            .expect("spawn nanorix-verify");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            output.stdout.is_empty(),
            "{args:?}: no verdict may be printed"
        );
        assert!(stderr.contains("needs --trust-chain"), "{args:?}: {stderr}");
    }
}

/// boundary verify exits 0 on the key an attestation carries, which a proof
/// would exit 4 for, so its output and a stderr note say the key is not
/// anchored.
#[test]
fn cli_boundary_verify_exit_zero_says_the_key_is_not_anchored() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/boundary/0001_single_signed.json"
    );
    let output = Command::new(BIN_PATH)
        .args(["boundary", "verify", fixture])
        .output()
        .expect("spawn nanorix-verify boundary verify");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("key NOT anchored"), "{stdout}");
    assert!(
        stderr.contains("note: exiting 0") && stderr.contains("no key list anchored it"),
        "{stderr}"
    );
}

/// Under a hybrid pin `boundary verify` exits 2 before reading any document,
/// even with a key list that loads under that pin: a boundary attestation has
/// no ML-DSA half, so none is anchored under one. The pin is given with
/// surrounding whitespace, which the gate trims.
#[test]
fn cli_boundary_verify_under_a_hybrid_pin_exits_2() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/boundary/0001_single_signed.json"
    );
    let vectors = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/trust_chain_hybrid");
    let cases: serde_json::Value = serde_json::from_slice(
        &std::fs::read(format!("{vectors}/cases.json")).expect("read hybrid cases"),
    )
    .expect("hybrid cases parse");
    let case = cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "hybrid_list_verifies_under_hybrid_pin")
        .expect("the loading case is in the vectors");
    let key_list = format!("{vectors}/{}", case["key_list"].as_str().unwrap());
    let pin = case["pin"].as_str().unwrap();
    for given in [pin.to_string(), format!(" {pin}\n")] {
        let output = Command::new(BIN_PATH)
            .args(["--trust-chain", &key_list, "--identity-fingerprint", &given])
            .args(["boundary", "verify", fixture])
            .output()
            .expect("spawn nanorix-verify boundary verify");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stdout}\n{stderr}");
        assert!(
            stderr.contains("boundary verify cannot anchor under a hybrid1-sha256: pin"),
            "{stderr}"
        );
        assert!(stdout.is_empty(), "nothing is reported verified: {stdout}");
    }
}

/// The README prints the identity fingerprint the site serves, so a reader
/// can compare what the host hands out with a value from another channel.
#[test]
fn readme_prints_the_identity_fingerprint_the_site_serves() {
    let static_root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../static/.well-known");
    let pin = std::fs::read_to_string(format!("{static_root}/identity.txt"))
        .expect("read published identity pin")
        .trim()
        .to_string();
    let readme = include_str!("../README.md");
    assert!(
        readme.contains(&pin),
        "README.md does not print the served identity fingerprint {pin}"
    );
}
