//! `nanorix-verify verify --input` and `--api-key` refuse (exit 2) before any
//! file is read, because this build does not compare a file with the input_hash
//! of a signed input_provenance_verified event and cannot re-derive the signer
//! key from an API key. A run without the flags is unchanged.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json")
}

fn run(args: &[&str], env_key: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN_PATH);
    cmd.env_remove("NANORIX_API_KEY").args(args);
    if let Some(k) = env_key {
        cmd.env("NANORIX_API_KEY", k);
    }
    cmd.output().expect("run nanorix-verify")
}

#[test]
fn input_flag_refuses_with_exit_2() {
    let proof = fixture();
    let out = run(
        &["verify", proof.to_str().unwrap(), "--input", "whatever.bin"],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--input is not available in this build"),
        "{err}"
    );
    assert!(!err.contains("--api-key"), "{err}");
    assert!(out.stdout.is_empty(), "no verdict may be printed");
}

#[test]
fn api_key_flag_refuses_with_exit_2() {
    let proof = fixture();
    let out = run(&["verify", proof.to_str().unwrap(), "--api-key", "k"], None);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--api-key is not available in this build"),
        "{err}"
    );
    assert!(!err.contains("--input"), "{err}");
    assert!(err.contains("Re-run without the flag."), "{err}");
    assert!(out.stdout.is_empty(), "no verdict may be printed");
}

#[test]
fn environment_key_alone_is_not_read_and_does_not_refuse() {
    let proof = fixture();
    let with = run(&["verify", proof.to_str().unwrap()], Some("env-key"));
    let without = run(&["verify", proof.to_str().unwrap()], None);
    // Not anchored without a trust chain: exit 4.
    assert_eq!(with.status.code(), Some(4));
    assert_eq!(with.status.code(), without.status.code());
    assert_eq!(with.stdout, without.stdout);
}

#[test]
fn verify_without_flags_is_unchanged() {
    let proof = fixture();
    let verify = run(&["verify", proof.to_str().unwrap()], None);
    let bare = run(&[proof.to_str().unwrap()], None);
    assert_eq!(verify.status.code(), Some(4));
    assert_eq!(verify.status.code(), bare.status.code());
    assert_eq!(verify.stdout, bare.stdout);
    assert!(!verify.stdout.is_empty());
}

fn assert_input_refusal(out: &Output) {
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--input is not available in this build"),
        "{err}"
    );
    assert!(out.stdout.is_empty(), "no verdict may be printed");
}

#[test]
fn refuses_before_the_proof_file_is_read() {
    let out = run(
        &["verify", "/nonexistent/proof.json", "--input", "x.bin"],
        None,
    );
    assert_input_refusal(&out);
}

#[test]
fn refuses_before_a_missing_trust_chain_file_is_read() {
    let proof = fixture();
    let out = run(
        &[
            "--trust-chain",
            "/nonexistent/key-list.json",
            "--identity-fingerprint",
            "sha256:00",
            "verify",
            proof.to_str().unwrap(),
            "--input",
            "x.bin",
        ],
        None,
    );
    assert_input_refusal(&out);
}

#[test]
fn refuses_before_a_missing_activity_record_is_read() {
    let proof = fixture();
    let out = run(
        &[
            "--customer-activity",
            "/nonexistent/activity_events.jsonl",
            "verify",
            proof.to_str().unwrap(),
            "--input",
            "x.bin",
        ],
        None,
    );
    assert_input_refusal(&out);
}

#[test]
fn both_flags_are_named_with_their_own_reasons() {
    let proof = fixture();
    let out = run(
        &[
            "verify",
            proof.to_str().unwrap(),
            "--input",
            "x.bin",
            "--api-key",
            "k",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--input is not available in this build"),
        "{err}"
    );
    assert!(
        err.contains("--api-key is not available in this build"),
        "{err}"
    );
    assert!(err.contains("input_provenance_verified"), "{err}");
    assert!(err.contains("nor its salt"), "{err}");
    assert_eq!(err.lines().count(), 1, "one refusal line: {err}");
    assert!(err.contains("Re-run without the flags."), "{err}");
}

#[test]
fn json_output_mode_still_refuses() {
    let proof = fixture();
    let out = run(
        &[
            "--json",
            "verify",
            proof.to_str().unwrap(),
            "--input",
            "x.bin",
        ],
        None,
    );
    assert_input_refusal(&out);
}

#[test]
fn api_key_refuses_before_a_missing_trust_chain_file_is_read() {
    let proof = fixture();
    let out = run(
        &[
            "--trust-chain",
            "/nonexistent/key-list.json",
            "--identity-fingerprint",
            "sha256:00",
            "verify",
            proof.to_str().unwrap(),
            "--api-key",
            "k",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--api-key is not available in this build"),
        "{err}"
    );
    assert!(!err.contains("--input"), "{err}");
    assert!(out.stdout.is_empty(), "no verdict may be printed");
}

#[test]
fn verify_help_describes_this_build() {
    let out = run(&["verify", "--help"], None);
    assert_eq!(out.status.code(), Some(0));
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("input_provenance_verified"), "{help}");
    assert!(help.contains("nor its salt"), "{help}");
    assert!(!help.contains("does not carry"), "{help}");
}

#[test]
fn proof_path_before_a_subcommand_is_refused_and_nothing_is_verified() {
    let proof = fixture();
    let out = run(
        &["/nonexistent/first.json", "verify", proof.to_str().unwrap()],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("before a subcommand"), "{err}");
    assert!(out.stdout.is_empty(), "nothing may be verified: {err}");
}

/// `bundle verify` checks a bundle against the key the bundle carries and
/// reads no key list, so `--trust-chain` handed to it refuses instead of
/// being silently ignored.
#[test]
fn bundle_verify_refuses_trust_chain_with_exit_2() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let bundle = root.join("bundles/a_legacy_n1_idx0.prb.json");
    let key_list = root.join("trust_chain/key_lists/customer_v1.json");
    let pin = "sha256:3097e2dee2cb4a34b53840cdb705aed71067c36f68db0e0f559c3f3fa043315f";

    let plain = run(&["bundle", "verify", bundle.to_str().unwrap()], None);
    assert_eq!(
        plain.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );

    let out = run(
        &[
            "--trust-chain",
            key_list.to_str().unwrap(),
            "--identity-fingerprint",
            pin,
            "bundle",
            "verify",
            bundle.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("bundle verify does not read --trust-chain"),
        "{err}"
    );
    assert!(out.stdout.is_empty(), "no verdict may be printed: {err}");
}

/// `bundle verify` checks one record's receipt and never reads the
/// AuditProof's activity trail, region, authority or declared activity root,
/// so each proof policy flag handed to it refuses, with exit 2 and before any
/// file is read, instead of being silently ignored, as `population` refuses
/// them.
#[test]
fn bundle_verify_refuses_every_proof_policy_flag_with_exit_2() {
    let bundle =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/bundles/a_legacy_n1_idx0.prb.json");
    let bundle = bundle.to_str().unwrap();
    let control = run(&["bundle", "verify", bundle], None);
    assert_eq!(control.status.code(), Some(0), "the bundle verifies alone");

    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("absent.jsonl");
    let record = record.to_str().unwrap();
    for flag in [
        vec!["--reject-diagnostic"],
        vec!["--required-region", "europe-west1"],
        vec!["--required-authority-id", "customer-kms-example-a-v1"],
        vec!["--customer-activity", record],
    ] {
        let mut args = flag.clone();
        args.extend(["bundle", "verify", bundle]);
        let out = run(&args, None);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flag:?}: {err}");
        assert!(
            err.contains(&format!("bundle verify does not read {}.", flag[0])),
            "{flag:?}: {err}"
        );
        assert!(out.stdout.is_empty(), "{flag:?}: no verdict may be printed");

        // After the subcommand the flag is not one `bundle verify` takes.
        let mut after = vec!["bundle", "verify", bundle];
        after.extend(&flag);
        let out = run(&after, None);
        assert_eq!(out.status.code(), Some(2), "{flag:?} after the subcommand");
        assert!(out.stdout.is_empty(), "{flag:?} after the subcommand");
    }

    let out = run(
        &[
            "--reject-diagnostic",
            "--required-region",
            "europe-west1",
            "bundle",
            "verify",
            bundle,
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("bundle verify does not read --reject-diagnostic, --required-region."),
        "{err}"
    );
}

/// Runs `subcommand` with each proof policy flag before it and after it.
/// Before it, the subcommand refuses the flag by name with exit 2; after it,
/// the flag is not one the subcommand takes, so the parser refuses it with
/// exit 2. Neither prints a verdict.
fn assert_policy_flags_refused(subcommand: &[&str], label: &str) {
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("absent.jsonl");
    let record = record.to_str().unwrap();
    for flag in [
        vec!["--reject-diagnostic"],
        vec!["--required-region", "europe-west1"],
        vec!["--required-authority-id", "customer-kms-example-a-v1"],
        vec!["--customer-activity", record],
    ] {
        let mut before = flag.clone();
        before.extend(subcommand);
        let out = run(&before, None);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flag:?} before: {err}");
        assert!(
            err.contains(&format!("{label} does not read {}.", flag[0])),
            "{flag:?} before: {err}"
        );
        assert!(out.stdout.is_empty(), "{flag:?} before: no verdict");

        let (words, files) = subcommand.split_at(2);
        let mut after = words.to_vec();
        after.extend(&flag);
        after.extend(files);
        let out = run(&after, None);
        assert_eq!(out.status.code(), Some(2), "{flag:?} after the subcommand");
        assert!(out.stdout.is_empty(), "{flag:?} after the subcommand");
    }
}

/// `boundary verify` checks BoundaryAttestations, not an AuditProof, so each
/// proof policy flag handed to it refuses with exit 2 instead of being
/// silently ignored, as `bundle verify` refuses them.
#[test]
fn boundary_verify_refuses_every_proof_policy_flag_with_exit_2() {
    let attestation =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/boundary/0001_single_signed.json");
    let attestation = attestation.to_str().unwrap();
    let control = run(&["boundary", "verify", attestation], None);
    assert_eq!(
        control.status.code(),
        Some(0),
        "the attestation verifies alone"
    );
    assert_policy_flags_refused(&["boundary", "verify", attestation], "boundary verify");
}

/// `pubkey-bundle verify` checks a signed bundle of public keys, not an
/// AuditProof, so each proof policy flag handed to it refuses with exit 2.
#[test]
fn pubkey_bundle_verify_refuses_every_proof_policy_flag_with_exit_2() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let seed = [9u8; 32];
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let listed = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
    let seed_path = dir.path().join("seed.bin");
    std::fs::write(&seed_path, seed).unwrap();
    let pub_path = dir.path().join("publisher.bin");
    std::fs::write(&pub_path, signer.verifying_key().to_bytes()).unwrap();
    let keys_path = dir.path().join("keys.json");
    let keys = serde_json::json!({ "pubkeys": [{
        "key_id": "nrx-verify-test-1",
        "algorithm": "Ed25519",
        "public_key": base64::engine::general_purpose::STANDARD
            .encode(listed.verifying_key().to_bytes()),
        "valid_from": "2026-01-01T00:00:00Z",
        "issued_by_org": "vendor:example",
    }]});
    std::fs::write(&keys_path, keys.to_string()).unwrap();
    let bundle_path = dir.path().join("bundle.ppb.json");
    let (seed_s, pub_s, keys_s, bundle_s) = (
        seed_path.to_str().unwrap(),
        pub_path.to_str().unwrap(),
        keys_path.to_str().unwrap(),
        bundle_path.to_str().unwrap(),
    );
    let built = run(
        &[
            "pubkey-bundle",
            "build",
            "--keys",
            keys_s,
            "--output",
            bundle_s,
            "--signer-seed",
            seed_s,
            "--signer-key-id",
            "nrx-bundle-publisher-test",
            "--issuer-org",
            "vendor:example",
        ],
        None,
    );
    assert_eq!(
        built.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let control = run(
        &[
            "pubkey-bundle",
            "verify",
            bundle_s,
            "--publisher-pubkey",
            pub_s,
        ],
        None,
    );
    assert_eq!(
        control.status.code(),
        Some(0),
        "the bundle verifies alone: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert_policy_flags_refused(
        &[
            "pubkey-bundle",
            "verify",
            bundle_s,
            "--publisher-pubkey",
            pub_s,
        ],
        "pubkey-bundle verify",
    );
}

/// The CLI applies `--reject-diagnostic` to a single AuditProof: a proof whose
/// signed trail records diagnostic mode, and a 1.0 proof, each exit 1 with the
/// refusal; without the flag each is valid against its embedded key (exit 4).
#[test]
fn reject_diagnostic_refuses_on_the_cli() {
    let dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/corpus/12_failure_diagnostic_refused");
    for name in ["0000_v2_2_signed_diagnostic_mode", "0001_v1_0_signed"] {
        let proof = dir.join(format!("{name}.json"));
        let proof = proof.to_str().unwrap();

        let plain = run(&[proof], None);
        assert_eq!(plain.status.code(), Some(4), "{name}");

        let human = run(&["--reject-diagnostic", proof], None);
        assert_eq!(human.status.code(), Some(1), "{name}");
        let text = String::from_utf8_lossy(&human.stdout);
        assert!(
            text.contains("--reject-diagnostic refused it"),
            "{name}: {text}"
        );

        let json = run(&["--reject-diagnostic", "--json", proof], None);
        assert_eq!(json.status.code(), Some(1), "{name}");
        let verdict: serde_json::Value =
            serde_json::from_slice(&json.stdout).expect("JSON verdict");
        assert_eq!(
            verdict["failure_reason"],
            serde_json::json!({ "type": "diagnostic_proof_refused" }),
            "{name}"
        );
        assert_eq!(verdict["stage_reached"], 2, "{name}");
        assert_eq!(verdict["status"], "not_verified", "{name}");
    }
}
