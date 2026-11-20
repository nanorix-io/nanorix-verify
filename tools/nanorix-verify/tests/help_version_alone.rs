//! `--help` and `--version` exit 0 only when every other argument is a
//! subcommand word. Beside a flag or a file they exit 2 and print nothing on
//! stdout, so `nanorix-verify <pins> --version proof.json` cannot read as a
//! pass to a caller that checks only the exit code.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN_PATH: &str = env!("CARGO_BIN_EXE_nanorix-verify");

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus/01_single_capsule_success/0000_v2_1_signed.json")
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN_PATH)
        .args(args)
        .output()
        .expect("run nanorix-verify")
}

#[test]
fn help_or_version_beside_another_argument_exits_2_with_no_stdout() {
    let proof = fixture();
    let proof = proof.to_str().unwrap();
    let cases: Vec<Vec<&str>> = vec![
        vec![
            "--trust-chain",
            "list.json",
            "--identity-fingerprint",
            "sha256:00",
            "--version",
            proof,
        ],
        vec![proof, "--version"],
        vec!["-V", "--required-region", "europe-west1"],
        vec!["--json", "-h"],
        vec!["verify", proof, "--help"],
        vec!["verify", "-h", proof],
        vec!["bundle", "verify", "-h", "claim.prb.json"],
        vec![
            "pubkey-bundle",
            "verify",
            "--help",
            "--publisher-pubkey",
            "k.bin",
        ],
        vec!["--version", proof],
        vec!["-V", proof],
        vec!["--version", "verify", proof],
        vec!["--json", "--version"],
        vec!["--version", "--json"],
    ];
    for args in cases {
        let out = run(&args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: stderr {err}");
        assert!(
            err.contains("--help and --version are given alone"),
            "{args:?}: stderr {err}"
        );
        assert!(
            out.stdout.is_empty(),
            "{args:?}: stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// A version or help flag glued to a value, or the help subcommand after a
/// proof file, is never read as a request for help alone.
#[test]
fn glued_or_late_help_and_version_exit_2_with_no_stdout() {
    let proof = fixture();
    let proof = proof.to_str().unwrap();
    let glued = format!("-V{proof}");
    let assigned = format!("-V={proof}");
    for args in [
        vec![glued.as_str()],
        vec![assigned.as_str()],
        vec![proof, "help"],
    ] {
        let out = run(&args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: stderr {err}");
        assert!(
            out.stdout.is_empty(),
            "{args:?}: stdout {:?}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn help_or_version_alone_still_exits_0() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["--help"],
        vec!["-h"],
        vec!["--version"],
        vec!["-V"],
        vec!["verify", "--help"],
        vec!["bundle", "extract", "-h"],
        vec!["pubkey-bundle", "verify", "--help"],
        vec!["print-trust-chain", "-h"],
        vec!["help"],
        vec!["help", "bundle", "extract"],
    ];
    for args in cases {
        let out = run(&args);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{args:?}: stderr {err}");
        assert!(
            !out.stdout.is_empty(),
            "{args:?}: no help or version printed"
        );
        assert!(!err.contains("given alone"), "{args:?}: stderr {err}");
    }
}
