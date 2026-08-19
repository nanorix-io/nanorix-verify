//! Cross-implementation fixture-corpus sweep.
//!
//! The corpus at `fixtures/corpus/` is the public byte-equivalence artifact:
//! it is what a skeptic runs first, and what the Go / Python / TypeScript
//! verifiers are held to. Until this file existed, **no test read it at all** —
//! which is how the corpus came to ship in a state where every success fixture
//! failed to verify (the generator signed the v1.0 message, `final_hash`, into
//! documents stamped `cdp_version: "2.1"`, whose signed message is the ADR-011
//! Part-3 canonical-view hash). The chain integrity checks all passed, so
//! nothing else noticed.
//!
//! Three guarantees are asserted here, and all three are load-bearing:
//!
//! 1. **Every fixture verifies to its committed verdict** — `valid`,
//!    `stage_reached`, and the full `failure_reason` wire object, under the
//!    policy the fixture itself declares.
//! 2. **The corpus is exactly what the generator produces** — regenerated into
//!    a tempdir and compared byte-for-byte. Without this, a hand-edited fixture
//!    (or a hand-edited `.expected.json` "fixing" a failure) silently becomes
//!    the new truth, which is the failure mode that produced the original bug.
//! 3. **The corpus is structurally whole** — no fixture without an expected
//!    file, no expected file without a fixture, and the count agrees with
//!    `index.json`.

use nanorix_verify::{verify_auditproof, VerifierPolicy};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("corpus")
}

/// Every `*.json` in the corpus that is a fixture (not an expected-verdict
/// sibling, not the index manifest), sorted for deterministic ordering.
fn collect_fixtures(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read corpus dir {}: {e}", dir.display()))
            .map(|e| e.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else {
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                if name.ends_with(".json")
                    && !name.ends_with(".expected.json")
                    && name != "index.json"
                {
                    out.push(path);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

fn expected_path_for(fixture: &Path) -> PathBuf {
    let stem = fixture.file_stem().unwrap().to_string_lossy().to_string();
    fixture.with_file_name(format!("{stem}.expected.json"))
}

fn read_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Build the policy a fixture declares it needs. A `region_mismatch` /
/// `authority_id_mismatch` verdict is only reachable under the matching pin, so
/// the pin travels with the fixture rather than living in this harness where
/// the other language implementations cannot see it.
fn policy_from_expected(expected: &Value) -> VerifierPolicy {
    let pin = |key: &str| {
        expected
            .pointer(&format!("/policy/{key}"))
            .and_then(|v| v.as_str())
            .map(String::from)
    };
    VerifierPolicy {
        required_region: pin("required_region"),
        required_authority_id: pin("required_authority_id"),
        ..Default::default()
    }
}

#[test]
fn every_corpus_fixture_verifies_to_its_committed_verdict() {
    let root = corpus_root();
    let fixtures = collect_fixtures(&root);
    assert!(
        !fixtures.is_empty(),
        "corpus at {} is empty — the sweep would vacuously pass",
        root.display()
    );

    let mut failures: Vec<String> = Vec::new();

    for fixture in &fixtures {
        let rel = fixture.strip_prefix(&root).unwrap().display().to_string();
        let expected_path = expected_path_for(fixture);
        assert!(
            expected_path.exists(),
            "fixture {rel} has no .expected.json sibling"
        );

        let proof = read_json(fixture);
        let expected = read_json(&expected_path);
        let policy = policy_from_expected(&expected);

        let result = verify_auditproof(&proof, &[], &policy);

        let actual_reason = result
            .failure_reason
            .as_ref()
            .map(|r| serde_json::to_value(r).expect("serialize failure reason"))
            .unwrap_or(Value::Null);
        let expected_reason = expected
            .get("failure_reason")
            .cloned()
            .unwrap_or(Value::Null);

        if result.valid != expected["valid"].as_bool().expect("expected.valid") {
            failures.push(format!(
                "{rel}: valid — expected {}, got {}",
                expected["valid"], result.valid
            ));
        }
        if u64::from(result.stage_reached) != expected["stage_reached"].as_u64().expect("stage") {
            failures.push(format!(
                "{rel}: stage_reached — expected {}, got {}",
                expected["stage_reached"], result.stage_reached
            ));
        }
        if actual_reason != expected_reason {
            failures.push(format!(
                "{rel}: failure_reason — expected {expected_reason}, got {actual_reason}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} corpus fixtures disagree with their committed verdict:\n  {}",
        failures.len(),
        fixtures.len(),
        failures.join("\n  ")
    );
}

/// The committed corpus must be byte-identical to a fresh generator run.
///
/// This is the guard that makes the sweep above meaningful: without it, the
/// cheapest way to make a failing fixture "pass" is to edit its
/// `.expected.json`, which converts a real defect into a committed expectation.
#[test]
fn committed_corpus_is_byte_identical_to_a_fresh_generator_run() {
    let root = corpus_root();
    let tmp = tempfile::tempdir().expect("create tempdir");

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_nanorix-verify-fixtures-gen"))
        .arg(tmp.path())
        .status()
        .expect("run fixture generator");
    assert!(status.success(), "fixture generator exited {status}");

    // Only JSON is generator-owned. Hand-written companions such as README.md
    // live in the corpus directory but are not the generator's output.
    let committed = collect_generated_files(&root);
    let regenerated = collect_generated_files(tmp.path());

    let committed_names: Vec<_> = committed
        .iter()
        .map(|p| p.strip_prefix(&root).unwrap().to_path_buf())
        .collect();
    let regenerated_names: Vec<_> = regenerated
        .iter()
        .map(|p| p.strip_prefix(tmp.path()).unwrap().to_path_buf())
        .collect();

    assert_eq!(
        committed_names, regenerated_names,
        "corpus file list drifted from the generator — regenerate with \
         `cargo run --bin nanorix-verify-fixtures-gen` and commit the result"
    );

    let mut drifted = Vec::new();
    for name in &committed_names {
        let a = std::fs::read(root.join(name)).expect("read committed");
        let b = std::fs::read(tmp.path().join(name)).expect("read regenerated");
        if a != b {
            drifted.push(name.display().to_string());
        }
    }
    assert!(
        drifted.is_empty(),
        "{} corpus file(s) differ from a fresh generator run (hand-edited?):\n  {}\n\
         Fix the generator, then regenerate — never hand-edit a fixture or an \
         .expected.json.",
        drifted.len(),
        drifted.join("\n  ")
    );
}

fn collect_generated_files(root: &Path) -> Vec<PathBuf> {
    collect_all_files(root)
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect()
}

fn collect_all_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

#[test]
fn corpus_index_manifest_agrees_with_what_is_on_disk() {
    let root = corpus_root();
    let index = read_json(&root.join("index.json"));
    let fixtures = collect_fixtures(&root);

    assert_eq!(
        index["total_fixtures"].as_u64().expect("total_fixtures"),
        fixtures.len() as u64,
        "index.json total_fixtures disagrees with the fixtures on disk"
    );

    for category in index["categories"].as_array().expect("categories") {
        let path = category["path"].as_str().expect("category path");
        let claimed = category["fixture_count"].as_u64().expect("fixture_count");
        let dir = root.join(path);
        assert!(dir.is_dir(), "index.json names a missing category: {path}");
        let found = collect_fixtures(&dir).len() as u64;
        assert_eq!(
            claimed, found,
            "index.json claims {claimed} fixtures in {path}, found {found}"
        );
    }
}

/// No orphaned `.expected.json` — an expected file whose fixture was renamed or
/// deleted would otherwise sit in the corpus asserting nothing.
#[test]
fn every_expected_file_has_a_fixture() {
    let root = corpus_root();
    let mut orphans = Vec::new();
    for path in collect_all_files(&root) {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if let Some(stem) = name.strip_suffix(".expected.json") {
            let fixture = path.with_file_name(format!("{stem}.json"));
            if !fixture.exists() {
                orphans.push(path.strip_prefix(&root).unwrap().display().to_string());
            }
        }
    }
    assert!(
        orphans.is_empty(),
        "orphaned expected-verdict files (no matching fixture):\n  {}",
        orphans.join("\n  ")
    );
}

/// The success fixtures are the corpus's headline claim — a genuinely signed
/// AuditProof verifies. Asserted separately from the sweep so that a
/// regression here names itself instead of hiding in an aggregate count.
#[test]
fn success_categories_verify_under_default_policy() {
    let root = corpus_root();
    for category in ["01_single_capsule_success", "02_multi_step_pipeline"] {
        let dir = root.join(category);
        let fixtures = collect_fixtures(&dir);
        assert_eq!(fixtures.len(), 10, "{category} should hold 10 fixtures");
        for fixture in fixtures {
            let proof = read_json(&fixture);
            let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());
            assert!(
                result.valid,
                "{}/{} must verify but failed: {:?}",
                category,
                fixture.file_name().unwrap().to_string_lossy(),
                result.failure_reason
            );
            assert_eq!(
                result.stage_reached,
                7,
                "{}/{} should reach integrity stage 7 without a trust-chain manifest",
                category,
                fixture.file_name().unwrap().to_string_lossy()
            );
        }
    }
}
