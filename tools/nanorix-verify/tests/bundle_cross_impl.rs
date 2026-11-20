//! Shared Portable Receipt Bundle fixture corpus, Rust reader.
//!
//! `fixtures/bundles/` holds deterministic bundles (written by
//! `generate_bundle_fixtures.py` from a fixed test-only key) and one
//! `<name>.expected.json` per bundle naming the outcome kind. The Go, Python
//! and TypeScript suites read the same files and must reach the same outcome
//! kind for every bundle.
//!
//! Outcome vocabulary:
//! - `valid`: signature authentic and receipt bound.
//! - `receipt_not_bound`: signature authentic, receipt not bound by the
//!   bundle alone; the strict entry point returns `ReceiptNotBound`.
//! - any other value: the `BundleError::kind()` both entry points must return.

use std::path::PathBuf;

use nanorix_verify::{
    verify_receipt_bundle, verify_receipt_bundle_detailed, BundleError, PortableReceiptBundle,
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("bundles")
}

fn bundle_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(fixture_dir())
        .expect("fixtures/bundles directory exists")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".prb.json"))
        })
        .collect();
    paths.sort();
    paths
}

fn expected_for(bundle_path: &std::path::Path) -> serde_json::Value {
    let name = bundle_path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_suffix(".prb.json"))
        .expect("fixture file name");
    let expected_path = fixture_dir().join(format!("{name}.expected.json"));
    let raw = std::fs::read(&expected_path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", expected_path.display()));
    serde_json::from_slice(&raw).expect("expected.json is valid JSON")
}

fn kind_of(result: &Result<impl std::fmt::Debug, BundleError>) -> String {
    match result {
        Ok(v) => format!("ok:{v:?}"),
        Err(e) => e.kind().to_string(),
    }
}

#[test]
fn fixture_corpus_is_present() {
    assert!(
        bundle_paths().len() >= 20,
        "expected the shared bundle fixture corpus in {}",
        fixture_dir().display()
    );
}

#[test]
fn fixture_corpus_matches_expected_outcomes() {
    for path in bundle_paths() {
        let label = path.display().to_string();
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {label}: {e}"));
        let bundle: PortableReceiptBundle =
            serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("parse {label}: {e}"));
        let expected = expected_for(&path);
        let outcome = expected["outcome"].as_str().expect("expected.outcome");

        let detailed = verify_receipt_bundle_detailed(&bundle);
        let strict = verify_receipt_bundle(&bundle);

        match outcome {
            "valid" | "receipt_not_bound" => {
                let result = detailed.unwrap_or_else(|e| panic!("{label}: detailed verify: {e}"));
                assert_eq!(
                    result.signature_authentic,
                    expected["signature_authentic"].as_bool().unwrap(),
                    "{label}: signature_authentic"
                );
                assert_eq!(
                    result.receipt_bound,
                    expected["receipt_bound"].as_bool().unwrap(),
                    "{label}: receipt_bound"
                );
                let declared_target = bundle
                    .audit_proof_anchors
                    .signature_target
                    .as_deref()
                    .unwrap_or("step8_chain_hash");
                assert_eq!(
                    result.signature_target, declared_target,
                    "{label}: signature_target"
                );
                if outcome == "valid" {
                    strict.unwrap_or_else(|e| panic!("{label}: strict verify: {e}"));
                } else {
                    assert!(
                        matches!(strict, Err(BundleError::ReceiptNotBound)),
                        "{label}: strict verify must return receipt_not_bound, got {}",
                        kind_of(&strict)
                    );
                }
            }
            kind => {
                assert_eq!(kind_of(&detailed), kind, "{label}: detailed verify");
                assert_eq!(kind_of(&strict), kind, "{label}: strict verify");
            }
        }
    }
}

/// The struct round trip must neither add nor drop a field: optional anchors
/// absent from a fixture stay absent when it is serialized again.
#[test]
fn fixture_corpus_round_trips_without_gaining_fields() {
    for path in bundle_paths() {
        let label = path.display().to_string();
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {label}: {e}"));
        let original: serde_json::Value =
            serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("json {label}: {e}"));
        let bundle: PortableReceiptBundle =
            serde_json::from_value(original.clone()).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(
            serde_json::to_value(&bundle).expect("serialize"),
            original,
            "{label}: bundle JSON changed on round trip"
        );
    }
}
