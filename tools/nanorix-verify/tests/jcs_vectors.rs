//! Shared canonical JSON vectors, read with the same `serde_jcs::to_vec` call the verifier makes.
//!
//! `tests/fixtures/jcs_vectors.json` is generated from the Rust canonicalizer and
//! also loaded by the Go test in `tools/auditproof-verifier-go`. This crate
//! canonicalizes with `serde_jcs::to_vec` on a `serde_json::Value`
//! (`src/canonical_recompute.rs`), so that is the call checked here, with SHA-512.
//!
//! A missing or empty fixture fails the test; it never skips.

use nanorix_verify::{recompute_activity_commitment, NANORIX_GENESIS_HASH};
use serde_json::Value;
use sha2::{Digest, Sha512};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/jcs_vectors.json"
);

#[test]
fn every_shared_vector_canonicalizes_to_its_bytes_and_hash() {
    let text = std::fs::read_to_string(FIXTURE)
        .unwrap_or_else(|e| panic!("shared vector fixture {FIXTURE} is required: {e}"));
    let vectors: Vec<Value> = serde_json::from_str(&text).expect("fixture parses");
    assert!(!vectors.is_empty(), "fixture holds no vectors");
    for v in &vectors {
        let name = v["name"].as_str().expect("name");
        let bytes = serde_jcs::to_vec(&v["input"]).expect("canonicalize");
        assert_eq!(
            std::str::from_utf8(&bytes).expect("utf8"),
            v["canonical_bytes_utf8"].as_str().expect("bytes"),
            "canonical bytes of {name}"
        );
        let hash: String = Sha512::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hash,
            v["sha512_hex"].as_str().expect("hash"),
            "sha512 of {name}"
        );
        // The verifier's activity commitment over one event is
        // SHA-512(genesis || 0x00 || hex(SHA-512(JCS(event)))) (boundary.rs).
        let mut data = NANORIX_GENESIS_HASH.as_bytes().to_vec();
        data.push(0x00);
        data.extend_from_slice(v["sha512_hex"].as_str().expect("hash").as_bytes());
        let expected: String = Sha512::digest(&data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            recompute_activity_commitment(std::slice::from_ref(&v["input"])),
            expected,
            "activity commitment of {name}"
        );
    }
}
