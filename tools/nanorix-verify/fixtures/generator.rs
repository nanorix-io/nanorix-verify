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
//!   (10 each, 11 for region mismatch, 15 for authority unknown and 15 for
//!   version unsupported = 71 fixtures)
//! - Tamper patterns — byte-flip, re-order, version downgrade, signature
//!   substitution (5 each = 20 fixtures)
//! - CDP 2.2 — `policy_denial_summary` in the trail and the customer-declared activity specification
//!   `customer_declared_activity_root`, positive and tampered (7 fixtures)
//! - JSON parse boundary — documents at the edge of what serde_json, the
//!   parser in front of the reference verifier, accepts: nesting depth,
//!   invalid UTF-8, half a surrogate pair, a BOM, `NaN`, a number past the
//!   64-bit float range, a repeated key whose earlier copy holds half a
//!   surrogate pair, deep nesting, a number past the float range or `NaN`,
//!   a repeated key whose last copy is the one that counts, the two sides of the float boundary, brackets inside a string,
//!   and a top-level array or `null` (28 fixtures). These are
//!   written as raw bytes, since most of them are not JSON serde_json can
//!   produce.
//! - The reject-diagnostic setting — a signed 2.2 proof whose activity trail
//!   records diagnostic mode, and a signed 1.0 proof, whose activity is
//!   unsigned; both are refused under the setting (2 fixtures)
//! - `signing_mode: "customer_only"` (section 4) — the
//!   amendment's five shared vectors plus a legacy `nanorix_only` proof under
//!   a customer-classified authority (6 fixtures)
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
//!   "status":        "verified" | "not_anchored" | "not_verified",
//!   "failure_reason": null | { "type": "<snake_case_variant>", ... },
//!   "stage_reached":  1..=8,
//!   "policy":         { "required_region": "...",
//!                       "required_authority_id": "...",
//!                       "reject_diagnostic": true },        // optional
//!   "note":           "..."                                  // optional
//! }
//! ```
//!
//! `policy` is what makes a fixture self-describing: the `05_*`, `06_*` and
//! `12_*` verdicts are only reachable when the verifier is configured with that
//! pin or setting, so it travels with the fixture instead of living in a
//! harness the other implementations cannot see. Absent `policy` means
//! `VerifierPolicy::default()`.
//!
//! ## The signed message (why every v2.1 fixture must carry canonical fields)
//!
//! A v2.1 `nanorix_only` AuditProof is NOT signed over `final_hash` — that is
//! the v1.0 message. It is signed over the canonical-view hash:
//! `hex(sha512(serde_jcs(canonical_view)))`, built by
//! `canonical_view` in `the AuditProof document builder()` and mirrored
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
use nanorix_verify::customer_activity::compute_customer_declared_activity_root;
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
    /// chain + final_hash only). Signing is a separate step — see
    /// `sign_v1_in_place`, because the 1.0 signed message is `final_hash`,
    /// not the canonical view.
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
            // real path. Production emits region the same way (the specification G1).
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

    /// Sign a built document over its canonical hash and attach
    /// the attestation block. Must run AFTER every canonical-bound field is
    /// set; tamper fixtures mutate only after this returns.
    fn sign_in_place(&self, proof: &mut Value) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let canonical_hash = recompute_canonical_hash(proof);
        // Ed25519 over the canonical hash's ASCII hex characters (128 bytes),
        // not its 64 raw digest bytes — Forever-Standard.
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
            // Mirrors the chain specification: the timestamp's ':' separators
            // are replaced with '-', and the suffix is the capsule_id's FIRST 8
            // characters.
            "key_id": format!(
                "nrx-verify-{}-{}",
                destroyed_at.replace(':', "-"),
                &capsule_id[..8.min(capsule_id.len())]
            ),
        });
    }

    /// Sign a 1.0 document over its prefix-stripped `final_hash` — the 1.0
    /// signed message — and attach the attestation block. Everything outside
    /// the chain is unsigned on this version, which is what the
    /// version-gate fixture demonstrates.
    fn sign_v1_in_place(&self, proof: &mut Value) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let final_hash = proof["final_hash"].as_str().unwrap_or_default();
        let message = final_hash.strip_prefix("sha512:").unwrap_or(final_hash);
        let signature_b64 = B64.encode(self.signing_key.sign(message.as_bytes()).to_bytes());

        let capsule_id = proof["capsule_id"].as_str().unwrap_or_default().to_string();
        let destroyed_at = proof["destroyed_at"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        proof["attestation"] = json!({
            "algorithm": "Ed25519",
            "public_key": format!("base64:{}", self.public_key_b64),
            "signature": format!("base64:{}", signature_b64),
            "key_id": format!(
                "nrx-verify-{}-{}",
                destroyed_at.replace(':', "-"),
                &capsule_id[..8.min(capsule_id.len())]
            ),
        });
    }

    /// A deterministic `sha512:`-prefixed value standing in for a declared
    /// `document_hash` on a 2.0-labelled document. It is derived from a label,
    /// not from the document's content.
    fn declared_document_hash(&self, label: &str) -> String {
        format!("sha512:{}", hex::encode(Sha512::digest(label.as_bytes())))
    }

    /// Sign a 2.0-labelled document over its own declared `document_hash`
    /// (prefix stripped) with the corpus key and attach the attestation
    /// block. The signature is genuine over that string; the version gate
    /// refuses the document regardless.
    fn sign_declared_hash_in_place(&self, proof: &mut Value) {
        let declared = proof["document_hash"].as_str().unwrap_or_default();
        let message = declared
            .strip_prefix("sha512:")
            .unwrap_or(declared)
            .to_string();
        self.attach_attestation_over(proof, &message);
    }

    /// Sign a 2.0-labelled document over its declared `document_hash` string
    /// exactly as written, prefix included: the message the hosted 2.0 check
    /// reads.
    fn sign_declared_hash_as_written_in_place(&self, proof: &mut Value) {
        let message = proof["document_hash"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        self.attach_attestation_over(proof, &message);
    }

    fn attach_attestation_over(&self, proof: &mut Value, message: &str) {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};

        let signature_b64 = B64.encode(self.signing_key.sign(message.as_bytes()).to_bytes());

        let capsule_id = proof["capsule_id"].as_str().unwrap_or_default().to_string();
        let destroyed_at = proof["destroyed_at"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        proof["attestation"] = json!({
            "algorithm": "Ed25519",
            "public_key": format!("base64:{}", self.public_key_b64),
            "signature": format!("base64:{}", signature_b64),
            "key_id": format!(
                "nrx-verify-{}-{}",
                destroyed_at.replace(':', "-"),
                &capsule_id[..8.min(capsule_id.len())]
            ),
        });
    }

    /// A 2.0-labelled document with a full 8-step chain, a declared
    /// `document_hash`, and a valid corpus-key signature over that declared
    /// value.
    fn build_v2_0_declared_hash_signed(&self, capsule_idx: usize) -> Value {
        let mut proof = self.build_v2_1_unsigned(capsule_idx, "us-central1");
        proof["cdp_version"] = Value::String("2.0".into());
        proof["document_hash"] =
            Value::String(self.declared_document_hash(&format!("v2.0-full-{capsule_idx}")));
        self.sign_declared_hash_in_place(&mut proof);
        proof
    }

    /// A 2.0 stripped projection: no `chain`, no `activity`, a declared
    /// `document_hash`, and a corpus-key signature over that declared string
    /// as written. It carries every summary field the hosted 2.0 check
    /// requires, a complete `destruction.chain` string and a well-formed
    /// `destruction.chain_hash`, so the hosted route returns valid under its
    /// declared_hash_only scope while every offline verifier refuses it at
    /// the version gate.
    fn build_v2_0_stripped_projection(&self, capsule_idx: usize) -> Value {
        let mut proof = json!({
            "cdp_version": "2.0",
            "capsule_id": self.capsule_id(capsule_idx),
            "signing_key_version": "1",
            "destroyed_at": FIXTURE_TIMESTAMP,
            "environment": { "sealed": true, "encryption": "aes-256-gcm", "network": "isolated" },
            "data_ingested": {
                "file_count": 1,
                "total_bytes": 1024,
                "content_hash": self.declared_document_hash(&format!("v2.0-ingested-{capsule_idx}")),
            },
            "data_extracted": {
                "file_count": 1,
                "total_bytes": 512,
                "content_hash": self.declared_document_hash(&format!("v2.0-extracted-{capsule_idx}")),
            },
            "residency": {
                "started": FIXTURE_TIMESTAMP,
                "destroyed": FIXTURE_TIMESTAMP,
                "total_seconds": 0,
            },
            "destruction": {
                "trigger": "user_explicit",
                "chain": "8/8 steps",
                "chain_hash": self.declared_document_hash(&format!("v2.0-terminus-{capsule_idx}")),
            },
            "document_hash": self.declared_document_hash(&format!("v2.0-projection-{capsule_idx}")),
        });
        self.sign_declared_hash_as_written_in_place(&mut proof);
        proof
    }

    /// A 2.0-labelled document with a full chain and a declared
    /// `document_hash` but no `attestation` block.
    fn build_v2_0_without_attestation(&self, capsule_idx: usize) -> Value {
        let mut proof = self.build_v2_1_unsigned(capsule_idx, "us-central1");
        proof["cdp_version"] = Value::String("2.0".into());
        proof["document_hash"] =
            Value::String(self.declared_document_hash(&format!("v2.0-unattested-{capsule_idx}")));
        proof
    }

    /// A genuinely signed 2.1 document re-labelled 2.0, whose declared
    /// `document_hash` carries the canonical-view hash the 2.1 signature
    /// covers. The attestation is the 2.1 attestation, unchanged.
    fn build_v2_1_relabelled_v2_0(&self, capsule_idx: usize) -> Value {
        let mut proof = self.build_v2_1_signed(capsule_idx, "us-central1");
        let covered = recompute_canonical_hash(&proof);
        proof["cdp_version"] = Value::String("2.0".into());
        proof["document_hash"] = Value::String(format!("sha512:{covered}"));
        proof
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

    /// Build an UNSIGNED v2.2 AuditProof. CDP 2.2 is the
    /// 2.1 shape with a different version string; what it adds rides in the
    /// activity trail (`policy_denial_summary`) and in the optional
    /// `customer_declared_activity_root`, both of which the caller sets
    /// before `sign_in_place`.
    fn build_v2_2_unsigned(&self, capsule_idx: usize, region: &str) -> Value {
        let mut proof = self.build_v2_1_unsigned(capsule_idx, region);
        proof["cdp_version"] = Value::String("2.2".into());
        proof
    }

    /// Build a signed v2.2 AuditProof whose trail ends with an deny-side evidence specification
    /// `policy_denial_summary` event carrying `by_reason`. An empty
    /// `by_reason` is "no enumerated check ran"; a `count: 0` row is the
    /// honest zero — the check ran and refused nothing.
    fn build_v2_2_with_denial_summary(&self, capsule_idx: usize, by_reason: Value) -> Value {
        let mut proof = self.build_v2_2_unsigned(capsule_idx, "us-central1");
        proof["activity"]
            .as_array_mut()
            .expect("activity array")
            .push(json!({
                "event": "policy_denial_summary",
                "by_reason": by_reason,
                "at": FIXTURE_TIMESTAMP,
            }));
        self.sign_in_place(&mut proof);
        proof
    }

    /// Build a signed v2.2 AuditProof declaring `customer_declared_activity_root`.
    /// The root is canonical-bound, so it is set BEFORE signing. The corpus
    /// carries the root only — the customer's record is not a fixture — so
    /// the verdict discloses it as declared, not checked.
    fn build_v2_2_with_activity_root(&self, capsule_idx: usize, root: &str) -> Value {
        self.build_v2_2_with_activity_root_value(capsule_idx, Value::String(root.to_string()))
    }

    /// The same, with an arbitrary JSON value in the root's place. Signed over
    /// the value as written, so the signature would verify — which is why a
    /// shape no signer emits has to be rejected before the signature stage.
    fn build_v2_2_with_activity_root_value(&self, capsule_idx: usize, root: Value) -> Value {
        let mut proof = self.build_v2_2_unsigned(capsule_idx, "us-central1");
        proof["customer_declared_activity_root"] = root;
        self.sign_in_place(&mut proof);
        proof
    }

    /// Build a signed v2.2 AuditProof for a whole Capsulefile run under an
    /// egress allowlist, with the activity trail a production run emits
    /// (the AuditProof document builder `ActivityEvent`). It is the only
    /// fixture whose `capsule_started` carries `capsulefile_content_hash`, so it
    /// is the one that shows the declared environment bound into the signature.
    /// Every content hash is the SHA-512 of the example bytes named beside it,
    /// not a placeholder. The authority is an example customer authority: the
    /// fixture key is the corpus test key, which signs for no real authority.
    fn build_v2_2_reference_run(&self, capsule_idx: usize) -> Value {
        let sha512 = |bytes: &[u8]| format!("sha512:{}", hex::encode(Sha512::digest(bytes)));
        let capsulefile = b"name: claims-deidentify\nruntime: python3.12\n\
entrypoint: python deidentify.py\negress:\n  allow:\n    - api.example-health.org\n";
        let input = b"patient_id,dob,diagnosis\nsynthetic-0001,1970-01-01,J45\n";
        let output = b"record_id,age_band,diagnosis\nr-0001,50-59,J45\n";

        let mut proof = self.build_v2_2_unsigned(capsule_idx, "us-east-1");
        proof["authority_id"] = json!("customer-kms-example-health-v1");
        proof["org_id"] = json!("00000000-0000-0000-0000-0000000000a1");
        proof["activity"] = json!([
            {
                "event": "capsule_started",
                "runtime": "python3.12",
                "entrypoint": "python deidentify.py",
                "encryption": "aes-256-gcm",
                "network": "egress_filtered",
                "capsulefile_id": "cf_ExampleHlth1",
                "capsulefile_version": 3,
                "capsulefile_content_hash": sha512(capsulefile),
                "egress_profile_id": "ep_ExHlth01",
                "egress_profile_name": "example-health-api-only",
                "egress_declaration": ["api.example-health.org"],
                "region": "us-east-1",
                "metadata_hash": null,
                "at": "2026-05-07T23:58:10Z",
            },
            {
                "event": "file_uploaded",
                "filename": "claims.csv",
                "size_bytes": input.len(),
                "content_hash": sha512(input),
                "at": "2026-05-07T23:58:12Z",
            },
            {
                "event": "execution_started",
                "command": null,
                "command_hash": sha512(b"python deidentify.py"),
                "at": "2026-05-07T23:58:13Z",
            },
            {
                "event": "execution_completed",
                "exit_code": 0,
                "duration_seconds": 41,
                "at": "2026-05-07T23:58:54Z",
            },
            {
                "event": "egress_summary",
                "policy": "allowlist",
                "dns_queries": 5,
                "domains_resolved": ["api.example-health.org"],
                "blocked_queries": 2,
                "network_interface": true,
                "egress_profile_id": "ep_ExHlth01",
                "egress_profile_name": "example-health-api-only",
                "at": "2026-05-07T23:58:54Z",
            },
            {
                "event": "policy_denial_summary",
                "by_reason": [{ "reason": "egress_profile_denied", "count": 2 }],
                "at": "2026-05-07T23:58:54Z",
            },
            {
                "event": "file_downloaded",
                "filename": "claims-deidentified.csv",
                "size_bytes": output.len(),
                "content_hash": sha512(output),
                "at": "2026-05-07T23:59:02Z",
            },
            {
                "event": "destruction_initiated",
                "trigger": "user_explicit",
                "at": "2026-05-07T23:59:59Z",
            },
        ]);
        self.sign_in_place(&mut proof);
        proof
    }

    /// Build a signed v2.2 AuditProof whose trail holds a streamed response
    /// the relay stopped on a size budget: `streaming_egress_started`, the two
    /// chunks read before the break, one `streaming_policy_violation` naming
    /// the third chunk, and no `streaming_egress_completed`. The events are in
    /// the shape the signed activity serializes them in
    /// (the reference server implementation `push_streaming_egress_events`,
    /// whose test `the_corpus_fixture_is_what_the_producer_emits` reads this
    /// fixture). Every hash is the SHA-512 of the example bytes beside it.
    fn build_v2_2_streaming_policy_violation(&self, capsule_idx: usize) -> Value {
        let sha512 = |bytes: &[u8]| format!("sha512:{}", hex::encode(Sha512::digest(bytes)));
        let at = "2026-05-07T23:59:30Z";
        let mut proof = self.build_v2_2_unsigned(capsule_idx, "us-central1");
        proof["activity"][0]["network"] = json!("egress_filtered");
        proof["activity"]
            .as_array_mut()
            .expect("activity array")
            .extend([
                json!({
                    "event": "streaming_egress_started",
                    "destination": "api.example.com",
                    "protocol": "sse",
                    "request_hash": sha512(b"POST /v1/stream HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
                    "at": at,
                }),
                json!({
                    "event": "streaming_egress_chunk",
                    "seq": 0,
                    "chunk_hash": sha512(b"data: {\"delta\":\"Hel\"}\n\n"),
                    "at": at,
                    "chunk_size_bytes": null,
                }),
                json!({
                    "event": "streaming_egress_chunk",
                    "seq": 1,
                    "chunk_hash": sha512(b"data: {\"delta\":\"lo\"}\n\n"),
                    "at": at,
                    "chunk_size_bytes": null,
                }),
                json!({
                    "event": "streaming_policy_violation",
                    "seq": 2,
                    "violation_kind": "unauthorized_size",
                    "at": at,
                    "violation_detail": null,
                }),
            ]);
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
/// Stage 7 is the highest stage reached without a trust-chain manifest, and it
/// is not_anchored: sub-A proves integrity against the embedded key, not who
/// signed. Stage 8, verified, needs `--trust-chain`, which
/// the corpus deliberately does not pin (the manifest is an operator artifact,
/// not a fixture).
fn expected_success() -> Value {
    json!({
        "valid": true,
        "status": "not_anchored",
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
        "status": "not_verified",
        "failure_reason": failure,
        "stage_reached": stage_reached,
    })
}

/// The status every verifier derives from `valid` and `stage_reached`:
/// verified only at stage 8, not_anchored at stage 7, not_verified otherwise.
fn status_for(valid: bool, stage_reached: u64) -> &'static str {
    if valid && stage_reached >= 8 {
        "verified"
    } else if valid && stage_reached == 7 {
        "not_anchored"
    } else {
        "not_verified"
    }
}

/// Attach the verifier policy a fixture's verdict depends on. Without this the
/// `05_*`, `06_*` and `12_*` verdicts are unreachable and the fixture silently "passes"
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

/// The verdict pinned for a document serde_json refuses to parse. The reference
/// CLI refuses it before verification (exit 1, no verdict document); the Go,
/// Python and TypeScript verifiers report it as this stage 1 verdict, the form
/// they already gave any document they could not parse.
fn expected_unparseable(why: &str) -> Value {
    with_note(
        expected_failure("required_field_missing", json!({ "field": "json_root" }), 1),
        &format!(
            "{why} serde_json, the parser in front of nanorix-verify, refuses the \
             document, so the CLI exits 1 with no verdict; the other verifiers report \
             this verdict."
        ),
    )
}

// ── Category writers ─────────────────────────────────────────────────

/// Refuse a verdict whose `status` does not follow from its `valid` and
/// `stage_reached`, so no fixture is written with a status nobody derived.
fn assert_status_follows(name: &str, expected: &Value) {
    let valid = expected["valid"].as_bool().expect("expected.valid");
    let stage = expected["stage_reached"]
        .as_u64()
        .expect("expected.stage_reached");
    assert_eq!(
        expected["status"].as_str(),
        Some(status_for(valid, stage)),
        "{name}: expected.status must follow from valid and stage_reached"
    );
}

fn write_fixture(out_dir: &Path, name: &str, proof: &Value, expected: &Value) {
    assert_status_follows(name, expected);
    fs::create_dir_all(out_dir).expect("create category dir");
    let proof_path = out_dir.join(format!("{}.json", name));
    let expected_path = out_dir.join(format!("{}.expected.json", name));

    let proof_bytes = serde_json::to_vec_pretty(proof).expect("serialize proof");
    let expected_bytes = serde_json::to_vec_pretty(expected).expect("serialize expected");

    fs::write(&proof_path, &proof_bytes).expect("write proof file");
    fs::write(&expected_path, &expected_bytes).expect("write expected file");
}

/// Like `write_fixture`, for a document given as bytes because serde_json
/// would refuse it or could not write it.
fn write_raw_fixture(out_dir: &Path, name: &str, proof_bytes: &[u8], expected: &Value) {
    assert_status_follows(name, expected);
    fs::create_dir_all(out_dir).expect("create category dir");
    let expected_bytes = serde_json::to_vec_pretty(expected).expect("serialize expected");
    fs::write(out_dir.join(format!("{}.json", name)), proof_bytes).expect("write proof file");
    fs::write(
        out_dir.join(format!("{}.expected.json", name)),
        &expected_bytes,
    )
    .expect("write expected file");
}

/// A signed proof's bytes with `"<key>": <value>` added as its first member.
/// No verifier reads `future_field` and the signature does not cover it, so
/// the proof still verifies and any other verdict comes from the added text.
fn with_first_member(proof: &Value, key: &[u8], value: &[u8]) -> Vec<u8> {
    let pretty = serde_json::to_vec_pretty(proof).expect("serialize proof");
    prepend_member(&pretty, key, value)
}

/// `document`, a JSON object's bytes, with `"<key>": <value>` put before its
/// first member. Applied twice with one key it repeats the key.
fn prepend_member(document: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
    assert_eq!(document.first(), Some(&b'{'), "a proof is a JSON object");
    let mut out = b"{\n  \"".to_vec();
    out.extend_from_slice(key);
    out.extend_from_slice(b"\": ");
    out.extend_from_slice(value);
    out.push(b',');
    out.extend_from_slice(&document[1..]);
    out
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

/// Category 3c — region mismatch failures (12 fixtures). Ten signed 2.1
/// proofs each declare a region and expect rejection against a different
/// policy region. The eleventh is a signed 1.0 proof with a `capsule_started`
/// region equal to the pin added after signing: 1.0 signs only `final_hash`,
/// so that region is unsigned, and the pin reads no region on 1.0 and refuses.
/// The twelfth is a 2.2 proof without a signature whose region equals the pin:
/// no signature covers that region either, so the pin refuses it the same way.
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

    let mut v1 = builder.build_v1_minimal(410);
    builder.sign_v1_in_place(&mut v1);
    v1["activity"] = json!([{
        "event": "capsule_started",
        "encryption": "aes-256-gcm",
        "network": "sealed",
        "region": "europe-west1",
    }]);
    let expected = with_policy(
        with_note(
            expected_failure(
                "region_mismatch",
                json!({ "required": "europe-west1", "actual": "" }),
                2,
            ),
            "cdp_version 1.0 signs only final_hash, so a region in its activity is \
             unsigned: the residency pin reads no region on 1.0 and refuses the proof, \
             even with a capsule_started region equal to the pin added after signing. \
             Without the pin it verifies.",
        ),
        json!({ "required_region": "europe-west1" }),
    );
    write_fixture(&dir, "0010_v1_0_unsigned_region", &v1, &expected);
    count += 1;

    let unsigned = builder.build_v2_2_unsigned(411, "europe-west1");
    let expected = with_policy(
        with_note(
            expected_failure(
                "region_mismatch",
                json!({ "required": "europe-west1", "actual": "" }),
                2,
            ),
            "A cdp_version 2.2 proof without a signature: no signature covers its \
             activity, so the residency pin reads no region and refuses the proof, \
             even though its capsule_started region equals the pin. Without the pin \
             it is valid at stage 4 and not verified.",
        ),
        json!({ "required_region": "europe-west1" }),
    );
    write_fixture(&dir, "0011_v2_2_unsigned_region", &unsigned, &expected);
    count += 1;

    count
}

/// Category 3d — authority pin fixtures (15 fixtures). Ten proofs carry an
/// unsigned `signing_authority` naming an unregistered authority; three more
/// pin the signed top-level `authority_id`; two sign a 1.0 proof,
/// whose top-level `authority_id` no signature covers.
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

    // The pin binds the signed top-level `authority_id`, never the
    // unsigned `signing_authority` object.
    let customer_pin = "customer-hsm-example-org-v1";

    // The attack: a genuine proof under the Nanorix authority plus an
    // unsigned `signing_authority` naming the pin. Refused, never accepted.
    let mut attack = builder.build_v2_1_signed(510, "us-central1");
    attack["signing_authority"] = json!({ "authority_id": customer_pin });
    let expected = with_policy(
        with_note(
            expected_failure(
                "authority_id_mismatch",
                json!({
                    "claimed_authority_id": customer_pin,
                    "expected_authority_id": customer_pin,
                    "reason": "verifier_policy_authority_id_mismatch",
                }),
                2,
            ),
            "An unsigned signing_authority that disagrees with the signed \
             top-level authority_id is refused even when it equals the pin.",
        ),
        json!({ "required_authority_id": customer_pin }),
    );
    write_fixture(
        &dir,
        "0010_unsigned_signing_authority_attack",
        &attack,
        &expected,
    );
    count += 1;

    // A genuine proof under the Nanorix authority against a different pin:
    // mismatch on the signed top-level value.
    let genuine = builder.build_v2_1_signed(511, "us-central1");
    let expected = with_policy(
        expected_failure(
            "authority_id_mismatch",
            json!({
                "claimed_authority_id": "us-kms-nanorix-v1",
                "expected_authority_id": customer_pin,
                "reason": "verifier_policy_authority_id_mismatch",
            }),
            2,
        ),
        json!({ "required_authority_id": customer_pin }),
    );
    write_fixture(&dir, "0011_genuine_proof_other_pin", &genuine, &expected);
    count += 1;

    // The same genuine proof against a pin equal to its signed authority: the
    // gate passes and the proof verifies.
    let genuine = builder.build_v2_1_signed(512, "us-central1");
    let expected = with_policy(
        expected_success(),
        json!({ "required_authority_id": "us-kms-nanorix-v1" }),
    );
    write_fixture(&dir, "0012_genuine_proof_matching_pin", &genuine, &expected);
    count += 1;

    // cdp_version 1.0 signs `final_hash`: nothing signed covers a top-level
    // `authority_id` there, and no issuer writes one. Adding it to a genuine
    // proof must not satisfy a pin; leaving it off must still meet a pin on
    // the Nanorix default. No 2.0-labelled copy is pinned here: the version
    // gate refuses 2.0 with or without a pin, and a fixture carrying a
    // `policy` must verify without it (the hosted parity sweep in
    // the reference server implementation relies on that). Each implementation's pin tests check the
    // 2.0 refusal instead.
    let unsigned_note = "cdp_version 1.0 signs no authority_id, so a top-level \
                         authority_id added after signing is refused at stage 2 and a \
                         pin accepts only us-kms-nanorix-v1.";
    let build = |idx: usize| {
        let mut p = builder.build_v1_minimal(idx);
        builder.sign_v1_in_place(&mut p);
        p
    };

    let mut relabelled = build(513);
    relabelled["authority_id"] = json!(customer_pin);
    let expected = with_policy(
        with_note(
            expected_failure(
                "authority_id_mismatch",
                json!({
                    "claimed_authority_id": customer_pin,
                    "expected_authority_id": customer_pin,
                    "reason": "verifier_policy_authority_id_mismatch",
                }),
                2,
            ),
            unsigned_note,
        ),
        json!({ "required_authority_id": customer_pin }),
    );
    write_fixture(
        &dir,
        "0013_v1_0_signed_relabelled_authority",
        &relabelled,
        &expected,
    );
    count += 1;

    let genuine = build(514);
    let expected = with_policy(
        expected_success(),
        json!({ "required_authority_id": "us-kms-nanorix-v1" }),
    );
    write_fixture(
        &dir,
        "0014_v1_0_signed_default_authority_pin",
        &genuine,
        &expected,
    );
    count += 1;

    count
}

/// Category 3e — cdp_version unsupported failures (15 fixtures). Ten declare a
/// future or invalid version; five are 2.0-labelled documents of different
/// shapes, which the version gate refuses because 2.0 is retired.
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

    // cdp_version 2.0 is retired: refused at the version gate, before any
    // other stage, whatever else the document carries. Each vector below is
    // a different shape of 2.0-labelled document; all five expect the same
    // verdict.
    let activity_root = activity_root_three_vector();
    let refused_v2_0: Vec<(&str, Value)> = vec![
        // Full chain, declared document_hash, valid signature over that
        // declared value under the corpus key.
        (
            "declared_hash_signed",
            builder.build_v2_0_declared_hash_signed(610),
        ),
        // No chain and no activity: only a declared document_hash and a
        // signature over it.
        (
            "stripped_projection",
            builder.build_v2_0_stripped_projection(611),
        ),
        // Full chain and declared document_hash, no attestation block.
        (
            "no_attestation",
            builder.build_v2_0_without_attestation(612),
        ),
        // A genuine 2.1 document re-labelled 2.0, its declared document_hash
        // set to the canonical-view hash the 2.1 signature covers.
        (
            "relabelled_from_2_1",
            builder.build_v2_1_relabelled_v2_0(613),
        ),
        // The class-1 document carrying a customer_declared_activity_root.
        ("with_activity_root", {
            let mut proof = builder.build_v2_0_declared_hash_signed(614);
            proof["customer_declared_activity_root"] = Value::String(activity_root);
            proof
        }),
    ];
    for (j, (descriptor, proof)) in refused_v2_0.iter().enumerate() {
        let expected = expected_failure("cdp_version_unsupported", json!({ "found": "2.0" }), 2);
        write_fixture(
            &dir,
            &format!("{:04}_v2_0_{}", bad_versions.len() + j, descriptor),
            proof,
            &expected,
        );
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
                    "status": "not_verified",
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
            // Algorithm dispatch precedes byte-shape checks — a
            // document declaring a non-Ed25519 algorithm fails typed at stage
            // 4 (this build cannot evaluate what the document declares), not
            // as a presumed-Ed25519 mismatch at stage 7. Same path is the
            // graceful degradation an old verifier applies to a genuine
            // future-algorithm proof.
            with_note(
                expected_failure("algorithm_unsupported", json!({ "found": "RSA-PSS" }), 4),
                "Algorithm dispatch precedes byte-shape checks. A \
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
    // 1.0 is a supported version, so the version gate lets it through and the
    // rejection has to come from the signature stage: the 1.0 signed message
    // is the document's own recomputed final chain hash, which the 2.1
    // signature was never made over. The other four targets (2.0 included,
    // which is retired) are not in the supported set and are rejected at the
    // version gate, five stages earlier.
    let dir = dir_root.join("c_version_downgrade");
    let downgrades = ["2.0", "1.0", "0.9", "1", "two.one"];
    for (i, to) in downgrades.iter().enumerate() {
        let mut proof = builder.build_v2_1_signed(820 + i, "us-central1");
        proof["cdp_version"] = Value::String(to.to_string());
        let expected = if *to == "1.0" {
            with_note(
                expected_failure(
                    "signature_mismatch",
                    json!({ "reason": "does_not_verify" }),
                    7,
                ),
                "Supported version, so the version gate lets it through; the \
                 downgrade is caught at the signature stage because the 1.0 signed \
                 message is the document's own recomputed final chain hash, which \
                 the 2.1 signature was not made over.",
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

/// The cross-implementation vectors, read rather than copied so the corpus
/// cannot drift from what every verifier is held to.
const ACTIVITY_ROOT_VECTORS: &str = include_str!("customer_declared_activity_root_vectors.json");

/// The "three" vector's root — three JSONL lines, pinned across every
/// implementation — computed by the verifier's own function over the
/// vector's input and checked against the root the vectors file records.
/// The generator refuses to run if the two disagree: a corpus written from
/// a root no verifier reproduces would pin the wrong algorithm.
fn activity_root_three_vector() -> String {
    let doc: Value = serde_json::from_str(ACTIVITY_ROOT_VECTORS).expect("vectors file parses");
    let three = doc["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["name"] == "three")
        .expect("vector `three`");
    let input = three["input_utf8"].as_str().expect("input_utf8").as_bytes();
    let computed = compute_customer_declared_activity_root(input);
    let recorded = three["root"].as_str().expect("root");
    assert_eq!(
        computed, recorded,
        "the verifier's activity root and the vectors file disagree on `three`"
    );
    computed
}

/// Category 10 — CDP 2.2 (13 fixtures). The deny-side evidence specification's `policy_denial_summary`
/// trail event and the customer-declared activity specification's `customer_declared_activity_root`, each positive
/// and each tampered after signing; a root on 1.0 or malformed, refused at
/// stage 2; a reference run and its Capsulefile hash tampered after signing;
/// and a stream stopped on a policy break. 2.2 is verified exactly as 2.1, so
/// every tamper after signing here is caught where a 2.1 tamper of the same
/// field would be: the trail and the root are canonical-bound, and the
/// rejection is the signature.
fn generate_v2_2(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("10_v2_2");
    let mut count = 0;

    // A 2.2 label alone, nothing new carried, verifies.
    let plain = {
        let mut p = builder.build_v2_2_unsigned(900, "us-central1");
        builder.sign_in_place(&mut p);
        p
    };
    write_fixture(&dir, "0000_v2_2_plain", &plain, &expected_success());
    count += 1;

    // No enumerated check ran.
    let empty = builder.build_v2_2_with_denial_summary(901, json!([]));
    write_fixture(
        &dir,
        "0001_v2_2_denial_summary_empty",
        &empty,
        &expected_success(),
    );
    count += 1;

    // The check ran and refused nothing — the honest zero.
    let zero = builder.build_v2_2_with_denial_summary(
        902,
        json!([{ "reason": "proxy_request_denied", "count": 0 }]),
    );
    write_fixture(
        &dir,
        "0002_v2_2_denial_summary_zero_row",
        &zero,
        &expected_success(),
    );
    count += 1;

    // Refusals happened.
    let nonzero = builder.build_v2_2_with_denial_summary(
        903,
        json!([
            { "reason": "egress_profile_denied", "count": 2 },
            { "reason": "proxy_request_denied", "count": 3 },
        ]),
    );
    write_fixture(
        &dir,
        "0003_v2_2_denial_summary_nonzero",
        &nonzero,
        &expected_success(),
    );
    count += 1;

    // A count rewritten after signing. The trail is inside the canonical
    // view, so the signature no longer covers the document in front of us.
    let mut flipped_count = builder.build_v2_2_with_denial_summary(
        904,
        json!([{ "reason": "proxy_request_denied", "count": 3 }]),
    );
    flipped_count["activity"][1]["by_reason"][0]["count"] = json!(0);
    write_fixture(
        &dir,
        "0004_v2_2_denial_count_flipped_after_signing",
        &flipped_count,
        &with_note(
            expected_failure(
                "signature_mismatch",
                json!({ "reason": "does_not_verify" }),
                7,
            ),
            "policy_denial_summary.by_reason[0].count was 3 when signed and is 0 \
             here. The activity trail is canonical-bound, so a rewritten count is \
             detected as a signature failure over the recomputed canonical hash.",
        ),
    );
    count += 1;

    // A declared customer activity root. The corpus carries no
    // record, so the verdict discloses the root as declared, not checked.
    let three_root = activity_root_three_vector();
    let with_root = builder.build_v2_2_with_activity_root(905, &three_root);
    write_fixture(
        &dir,
        "0005_v2_2_customer_declared_activity_root",
        &with_root,
        &with_note(
            expected_success(),
            "customer_declared_activity_root is the `three` vector from \
             fixtures/customer_declared_activity_root_vectors.json. The corpus does \
             not carry the customer's record, so the root is declared, not checked; \
             the signature covers it either way.",
        ),
    );
    count += 1;

    // The root byte-flipped after signing. Canonical-bound, so the signature
    // catches it — the record is not needed to detect a tampered root.
    let mut flipped_root = builder.build_v2_2_with_activity_root(906, &three_root);
    let mut chars: Vec<char> = three_root.chars().collect();
    // "sha512:" prefix has length 7; flip the first hex character.
    chars[7] = if chars[7] == '3' { '4' } else { '3' };
    flipped_root["customer_declared_activity_root"] = Value::String(chars.into_iter().collect());
    write_fixture(
        &dir,
        "0006_v2_2_customer_declared_activity_root_flipped_after_signing",
        &flipped_root,
        &with_note(
            expected_failure(
                "signature_mismatch",
                json!({ "reason": "does_not_verify" }),
                7,
            ),
            "customer_declared_activity_root is inside the canonical view, so a root \
             altered after signing is detected as a signature failure without the \
             customer's record. customer_declared_activity_root_mismatch is reserved \
             for a genuine root whose supplied record does not reproduce it.",
        ),
    );
    count += 1;

    // A genuine 1.0 proof carrying a root. The 1.0 signed message is
    // `final_hash`, so the root sits outside the signature and anyone holding
    // the document can write one — and then present any bytes as "the
    // record" it commits to. Rejected before the chain walk, the way the
    // reserved attestation slots are; never "declared, not checked".
    let mut v1_with_root = builder.build_v1_minimal(907);
    v1_with_root["customer_declared_activity_root"] = json!(three_root);
    builder.sign_v1_in_place(&mut v1_with_root);
    write_fixture(
        &dir,
        "0007_v1_0_customer_declared_activity_root_unsigned",
        &v1_with_root,
        &with_note(
            expected_failure(
                "unsigned_field_populated",
                json!({ "field": "customer_declared_activity_root" }),
                2,
            ),
            "The signature on a 1.0 proof covers final_hash only, so a \
             customer_declared_activity_root on it is a value the signature never \
             saw. The root is signed only where the signed message is the canonical \
             view (2.1 and 2.2); on any other version a present non-null root is \
             rejected before the chain walk and is never reported as checked.",
        ),
    );
    count += 1;

    // An empty-string root on 2.2, signed over as written. The canonical view
    // binds "" as a value, so it is malformed, not absent — and it is named
    // as malformed before the signature stage, which would have verified it.
    let empty_root = builder.build_v2_2_with_activity_root_value(908, json!(""));
    write_fixture(
        &dir,
        "0008_v2_2_customer_declared_activity_root_empty_string",
        &empty_root,
        &with_note(
            expected_failure(
                "field_malformed",
                json!({
                    "field": "customer_declared_activity_root",
                    "reason": "empty string",
                }),
                2,
            ),
            "A present non-null root must be a JSON string of sha512: + 128 \
             lowercase hex (bare 128-hex accepted). The empty string is malformed, \
             not absent: every verifier binds it as a value in the canonical view, \
             so one that read it as \"no root\" would contradict its own recompute. \
             The document is signed over the empty string, so the defect is named \
             at stage 2 before the signature stage could have verified it.",
        ),
    );
    count += 1;

    // A numeric root on 2.2, likewise signed over as written.
    let numeric_root = builder.build_v2_2_with_activity_root_value(909, json!(42));
    write_fixture(
        &dir,
        "0009_v2_2_customer_declared_activity_root_numeric",
        &numeric_root,
        &with_note(
            expected_failure(
                "field_malformed",
                json!({
                    "field": "customer_declared_activity_root",
                    "reason": "expected a JSON string",
                }),
                2,
            ),
            "A root that is not a JSON string is a shape no signer emits. Named as \
             malformed at stage 2, before any recompute consumes it, so the verdict \
             blames the field and not the signature or the record.",
        ),
    );
    count += 1;

    // A whole Capsulefile run under an egress allowlist, with the activity
    // trail a production run emits. The landing page renders this one.
    let reference_run = builder.build_v2_2_reference_run(910);
    write_fixture(
        &dir,
        "0010_v2_2_reference_run_declared_environment",
        &reference_run,
        &with_note(
            expected_success(),
            "A run of a declared Capsulefile under an egress allowlist: upload, \
             execution, two denied lookups, download and destruction. The \
             Capsulefile content hash in capsule_started is inside the canonical \
             view, so the declared environment is bound into the signature. The \
             authority is an example customer authority; the key is the corpus \
             test key, so no trust-chain manifest vouches for it.",
        ),
    );
    count += 1;

    // The same run with one hex character of the declared Capsulefile hash
    // changed after signing.
    let mut swapped_capsulefile = reference_run.clone();
    let declared = swapped_capsulefile["activity"][0]["capsulefile_content_hash"]
        .as_str()
        .expect("capsulefile_content_hash")
        .to_string();
    let mut chars: Vec<char> = declared.chars().collect();
    // "sha512:" prefix has length 7; flip the first hex character.
    chars[7] = if chars[7] == '3' { '4' } else { '3' };
    swapped_capsulefile["activity"][0]["capsulefile_content_hash"] =
        Value::String(chars.into_iter().collect());
    write_fixture(
        &dir,
        "0011_v2_2_capsulefile_content_hash_flipped_after_signing",
        &swapped_capsulefile,
        &with_note(
            expected_failure(
                "signature_mismatch",
                json!({ "reason": "does_not_verify" }),
                7,
            ),
            "0010 with one hex character of the declared Capsulefile hash changed \
             after signing. The activity trail is inside the canonical view, so a \
             record that claims a different environment from the one signed fails \
             at the signature.",
        ),
    );
    count += 1;

    // A stream the relay stopped on its size budget.
    let stopped_stream = builder.build_v2_2_streaming_policy_violation(911);
    write_fixture(
        &dir,
        "0012_v2_2_streaming_policy_violation",
        &stopped_stream,
        &with_note(
            expected_success(),
            "A streamed response stopped on the relay's size budget: started, the two \
             chunks read before the break, a streaming_policy_violation naming the \
             third chunk, and no streaming_egress_completed. A streaming Merkle root \
             is recomputed only at a completed event, so the stopped stream's leaves \
             are carried past rather than failed, and the trail is signed like any \
             other.",
        ),
    );
    count += 1;

    count
}

/// Category 11 — the JSON parse boundary (28 fixtures). Each document is a
/// genuine signed v2.1 proof with one member added, in a field no verifier
/// reads, or a document that is not an object. serde_json starts its depth
/// budget at 128 and refuses the container that spends the last of it, so
/// 127 nested containers parse and 128 do not, counting the top-level object.
fn generate_parse_boundary(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("11_json_parse_boundary");
    let genuine = builder.build_v2_1_signed(0, "us-central1");
    let other = |value: &[u8]| with_first_member(&genuine, b"future_field", value);
    let arrays = |n: usize| [vec![b'['; n], vec![b']'; n]].concat();
    // `future_field` twice: `earlier` first, then 2, the copy serde_json keeps.
    let repeated = |earlier: &[u8]| {
        let pretty = serde_json::to_vec_pretty(&genuine).expect("serialize proof");
        prepend_member(
            &prepend_member(&pretty, b"future_field", b"2"),
            b"future_field",
            earlier,
        )
    };
    let big_integer = [b"1".to_vec(), vec![b'0'; 400]].concat();
    let bracket_string = [b"\"\\\"".to_vec(), vec![b'['; 200], b"{\"".to_vec()].concat();

    let mut bom = b"\xEF\xBB\xBF".to_vec();
    bom.extend_from_slice(&serde_json::to_vec_pretty(&genuine).expect("serialize proof"));

    let fixtures: Vec<(&str, Vec<u8>, Value)> = vec![
        (
            "0000_nesting_127_accepted",
            other(&arrays(126)),
            with_note(
                expected_success(),
                "126 nested arrays inside the top-level object: 127 containers deep, \
                 the deepest serde_json parses.",
            ),
        ),
        (
            "0001_nesting_128_refused",
            other(&arrays(127)),
            expected_unparseable(
                "127 nested arrays inside the top-level object: 128 containers deep.",
            ),
        ),
        (
            "0002_invalid_utf8_in_unread_field",
            other(b"\"\xFF\""),
            expected_unparseable("A string holding the byte 0xFF, which is not UTF-8."),
        ),
        (
            "0003_cesu8_surrogate_bytes_in_unread_field",
            other(b"\"\xED\xA0\x80\""),
            expected_unparseable(
                "A string holding the bytes ED A0 80, a surrogate encoded as if it were a \
                 character (CESU-8), which is not UTF-8.",
            ),
        ),
        (
            "0004_utf8_bom_before_document",
            bom,
            expected_unparseable("The proof preceded by a UTF-8 byte order mark."),
        ),
        (
            "0005_lone_high_surrogate_escape_in_unread_field",
            other(b"\"\\ud800\""),
            expected_unparseable(
                "The escape \\ud800, half a surrogate pair, with nothing after it.",
            ),
        ),
        (
            "0006_high_surrogate_escape_then_non_low_escape",
            other(b"\"\\ud800\\u0041\""),
            expected_unparseable(
                "The escape \\ud800 followed by \\u0041, which is not the low half of a pair.",
            ),
        ),
        (
            "0007_lone_low_surrogate_escape_in_key",
            with_first_member(&genuine, b"future_\\udc00", b"1"),
            expected_unparseable(
                "A member name holding the escape \\udc00, a low surrogate alone.",
            ),
        ),
        (
            "0008_surrogate_pair_escape_accepted",
            other(b"\"\\ud83d\\ude00\""),
            with_note(
                expected_success(),
                "A complete surrogate pair escape, one character: the control for 0005-0007.",
            ),
        ),
        (
            "0009_nan_literal_in_unread_field",
            other(b"NaN"),
            expected_unparseable("The bare word NaN, which JSON does not define."),
        ),
        (
            "0010_number_beyond_f64_in_unread_field",
            other(b"1e400"),
            expected_unparseable("The number 1e400, past the largest 64-bit float."),
        ),
        (
            "0011_top_level_array",
            b"[]".to_vec(),
            with_note(
                expected_failure(
                    "required_field_missing",
                    json!({ "field": "cdp_version" }),
                    1,
                ),
                "An empty array parses, so this is not a parse failure: like any document \
                 that is not an object, it has no cdp_version.",
            ),
        ),
        (
            "0012_repeated_key_accepted",
            repeated(b"1"),
            with_note(
                expected_success(),
                "future_field twice, 1 then 2. serde_json keeps the last copy and \
                 does not refuse a repeated key: the control for 0013-0016.",
            ),
        ),
        (
            "0013_repeated_key_earlier_copy_lone_surrogate",
            repeated(b"\"\\ud800\""),
            expected_unparseable(
                "future_field twice; the earlier copy holds the escape \\ud800, half a \
                 surrogate pair. A parser that keeps only the last copy never sees it.",
            ),
        ),
        (
            "0014_repeated_key_earlier_copy_nesting_128",
            repeated(&arrays(127)),
            expected_unparseable(
                "future_field twice; the earlier copy is 127 nested arrays, 128 containers \
                 deep counting the top-level object.",
            ),
        ),
        (
            "0015_repeated_key_earlier_copy_number_beyond_f64",
            repeated(b"1e400"),
            expected_unparseable(
                "future_field twice; the earlier copy is the number 1e400, past the \
                 largest 64-bit float.",
            ),
        ),
        (
            "0016_repeated_key_earlier_copy_nan",
            repeated(b"NaN"),
            expected_unparseable(
                "future_field twice; the earlier copy is the bare word NaN, which JSON \
                 does not define.",
            ),
        ),
        (
            "0017_integer_of_401_digits",
            other(&big_integer),
            expected_unparseable("An integer of 401 digits, past the largest 64-bit float."),
        ),
        (
            "0018_nesting_20000",
            other(&arrays(20000)),
            expected_unparseable(
                "20000 nested arrays, far past the depth a recursive parser can follow.",
            ),
        ),
        (
            "0019_top_level_null",
            b"null".to_vec(),
            with_note(
                expected_failure(
                    "required_field_missing",
                    json!({ "field": "cdp_version" }),
                    1,
                ),
                "null parses, so this is not a parse failure: like any document that is \
                 not an object, it has no cdp_version.",
            ),
        ),
        (
            "0020_brackets_and_escaped_quote_inside_a_string",
            other(&bracket_string),
            with_note(
                expected_success(),
                "A string holding an escaped quote, then 200 [, then {. An escaped quote \
                 does not end the string, and brackets inside a string are text, not \
                 nesting.",
            ),
        ),
        (
            "0021_largest_f64_accepted",
            other(b"1.7976931348623158e308"),
            with_note(
                expected_success(),
                "1.7976931348623158e308, the largest 64-bit float: the in-range side of \
                 the boundary 0022 crosses.",
            ),
        ),
        (
            "0022_just_past_largest_f64_refused",
            other(b"1.7976931348623159e308"),
            expected_unparseable(
                "1.7976931348623159e308, which rounds past the largest 64-bit float.",
            ),
        ),
        (
            "0023_repeated_key_earlier_copy_lone_low_surrogate",
            repeated(b"\"\\udc00\""),
            expected_unparseable(
                "future_field twice; the earlier copy holds the escape \\udc00, a low \
                 surrogate with no high one before it.",
            ),
        ),
        (
            "0024_repeated_key_earlier_copy_high_surrogate_then_text",
            repeated(b"\"\\ud800A\""),
            expected_unparseable(
                "future_field twice; the earlier copy holds the escape \\ud800 followed \
                 by the letter A, not by a low surrogate escape.",
            ),
        ),
        (
            "0025_repeated_key_earlier_copy_high_surrogate_then_other_escape",
            repeated(b"\"\\ud800\\u0041\""),
            expected_unparseable(
                "future_field twice; the earlier copy holds the escape \\ud800 followed \
                 by the escape \\u0041, which is not a low surrogate.",
            ),
        ),
        (
            "0026_repeated_key_earlier_copy_escaped_backslash_then_ud800",
            repeated(b"\"\\\\ud800\""),
            with_note(
                expected_success(),
                "future_field twice; the earlier copy is an escaped backslash followed by \
                 the text ud800, which is no surrogate escape: the control for 0023 to 0025.",
            ),
        ),
        (
            "0027_repeated_cdp_version_last_copy_counts",
            with_first_member(&genuine, b"cdp_version", b"\"9.9\""),
            with_note(
                expected_success(),
                "cdp_version twice, the unsupported \"9.9\" first and the real version \
                 last. serde_json keeps the last copy, so every verifier reads the real one.",
            ),
        ),
    ];

    for (name, bytes, expected) in &fixtures {
        write_raw_fixture(&dir, name, bytes, expected);
    }
    fixtures.len()
}

/// Category 12 — the reject-diagnostic setting (4 fixtures). Under
/// `reject_diagnostic` a proof whose signed activity trail records diagnostic
/// mode is refused at stage 2, and so is every proof whose activity no
/// signature covers: cdp_version 1.0, which signs only `final_hash`, and a 2.1
/// or 2.2 proof without a signature. Neither can show that the event is
/// absent. A signed proof whose event was removed after signing keeps its
/// signature, passes stage 2 and fails at the signature step, stage 7.
fn generate_diagnostic_refused(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("12_failure_diagnostic_refused");
    let policy = json!({ "reject_diagnostic": true });
    let mut count = 0;

    // The event in the wire form the issuing service writes at capsule start
    // for a capsule created with `diagnostic_mode: true`. It is
    // added before signing, so the 2.2 signature covers it.
    let mut diagnostic = builder.build_v2_2_unsigned(1200, "us-central1");
    diagnostic["activity"]
        .as_array_mut()
        .expect("activity array")
        .push(json!({ "event": "diagnostic_mode_enabled", "at": FIXTURE_TIMESTAMP }));
    builder.sign_in_place(&mut diagnostic);
    let expected = with_policy(
        with_note(
            expected_failure("diagnostic_proof_refused", json!({}), 2),
            "The signed activity trail records diagnostic mode, so reject_diagnostic \
             refuses the proof at stage 2. Without the setting it verifies.",
        ),
        policy.clone(),
    );
    write_fixture(
        &dir,
        "0000_v2_2_signed_diagnostic_mode",
        &diagnostic,
        &expected,
    );
    count += 1;

    let mut v1 = builder.build_v1_minimal(1201);
    builder.sign_v1_in_place(&mut v1);
    let expected = with_policy(
        with_note(
            expected_failure("diagnostic_proof_refused", json!({}), 2),
            "cdp_version 1.0 signs only final_hash, so its activity is unsigned and \
             cannot show that the proof was not run in diagnostic mode: \
             reject_diagnostic refuses every 1.0 proof at stage 2. Without the setting \
             it verifies.",
        ),
        policy.clone(),
    );
    write_fixture(&dir, "0001_v1_0_signed", &v1, &expected);
    count += 1;

    let unsigned = builder.build_v2_2_unsigned(1202, "us-central1");
    let expected = with_policy(
        with_note(
            expected_failure("diagnostic_proof_refused", json!({}), 2),
            "A cdp_version 2.2 proof without a signature and without the \
             diagnostic_mode_enabled event: no signature covers its activity, so it \
             cannot show that the event is absent, and reject_diagnostic refuses it at \
             stage 2. Without the setting it is valid at stage 4 and not verified.",
        ),
        policy.clone(),
    );
    write_fixture(
        &dir,
        "0002_v2_2_unsigned_without_event",
        &unsigned,
        &expected,
    );
    count += 1;

    let mut stripped = builder.build_v2_2_unsigned(1203, "us-central1");
    stripped["activity"]
        .as_array_mut()
        .expect("activity array")
        .push(json!({ "event": "diagnostic_mode_enabled", "at": FIXTURE_TIMESTAMP }));
    builder.sign_in_place(&mut stripped);
    stripped["activity"]
        .as_array_mut()
        .expect("activity array")
        .retain(|entry| entry["event"] != "diagnostic_mode_enabled");
    let expected = with_policy(
        with_note(
            expected_failure(
                "signature_mismatch",
                json!({ "reason": "does_not_verify" }),
                7,
            ),
            "Signed with the diagnostic_mode_enabled event, which was then removed. \
             The proof still carries its signature, so reject_diagnostic reads the \
             trail, finds no event and lets the proof on; the signature, made over \
             the trail with the event, then fails at stage 7. Without the setting the \
             verdict is the same.",
        ),
        policy,
    );
    write_fixture(
        &dir,
        "0003_v2_2_event_removed_signature_kept",
        &stripped,
        &expected,
    );
    count += 1;

    count
}

/// The customer authority the `13_customer_only` vectors name. Its
/// `customer-kms-` segment is not at the start of the id, which the issuer's
/// test (a substring match) classifies as customer-classified all the same.
const CUSTOMER_AUTHORITY: &str = "us-customer-kms-acme-v1";

/// Category 13 — `signing_mode: "customer_only"` (6 fixtures): the five shared
/// vectors of the amendment, section 4, in its order, and a legacy
/// proof.
///
/// The fixture key stands in for a customer authority's signing key: the signed message is the
/// same canonical view `nanorix_only` signs, and only the mode string inside
/// it differs. Every verifier recomputes it, refuses the same proof with its
/// mode edited after signing, and refuses `customer_only` under a
/// Nanorix-classified authority even when the signature is valid.
fn generate_customer_only(builder: &FixtureBuilder, root: &Path) -> usize {
    let dir = root.join("13_customer_only");
    let signed_as = |idx: usize, mode: &str, authority: &str| {
        let mut proof = builder.build_v2_1_unsigned(idx, "us-central1");
        proof["signing_mode"] = json!(mode);
        proof["authority_id"] = json!(authority);
        builder.sign_in_place(&mut proof);
        // The install-authority key id; unsigned, and it does not start with
        // `nrx-verify-`, so no verifier reads a timestamp from it.
        proof["attestation"]["key_id"] = json!(format!("{authority}-v1"));
        proof
    };

    let valid = signed_as(1300, "customer_only", CUSTOMER_AUTHORITY);
    write_fixture(
        &dir,
        "0000_v2_1_customer_only_signed",
        &valid,
        &with_note(
            expected_success(),
            "customer_only under us-customer-kms-acme-v1, whose customer-kms- segment is \
             not at the start of the id: customer-classified, so it passes the consistency \
             rule. The signature covers the canonical view, mode included, exactly as for \
             nanorix_only; without a key list it is not_anchored at stage 7.",
        ),
    );

    let nanorix = signed_as(1301, "customer_only", "us-kms-nanorix-v1");
    write_fixture(
        &dir,
        "0001_v2_1_customer_only_nanorix_authority",
        &nanorix,
        &with_note(
            expected_failure(
                "signing_mode_authority_mismatch",
                json!({ "claimed_authority_id": "us-kms-nanorix-v1" }),
                4,
            ),
            "customer_only under a Nanorix-classified authority, validly signed. Both \
             labels are signed, so the pair is refused at stage 4, before the signature \
             check, and no signer is named.",
        ),
    );

    let wrong_case = signed_as(1302, "customer_only", "us-Customer-kms-acme-v1");
    write_fixture(
        &dir,
        "0002_v2_1_customer_only_authority_wrong_case",
        &wrong_case,
        &with_note(
            expected_failure(
                "signing_mode_authority_mismatch",
                json!({ "claimed_authority_id": "us-Customer-kms-acme-v1" }),
                4,
            ),
            "The classification is case-sensitive: Customer-kms- is not customer-kms-, so \
             this id is Nanorix-classified and the pair is refused. Registration refuses \
             this id; the proof is hand-built.",
        ),
    );

    let mut relabelled = valid.clone();
    relabelled["signing_mode"] = json!("nanorix_only");
    write_fixture(
        &dir,
        "0003_v2_1_customer_only_mode_edited_to_nanorix_only",
        &relabelled,
        &with_note(
            expected_failure(
                "signature_mismatch",
                json!({ "reason": "does_not_verify" }),
                7,
            ),
            "0000 with signing_mode edited to nanorix_only after signing. The mode is \
             inside the canonical view, so the edit breaks the signature.",
        ),
    );

    let mut other_algorithm = signed_as(1304, "customer_only", "us-kms-nanorix-v1");
    other_algorithm["attestation"]["algorithm"] = json!("Ed448");
    write_fixture(
        &dir,
        "0004_v2_1_customer_only_nanorix_authority_other_algorithm",
        &other_algorithm,
        &with_note(
            expected_failure("algorithm_unsupported", json!({ "found": "Ed448" }), 4),
            "customer_only under a Nanorix-classified authority that declares an algorithm \
             other than Ed25519. The algorithm check runs before the consistency rule, so \
             the reason is algorithm_unsupported.",
        ),
    );

    let legacy = signed_as(1305, "nanorix_only", CUSTOMER_AUTHORITY);
    write_fixture(
        &dir,
        "0005_v2_1_legacy_nanorix_only_customer_authority",
        &legacy,
        &with_note(
            expected_success(),
            "A legacy proof: nanorix_only under a customer-classified authority, the shape \
             issued before customer_only. It keeps verifying (legacy proofs stay valid); a \
             verifier that prints notes it, and nothing refuses it.",
        ),
    );

    6
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
        ("05_failure_region_mismatch", 12),
        ("06_failure_authority_unknown", 15),
        ("07_failure_version_unsupported", 15),
        ("08_failure_canonical_hash_drift", 10),
        ("09_tamper_patterns/a_byte_flip", 5),
        ("09_tamper_patterns/b_re_order", 5),
        ("09_tamper_patterns/c_version_downgrade", 5),
        ("09_tamper_patterns/d_signature_substitution", 5),
        ("10_v2_2", 13),
        ("11_json_parse_boundary", 28),
        ("12_failure_diagnostic_refused", 4),
        ("13_customer_only", 6),
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
            "valid": "bool — the chain and signature hold under the key used; not a verdict on its own (true at stage 7, where the key is the one the proof carries)",
            "status": "the verdict: verified (valid at stage 8, which needs a trust-chain manifest the corpus does not pin), not_anchored (valid at stage 7) or not_verified",
            "failure_reason": "null on success; otherwise the FailureReason wire object, tag key `type`",
            "stage_reached": "1..=8; 7 is not_anchored, 8 is verified",
            "policy": "optional — VerifierPolicy pins REQUIRED to reach this verdict; absent means defaults",
            "note": "optional — prose for verdicts that are not the obvious guess from the category name",
        },
        "signed_message": "v1.0 signs final_hash; v2.1 and v2.2 nanorix_only and customer_only sign the canonical-view hash (hex(sha512(jcs(view)))) — 2.2 is verified exactly as 2.1; cdp_version 2.0 is retired and refused at the version gate by the offline verifiers",
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
    total += generate_v2_2(&builder, &root);
    total += generate_parse_boundary(&builder, &root);
    total += generate_diagnostic_refused(&builder, &root);
    total += generate_customer_only(&builder, &root);

    write_index(&root, total);

    println!("Generated {} fixtures.", total);
    println!("Index manifest at {:?}", root.join("index.json"));
}
