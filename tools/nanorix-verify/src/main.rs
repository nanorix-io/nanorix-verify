//! `nanorix-verify` — standalone CLI for AuditProof verification.
//!
//! The literal moment-of-truth artifact when an OCR / Big-4 / sovereign-country
//! auditor receives a Nanorix AuditProof and needs to confirm authenticity
//! without any Nanorix SaaS dependency.
//!
//! Per Nanorix EO-07 (G3 Adoption-Blocker, dispatched 2026-05-06):
//! ```text
//! $ brew install nanorix-verify
//! $ nanorix-verify auditproof.json
//! ✓ Verified · capsule cap_01HXX... · region us-central1
//!   Authority: us-kms-nanorix-v1 (signing_key_version 7)
//!   Activity events: 12
//!   Signed: 2026-05-06T14:23:11Z
//! ```

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use colored::Colorize;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nanorix_verify::{
    build_pubkey_bundle, extract_receipt_bundle, verify_auditproof, verify_boundary_attestation,
    verify_boundary_chain, verify_disclosed_activity_trail, verify_pubkey_bundle,
    verify_receipt_bundle, AuthorityIdMismatchReason, BoundaryVerificationResult, FailureReason,
    PortablePubkeyBundle, PortableReceiptBundle, PubKeyEntry, VerificationResult, VerifierPolicy,
};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "nanorix-verify",
    version,
    about = "Verify a Nanorix AuditProof — auditor moment-of-truth tool",
    long_about = "Verifies a Nanorix AuditProof JSON document independently of the Nanorix \
                  SaaS. Performs 8-stage verification per ADR-011 I8: schema, version, chain \
                  reproducibility, final-hash binding, canonical-hash binding, signing-key \
                  resolution, Ed25519 signature, authority status."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// AuditProof JSON file to verify (positional shortcut for `verify`).
    proof: Option<PathBuf>,

    /// Output verification result as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Refuse AuditProofs whose attestation indicates `diagnostic_mode: true`
    /// (per Nanorix EO-09 verifier policy).
    #[arg(long)]
    reject_diagnostic: bool,

    /// Required region (e.g., `europe-west1`). When set, AuditProofs whose
    /// region disagrees fail with `RegionMismatch` (per Nanorix EO-03 G1).
    #[arg(long)]
    required_region: Option<String>,

    /// Required signing-authority id (e.g., `customer-hsm-example-org-v1`).
    /// When set, AuditProofs whose `signing_authority.authority_id` is
    /// absent (Nanorix-default signing path) OR differs from this value
    /// fail with `AuthorityIdMismatch` (per ADR-031 G7 / VP Security
    /// extended-review F4.3). Use this when your compliance posture
    /// requires customer-HSM-attested AuditProofs and rejecting
    /// Nanorix-default signing.
    #[arg(long)]
    required_authority_id: Option<String>,

    /// Path to a trust-chain manifest (`trust-chain.json`). When supplied, the
    /// verifier resolves each proof's signing key against this manifest and
    /// verifies the signature against the manifest key — reaching full "verify
    /// without trusting Nanorix" (stage 8). The manifest's OWN signature is
    /// verified against the pinned identity fingerprint first; if that fails,
    /// the verifier aborts before checking any proof. (EO-07 sub-B.)
    #[arg(long)]
    trust_chain: Option<PathBuf>,

    /// SHA-256 fingerprint of the Nanorix long-term identity key
    /// (`sha256:<hex>`), obtained out-of-band from
    /// `nanorix.io/.well-known/identity.txt`, a GitHub release, or the docs.
    /// Pins the trust root for `--trust-chain`. Falls back to the compiled-in
    /// `NANORIX_IDENTITY_FINGERPRINT` when omitted.
    #[arg(long)]
    identity_fingerprint: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify an AuditProof JSON file.
    Verify {
        /// Path to the AuditProof JSON.
        proof: PathBuf,

        /// Optional path to the original input bytes (verifies input_hash if
        /// present in the manifest). Per ADR-008.
        #[arg(long)]
        input: Option<PathBuf>,

        /// Optional API key for HKDF derivation (verifies input-provenance
        /// signer key matches).
        #[arg(long, env = "NANORIX_API_KEY")]
        api_key: Option<String>,
    },

    /// Wave 18-7 / CTI-T7-007 — bulk verification mode.
    ///
    /// Walks `<directory>` recursively, verifies every `*.json` AuditProof,
    /// reports a per-file PASS / FAIL line + aggregate summary. Exit code
    /// is 0 if all proofs verified, 1 if any failed.
    ///
    /// Auditor efficiency artifact: a 7-year retention corpus might contain
    /// thousands of AuditProofs; an auditor running this command against
    /// the directory gets a single-page verdict instead of N individual
    /// CLI invocations.
    Batch {
        /// Directory containing AuditProof JSON files (walked recursively).
        directory: PathBuf,

        /// Glob-like pattern of file extensions to verify. Default `.json`.
        /// Used to skip irrelevant files in a mixed-content directory.
        #[arg(long, default_value = ".json")]
        extension: String,
    },

    /// Print the embedded trust chain (signing authorities + their public
    /// keys + revocation status).
    PrintTrustChain,

    /// Wave B Item 7 — Portable Receipt Bundle (.prb.json) operations.
    ///
    /// Extract a single RecordReceipt + outer AuditProof anchors into a
    /// portable JSON bundle that can be verified independently of the
    /// producing Nanorix account. Or verify an existing bundle.
    Bundle {
        #[command(subcommand)]
        op: BundleOp,
    },

    /// Wave B Item 8 — Portable Pubkey Bundle (.ppb.json) operations.
    ///
    /// Build a bundle of N cross-org Ed25519 verification pubkeys (signed by
    /// the publishing party), or verify an existing bundle, used when an
    /// ADR-041 cross-org chain references a parent AuditProof signed under
    /// a different account OR an offline/air-gap environment where
    /// `/v1/keys/:id` lookup is unavailable.
    PubkeyBundle {
        #[command(subcommand)]
        op: PubkeyBundleOp,
    },

    /// ADR-050 — BoundaryAttestation (retain mode) operations.
    ///
    /// A BoundaryAttestation is a point-in-time signed snapshot of a LIVE
    /// capsule's isolation boundary — the sibling primitive to the
    /// destruction AuditProof. It is NOT a destruction claim; its signed
    /// continuation statement says so explicitly.
    Boundary {
        #[command(subcommand)]
        op: BoundaryOp,
    },
}

#[derive(Subcommand, Debug)]
enum BoundaryOp {
    /// Verify one BoundaryAttestation, or a chain of them.
    ///
    /// With one file: canonical-hash recompute + Ed25519 signature (against
    /// the embedded key, and against the trust-chain manifest when
    /// --trust-chain is supplied). With several files: additionally walks the
    /// per-capsule chain — prev_attestation_hash linkage, strict
    /// attestation_index monotonicity, cutoff_ts ordering, genesis rule at
    /// index 1.
    ///
    /// Exit codes follow the AuditProof ladder: 0 = every supplied document's
    /// signature was checked and verified; 1 = verification failed; 2 = setup
    /// error; 3 = structure verified but at least one signature was NOT
    /// checked (unsigned document) — never acceptable to an automated gate.
    Verify {
        /// One or more BoundaryAttestation JSON files (one capsule's chain).
        #[arg(required = true)]
        attestations: Vec<PathBuf>,

        /// Disclosed activity-trail JSON ({"events": [...]} or a bare
        /// array). Recomputes the ADR-039-shaped commitment chain and
        /// compares activity_commitment + activity_event_count.
        /// Single-attestation mode only.
        #[arg(long)]
        activity_trail: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum BundleOp {
    /// Extract a Portable Receipt Bundle from a full AuditProof JSON file.
    Extract {
        /// Path to the AuditProof JSON.
        proof: PathBuf,
        /// Zero-indexed record position within the AuditProof's record_receipts.
        #[arg(long)]
        record: u32,
        /// Path to write the bundle JSON.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a Portable Receipt Bundle (Mode B standalone verification).
    Verify {
        /// Path to the bundle JSON file.
        bundle: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum PubkeyBundleOp {
    /// Build a signed Portable Pubkey Bundle.
    Build {
        /// Path to JSON file containing a `[pubkeys]` array (see schema).
        #[arg(long)]
        keys: PathBuf,
        /// Path to write the bundle JSON.
        #[arg(long)]
        output: PathBuf,
        /// Path to a raw Ed25519 32-byte signing-key seed (raw bytes, no
        /// header). For demo / testing only — real publishers MUST use an
        /// HSM and never expose the seed to disk.
        #[arg(long)]
        signer_seed: PathBuf,
        /// Authority key identifier of the publisher (nrx-bundle-publisher-*).
        #[arg(long)]
        signer_key_id: String,
        /// Opaque issuer organization tag (e.g., "vendor:example-health").
        #[arg(long)]
        issuer_org: String,
    },
    /// Verify a signed Portable Pubkey Bundle's publisher signature.
    Verify {
        /// Path to the bundle JSON file.
        bundle: PathBuf,
        /// Path to publisher's Ed25519 public key (raw 32-byte file).
        #[arg(long)]
        publisher_pubkey: PathBuf,
    },
}

/// Compiled-in pin for the Nanorix long-term identity key (`sha256:<hex>`) —
/// the EO-07 sub-B trust root. `None` until the HSM identity key is provisioned
/// when the identity key is provisioned; set it to the published fingerprint
/// then (also published at `nanorix.io/.well-known/identity.txt` + GitHub
/// releases for out-of-band cross-confirmation). While `None`, `--trust-chain`
/// requires an explicit `--identity-fingerprint`.
const NANORIX_IDENTITY_FINGERPRINT: Option<&str> = None;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut policy = VerifierPolicy {
        reject_diagnostic: cli.reject_diagnostic,
        required_region: cli.required_region.clone(),
        required_authority_id: cli.required_authority_id.clone(),
        ..Default::default()
    };

    // EO-07 sub-B: if a trust-chain manifest is supplied, verify its OWN
    // signature against the pinned identity fingerprint BEFORE verifying any
    // proof. A bad trust root is a setup error — fail loud, exit 2; never
    // silently downgrade to integrity-only verification.
    if let Some(path) = cli.trust_chain.as_ref() {
        let manifest = nanorix_verify::trust_chain::load_from_file(path)
            .with_context(|| format!("failed to load trust-chain manifest: {}", path.display()))?;
        let pin = cli
            .identity_fingerprint
            .clone()
            .or_else(|| NANORIX_IDENTITY_FINGERPRINT.map(String::from))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no pinned identity fingerprint: pass --identity-fingerprint <sha256:...> \
                     (from nanorix.io/.well-known/identity.txt) — this build has no compiled-in pin"
                )
            })?;
        if let Err(e) = manifest.verify_signature(&pin) {
            eprintln!(
                "✗ trust-chain manifest verification FAILED: {e}\n  The supplied trust root is \
                 not the pinned Nanorix identity — refusing to verify any proof against it."
            );
            std::process::exit(2);
        }
        policy.trust_chain = Some(manifest);
        policy.pinned_identity_fingerprint = Some(pin);
    }

    match cli.command {
        Some(Commands::Verify {
            proof,
            input: _,
            api_key: _,
        }) => verify_path(&proof, &policy, cli.json),
        Some(Commands::Batch {
            directory,
            extension,
        }) => verify_batch(&directory, &extension, &policy, cli.json),
        Some(Commands::PrintTrustChain) => print_trust_chain(),
        Some(Commands::Bundle { op }) => match op {
            BundleOp::Extract {
                proof,
                record,
                output,
            } => bundle_extract(&proof, record, &output, cli.json),
            BundleOp::Verify { bundle } => bundle_verify(&bundle, cli.json),
        },
        Some(Commands::PubkeyBundle { op }) => match op {
            PubkeyBundleOp::Build {
                keys,
                output,
                signer_seed,
                signer_key_id,
                issuer_org,
            } => pubkey_bundle_build(
                &keys,
                &output,
                &signer_seed,
                &signer_key_id,
                &issuer_org,
                cli.json,
            ),
            PubkeyBundleOp::Verify {
                bundle,
                publisher_pubkey,
            } => pubkey_bundle_verify(&bundle, &publisher_pubkey, cli.json),
        },
        Some(Commands::Boundary { op }) => match op {
            BoundaryOp::Verify {
                attestations,
                activity_trail,
            } => boundary_verify(&attestations, activity_trail.as_deref(), &policy, cli.json),
        },
        None => {
            // Positional shortcut: `nanorix-verify auditproof.json`
            if let Some(path) = cli.proof {
                verify_path(&path, &policy, cli.json)
            } else {
                let mut cmd = <Cli as clap::CommandFactory>::command();
                cmd.print_help()?;
                println!();
                std::process::exit(2);
            }
        }
    }
}

/// Wave 18-7 / CTI-T7-007 — bulk verification entry point.
///
/// Walks `directory` recursively, collects every regular file whose path
/// ends in `extension` (default `.json`), and verifies each as an
/// AuditProof. Per-file output: PASS / FAIL with stage_reached + failure
/// reason. Aggregate summary at end: N passed, M failed. Exit code: 0
/// if all pass, 1 if any fail.
///
/// Determinism: file ordering is sorted lexicographically so two
/// invocations against the same corpus produce byte-identical output
/// (auditors diff this).
///
/// Forever-Standard: per-file output line shape is permanent. JSON-mode
/// (`--json`) emits a single top-level object `{summary: {...}, files:
/// [...]}` for machine-readable consumption.
fn verify_batch(
    directory: &Path,
    extension: &str,
    policy: &VerifierPolicy,
    json_output: bool,
) -> Result<()> {
    if !directory.is_dir() {
        anyhow::bail!(
            "batch directory does not exist or is not a directory: {}",
            directory.display()
        );
    }

    let files = collect_proof_files(directory, extension)
        .with_context(|| format!("failed to walk batch directory: {}", directory.display()))?;

    if files.is_empty() {
        if json_output {
            let empty = serde_json::json!({
                "summary": { "passed": 0, "failed": 0, "total": 0 },
                "files": [],
            });
            println!("{}", serde_json::to_string_pretty(&empty)?);
        } else {
            println!(
                "{} No AuditProof files matching '*{}' under {}",
                "!".yellow().bold(),
                extension,
                directory.display()
            );
        }
        // Empty corpus is NOT a failure — exit 0. Auditor distinguishes
        // empty-directory from any-failure by the summary numbers.
        return Ok(());
    }

    let mut json_entries: Vec<serde_json::Value> = Vec::with_capacity(files.len());
    let mut passed = 0usize;
    let mut failed = 0usize;

    for path in &files {
        let result = verify_one_for_batch(path, policy);
        match &result {
            BatchEntry::Passed { .. } => passed += 1,
            BatchEntry::Failed { .. } => failed += 1,
        }

        if json_output {
            json_entries.push(result.to_json());
        } else {
            result.print_human();
        }
    }

    if json_output {
        let envelope = serde_json::json!({
            "summary": {
                "passed": passed,
                "failed": failed,
                "total": passed + failed,
            },
            "files": json_entries,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        println!();
        let total = passed + failed;
        if failed == 0 {
            println!(
                "{} Batch verification: {} / {} passed",
                "✓".green().bold(),
                passed.to_string().bold(),
                total.to_string().bold(),
            );
        } else {
            println!(
                "{} Batch verification: {} passed, {} failed (total {})",
                "✗".red().bold(),
                passed.to_string().bold(),
                failed.to_string().red().bold(),
                total.to_string().bold(),
            );
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Per-file result for batch mode. Compact wrapper around either a
/// `VerificationResult` (when the file parsed) or an upstream filesystem /
/// JSON-parse error (which we treat as a verification failure entry, NOT
/// as an abort, so the batch keeps walking).
enum BatchEntry {
    Passed {
        path: PathBuf,
        capsule_id: Option<String>,
        stage_reached: u8,
    },
    Failed {
        path: PathBuf,
        capsule_id: Option<String>,
        stage_reached: u8,
        reason: String,
    },
}

impl BatchEntry {
    fn to_json(&self) -> serde_json::Value {
        match self {
            BatchEntry::Passed {
                path,
                capsule_id,
                stage_reached,
            } => serde_json::json!({
                "path": path.display().to_string(),
                "status": "pass",
                "capsule_id": capsule_id,
                "stage_reached": stage_reached,
            }),
            BatchEntry::Failed {
                path,
                capsule_id,
                stage_reached,
                reason,
            } => serde_json::json!({
                "path": path.display().to_string(),
                "status": "fail",
                "capsule_id": capsule_id,
                "stage_reached": stage_reached,
                "reason": reason,
            }),
        }
    }

    fn print_human(&self) {
        match self {
            BatchEntry::Passed {
                path,
                capsule_id,
                stage_reached,
            } => {
                let cap = capsule_id.as_deref().unwrap_or("(unknown)");
                println!(
                    "{} {} · capsule {} · stage {}/8",
                    "PASS".green().bold(),
                    path.display(),
                    cap,
                    stage_reached
                );
            }
            BatchEntry::Failed {
                path,
                capsule_id,
                stage_reached,
                reason,
            } => {
                let cap = capsule_id.as_deref().unwrap_or("(unknown)");
                println!(
                    "{} {} · capsule {} · stage {}/8 · {}",
                    "FAIL".red().bold(),
                    path.display(),
                    cap,
                    stage_reached,
                    reason.as_str().red()
                );
            }
        }
    }
}

fn verify_one_for_batch(path: &Path, policy: &VerifierPolicy) -> BatchEntry {
    // Read + parse. A filesystem or JSON-parse failure becomes a per-file
    // FAIL entry (not an aborting error) — auditor wants to see the
    // partial verdict on every file.
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return BatchEntry::Failed {
                path: path.to_path_buf(),
                capsule_id: None,
                stage_reached: 0,
                reason: format!("read_error ({e})"),
            };
        }
    };

    let proof: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return BatchEntry::Failed {
                path: path.to_path_buf(),
                capsule_id: None,
                stage_reached: 0,
                reason: format!("invalid_json ({e})"),
            };
        }
    };

    let result = verify_auditproof(&proof, &[], policy);
    let capsule_id = result.metadata.capsule_id.clone();

    if result.valid {
        BatchEntry::Passed {
            path: path.to_path_buf(),
            capsule_id,
            stage_reached: result.stage_reached,
        }
    } else {
        let reason = result
            .failure_reason
            .as_ref()
            .map(format_reason)
            .unwrap_or_else(|| "unknown_failure".to_string());
        BatchEntry::Failed {
            path: path.to_path_buf(),
            capsule_id,
            stage_reached: result.stage_reached,
            reason,
        }
    }
}

/// Walk `dir` recursively and return every regular file whose path ends
/// in `extension`. Result is sorted lexicographically for deterministic
/// output (audit diff stability).
fn collect_proof_files(dir: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in
            std::fs::read_dir(&d).with_context(|| format!("read_dir failed: {}", d.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let ftype = entry.file_type()?;
            if ftype.is_dir() {
                stack.push(path);
            } else if ftype.is_file()
                && path
                    .to_string_lossy()
                    .to_lowercase()
                    .ends_with(&extension.to_lowercase())
            {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

fn verify_path(path: &PathBuf, policy: &VerifierPolicy, json_output: bool) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read AuditProof file: {}", path.display()))?;

    let proof: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("AuditProof file is not valid JSON: {}", path.display()))?;

    let result = verify_auditproof(&proof, &[], policy);

    if json_output {
        let line = serde_json::to_string_pretty(&result)?;
        println!("{line}");
    } else {
        print_human(&result);
    }

    if !result.valid {
        std::process::exit(1);
    }
    // Exit-code contract. `valid` alone is NOT sufficient for an automated
    // `verify && accept` gate: a proof carrying no signature at all still walks
    // its chain successfully and sets `valid = true` at stage 4. Scripts that
    // treated exit 0 as "trustworthy" would therefore accept an unsigned
    // document. Exit codes are the machine-readable verdict, so they carry the
    // same ladder the human output does:
    //   0 → signature was checked and verified (stage >= 7)
    //   1 → verification failed
    //   2 → setup error (bad trust root, bad usage)
    //   3 → chain verified but the signature was NOT checked (unsigned partial,
    //       or a signing_mode this build cannot verify). Not invalid — but not
    //       something an automated gate may accept.
    if result.stage_reached < 7 {
        eprintln!(
            "note: exiting 3 — the chain verified, but this document carries no \
             signature this build could check, so integrity is not established. \
             Do not treat this as an accepted proof in an automated gate."
        );
        std::process::exit(3);
    }
    Ok(())
}

/// ADR-050 D7 — verify one BoundaryAttestation or a chain of them.
///
/// Exit-code ladder (same contract as `verify_path`, commit b372515):
///   0 → every supplied document's signature was checked and verified
///   1 → verification failed (structure, canonical hash, signature, chain,
///       or disclosed activity trail)
///   2 → setup error (bad usage: --activity-trail with a multi-file chain)
///   3 → structure verified but at least one document carried no signature
///       this build could check — not invalid, but never acceptable to an
///       automated `verify && accept` gate
fn boundary_verify(
    paths: &[PathBuf],
    activity_trail: Option<&Path>,
    policy: &VerifierPolicy,
    json_output: bool,
) -> Result<()> {
    if activity_trail.is_some() && paths.len() > 1 {
        eprintln!(
            "✗ usage: --activity-trail applies to exactly one attestation (the trail is \
             committed per-attestation); verify the chain and the trail separately."
        );
        std::process::exit(2);
    }

    let mut docs: Vec<serde_json::Value> = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read BoundaryAttestation: {}", path.display()))?;
        let doc: serde_json::Value = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "BoundaryAttestation file is not valid JSON: {}",
                path.display()
            )
        })?;
        docs.push(doc);
    }

    // Disclosed-trail events, when supplied: {"events": [...]} or bare array.
    let trail_events: Option<Vec<serde_json::Value>> = match activity_trail {
        None => None,
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read activity trail: {}", path.display()))?;
            let v: serde_json::Value = serde_json::from_slice(&bytes)
                .with_context(|| format!("activity trail not valid JSON: {}", path.display()))?;
            let events = v
                .get("events")
                .cloned()
                .unwrap_or_else(|| v.clone())
                .as_array()
                .cloned();
            match events {
                Some(e) => Some(e),
                None => anyhow::bail!("activity trail must be {{\"events\": [...]}} or [...]"),
            }
        }
    };

    if docs.len() == 1 {
        let result = verify_boundary_attestation(&docs[0], policy);
        let trail_failure = if result.valid {
            trail_events
                .as_deref()
                .and_then(|events| verify_disclosed_activity_trail(&docs[0], events))
        } else {
            None
        };

        if json_output {
            let envelope = serde_json::json!({
                "document": result,
                "activity_trail_checked": trail_events.is_some(),
                "activity_trail_failure": trail_failure,
            });
            println!("{}", serde_json::to_string_pretty(&envelope)?);
        } else {
            print_boundary_human(&result);
            if let Some(f) = &trail_failure {
                println!(
                    "{} Disclosed activity trail INVALID: {}",
                    "✗".red().bold(),
                    format!("{f:?}").red()
                );
            } else if trail_events.is_some() {
                println!("  Disclosed activity trail: commitment + event count recompute VALID");
            }
        }

        if !result.valid || trail_failure.is_some() {
            std::process::exit(1);
        }
        if !result.signature_checked {
            eprintln!(
                "note: exiting 3 — the canonical form verified, but this document carries \
                 no signature this build could check, so integrity is not established. \
                 Do not treat this as an accepted attestation in an automated gate."
            );
            std::process::exit(3);
        }
        return Ok(());
    }

    // Chain mode.
    let result = verify_boundary_chain(&docs, policy);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.valid {
        let (lo, hi) = result.chain_span.unwrap_or((0, 0));
        let capsule = result
            .per_document
            .first()
            .and_then(|d| d.metadata.capsule_id.clone())
            .unwrap_or_else(|| "(unknown)".into());
        println!(
            "{} Boundary attestation chain VALID · capsule {} · indices {}..={} ({} attestations)",
            "✓".green().bold(),
            capsule.bold(),
            lo,
            hi,
            result.per_document.len()
        );
        if result.genesis_anchored {
            println!("  Chain origin: index 1 · genesis prev_attestation_hash checked");
        } else {
            println!(
                "  {}",
                "Chain suffix only: the earliest supplied attestation is not index 1, so \
                 its prev link points at a document not supplied here. Internal \
                 consistency of the supplied span is verified; the origin is not."
                    .dimmed()
            );
        }
        for d in &result.per_document {
            print_boundary_human(d);
        }
    } else {
        println!("{} Boundary attestation chain INVALID", "✗".red().bold());
        if let Some(reason) = &result.failure_reason {
            println!("  Failure: {}", format!("{reason:?}").red());
        }
        if let Some(idx) = result.failed_at_index {
            println!("  At attestation_index: {idx}");
        }
    }

    if !result.valid {
        std::process::exit(1);
    }
    if !result.all_signatures_checked {
        eprintln!(
            "note: exiting 3 — the chain verified, but at least one attestation carries \
             no signature this build could check, so integrity is not established for \
             the whole span. Do not treat this as accepted in an automated gate."
        );
        std::process::exit(3);
    }
    Ok(())
}

/// One verdict line per BoundaryAttestation. Kind is named FIRST (ADR-050:
/// verifier output names the document kind before anything else, so a mid-run
/// snapshot can never read as terminal destruction evidence).
fn print_boundary_human(r: &BoundaryVerificationResult) {
    let cap = r.metadata.capsule_id.as_deref().unwrap_or("(unknown)");
    let idx = r
        .metadata
        .attestation_index
        .map(|i| i.to_string())
        .unwrap_or_else(|| "?".into());
    let cutoff = r.metadata.cutoff_ts.as_deref().unwrap_or("(unset)");
    if r.valid {
        if r.trust_anchored {
            println!(
                "{} BoundaryAttestation VALID · capsule {} · index {} · cutoff {}",
                "✓".green().bold(),
                cap.bold(),
                idx,
                cutoff
            );
            println!("  Signature verified against the trust-chain manifest key (not a destruction claim)");
        } else if r.signature_checked {
            println!(
                "{} BoundaryAttestation signature valid · key NOT anchored to Nanorix trust root · capsule {} · index {} · cutoff {}",
                "⚠".yellow().bold(),
                cap.bold(),
                idx,
                cutoff
            );
            println!(
                "  {}",
                "Integrity verified (not tampered since signing) against the key embedded \
                 in the document. Authenticity pending: supply --trust-chain to resolve \
                 the signing key against the Nanorix manifest. Not a destruction claim."
                    .dimmed()
            );
        } else {
            println!(
                "{} BoundaryAttestation canonical form verified · signature NOT checked · capsule {} · index {} · cutoff {}",
                "⚠".yellow().bold(),
                cap.bold(),
                idx,
                cutoff
            );
        }
    } else {
        println!(
            "{} BoundaryAttestation INVALID · capsule {} · index {}",
            "✗".red().bold(),
            cap,
            idx
        );
        if let Some(reason) = &r.failure_reason {
            println!("  Failure: {}", format!("{reason:?}").red());
            println!("  Stage reached: {} / 3", r.stage_reached);
        }
    }
}

fn print_human(r: &VerificationResult) {
    if r.valid {
        let cap = r.metadata.capsule_id.as_deref().unwrap_or("(unknown)");
        let region = r.metadata.region.as_deref().unwrap_or("(unset)");
        // Honest verdict ladder — the green "Verified" is reserved for FULL
        // trust-anchored verification and nothing weaker:
        //   stage 8  → signature verified AND the signing key resolved against
        //              the Nanorix trust-chain manifest (EO-07 sub-B). Only this
        //              is "verify without trusting Nanorix".
        //   stage 7  → signature is cryptographically valid, but against the key
        //              EMBEDDED in the proof — proves integrity (not tampered
        //              since signing), NOT authenticity. A forged proof carries
        //              its own key + signature and also reaches stage 7, so this
        //              must NOT be shown as an unqualified "Verified".
        //   stage <7 → signature was not checked at all (unsigned partial, or a
        //              signing_mode this build cannot verify).
        if r.stage_reached >= 8 {
            println!(
                "{} Verified · capsule {} · region {}",
                "✓".green().bold(),
                cap.bold(),
                region
            );
        } else if r.stage_reached >= 7 {
            println!(
                "{} Signature valid · key NOT anchored to Nanorix trust root · capsule {} · region {}",
                "⚠".yellow().bold(),
                cap.bold(),
                region
            );
            println!(
                "  {}",
                "Integrity verified (proof not tampered since signing). Authenticity \
                 pending: the signing key was read from the proof itself, not yet \
                 resolved against the Nanorix trust-chain manifest (EO-07 sub-B)."
                    .dimmed()
            );
            // Tell them how to finish, here, where they are reading.
            //
            // This warning is what a first-time auditor sees, because bare
            // `nanorix-verify proof.json` is the obvious thing to type. It is
            // accurate and it reads exactly like a broken trust chain. The two
            // inputs that turn it into a clean pass are both public, and until
            // 2026-08-21 nothing in the output said so -- the flags were
            // discoverable only from `--help`, which nobody reads after seeing
            // a warning.
            //
            // This binary deliberately has no HTTP client (air-gap posture), so
            // fetching is the reader's step. Give them the exact commands.
            println!();
            println!(
                "  {}",
                "To resolve authenticity offline, fetch both public files and re-run:".bold()
            );
            println!(
                "    {}",
                "curl -sO https://nanorix.io/.well-known/trust-chain.json".cyan()
            );
            println!(
                "    {}",
                "FP=$(curl -s https://nanorix.io/.well-known/identity.txt)".cyan()
            );
            println!(
                "    {}",
                "nanorix-verify <proof.json> --trust-chain trust-chain.json --identity-fingerprint \"$FP\"".cyan()
            );
            println!(
                "  {}",
                "Neither file is fetched for you on purpose. Verifying without \
                 trusting Nanorix means you obtain the trust root yourself, and \
                 an auditor should archive it at evidence-receipt time."
                    .dimmed()
            );
        } else {
            println!(
                "{} Chain verified · signature NOT checked · capsule {} · region {}",
                "⚠".yellow().bold(),
                cap.bold(),
                region
            );
        }
        if let Some(ver) = &r.metadata.signing_key_version {
            println!("  Signing key version: {ver}");
        }
        if let Some(alg) = &r.metadata.algorithm {
            println!("  Algorithm: {alg}");
        }
        if let Some(steps) = r.metadata.step_count {
            println!("  Chain steps: {steps} / 8");
        }
        if let Some(n) = r.metadata.unattested_parent_attribution {
            println!(
                "  {}",
                format!(
                    "Parent links: {n} carry attribution the signature does NOT cover \
                     (parent_key_id, parent_signature, parent_role, parent_jurisdiction, \
                     parent_organization_tag). Only parent_chain_hash is bound to the signed \
                     Merkle root. Do not read the rest as attested."
                )
                .yellow()
            );
        }
        if let Some(ts) = &r.metadata.recovered_chain_timestamp {
            println!("  Chain timestamp: {ts} (recovered from attestation key_id)");
            println!(
                "  {}",
                "This proof predates the restoration of the document-level \
                 `destroyed_at` field (ADR-047), so the timestamp the chain hashes \
                 was read from the attestation key_id. The chain still had to \
                 reproduce against it — a wrong timestamp cannot pass."
                    .dimmed()
            );
        }
        if r.stage_reached < 7 {
            println!(
                "  {}",
                "Note: this build reproduced the 8-step chain (stages 1-4); the proof \
                 carried no signature this build could verify (unsigned partial or an \
                 unsupported signing_mode)."
                    .dimmed()
            );
        }
    } else {
        println!("{} Verification FAILED", "✗".red().bold());
        if let Some(reason) = &r.failure_reason {
            println!("  Failure: {}", format_reason(reason).red());
            println!("  Stage reached: {} / 8", r.stage_reached);
            println!();
            print_resolution_hint(reason);
        }
    }
}

fn format_reason(r: &FailureReason) -> String {
    match r {
        FailureReason::CdpVersionUnsupported { found } => {
            format!("cdp_version_unsupported (found: {found})")
        }
        FailureReason::RequiredFieldMissing { field } => {
            format!("required_field_missing (field: {field})")
        }
        FailureReason::StepCountInvalid { expected, found } => {
            format!("step_count_invalid (expected: {expected}, found: {found})")
        }
        FailureReason::StepHashMismatch {
            step_idx,
            subsystem,
        } => format!("step_hash_mismatch (step {step_idx}, subsystem: {subsystem})"),
        FailureReason::ChainStepIdentityMismatch {
            step_idx,
            expected_subsystem,
            found_subsystem,
        } => format!(
            "chain_step_identity_mismatch (step {step_idx}, expected: {expected_subsystem}, found: {found_subsystem})"
        ),
        FailureReason::GenesisHashMismatch => "genesis_hash_mismatch".into(),
        FailureReason::FinalHashMismatch { .. } => "final_hash_mismatch".into(),
        FailureReason::SignatureMismatch { reason } => format!("signature_mismatch ({reason:?})"),
        FailureReason::SigningKeyVersionUnknown { version } => {
            format!("signing_key_version_unknown (version: {version})")
        }
        FailureReason::AuthorityRevoked => "authority_revoked".into(),
        FailureReason::RegionMismatch { required, actual } => {
            format!("region_mismatch (required: {required}, actual: {actual})")
        }
        FailureReason::DiagnosticProofRefused => "diagnostic_proof_refused".into(),
        FailureReason::AlgorithmUnsupported { found } => {
            format!("algorithm_unsupported (found: {found})")
        }
        FailureReason::AuthorityModeMismatch {
            claimed_authority_id,
            expected_algorithm,
            actual_algorithm,
        } => {
            let actual = actual_algorithm.as_deref().unwrap_or("<unregistered>");
            format!(
                "authority_mode_mismatch (authority_id: {claimed_authority_id}, expected: {expected_algorithm}, actual: {actual})"
            )
        }
        FailureReason::AuthorityIdMismatch {
            claimed_authority_id,
            expected_authority_id,
            reason,
        } => {
            let claimed = claimed_authority_id
                .as_deref()
                .unwrap_or("<none — AuditProof omits signing_authority>");
            let sub = match reason {
                AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone => {
                    "verifier_policy_demands_customer_hsm_audit_proof_has_none"
                }
                AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch => {
                    "verifier_policy_authority_id_mismatch"
                }
            };
            format!(
                "authority_id_mismatch (claimed: {claimed}, expected: {expected_authority_id}, reason: {sub})"
            )
        }
        FailureReason::StreamingMerkleRootMismatch { claimed, computed } => {
            format!("streaming_merkle_root_mismatch (claimed: {claimed}, computed: {computed})")
        }
        FailureReason::UnsignedFieldPopulated { field } => {
            format!("unsigned_field_populated (field: {field})")
        }
        FailureReason::Reserved => "reserved".into(),
    }
}

fn print_resolution_hint(r: &FailureReason) {
    let hint = match r {
        FailureReason::CdpVersionUnsupported { .. } => {
            "→ This verifier supports cdp_version 1.0 / 2.0 / 2.1. Update nanorix-verify."
        }
        FailureReason::RequiredFieldMissing { .. } => {
            "→ The AuditProof is structurally invalid. It may not be a Nanorix-issued proof."
        }
        FailureReason::StepCountInvalid { .. } => {
            "→ Nanorix CDPs always have exactly 8 chain steps. Truncation or tampering."
        }
        FailureReason::StepHashMismatch { .. } => {
            "→ The chain was tampered with at the named step. Reject the proof."
        }
        FailureReason::ChainStepIdentityMismatch { .. } => {
            "→ A chain step names a subsystem that is not the canonical one for its \
             position. The 8-step order is fixed for the life of the format. Reject \
             the proof."
        }
        FailureReason::GenesisHashMismatch => {
            "→ First step's prev_hash != SHA-512(empty). Tampered or truncated."
        }
        FailureReason::FinalHashMismatch { .. } => {
            "→ final_hash does not match the chain's terminal hash. Tampered."
        }
        FailureReason::SignatureMismatch { .. } => {
            "→ Ed25519 signature did not verify against the public key. Tampered, OR your \
             public key copy is stale (refresh from /v1/keys/<key_id>)."
        }
        FailureReason::SigningKeyVersionUnknown { .. } => {
            "→ The signing key isn't in this verifier's trust chain. Run \
             `nanorix-verify --print-trust-chain` to inspect."
        }
        FailureReason::AuthorityRevoked => {
            "→ The signing authority has been revoked. Reject the proof."
        }
        FailureReason::RegionMismatch { .. } => {
            "→ The AuditProof's region disagrees with the required_region constraint."
        }
        FailureReason::DiagnosticProofRefused => {
            "→ The AuditProof was generated in diagnostic mode. Verifier policy refused it."
        }
        FailureReason::AlgorithmUnsupported { .. } => {
            "→ Unknown signature algorithm. May indicate post-quantum migration; update verifier."
        }
        FailureReason::AuthorityModeMismatch { .. } => {
            "→ Customer-attested authority signature failed against the registered Ed25519 \
             public key (ADR-031 Amendment 1). Either the authority's published key is stale \
             OR the AuditProof was signed with a non-Ed25519 algorithm. Re-publish the key OR \
             reject the proof."
        }
        FailureReason::AuthorityIdMismatch { reason, .. } => match reason {
            AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone => {
                "→ Your --required-authority-id policy demands customer-HSM-signed AuditProofs, \
                 but this AuditProof was signed under Nanorix's default signing authority. \
                 Either accept Nanorix-default proofs (drop --required-authority-id) OR \
                 require the capsule producer to configure customer-HSM signing in their \
                 Capsulefile (per ADR-031)."
            }
            AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch => {
                "→ Your --required-authority-id policy demands a specific customer authority, \
                 but this AuditProof carries a different authority_id. Either update your \
                 policy pin OR reject the proof; this is operational misconfiguration, not \
                 a cryptographic concern."
            }
        },
        FailureReason::StreamingMerkleRootMismatch { .. } => {
            "→ A streaming-egress Merkle root in the activity trail does not match the root \
             recomputed from the chunk hashes disclosed beside it. The destruction chain itself \
             reproduced — this is the record of what the capsule streamed out, not the record of \
             its destruction. Treat the streamed-response evidence as unreliable and ask the \
             capsule producer to re-issue the proof."
        }
        FailureReason::UnsignedFieldPopulated { .. } => {
            "→ The named field is outside the signature's coverage and no Nanorix signer \
             populates it, so its contents were added after signing by someone holding no \
             key. The signature over the covered fields still checks out; that is precisely \
             why this is rejected rather than reported as verified. Reject the proof and \
             obtain a fresh copy from the issuer."
        }
        FailureReason::Reserved => "→ Reserved value; should not appear.",
    };
    println!("  {}", hint.dimmed());
}

fn bundle_extract(
    proof_path: &Path,
    record: u32,
    output_path: &Path,
    json_output: bool,
) -> Result<()> {
    let proof_bytes = std::fs::read(proof_path)
        .with_context(|| format!("failed to read AuditProof: {}", proof_path.display()))?;
    let proof: serde_json::Value = serde_json::from_slice(&proof_bytes)
        .with_context(|| format!("AuditProof file not valid JSON: {}", proof_path.display()))?;

    let bundle = extract_receipt_bundle(&proof, record)
        .with_context(|| format!("failed to extract receipt bundle for record {record}"))?;

    let bundle_json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(output_path, &bundle_json)
        .with_context(|| format!("failed to write bundle to {}", output_path.display()))?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "output_path": output_path.display().to_string(),
                "record_index": record,
            })
        );
    } else {
        println!(
            "{} Extracted record {} bundle → {}",
            "✓".green().bold(),
            record,
            output_path.display()
        );
    }
    Ok(())
}

fn bundle_verify(bundle_path: &Path, json_output: bool) -> Result<()> {
    let bytes = std::fs::read(bundle_path)
        .with_context(|| format!("failed to read bundle: {}", bundle_path.display()))?;
    let bundle: PortableReceiptBundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("bundle file not valid JSON: {}", bundle_path.display()))?;

    match verify_receipt_bundle(&bundle) {
        Ok(()) => {
            let signature_target = bundle
                .audit_proof_anchors
                .signature_target
                .as_deref()
                .unwrap_or(nanorix_verify::SIGNATURE_TARGET_STEP8_CHAIN_HASH);
            let verdict = nanorix_verify::bundle_verdict_text(&bundle);
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "bundle_version": bundle.bundle_version,
                        "bundle_type": bundle.bundle_type,
                        "capsule_id": bundle.audit_proof_anchors.capsule_id,
                        "signature_target": signature_target,
                        "verdict": verdict,
                    })
                );
            } else {
                println!(
                    "{} Bundle verifies · capsule {} · record_id {}",
                    "✓".green().bold(),
                    bundle.audit_proof_anchors.capsule_id.bold(),
                    bundle
                        .receipt
                        .get("record_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("(unknown)")
                );
                println!("  {verdict}");
            }
            Ok(())
        }
        Err(e) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "error": e.to_string(),
                    })
                );
            } else {
                println!("{} Bundle verification FAILED", "✗".red().bold());
                println!("  {}", e.to_string().red());
            }
            std::process::exit(1);
        }
    }
}

fn pubkey_bundle_build(
    keys_path: &Path,
    output_path: &Path,
    signer_seed_path: &Path,
    signer_key_id: &str,
    issuer_org: &str,
    json_output: bool,
) -> Result<()> {
    let keys_bytes = std::fs::read(keys_path)
        .with_context(|| format!("failed to read keys file: {}", keys_path.display()))?;
    let keys_doc: serde_json::Value = serde_json::from_slice(&keys_bytes)
        .with_context(|| format!("keys file not valid JSON: {}", keys_path.display()))?;
    let entries: Vec<PubKeyEntry> = serde_json::from_value(
        keys_doc
            .get("pubkeys")
            .cloned()
            .unwrap_or_else(|| keys_doc.clone()),
    )
    .with_context(|| "keys file must be {pubkeys: [...]} or [...]")?;

    let seed_bytes = std::fs::read(signer_seed_path)
        .with_context(|| format!("failed to read signer seed: {}", signer_seed_path.display()))?;
    if seed_bytes.len() != 32 {
        anyhow::bail!(
            "signer seed must be exactly 32 raw bytes (got {})",
            seed_bytes.len()
        );
    }
    let seed_array: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer seed conversion failed"))?;
    let signing_key = SigningKey::from_bytes(&seed_array);

    let bundle = build_pubkey_bundle(entries, &signing_key, signer_key_id, issuer_org)?;
    let bundle_json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(output_path, &bundle_json)
        .with_context(|| format!("failed to write bundle to {}", output_path.display()))?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "status": "ok",
                "output_path": output_path.display().to_string(),
                "key_count": bundle.pubkeys.len(),
                "publisher_pubkey_b64": base64::engine::general_purpose::STANDARD
                    .encode(signing_key.verifying_key().to_bytes()),
            })
        );
    } else {
        println!(
            "{} Built pubkey bundle ({} keys) → {}",
            "✓".green().bold(),
            bundle.pubkeys.len(),
            output_path.display()
        );
        println!(
            "  Publisher pubkey (base64): {}",
            base64::engine::general_purpose::STANDARD
                .encode(signing_key.verifying_key().to_bytes())
        );
    }
    Ok(())
}

fn pubkey_bundle_verify(
    bundle_path: &Path,
    publisher_pubkey_path: &Path,
    json_output: bool,
) -> Result<()> {
    let bytes = std::fs::read(bundle_path)
        .with_context(|| format!("failed to read bundle: {}", bundle_path.display()))?;
    let bundle: PortablePubkeyBundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("bundle file not valid JSON: {}", bundle_path.display()))?;

    let pub_bytes = std::fs::read(publisher_pubkey_path).with_context(|| {
        format!(
            "failed to read publisher pubkey: {}",
            publisher_pubkey_path.display()
        )
    })?;
    if pub_bytes.len() != 32 {
        anyhow::bail!(
            "publisher pubkey must be exactly 32 raw bytes (got {})",
            pub_bytes.len()
        );
    }
    let pub_array: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("publisher pubkey conversion failed"))?;
    let pubkey = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| anyhow::anyhow!("invalid Ed25519 pubkey: {e}"))?;

    match verify_pubkey_bundle(&bundle, &pubkey) {
        Ok(()) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "issuer_organization": bundle.issuer_organization,
                        "key_count": bundle.pubkeys.len(),
                    })
                );
            } else {
                println!(
                    "{} Pubkey bundle verifies · issuer {} · {} keys",
                    "✓".green().bold(),
                    bundle.issuer_organization.bold(),
                    bundle.pubkeys.len()
                );
            }
            Ok(())
        }
        Err(e) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "error": e.to_string(),
                    })
                );
            } else {
                println!("{} Pubkey bundle verification FAILED", "✗".red().bold());
                println!("  {}", e.to_string().red());
            }
            std::process::exit(1);
        }
    }
}

fn print_trust_chain() -> Result<()> {
    println!("{}", "Trust-chain manifest (EO-07 + EO-07 ext):".bold());
    println!();
    println!(
        "  {} Source: pass a local manifest via --trust-chain (offline / air-gap). This build has no HTTP client and retrieves nothing; obtain a manifest yourself and pass it in.",
        "•".dimmed()
    );
    println!(
        "  {} Manifest signed by Nanorix long-term identity key; fingerprint published at https://nanorix.io/.well-known/identity.txt + GitHub release notes",
        "•".dimmed()
    );
    println!(
        "  {} {} discipline: archived_versions are forever-retained per EO-07 ext (G2 long-term verifiability). Healthcare retention is 7-30 years; AuditProof signed under version N must verify after we rotate to version N+K. Archived keys are NEVER removed.",
        "•".dimmed(),
        "Archive-forever".bold()
    );
    println!(
        "  {} Manifest schema (per addendum 2026-05-06):",
        "•".dimmed()
    );
    println!(
        "{}",
        r#"      {
        "schema_version": "1",
        "issued_at": "2026-05-06T00:00:00Z",
        "authorities": {
          "us-kms-nanorix-v1": {
            "active_versions":   [{"signing_key_version": "7", ...}],
            "archived_versions": [{"signing_key_version": "6", "archived_at": "..."}, ...]
          }
        },
        "identity_fingerprint": "sha256:...",
        "identity_public_key_b64": "<ed25519 identity pubkey>",
        "manifest_signature": "base64:..."
      }"#
        .dimmed()
    );
    println!();
    println!(
        "  {} EO-07 sub-B (WIRED + tested): manifest-signature verification, key resolution, and signature-against-manifest-key. Supply --trust-chain <manifest> + --identity-fingerprint <sha256:...> to verify a proof to stage 8. This build retrieves nothing over the network; supply the manifest as a file.",
        "✓".green()
    );
    println!();
    Ok(())
}
