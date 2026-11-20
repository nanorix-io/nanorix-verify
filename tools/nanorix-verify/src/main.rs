//! `nanorix-verify` — standalone CLI for AuditProof verification.
//!
//! The literal moment-of-truth artifact when an OCR / Big-4 / sovereign-country
//! auditor receives a Nanorix AuditProof and needs to confirm authenticity
//! without any Nanorix SaaS dependency.
//!
//! Per the verifier specification:
//! ```text
//! $ brew install nanorix-verify
//! $ nanorix-verify auditproof.json
//! ✓ Verified · capsule cap_01HXX... · region us-central1
//!   Authority: us-kms-nanorix-v1 (signing_key_version 7)
//!   Activity events: 12
//!   Signed: 2026-05-06T14:23:11Z
//! ```

// The CLI prints the deprecated wire field `valid` in its --json output, and
// its exit code reads `valid` and `stage_reached`, the two fields status()
// is formed from.
#![allow(deprecated)]

use anyhow::{Context, Result};
use base64::Engine;
use clap::error::ErrorKind;
use clap::{CommandFactory, Parser, Subcommand};
use colored::Colorize;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nanorix_verify::population_head::{
    verify_population, PopulationCheck, PopulationResult, PopulationVerdict,
};
use nanorix_verify::trust_chain::{repeated_member, VerifiedManifest};
use nanorix_verify::{
    build_pubkey_bundle, extract_receipt_bundle, verify_auditproof, verify_boundary_attestation,
    verify_boundary_chain, verify_disclosed_activity_trail, verify_pubkey_bundle,
    verify_receipt_bundle_detailed, AuthorityIdMismatchReason, BoundaryVerificationResult,
    FailureReason, PortablePubkeyBundle, PortableReceiptBundle, PubKeyEntry, VerificationResult,
    VerifierPolicy,
};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "nanorix-verify",
    version,
    about = "Verify a Nanorix AuditProof — auditor moment-of-truth tool",
    long_about = "Verifies a Nanorix AuditProof JSON document independently of the Nanorix \
                  SaaS. Performs 8-stage verification: schema, version, chain \
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

    /// Refuse an AuditProof whose signed activity trail records diagnostic
    /// mode (a `diagnostic_mode_enabled` event), and every AuditProof that
    /// cannot show it does not: one whose activity is unsigned, which is
    /// cdp_version 1.0, or 2.1 or 2.2 without a signature. Only a `verified`
    /// result (stage 8, with `--trust-chain`) ties the trail to a Nanorix key.
    /// `bundle verify`, `boundary verify` and `pubkey-bundle verify` do not
    /// read this flag and refuse it.
    #[arg(long)]
    reject_diagnostic: bool,

    /// Required region (e.g., `europe-west1`), compared with the region on the
    /// signed `capsule_started` activity event. When set, an AuditProof whose
    /// region disagrees fails with `RegionMismatch`, and so does every
    /// AuditProof whose region is unsigned: cdp_version 1.0, or 2.1 or 2.2
    /// without a signature. Only a `verified` result (stage 8, with
    /// `--trust-chain`) ties the region to a Nanorix key. `bundle verify`,
    /// `boundary verify` and `pubkey-bundle verify` do not read this flag and
    /// refuse it.
    #[arg(long)]
    required_region: Option<String>,

    /// Required signing-authority id (e.g., `customer-hsm-example-org-v1`).
    /// When set, it is compared with the AuditProof's top-level
    /// `authority_id` (absent means `us-kms-nanorix-v1`). A proof whose
    /// top-level `authority_id` differs fails with `AuthorityIdMismatch`, and
    /// so does one whose unsigned `signing_authority.authority_id` disagrees
    /// with it. The
    /// signature covers that field only on cdp_version 2.1 and 2.2; on 1.0
    /// a pin accepts only `us-kms-nanorix-v1`, and 2.0 is refused before the
    /// pin is read. Without `--trust-chain` the authority is only as
    /// trustworthy as the key embedded in the proof, so a pin is a full
    /// authority check only when the result reaches stage 8. `bundle verify`,
    /// `boundary verify` and `pubkey-bundle verify` do not read this flag and
    /// refuse it.
    #[arg(long)]
    required_authority_id: Option<String>,

    /// Path to a trust-chain manifest (`trust-chain.json`). When supplied, the
    /// verifier resolves each proof's signing key against this manifest and
    /// verifies the signature against the manifest key — reaching full "verify
    /// without trusting Nanorix" (stage 8). The manifest's OWN signature is
    /// verified against the pinned identity fingerprint first; if that fails,
    /// the verifier aborts before checking any proof. (trust-chain anchoring.)
    #[arg(long)]
    trust_chain: Option<PathBuf>,

    /// The pin of the identity that signed the `--trust-chain` key list,
    /// obtained apart from the list, never computed from it. A `sha256:<hex>`
    /// pin: for Nanorix's list from `verify.nanorix.io/.well-known/identity.txt`,
    /// a GitHub release, or the docs; for a proof whose signed labels name a
    /// customer authority, the fingerprint published for that authority. A
    /// `hybrid1-sha256:<hex>` pin for a BYOC install's list, from the client's
    /// contract or the auditor's engagement file. Required with
    /// `--trust-chain` while this build has no compiled-in pin
    /// (`NANORIX_IDENTITY_FINGERPRINT` is `None`).
    #[arg(long)]
    identity_fingerprint: Option<String>,

    /// Path to the customer's activity record (`activity_events.jsonl`) for a
    /// proof that carries `customer_declared_activity_root`. The
    /// verifier recomputes the root from the file's raw bytes and compares;
    /// a mismatch fails verification. Supplying a record to a proof that
    /// declares no root also fails (`required_field_missing`). Without this
    /// flag a declared root is reported as "declared, not checked".
    /// Single-proof verification only: `bundle verify`, `boundary verify` and
    /// `pubkey-bundle verify` do not read this flag and refuse it.
    #[arg(long)]
    customer_activity: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify an AuditProof JSON file.
    Verify {
        /// Path to the AuditProof JSON.
        proof: PathBuf,

        /// Not available in this build: nanorix-verify does not compare a
        /// file with the input_hash of a signed input_provenance_verified
        /// event. Giving this flag exits 2.
        #[arg(long)]
        input: Option<PathBuf>,

        /// Not available in this build: the AuditProof carries neither the
        /// input-provenance manifest nor its salt, so the signer key cannot
        /// be re-derived from an API key. Giving this flag exits 2.
        /// NANORIX_API_KEY is not read.
        #[arg(long)]
        api_key: Option<String>,
    },

    /// Bulk verification mode.
    ///
    /// Walks `<directory>` recursively, verifies every `*.json` AuditProof,
    /// reports a per-file verified / not anchored / not verified line + aggregate
    /// summary. A file is "verified" only when its signing key chains to the
    /// manifest given with --trust-chain, checked against the identity pinned with
    /// --identity-fingerprint, which this build requires with --trust-chain.
    /// Both are top-level options and go BEFORE the subcommand:
    /// `nanorix-verify --trust-chain KEYLIST --identity-fingerprint PIN batch DIR`.
    /// Without --trust-chain a file with a valid signature is "not anchored": the
    /// signature matches the key the file carries, so a self-signed file reaches
    /// the same result. Exit code is 1 if any file is not verified (including one whose
    /// signature was never checked), otherwise 4 if any file is not anchored,
    /// otherwise 0. As in single-file mode, 0 means every file is verified. A
    /// directory with no matching file exits 2: nothing was verified.
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

    /// Check one authority's handed proofs against its handed signed heads.
    /// Needs --trust-chain with a pinned identity fingerprint,
    /// given before this subcommand. Prints every check, including the two
    /// that cannot run yet.
    ///
    /// Exit codes: 1 = a check failed; 2 = setup error; 3 = no check failed,
    /// and the population is not externally witnessed. Never 0: checks (d)
    /// and (e) need a transparency log, so nothing here shows that the handed
    /// heads are every head, and no automated gate may accept the result.
    Population {
        /// AuditProof JSON files, or directories walked recursively for
        /// `.json` files.
        #[arg(required = true)]
        proofs: Vec<PathBuf>,

        /// JSON file holding an array of signed heads.
        #[arg(long)]
        heads: PathBuf,
    },

    /// Print the embedded trust chain (signing authorities + their public
    /// keys + revocation status).
    PrintTrustChain,

    /// Portable Receipt Bundle (.prb.json) operations.
    ///
    /// Extract a single RecordReceipt + outer AuditProof anchors into a
    /// portable JSON bundle that can be verified independently of the
    /// producing Nanorix account. Or verify an existing bundle.
    Bundle {
        #[command(subcommand)]
        op: BundleOp,
    },

    /// Portable Pubkey Bundle (.ppb.json) operations.
    ///
    /// Build a bundle of N cross-org Ed25519 verification pubkeys (signed by
    /// the publishing party), or verify an existing bundle, used when an
    /// cross-org chain references a parent AuditProof signed under
    /// a different account OR an offline/air-gap environment where
    /// `/v1/keys/:id` lookup is unavailable.
    PubkeyBundle {
        #[command(subcommand)]
        op: PubkeyBundleOp,
    },

    /// BoundaryAttestation (retain mode) operations.
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
    /// Exit codes are not the AuditProof ladder's: there is no exit 4. 0 =
    /// every supplied document's signature was checked and verified, against
    /// the key list when one anchored it, otherwise against the key the
    /// attestation carries, which is not anchored (a proof would exit 4; a
    /// note on stderr says so); 1 = verification failed; 2 = setup error; 3 =
    /// structure verified but at least one signature was NOT checked (unsigned
    /// document) — never acceptable to an automated gate.
    Verify {
        /// One or more BoundaryAttestation JSON files (one capsule's chain).
        #[arg(required = true)]
        attestations: Vec<PathBuf>,

        /// Disclosed activity-trail JSON ({"events": [...]} or a bare
        /// array). Recomputes the per-record receipt specification-shaped commitment chain and
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
    ///
    /// It checks the signature against the key the bundle carries and reads
    /// no key list, so its exit 0 is not anchored and is not the verified exit
    /// of a proof (a proof exits 4 on that key). 1 = the bundle did not verify.
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
    ///
    /// Exit 0 means the publisher signature holds under the key file given;
    /// it anchors no key in the bundle. This command reads no key list, so
    /// --trust-chain and --identity-fingerprint are refused (exit 2).
    Verify {
        /// Path to the bundle JSON file.
        bundle: PathBuf,
        /// Path to publisher's Ed25519 public key (raw 32-byte file).
        #[arg(long)]
        publisher_pubkey: PathBuf,
    },
}

/// Compiled-in pin for the Nanorix long-term identity key (`sha256:<hex>`) —
/// the trust-chain anchoring trust root. `None` until the HSM identity key is provisioned
/// when the identity key is provisioned; set it to the published fingerprint
/// then (also published at `verify.nanorix.io/.well-known/identity.txt` + GitHub
/// releases for out-of-band cross-confirmation). While `None`, `--trust-chain`
/// requires an explicit `--identity-fingerprint`.
const NANORIX_IDENTITY_FINGERPRINT: Option<&str> = None;

/// The refusal line for the `verify` flags whose check this build cannot
/// perform, naming every flag given with its own reason. `None` when neither
/// was given.
fn unavailable_verify_flags(input: bool, api_key: bool) -> Option<String> {
    let mut parts = Vec::new();
    if input {
        parts.push(
            "--input is not available in this build: nanorix-verify does not compare a file with the input_hash of a signed input_provenance_verified event",
        );
    }
    if api_key {
        parts.push(
            "--api-key is not available in this build: the AuditProof carries neither the input-provenance manifest nor its salt, so the signer key cannot be re-derived from an API key",
        );
    }
    if parts.is_empty() {
        None
    } else {
        let rerun = if parts.len() > 1 {
            "the flags"
        } else {
            "the flag"
        };
        Some(format!(
            "error: {}. No check was run. Re-run without {rerun}.",
            parts.join("; ")
        ))
    }
}

fn main() -> Result<()> {
    let cli = parse_cli();

    // A proof path given before a subcommand would be dropped while the
    // subcommand's own arguments are verified.
    if let (Some(path), Some(_)) = (&cli.proof, &cli.command) {
        eprintln!(
            "✗ usage: {} was given before a subcommand, which would leave it unverified; \
             pass the proof path after the subcommand.",
            printable(&path.display().to_string())
        );
        std::process::exit(2);
    }

    // Refuse before any file is read, so a missing trust-chain manifest or
    // activity record cannot turn this exit 2 into something else.
    if let Some(Commands::Verify { input, api_key, .. }) = &cli.command {
        if let Some(line) = unavailable_verify_flags(input.is_some(), api_key.is_some()) {
            eprintln!("{line}");
            std::process::exit(2);
        }
    }

    let mut policy = VerifierPolicy {
        reject_diagnostic: cli.reject_diagnostic,
        required_region: cli.required_region.clone(),
        required_authority_id: cli.required_authority_id.clone(),
        ..Default::default()
    };

    // The population checks build their own proof policy from the key list,
    // so a proof policy flag would be silently ignored.
    if matches!(cli.command, Some(Commands::Population { .. }))
        && (cli.reject_diagnostic
            || cli.required_region.is_some()
            || cli.required_authority_id.is_some()
            || cli.customer_activity.is_some())
    {
        eprintln!(
            "✗ usage: population takes only --trust-chain, --identity-fingerprint and --json; \
             its checks do not read the proof policy flags."
        );
        std::process::exit(2);
    }

    if cli.trust_chain.is_some()
        && matches!(
            cli.command,
            Some(Commands::PubkeyBundle {
                op: PubkeyBundleOp::Verify { .. }
            })
        )
    {
        eprintln!(
            "✗ usage: pubkey-bundle verify does not read --trust-chain or \
             --identity-fingerprint. It checks the publisher signature against the key file \
             given with --publisher-pubkey, so a key list would be ignored."
        );
        std::process::exit(2);
    }

    // The hybrid-pin gate: a BoundaryAttestation has no
    // hybrid form, so under a hybrid pin `boundary verify` refuses before any
    // document is read rather than anchor one with Ed25519 alone.
    if cli
        .identity_fingerprint
        .as_deref()
        .is_some_and(|pin| nanorix_verify::trust_chain::is_hybrid_pin(pin.trim()))
        && matches!(
            cli.command,
            Some(Commands::Boundary {
                op: BoundaryOp::Verify { .. }
            })
        )
    {
        eprintln!(
            "✗ usage: boundary verify cannot anchor under a hybrid1-sha256: pin. A boundary \
             attestation carries an Ed25519 signature only, and a hybrid pin requires both \
             halves, so no boundary attestation is anchored under one."
        );
        std::process::exit(2);
    }

    // Trust-chain anchoring: if a trust-chain manifest is supplied, verify its OWN
    // signature against the pinned identity fingerprint BEFORE verifying any
    // proof. A bad trust root is a setup error — fail loud, exit 2; never
    // silently downgrade to integrity-only verification.
    if cli.trust_chain.is_some()
        && matches!(
            cli.command,
            Some(Commands::Bundle {
                op: BundleOp::Verify { .. }
            })
        )
    {
        eprintln!(
            "✗ usage: bundle verify does not read --trust-chain yet. It checks a bundle \
             against the key the bundle carries, so a key list would be ignored. To resolve \
             the signer, verify the full AuditProof: nanorix-verify --trust-chain \
             <key-list.json> --identity-fingerprint <sha256:... or hybrid1-sha256:...> \
             <auditproof.json>"
        );
        std::process::exit(2);
    }
    // `bundle verify`, `boundary verify` and `pubkey-bundle verify` never read
    // an AuditProof's activity trail, region, authority or declared activity
    // root, so a proof policy flag would be silently ignored.
    let not_a_proof = match &cli.command {
        Some(Commands::Bundle {
            op: BundleOp::Verify { .. },
        }) => Some((
            "bundle verify",
            "A bundle carries one record's receipt, not the AuditProof",
        )),
        Some(Commands::Boundary {
            op: BoundaryOp::Verify { .. },
        }) => Some((
            "boundary verify",
            "A boundary attestation is not an AuditProof",
        )),
        Some(Commands::PubkeyBundle {
            op: PubkeyBundleOp::Verify { .. },
        }) => Some((
            "pubkey-bundle verify",
            "A pubkey bundle carries public keys, not an AuditProof",
        )),
        _ => None,
    };
    if let Some((subcommand, what)) = not_a_proof {
        let given: Vec<&str> = [
            (cli.reject_diagnostic, "--reject-diagnostic"),
            (cli.required_region.is_some(), "--required-region"),
            (
                cli.required_authority_id.is_some(),
                "--required-authority-id",
            ),
            (cli.customer_activity.is_some(), "--customer-activity"),
        ]
        .into_iter()
        .filter_map(|(set, flag)| set.then_some(flag))
        .collect();
        if !given.is_empty() {
            eprintln!(
                "✗ usage: {subcommand} does not read {}. {what}, so the proof policy flags \
                 would be ignored. To apply them, verify the full AuditProof with the same \
                 flags: nanorix-verify <flags> <auditproof.json>",
                given.join(", ")
            );
            std::process::exit(2);
        }
    }
    // A pin pins the identity that signed a key list. Without a key list it
    // would check nothing and the proof would end at stage 7, so it is refused
    // rather than dropped, as the Go and Python verifiers refuse it.
    if cli.identity_fingerprint.is_some() && cli.trust_chain.is_none() {
        eprintln!(
            "✗ usage: --identity-fingerprint pins the identity that signed a key list, so it \
             needs --trust-chain <key-list.json>; without one nothing would be checked \
             against the pin"
        );
        std::process::exit(2);
    }
    let mut key_list = None;
    if let Some(path) = cli.trust_chain.as_ref() {
        // `population` documents exit 2 for every setup error, and its exit 1
        // always means a failed check.
        let setup_error = |error: anyhow::Error| {
            if matches!(cli.command, Some(Commands::Population { .. })) {
                eprintln!("✗ {}", printable(&format!("{error:#}")));
                std::process::exit(2);
            }
            error
        };
        let load_context = || format!("failed to load trust-chain manifest: {}", path.display());
        let bytes = std::fs::read(path)
            .with_context(load_context)
            .map_err(setup_error)?;
        let manifest: nanorix_verify::trust_chain::TrustChainManifest =
            serde_json::from_slice(&bytes)
                .with_context(load_context)
                .map_err(setup_error)?;
        let pin = cli
            .identity_fingerprint
            .clone()
            .or_else(|| NANORIX_IDENTITY_FINGERPRINT.map(String::from))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no pinned identity fingerprint: pass --identity-fingerprint <sha256:...> \
                     (the hosted service's, from verify.nanorix.io/.well-known/identity.txt) or \
                     <hybrid1-sha256:...> (a BYOC install's, from the contract) — this build has \
                     no compiled-in pin"
                )
            })
            .map_err(setup_error)?;
        let verified = match manifest.clone().into_verified(&pin) {
            Ok(verified) => verified,
            Err(e) => {
                eprintln!(
                    "✗ trust-chain manifest verification FAILED: {e}\n  The supplied trust root \
                     is not the pinned identity — refusing to verify any proof against it."
                );
                std::process::exit(2);
            }
        };
        // (f) reads only what the signature covers, so population refuses a
        // list that shows a reader anything else.
        if matches!(cli.command, Some(Commands::Population { .. })) {
            let unsigned = verified
                .manifest()
                .member_not_signed(&bytes)
                .with_context(load_context)
                .map_err(setup_error)?;
            if let Some(member) = unsigned {
                eprintln!(
                    "✗ {}",
                    printable(&format!(
                        "the key list holds bytes its signature does not cover: {member}. \
                         Population reads only the signed members, so it refuses this list."
                    ))
                );
                std::process::exit(2);
            }
        }
        key_list = Some(verified);
        policy.trust_chain = Some(manifest);
        policy.pinned_identity_fingerprint = Some(pin);
    }

    // The customer's activity record is read as raw bytes — never
    // parsed — and handed to the verifier, which recomputes the committed
    // root from it. A record belongs to exactly one proof, so batch mode
    // refuses it rather than applying one file to every document.
    if let Some(path) = cli.customer_activity.as_ref() {
        if matches!(cli.command, Some(Commands::Batch { .. })) {
            eprintln!(
                "✗ usage: --customer-activity applies to exactly one proof (the record is \
                 committed per-capsule); verify each proof with its own record."
            );
            std::process::exit(2);
        }
        let record = std::fs::read(path).with_context(|| {
            format!(
                "failed to read customer activity record: {}",
                path.display()
            )
        })?;
        policy.customer_activity = Some(record);
    }

    match cli.command {
        Some(Commands::Verify { proof, .. }) => verify_path(&proof, &policy, cli.json),
        Some(Commands::Batch {
            directory,
            extension,
        }) => verify_batch(&directory, &extension, &policy, cli.json),
        Some(Commands::Population { proofs, heads }) => {
            population_verify(&proofs, &heads, key_list.as_ref(), cli.json)
        }
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

/// Bulk verification entry point.
///
/// Walks `directory` recursively, collects every regular file whose path
/// ends in `extension` (default `.json`), and verifies each as an
/// AuditProof. Per-file output: verified / not anchored / not verified with
/// stage_reached + failure reason. Aggregate summary at end: N verified, M not
/// anchored, K not verified.
/// A file is verified only at stage 8 (key chains to the --trust-chain
/// manifest); stage 7 is "not anchored"; anything lower is not verified.
/// Exit code: 1 if any file is not verified, else 4 if any file is not
/// anchored, else 0. As in single-file mode, 0 means every file reached stage 8.
/// No matching file exits 2 after the empty summary: nothing was verified.
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
                "summary": { "verified": 0, "not_anchored": 0, "not_verified": 0, "total": 0 },
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
        // No file was verified, so exit 0 ("every file is verified") would be
        // true of nothing: a CI glob that matched nothing must not pass.
        std::process::exit(2);
    }

    let mut json_entries: Vec<serde_json::Value> = Vec::with_capacity(files.len());
    let mut verified_count = 0usize;
    let mut not_anchored_count = 0usize;
    let mut not_verified_count = 0usize;
    let mut v1_0_not_anchored = 0usize;

    for path in &files {
        let result = verify_one_for_batch(path, policy);
        match &result {
            BatchEntry::Verified { .. } => verified_count += 1,
            BatchEntry::NotAnchored { v1_0, .. } => {
                not_anchored_count += 1;
                v1_0_not_anchored += usize::from(*v1_0);
            }
            BatchEntry::NotVerified { .. } => not_verified_count += 1,
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
                "verified": verified_count,
                "not_anchored": not_anchored_count,
                "not_verified": not_verified_count,
                "total": verified_count + not_anchored_count + not_verified_count,
            },
            "files": json_entries,
        });
        println!("{}", serde_json::to_string_pretty(&envelope)?);
    } else {
        println!();
        let total = verified_count + not_anchored_count + not_verified_count;
        if not_verified_count == 0 && not_anchored_count == 0 {
            println!(
                "{} Batch verification: {} / {} verified",
                "✓".green().bold(),
                verified_count.to_string().bold(),
                total.to_string().bold(),
            );
        } else if not_verified_count == 0 {
            // With a key list given, the hint to pass one would change nothing;
            // a 1.0 proof is never anchored whatever the list holds.
            let hint = if policy.trust_chain.is_some() {
                String::new()
            } else {
                " Signatures were checked against the keys the files carry; pass --trust-chain \
                 to anchor them."
                    .to_string()
            };
            let v1_0_note = if v1_0_not_anchored > 0 {
                format!(
                    " {v1_0_not_anchored} of them are 1.0 proofs: a 1.0 proof is never anchored; \
                     no key list changes this."
                )
            } else {
                String::new()
            };
            println!(
                "{} Batch verification: {} verified, {} not anchored (total {}).{}{}",
                "⚠".yellow().bold(),
                verified_count.to_string().bold(),
                not_anchored_count.to_string().yellow().bold(),
                total.to_string().bold(),
                hint,
                v1_0_note,
            );
        } else {
            println!(
                "{} Batch verification: {} verified, {} not anchored, {} not verified (total {})",
                "✗".red().bold(),
                verified_count.to_string().bold(),
                not_anchored_count.to_string().yellow().bold(),
                not_verified_count.to_string().red().bold(),
                total.to_string().bold(),
            );
        }
    }

    if not_verified_count > 0 {
        std::process::exit(1);
    }
    if not_anchored_count > 0 {
        std::process::exit(4);
    }
    Ok(())
}

/// Per-file result for batch mode. Compact wrapper around either a
/// `VerificationResult` (when the file parsed) or an upstream filesystem /
/// JSON-parse error (which we treat as a verification failure entry, NOT
/// as an abort, so the batch keeps walking).
enum BatchEntry {
    Verified {
        path: PathBuf,
        capsule_id: Option<String>,
        stage_reached: u8,
    },
    NotAnchored {
        path: PathBuf,
        capsule_id: Option<String>,
        stage_reached: u8,
        v1_0: bool,
    },
    NotVerified {
        path: PathBuf,
        capsule_id: Option<String>,
        stage_reached: u8,
        reason: String,
        v1_0: bool,
    },
}

/// The capsule a batch line names: the signed capsule_id, the 1.0 label (a
/// 1.0 signature does not cover it), or `(unknown)`.
fn batch_capsule_label(capsule_id: &Option<String>, v1_0: bool) -> &str {
    match capsule_id.as_deref() {
        Some(cap) => cap,
        None if v1_0 => V1_0_NOT_COVERED,
        None => "(unknown)",
    }
}

impl BatchEntry {
    fn to_json(&self) -> serde_json::Value {
        match self {
            BatchEntry::Verified {
                path,
                capsule_id,
                stage_reached,
            } => serde_json::json!({
                "path": path.display().to_string(),
                "status": "verified",
                "capsule_id": capsule_id,
                "stage_reached": stage_reached,
            }),
            BatchEntry::NotAnchored {
                path,
                capsule_id,
                stage_reached,
                ..
            } => serde_json::json!({
                "path": path.display().to_string(),
                "status": "not_anchored",
                "capsule_id": capsule_id,
                "stage_reached": stage_reached,
            }),
            BatchEntry::NotVerified {
                path,
                capsule_id,
                stage_reached,
                reason,
                ..
            } => serde_json::json!({
                "path": path.display().to_string(),
                "status": "not_verified",
                "capsule_id": capsule_id,
                "stage_reached": stage_reached,
                "reason": reason,
            }),
        }
    }

    fn print_human(&self) {
        match self {
            BatchEntry::Verified {
                path,
                capsule_id,
                stage_reached,
            } => {
                let cap = capsule_id.as_deref().unwrap_or("(unknown)");
                println!(
                    "{} {} · capsule {} · stage {}/8",
                    "verified".green().bold(),
                    path.display(),
                    cap,
                    stage_reached
                );
            }
            BatchEntry::NotAnchored {
                path,
                capsule_id,
                stage_reached,
                v1_0,
            } => {
                let cap = batch_capsule_label(capsule_id, *v1_0);
                let why = if *v1_0 {
                    "a 1.0 proof is never anchored"
                } else {
                    "key NOT anchored to a trust root"
                };
                println!(
                    "{} {} · capsule {} · stage {}/8 · signature valid · {}",
                    "not anchored".yellow().bold(),
                    path.display(),
                    cap,
                    stage_reached,
                    why
                );
            }
            BatchEntry::NotVerified {
                path,
                capsule_id,
                stage_reached,
                reason,
                v1_0,
            } => {
                let cap = batch_capsule_label(capsule_id, *v1_0);
                println!(
                    "{} {} · capsule {} · stage {}/8 · {}",
                    "not verified".red().bold(),
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
    // not-verified entry (not an aborting error) — auditor wants to see the
    // partial verdict on every file.
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return BatchEntry::NotVerified {
                path: path.to_path_buf(),
                capsule_id: None,
                stage_reached: 0,
                reason: format!("read_error ({e})"),
                v1_0: false,
            };
        }
    };

    let proof: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return BatchEntry::NotVerified {
                path: path.to_path_buf(),
                capsule_id: None,
                stage_reached: 0,
                reason: format!("invalid_json ({e})"),
                v1_0: false,
            };
        }
    };

    let result = verify_auditproof(&proof, &[], policy);
    let capsule_id = result.metadata.capsule_id.clone();
    let v1_0 = result.metadata.cdp_version.as_deref() == Some("1.0");

    if result.valid && result.stage_reached >= 8 {
        BatchEntry::Verified {
            path: path.to_path_buf(),
            capsule_id,
            stage_reached: result.stage_reached,
        }
    } else if result.valid && result.stage_reached == 7 {
        BatchEntry::NotAnchored {
            path: path.to_path_buf(),
            capsule_id,
            stage_reached: result.stage_reached,
            v1_0,
        }
    } else if result.valid {
        // The chain reproduced but no signature this build can check was
        // present (stage 4). Single-file mode exits 3 for the same document;
        // a batch has no third exit, so it is counted as not verified.
        BatchEntry::NotVerified {
            path: path.to_path_buf(),
            capsule_id,
            stage_reached: result.stage_reached,
            reason: format!("no_signature_checked (stage {})", result.stage_reached),
            v1_0,
        }
    } else {
        let reason = result
            .failure_reason
            .as_ref()
            .map(|r| format_reason_anchored(r, unnamed_manifest_authority(&proof, policy)))
            .unwrap_or_else(|| "unknown_failure".to_string());
        BatchEntry::NotVerified {
            path: path.to_path_buf(),
            capsule_id,
            stage_reached: result.stage_reached,
            reason,
            v1_0,
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

/// The result status shared with batch mode and the SDKs: `verified` only at
/// stage 8, `not_anchored` for a signature valid against the key the proof
/// carries (stage 7), `not_verified` otherwise.
fn verification_status(result: &VerificationResult) -> &'static str {
    result.status()
}

/// Single-file `--json` output: the verification result with its status.
#[derive(serde::Serialize)]
struct SingleFileJson<'a> {
    #[serde(flatten)]
    result: &'a VerificationResult,
    status: &'static str,
}

fn verify_path(path: &PathBuf, policy: &VerifierPolicy, json_output: bool) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read AuditProof file: {}", path.display()))?;

    let proof: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("AuditProof file is not valid JSON: {}", path.display()))?;

    let result = verify_auditproof(&proof, &[], policy);

    if json_output {
        let line = serde_json::to_string_pretty(&SingleFileJson {
            result: &result,
            status: verification_status(&result),
        })?;
        println!("{line}");
    } else {
        print_human(&result, unnamed_manifest_authority(&proof, policy), &proof);
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
    //   0 → verified: the signing key resolved in the --trust-chain manifest
    //       and the signature verified against it (stage 8)
    //   1 → verification failed, or a proof, trust-chain manifest or activity
    //       record could not be read or parsed, or --trust-chain has no pin
    //   2 → usage error, or a trust-chain manifest whose signature does not
    //       match the pinned identity
    //   3 → chain verified but the signature was NOT checked (an unsigned
    //       partial; a signing_mode this build cannot verify is invalid and
    //       exits 1). Not invalid — but not something an automated gate may
    //       accept.
    //   4 → not anchored: the signature is valid against the key the proof
    //       itself carries (stage 7). A proof self-signed with a fresh key
    //       reaches the same result, so an automated gate may not accept it.
    if result.stage_reached < 7 {
        eprintln!(
            "note: exiting 3 — the chain verified, but this document carries no \
             signature this build could check, so integrity is not established. \
             Do not treat this as an accepted proof in an automated gate."
        );
        std::process::exit(3);
    }
    if result.stage_reached < 8 {
        if result.metadata.cdp_version.as_deref() == Some("1.0") {
            eprintln!("{V1_0_EXIT_4_NOTE}");
        } else {
            eprintln!(
                "note: exiting 4 — the signature is valid against the key this document \
                 carries, and no trust chain resolved that key, so who signed it is not \
                 established. Pass --trust-chain <key-list.json> --identity-fingerprint \
                 <sha256:... or hybrid1-sha256:...> to resolve it."
            );
        }
        std::process::exit(4);
    }
    Ok(())
}

/// Check a handed population of proofs and heads.
///
/// Exit-code ladder:
///   1 → a check failed
///   2 → setup error (no verified key list, a key list holding bytes its
///       signature does not cover, a heads file writing a member twice in
///       one object, a file that cannot be read)
///   3 → no check failed, and the population is not externally witnessed
///
/// Never 0: checks (d) and (e) need a transparency log, so nothing here shows
/// that the handed heads are every head.
fn population_verify(
    paths: &[PathBuf],
    heads_path: &Path,
    key_list: Option<&VerifiedManifest>,
    json_output: bool,
) -> Result<()> {
    let Some(key_list) = key_list else {
        eprintln!(
            "✗ usage: population needs --trust-chain and a pinned identity fingerprint, given \
             before the subcommand; a head key can only be resolved from a verified key list."
        );
        std::process::exit(2);
    };
    let (proofs, heads) = match read_population(paths, heads_path) {
        Ok(population) => population,
        Err(e) => {
            eprintln!("✗ {}", printable(&format!("{e:#}")));
            std::process::exit(2);
        }
    };

    let result = verify_population(&proofs, &heads, Some(key_list));

    if json_output {
        println!("{}", ascii_json(&result)?);
    } else {
        print_population_human(&result);
    }

    if result.verdict == PopulationVerdict::Failed {
        std::process::exit(1);
    }
    eprintln!(
        "note: exiting 3 — no check failed, but nothing shows that these are every proof and \
         every head. Do not treat this as an accepted population in an automated gate."
    );
    std::process::exit(3);
}

/// The handed proofs, in the order given with each directory sorted, and the
/// handed heads.
fn read_population(
    paths: &[PathBuf],
    heads_path: &Path,
) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>)> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            files.extend(collect_proof_files(path, ".json")?);
        } else {
            files.push(path.clone());
        }
    }
    let mut proofs = Vec::with_capacity(files.len());
    for file in &files {
        let bytes = std::fs::read(file)
            .with_context(|| format!("failed to read AuditProof file: {}", file.display()))?;
        let proof: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("AuditProof file is not valid JSON: {}", file.display()))?;
        anyhow::ensure!(
            proof.is_object(),
            "not an AuditProof object: {}",
            file.display()
        );
        proofs.push(proof);
    }
    anyhow::ensure!(!proofs.is_empty(), "no proofs found");

    let bytes = std::fs::read(heads_path)
        .with_context(|| format!("failed to read heads file: {}", heads_path.display()))?;
    let not_json = || format!("heads file is not valid JSON: {}", heads_path.display());
    let heads: serde_json::Value = serde_json::from_slice(&bytes).with_context(not_json)?;
    let serde_json::Value::Array(heads) = heads else {
        anyhow::bail!("heads file is not a JSON array: {}", heads_path.display());
    };
    // A parser keeps one copy of a member written twice, so the checks would
    // read one head while a reader keeping the other copy sees another.
    if let Some(pointer) = repeated_member(&bytes).with_context(not_json)? {
        anyhow::bail!(
            "heads file writes member {pointer:?} twice, so population refuses it: {}",
            heads_path.display()
        );
    }
    Ok((proofs, heads))
}

/// Parses the command line. `--help` and `--version` print and exit 0 only
/// when every other argument is a subcommand word. Beside a flag or a file they
/// exit 2, so an argument added to a gate's line cannot turn its refusal into
/// exit 0 with no verdict.
fn parse_cli() -> Cli {
    let argv: Vec<OsString> = std::env::args_os().collect();
    match Cli::try_parse_from(&argv) {
        Ok(cli) => cli,
        Err(e) => {
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                if let Some(other) = beside_help_or_version(argv.get(1..).unwrap_or(&[])) {
                    eprintln!(
                        "✗ usage: --help and --version are given alone, after the subcommand \
                         words; this run also got {}",
                        printable(&other)
                    );
                    std::process::exit(2);
                }
            }
            e.exit()
        }
    }
}

/// The first argument that is neither a help or version flag nor a subcommand
/// word of the command reached so far. The built command includes clap's `help`
/// subcommand, which carries the same subcommand words.
fn beside_help_or_version(args: &[OsString]) -> Option<String> {
    let mut root = Cli::command();
    root.build();
    let mut current = &root;
    for arg in args {
        let word = arg.to_string_lossy();
        if matches!(word.as_ref(), "--help" | "-h" | "--version" | "-V") {
            continue;
        }
        match current.find_subcommand(word.as_ref()) {
            Some(sub) => current = sub,
            None => return Some(word.into_owned()),
        }
    }
    None
}

/// Text a handed file supplies, as printable ASCII: every other character,
/// the controls, DEL and everything beyond ASCII included, is written as
/// `\u{...}`, so supplied text cannot move the cursor, recolour the terminal
/// or reorder a line. A quoted field in a reason is already escaped by its
/// `Debug` form and holds only ASCII here, so nothing is escaped twice.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c == ' ' || c.is_ascii_graphic() {
                c.to_string()
            } else {
                c.escape_unicode().to_string()
            }
        })
        .collect()
}

/// Pretty JSON in ASCII alone: every character beyond ASCII, and DEL, is
/// written as a `\uXXXX` escape (UTF-16, as JSON escapes are). Only strings
/// hold such characters, and each escape decodes to the same string.
/// `serde_json` escapes the controls below U+0020 itself.
fn ascii_json(value: &impl serde::Serialize) -> Result<String> {
    use std::fmt::Write;
    let text = serde_json::to_string_pretty(value)?;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() && c != '\u{7f}' {
            out.push(c);
        } else {
            for unit in c.encode_utf16(&mut [0u16; 2]) {
                write!(out, "\\u{unit:04x}")?;
            }
        }
    }
    Ok(out)
}

fn print_population_check(label: &str, check: &PopulationCheck) {
    match check {
        PopulationCheck::Ok => println!("  {} {label}: ok", "✓".green().bold()),
        PopulationCheck::Failed { reason } => {
            // A reason can quote a proof's or the key list's own fields.
            println!(
                "  {} {label}: failed, {}",
                "✗".red().bold(),
                printable(&reason.to_string())
            )
        }
        PopulationCheck::NotChecked { reason } => {
            println!(
                "  {} {label}: not checked, {}",
                "-".yellow().bold(),
                reason.as_str()
            )
        }
    }
}

fn print_population_human(result: &PopulationResult) {
    println!(
        "Population: {} proofs, {} heads",
        result.proof_count, result.head_count
    );
    if let Some(authority) = &result.authority_id {
        println!("  Authority: {authority}");
    }
    if let Some(list) = &result.key_list {
        println!(
            "  Key list: issued {}, identity {}",
            printable(&list.issued_at),
            list.identity_fingerprint
        );
    }
    if let (Some(first), Some(last)) = (result.first_sequence, result.last_sequence) {
        println!("  Sequences: {first} to {last}");
    }
    let checks = &result.checks;
    print_population_check("(a) chain links", &checks.a_chain_links);
    print_population_check("(b) sequence contiguous", &checks.b_sequence_contiguous);
    print_population_check("(c) tips match proofs", &checks.c_tips_match_proofs);
    print_population_check("(d) log inclusion", &checks.d_log_inclusion);
    print_population_check("(e) log population", &checks.e_log_population);
    print_population_check("(f) head signatures", &checks.f_head_signatures);
    if !result.unwitnessed_proofs.is_empty() {
        println!("  Proofs no handed head names:");
        for proof in &result.unwitnessed_proofs {
            println!(
                "    proof {}: {:?}, {}",
                proof.proof_index,
                proof.reason,
                proof.tip_proof_hash.as_deref().unwrap_or("no leaf")
            );
        }
    }
    if let Some(label) = result.honesty_label {
        println!("  {}", label.as_str().yellow().bold());
    }
    println!(
        "  This covers only the proofs and heads handed in. It does not show that they are \
         every proof or every head, because checks (d) and (e) need a transparency log."
    );
}

/// Verify one BoundaryAttestation or a chain of them.
///
/// Exit-code ladder. It is not `verify_path`'s: a single AuditProof exits 4
/// when its key resolved in no trust chain, while this command has no exit 4
/// and exits 0 on the key each attestation carries (`trust_anchored` in the
/// JSON says which, and the human output and a stderr note say so):
///   0 → every supplied document's signature was checked and verified, against
///       the key list when one anchored it, else against the key the
///       attestation carries (not anchored)
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
        if !result.trust_anchored {
            eprintln!("{BOUNDARY_NOT_ANCHORED_NOTE}");
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
        let anchoring = if result.per_document.iter().all(|d| d.trust_anchored) {
            "every key anchored to the trust chain"
        } else {
            "checked against the key each attestation carries, NOT anchored to a trust root"
        };
        println!(
            "{} Boundary attestation chain VALID · {} · capsule {} · indices {}..={} ({} attestations)",
            "✓".green().bold(),
            anchoring,
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
    if !result.per_document.iter().all(|d| d.trust_anchored) {
        eprintln!("{BOUNDARY_NOT_ANCHORED_NOTE}");
    }
    Ok(())
}

/// Shown where a capsule id or region would be, on a 1.0 proof.
const V1_0_NOT_COVERED: &str = "not named (a 1.0 signature does not cover it)";

/// Printed on stderr when a 1.0 proof exits 4. No key list changes that exit,
/// so the note names none.
const V1_0_EXIT_4_NOTE: &str = "note: exiting 4 — a 1.0 proof is never anchored; no key list \
     changes this. Its signature covers final_hash alone, so it does not tie the signing key \
     to a capsule.";

/// What a valid 1.0 verdict establishes. The same words as the SDKs' 1.0 scope.
const V1_0_SCOPE: &str = "The 8-step chain reproduced and the Ed25519 signature over \
     final_hash verified against the key embedded in this 1.0 proof. A 1.0 signature covers \
     final_hash alone, which binds destroyed_at and the two optional Merkle roots \
     (record_receipts_merkle_root and parent_proofs_merkle_root). It does not bind the \
     capsule_id itself (only through record receipts, which a holder can remove), the \
     region or the key id, so this verdict names no capsule. A 1.0 proof is \
     never anchored to a key list (stage 7, not stage 8), with or without a trust-chain \
     manifest.";

/// Printed on stderr when boundary verify exits 0 with a key no key list
/// anchored, which a proof would exit 4 for.
const BOUNDARY_NOT_ANCHORED_NOTE: &str = "note: exiting 0 — the signature was checked against \
     the key the attestation carries, and no key list anchored it, so who signed is not \
     established. boundary verify exits 0 here, where a proof exits 4; pass --trust-chain and \
     --identity-fingerprint to anchor it.";

/// One verdict line per BoundaryAttestation. Kind is named FIRST (
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
                "Integrity verified (no signed byte changed since signing; fields outside \
                 the signed view, such as metadata, are not checked) against the key \
                 embedded in the document. Authenticity pending: supply --trust-chain to resolve \
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

fn print_human(r: &VerificationResult, unnamed_authority: Option<&str>, proof: &serde_json::Value) {
    if r.valid {
        let v1_0 = r.metadata.cdp_version.as_deref() == Some("1.0");
        let cap = match r.metadata.capsule_id.as_deref() {
            Some(cap) => cap,
            None if v1_0 => V1_0_NOT_COVERED,
            None => "(unknown)",
        };
        let region = match r.metadata.region.as_deref() {
            Some(region) => region,
            None if v1_0 => V1_0_NOT_COVERED,
            None if r.stage_reached < 7 => "(unsigned)",
            None => "(unset)",
        };
        // Honest verdict ladder — the green "Verified" is reserved for FULL
        // trust-anchored verification and nothing weaker:
        //   stage 8  → signature verified AND the signing key resolved against
        //              the Nanorix trust-chain manifest (trust-chain anchoring). Only this
        //              is "verify without trusting Nanorix".
        //   stage 7  → signature is cryptographically valid, but against the key
        //              EMBEDDED in the proof — proves integrity of the signed
        //              view (no signed byte changed since signing), NOT
        //              authenticity. A forged proof carries its own key + signature and also reaches stage 7, so this
        //              must NOT be shown as an unqualified "Verified".
        //   stage <7 → signature was not checked at all (an unsigned partial;
        //              a signing_mode this build cannot verify is refused as
        //              algorithm_unsupported and never reaches this branch).
        if r.stage_reached >= 8 {
            println!(
                "{} Verified · capsule {} · region {}",
                "✓".green().bold(),
                cap.bold(),
                region
            );
        } else if r.stage_reached >= 7 && v1_0 {
            println!(
                "{} Signature valid · AuditProof 1.0 binds its time and two Merkle roots only · never anchored to a key list",
                "⚠".yellow().bold(),
            );
            println!("  {}", V1_0_SCOPE.dimmed());
        } else if r.stage_reached >= 7 && customer_signer(r, proof) {
            println!(
                "{} Signature valid · key NOT anchored to a published key list · capsule {} · region {}",
                "⚠".yellow().bold(),
                cap.bold(),
                region
            );
            println!(
                "  {}",
                "Integrity verified (no signed byte changed since signing; fields outside \
                 the signed view, such as metadata, are not checked). Authenticity \
                 pending: the signing key was read from the proof itself, not yet \
                 resolved against the signer's published key list."
                    .dimmed()
            );
            println!();
            println!("  {}", customer_key_advice(proof).bold());
            println!(
                "    {}",
                "nanorix-verify <proof.json> --trust-chain <key-list.json> --identity-fingerprint <sha256:... or hybrid1-sha256:...>".cyan()
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
                "Integrity verified (no signed byte changed since signing; fields outside \
                 the signed view, such as metadata, are not checked). Authenticity \
                 pending: the signing key was read from the proof itself, not yet \
                 resolved against the Nanorix trust-chain manifest."
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
                "curl -sO https://verify.nanorix.io/.well-known/trust-chain.json".cyan()
            );
            println!(
                "    {}",
                "FP=$(curl -s https://verify.nanorix.io/.well-known/identity.txt)".cyan()
            );
            println!(
                "    {}",
                "nanorix-verify <proof.json> --trust-chain trust-chain.json --identity-fingerprint \"$FP\"".cyan()
            );
            println!(
                "  {}",
                "Neither file is fetched for you on purpose. Verifying without \
                 trusting Nanorix means you obtain the trust root yourself, and \
                 an auditor should archive it at evidence-receipt time. Both curls \
                 reach the same host, so compare the fingerprint with one you got \
                 another way (the README of this release prints it) before you rely on it."
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
        print_signer(r, proof);
        if let Some(ver) = &r.metadata.signing_key_version {
            // The metadata value is the attestation's when it carries one,
            // and the signature does not cover that field. Only the
            // top-level value is in the signed view, and only on 2.1 and 2.2:
            // a 1.0 signature covers final_hash alone.
            if r.metadata.cdp_version.as_deref() == Some("1.0") {
                println!("  Signing key version (not covered by a 1.0 signature): {ver}");
            } else if proof
                .pointer("/attestation/signing_key_version")
                .and_then(|v| v.as_str())
                .is_some()
            {
                println!(
                    "  Signing key version (attestation, not covered by the signature): {ver}"
                );
            } else {
                println!("  Signing key version: {ver}");
            }
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
                 `destroyed_at` field, so the timestamp the chain hashes \
                 was read from the attestation key_id. The chain still had to \
                 reproduce against it — a wrong timestamp cannot pass."
                    .dimmed()
            );
        }
        print_customer_activity_disclosure(r);
        if r.stage_reached >= 8 {
            println!("  Not established by this check:");
            for line in NOT_ESTABLISHED {
                println!("    {}", line.dimmed());
            }
        }
        if r.stage_reached < 7 {
            println!(
                "  {}",
                "Note: this build reproduced the 8-step chain (stages 1-4); no signature \
                 was checked (the proof carries no signature or no public key)."
                    .dimmed()
            );
        }
    } else {
        println!("{} Verification FAILED", "✗".red().bold());
        if let Some(reason) = &r.failure_reason {
            println!(
                "  Failure: {}",
                format_reason_anchored(reason, unnamed_authority).red()
            );
            println!("  Stage reached: {} / 8", r.stage_reached);
            println!();
            if matches!(reason, FailureReason::SigningKeyVersionUnknown { .. })
                && unnamed_authority.is_some()
            {
                println!("  {}", FOREIGN_AUTHORITY_HINT.dimmed());
            } else if let Some(cause) = unsigned_authority_cause(proof, reason) {
                println!("  {}", cause.hint().dimmed());
            } else {
                print_resolution_hint(reason);
            }
        }
    }
}

/// Stage-7 advice when the proof's signed labels name a customer authority:
/// the nanorix.io key list would not list that authority. States the label
/// and the action only; the label does not establish who holds the key.
fn customer_key_advice(proof: &serde_json::Value) -> String {
    format!(
        "This proof's signed labels name a customer authority ({}). To anchor its key, \
         supply the key list and identity fingerprint published for that authority.",
        printable(nanorix_verify::effective_authority_id(proof))
    )
}

/// Printed once under a stage-8 verdict: what anchoring the key does not show.
const NOT_ESTABLISHED: [&str; 4] = [
    "It does not say who the legal person behind the fingerprint is.",
    "It does not say the key is non-exportable or HSM-held.",
    "It does not say Nanorix's software could not have requested the signature.",
    "It makes no regulatory statement.",
];

/// The legacy customer shape, a signed `nanorix_only` under a
/// customer-classified authority, before stage 8 ("Legacy
/// proofs"): only the customer's key list anchors the authority to the signer.
const LEGACY_MODE_LINE: &str = "signing_mode predates customer_only; this proof names a \
     customer-classified authority, which only stage 8 (the customer's key list) anchors to \
     the key that signed.";

/// The same line once stage 8 has resolved the key in the key list.
const LEGACY_MODE_LINE_ANCHORED: &str = "signing_mode predates customer_only; this proof \
     names a customer-classified authority, and stage 8 resolved its key in the key list \
     below, so the signer is the customer authority named above.";

/// Whether the proof's signed labels name a customer authority: a signed
/// `customer_only`, or a customer-classified effective `authority_id`. On 1.0
/// the labels are unsigned, so they cannot redirect the reader away from
/// Nanorix's key list.
fn customer_signer(r: &VerificationResult, proof: &serde_json::Value) -> bool {
    r.metadata.authority_signed == Some(true)
        && (proof.get("signing_mode").and_then(|v| v.as_str())
            == Some(nanorix_verify::SIGNING_MODE_CUSTOMER_ONLY)
            || nanorix_verify::is_customer_authority(nanorix_verify::effective_authority_id(proof)))
}

/// What the result says about the signature over the labels: the three forms
/// of `metadata.authority_signed`.
#[derive(Clone, Copy, PartialEq)]
enum Coverage {
    Unchecked,
    NotCovered,
    Covered,
}

impl Coverage {
    fn of(r: &VerificationResult) -> Self {
        match r.metadata.authority_signed {
            None => Coverage::Unchecked,
            Some(false) => Coverage::NotCovered,
            Some(true) => Coverage::Covered,
        }
    }

    fn phrase(self) -> &'static str {
        match self {
            Coverage::Unchecked => "no signature was checked",
            Coverage::NotCovered => "not covered by the signature",
            Coverage::Covered => "covered by the signature",
        }
    }
}

/// A string label as printed: the proof's own string, or the issuer's default
/// with a note saying it is a default and what the signature binds instead
/// (the canonical view binds the raw value, `null` when absent).
fn label_text(
    proof: &serde_json::Value,
    key: &str,
    default: &str,
    coverage: Coverage,
) -> (String, Option<String>) {
    let (how, binds) = match proof.get(key) {
        Some(serde_json::Value::String(s)) => return (printable(s), None),
        None => ("absent from the proof", "its absence".to_string()),
        Some(other) => (
            "not a string in the proof",
            format!("the value {}", printable(&other.to_string())),
        ),
    };
    let tail = match coverage {
        Coverage::Covered => format!("the signature covers {binds}"),
        _ => coverage.phrase().to_string(),
    };
    (default.to_string(), Some(format!("default: {how}; {tail}")))
}

/// The top-level key version as printed. Under the signature it is the
/// integer the canonical view binds (the string's `i64` parse, 0 when it does
/// not parse); unsigned, it is the string as written.
fn key_version_text(
    r: &VerificationResult,
    proof: &serde_json::Value,
    coverage: Coverage,
) -> (String, Option<String>) {
    let raw = proof.get("signing_key_version");
    if coverage != Coverage::Covered {
        let version = raw
            .and_then(|v| v.as_str())
            .or(r.metadata.signing_key_version.as_deref())
            .unwrap_or("(none)");
        return (printable(version), None);
    }
    match raw {
        Some(serde_json::Value::String(s)) => match s.parse::<i64>() {
            Ok(n) if n.to_string() == *s => (n.to_string(), None),
            Ok(n) => (
                n.to_string(),
                Some(format!(
                    "written {} in the proof; the signature covers {n}",
                    printable(s)
                )),
            ),
            Err(_) => (
                printable(s),
                Some("not a number; the signature covers 0".to_string()),
            ),
        },
        None => (
            "none".to_string(),
            Some("absent from the proof; the signature covers 0".to_string()),
        ),
        Some(other) => (
            printable(&other.to_string()),
            Some("not a string; the signature covers 0".to_string()),
        ),
    }
}

/// Who signed, by the proof's own labels, and what the signature covers of
/// them; the key list at stage 8.
fn print_signer(r: &VerificationResult, proof: &serde_json::Value) {
    let coverage = Coverage::of(r);
    let (authority, authority_note) = label_text(
        proof,
        "authority_id",
        nanorix_verify::DEFAULT_AUTHORITY_ID,
        coverage,
    );
    let (version, version_note) = key_version_text(r, proof, coverage);
    if authority_note.is_none() && version_note.is_none() {
        println!(
            "  Signer: authority {authority}, key version {version} ({})",
            coverage.phrase()
        );
    } else {
        println!(
            "  Signer: authority {authority} ({}), key version {version} ({})",
            authority_note.as_deref().unwrap_or(coverage.phrase()),
            version_note.as_deref().unwrap_or(coverage.phrase())
        );
    }
    let signed_version = proof
        .get("cdp_version")
        .and_then(|v| v.as_str())
        .is_some_and(|v| nanorix_verify::CANONICAL_VIEW_SIGNED_VERSIONS.contains(&v));
    let mode_string = proof.get("signing_mode").and_then(|v| v.as_str());
    if mode_string.is_some() || signed_version {
        let (mode, mode_note) = label_text(proof, "signing_mode", "nanorix_only", coverage);
        println!(
            "  Signing mode: {mode} ({})",
            mode_note.as_deref().unwrap_or(coverage.phrase())
        );
    }
    if coverage == Coverage::Covered
        && r.stage_reached >= 7
        && mode_string.unwrap_or("nanorix_only") == "nanorix_only"
        && nanorix_verify::is_customer_authority(nanorix_verify::effective_authority_id(proof))
    {
        if r.stage_reached >= 8 {
            println!("  {LEGACY_MODE_LINE_ANCHORED}");
        } else {
            println!("  {LEGACY_MODE_LINE}");
        }
    }
    if r.stage_reached >= 8 {
        if let (Some(issued), Some(fingerprint)) = (
            r.metadata.trust_chain_issued_at.as_deref(),
            r.metadata.trust_chain_identity_fingerprint.as_deref(),
        ) {
            println!(
                "  Key list: issued {}, identity {} (the fingerprint you pinned)",
                printable(issued),
                printable(fingerprint)
            );
        }
        let resolved = proof
            .pointer("/attestation/signing_key_version")
            .and_then(|v| v.as_str());
        let signed = proof.get("signing_key_version").and_then(|v| v.as_str());
        if let Some(resolved) = resolved.filter(|v| Some(*v) != signed) {
            println!(
                "  Key list resolved key version {} (read from attestation.signing_key_version, \
                 which the signature does not cover)",
                printable(resolved)
            );
        }
    }
}

/// Say what was and was not established about a declared
/// customer activity root. Silence here would let "Signature valid" be read
/// as covering a record this build never saw.
fn print_customer_activity_disclosure(r: &VerificationResult) {
    let Some(root) = r.metadata.customer_declared_activity_root.as_deref() else {
        return;
    };
    match r.metadata.customer_declared_activity_checked {
        Some(true) => {
            println!("  Customer-declared activity root: {root}");
            println!(
                "  {}",
                "Recomputed from the supplied --customer-activity record and matched. \
                 The root commits to the record's raw bytes; Nanorix did not read or \
                 validate their content, and this check does not either."
                    .dimmed()
            );
        }
        _ => {
            println!(
                "  {}",
                format!("Customer-declared activity root: {root} — declared, NOT checked").yellow()
            );
            println!(
                "  {}",
                "The proof commits to the customer's activity record, but no record was \
                 supplied. Pass --customer-activity <activity_events.jsonl> to recompute \
                 the root and compare. The signature covers the root either way."
                    .dimmed()
            );
        }
    }
}

/// `Some(authority_id)` when a trust-chain manifest was supplied and does not
/// name the document's signing authority at all — the BYOC / self-hosted case,
/// which stage 6 reports as `signing_key_version_unknown`. Message-side only:
/// the verdict, wire reason, and exit code stay the ladder's.
fn unnamed_manifest_authority<'a>(
    proof: &'a serde_json::Value,
    policy: &VerifierPolicy,
) -> Option<&'a str> {
    let manifest = policy.trust_chain.as_ref()?;
    let authority_id = nanorix_verify::effective_authority_id(proof);
    (!manifest.names_authority(authority_id)).then_some(authority_id)
}

/// Why a pin refusal compared a value no signature covers. Message-side only:
/// the wire reason stays `verifier_policy_authority_id_mismatch`.
enum UnsignedAuthorityCause {
    /// `signing_authority.authority_id` contradicts the proof's `authority_id`.
    ContradictingSigningAuthority,
    /// cdp_version 1.0: no signature covers the top-level `authority_id`.
    UnsignedOnThisVersion,
}

impl UnsignedAuthorityCause {
    fn hint(&self) -> &'static str {
        match self {
            Self::ContradictingSigningAuthority => {
                "→ An unsigned signing_authority contradicts the proof's authority_id, so the \
                 document was altered after signing or is malformed. Do not accept it; ask \
                 the capsule producer for the original proof."
            }
            Self::UnsignedOnThisVersion => {
                "→ The proof's authority_id is not covered by its signature on this \
                 cdp_version (only 2.1 and 2.2 sign it), so a pin cannot rely on it. On 1.0 \
                 a pin accepts only us-kms-nanorix-v1; a different authority_id there was \
                 added after signing or the proof is malformed."
            }
        }
    }
}

fn unsigned_authority_cause(
    proof: &serde_json::Value,
    r: &FailureReason,
) -> Option<UnsignedAuthorityCause> {
    let FailureReason::AuthorityIdMismatch {
        claimed_authority_id: Some(claimed),
        reason: AuthorityIdMismatchReason::VerifierPolicyAuthorityIdMismatch,
        ..
    } = r
    else {
        return None;
    };
    let top_level = proof.get("authority_id").and_then(|v| v.as_str());
    let signed = proof
        .get("cdp_version")
        .and_then(|v| v.as_str())
        .is_some_and(|v| nanorix_verify::CANONICAL_VIEW_SIGNED_VERSIONS.contains(&v));
    if !signed
        && top_level == Some(claimed.as_str())
        && claimed != nanorix_verify::DEFAULT_AUTHORITY_ID
    {
        return Some(UnsignedAuthorityCause::UnsignedOnThisVersion);
    }
    let effective = top_level.unwrap_or(nanorix_verify::DEFAULT_AUTHORITY_ID);
    let unsigned = proof
        .pointer("/signing_authority/authority_id")
        .and_then(|v| v.as_str());
    (unsigned == Some(claimed.as_str()) && claimed != effective)
        .then_some(UnsignedAuthorityCause::ContradictingSigningAuthority)
}

/// `format_reason`, plus the one message-side amendment the wire reason cannot
/// carry: when stage 6 stopped because the supplied manifest does not name the
/// document's signing authority at all, say so — `(version: 1)` alone reads as
/// a Nanorix key-rotation problem on a proof that is simply not Nanorix-signed.
fn format_reason_anchored(r: &FailureReason, unnamed_authority: Option<&str>) -> String {
    match (r, unnamed_authority) {
        (FailureReason::SigningKeyVersionUnknown { .. }, Some(authority)) => format!(
            "{} — the supplied trust-chain manifest does not name signing authority \"{authority}\"",
            format_reason(r)
        ),
        _ => format_reason(r),
    }
}

/// Stage-6 disclosure for the foreign-authority case, mirroring the hosted
/// /v1/verify `FOREIGN_AUTHORITY_SCOPE` wording. The verdict class
/// (`signing_key_version_unknown`, stage 6, exit 1) is unchanged: under an
/// explicitly supplied manifest, an unanchorable proof must not pass an
/// automated `verify && accept` gate.
const FOREIGN_AUTHORITY_HINT: &str =
    "→ The document names a signing authority the supplied trust-chain manifest does \
     not carry. A BYOC customer's own signing key, a self-hosted install, and a \
     document signed by a key you have not yet established trust in all look like \
     this; this verifier cannot tell them apart. The chain reproduced and the \
     Ed25519 signature verified against the public key embedded in the document; \
     the key was not resolved against a published root here, so anchoring is not \
     established under this manifest. Only if you independently trust that \
     authority, anchor it with the manifest it publishes: nanorix-verify \
     <proof.json> --trust-chain <their-manifest> --identity-fingerprint <their-pin>.";

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
        } => {
            // `step_idx` is the 0-based wire index (Forever-Standard); the
            // human label is the step's own 1-based `step` number (1..=8).
            // Record receipts have no 1-based step — their subsystem label
            // already names the receipt by its 0-based index.
            if subsystem.starts_with("record_receipt") {
                format!("step_hash_mismatch ({subsystem})")
            } else {
                format!(
                    "step_hash_mismatch (step {}, subsystem: {subsystem})",
                    step_idx + 1
                )
            }
        }
        FailureReason::ChainStepIdentityMismatch {
            step_idx,
            expected_subsystem,
            found_subsystem,
        } => format!(
            "chain_step_identity_mismatch (step {}, expected: {expected_subsystem}, found: {found_subsystem})",
            step_idx + 1
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
                .unwrap_or("<none — the proof names no authority_id, so the Nanorix default applies>");
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
        FailureReason::CustomerDeclaredActivityRootMismatch { claimed, computed } => {
            format!(
                "customer_declared_activity_root_mismatch (claimed: {claimed}, computed: {computed})"
            )
        }
        FailureReason::FieldMalformed { field, reason } => {
            format!("field_malformed (field: {field}, reason: {reason})")
        }
        FailureReason::UnsignedFieldPopulated { field } => {
            format!("unsigned_field_populated (field: {field})")
        }
        FailureReason::SigningModeAuthorityMismatch {
            claimed_authority_id,
        } => {
            let authority = claimed_authority_id
                .as_deref()
                .map(printable)
                .unwrap_or_else(|| "absent or not a string, so the Nanorix default applies".into());
            format!(
                "signing_mode_authority_mismatch (signing_mode: customer_only, claimed_authority_id: {authority})"
            )
        }
        FailureReason::Reserved => "reserved".into(),
    }
}

fn print_resolution_hint(r: &FailureReason) {
    let hint = match r {
        FailureReason::CdpVersionUnsupported { found } if found.as_str() == "2.0" => {
            "→ cdp_version 2.0 is a retired format: a 2.0 signature covers a hash that no published \
             rule lets a verifier recompute from the document, so this verifier does not verify it. This verifier \
             supports cdp_version 1.0 / 2.1 / 2.2."
        }
        FailureReason::CdpVersionUnsupported { .. } => {
            "→ This verifier supports cdp_version 1.0 / 2.1 / 2.2. Update nanorix-verify \
             if the document declares a newer version."
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
            "→ The AuditProof's region disagrees with the required_region constraint, or its \
             region is unsigned (cdp_version 1.0, or 2.1 or 2.2 without a signature)."
        }
        FailureReason::DiagnosticProofRefused => {
            "→ --reject-diagnostic refused it: the AuditProof records diagnostic mode, or its \
             activity is unsigned (cdp_version 1.0, or 2.1 or 2.2 without a signature), so it \
             cannot show that it was not run in diagnostic mode."
        }
        FailureReason::AlgorithmUnsupported { .. } => {
            "→ Unknown signature algorithm. May indicate post-quantum migration; update verifier."
        }
        FailureReason::AuthorityModeMismatch { .. } => {
            "→ Customer-attested authority signature failed against the registered Ed25519 \
             public key. Either the authority's published key is stale \
             OR the AuditProof was signed with a non-Ed25519 algorithm. Re-publish the key OR \
             reject the proof."
        }
        FailureReason::AuthorityIdMismatch { reason, .. } => match reason {
            AuthorityIdMismatchReason::VerifierPolicyDemandsCustomerHsmAuditProofHasNone => {
                "→ Your --required-authority-id policy demands a customer authority, but this \
                 AuditProof names no authority_id, so the Nanorix default authority \
                 (us-kms-nanorix-v1) applies to it. Either accept Nanorix-default proofs (drop \
                 --required-authority-id) OR \
                 require the capsule producer to configure customer-HSM signing in their \
                 Capsulefile."
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
        FailureReason::CustomerDeclaredActivityRootMismatch { .. } => {
            "→ The supplied --customer-activity record does not reproduce the root the proof \
             declares. The destruction chain reproduced; this says only that the bytes in hand \
             are not the bytes the declared root commits to. Obtain the record returned with \
             the destroy response (byte-exact) and re-run — a record that has been reformatted, \
             re-encoded or re-ordered will not match. Verify the proof without the record to \
             learn whether the declared root itself is the signed one."
        }
        FailureReason::FieldMalformed { .. } => {
            "→ The named field is present but is not the JSON type or shape the document \
             format defines for it, so no Nanorix signer could have emitted this value. \
             Nothing was recomputed against it. The document was altered or produced by \
             something other than a Nanorix signer; obtain a fresh copy from the issuer."
        }
        FailureReason::UnsignedFieldPopulated { .. } => {
            "→ The named field is outside the signature's coverage and no Nanorix signer \
             populates it, so its contents were added after signing by someone holding no \
             key. The signature over the covered fields still checks out; that is precisely \
             why this is rejected rather than reported as verified. Reject the proof and \
             obtain a fresh copy from the issuer."
        }
        FailureReason::SigningModeAuthorityMismatch { .. } => {
            "→ The proof's signing_mode is customer_only, but the authority_id it names is not \
             customer-classified (it contains none of customer-hsm-, customer-kms-, \
             customer-tee- or customer-byo-, compared case-sensitively). No signature was \
             checked. This verifier names no signer for it. Reject the proof and ask the issuer which \
             authority signed it."
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

    match verify_receipt_bundle_detailed(&bundle) {
        Ok(result) => {
            let signature_target = result.signature_target.as_str();
            let verdict = nanorix_verify::bundle_verdict_text(&bundle);
            let valid = result.is_valid();
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": valid,
                        "receipt_bound": result.receipt_bound,
                        "signature_authentic": result.signature_authentic,
                        "bundle_version": bundle.bundle_version,
                        "bundle_type": bundle.bundle_type,
                        "capsule_id": bundle.audit_proof_anchors.capsule_id,
                        "signature_target": signature_target,
                        "verdict": verdict,
                    })
                );
            } else {
                let record_id = bundle
                    .receipt
                    .get("record_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(unknown)");
                if valid {
                    println!(
                        "{} Bundle verifies (signature checked against the key carried in the bundle, which was not anchored to a trust chain, so who signed is not established; exit 0 here is not the verified exit of a proof) · capsule {} · record_id {}",
                        "✓".green().bold(),
                        bundle.audit_proof_anchors.capsule_id.bold(),
                        record_id
                    );
                } else {
                    println!(
                        "{} Signature authentic, receipt NOT bound · capsule {} · record_id {}",
                        "!".yellow().bold(),
                        bundle.audit_proof_anchors.capsule_id.bold(),
                        record_id
                    );
                }
                println!("  {verdict}");
            }
            if !valid {
                std::process::exit(1);
            }
            Ok(())
        }
        Err(e) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": false,
                        "receipt_bound": false,
                        "signature_authentic": false,
                        "error_kind": e.kind(),
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
    println!("{}", "Trust-chain manifest:".bold());
    println!();
    println!(
        "  {} Source: pass a local manifest via --trust-chain (offline / air-gap). This build has no HTTP client and retrieves nothing; obtain a manifest yourself and pass it in.",
        "•".dimmed()
    );
    println!(
        "  {} Manifest signed by Nanorix long-term identity key; fingerprint published at https://verify.nanorix.io/.well-known/identity.txt + GitHub release notes",
        "•".dimmed()
    );
    println!(
        "  {} {} discipline: archived_versions are forever-retained for long-term verifiability. Healthcare retention is 7-30 years; AuditProof signed under version N must verify after we rotate to version N+K. Archived keys are NEVER removed.",
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
        "  {} Trust-chain anchoring (built and tested): manifest-signature verification, key resolution, and signature-against-manifest-key. Supply --trust-chain <manifest> + --identity-fingerprint <sha256:... or hybrid1-sha256:...> to verify a proof to stage 8; under a hybrid1-sha256: pin this build loads the key list and refuses every record, head and boundary attestation, because it does not check their ML-DSA half yet. This build retrieves nothing over the network; supply the manifest as a file.",
        "✓".green()
    );
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ascii_json, printable};

    #[test]
    fn printable_text_escapes_controls_del_and_everything_beyond_ascii_once() {
        assert_eq!(
            printable("a\u{1b}[2K\n\u{7f}\u{9b}\u{202e}\u{e9}\u{1f600}"),
            r"a\u{1b}[2K\u{a}\u{7f}\u{9b}\u{202e}\u{e9}\u{1f600}"
        );
        assert_eq!(
            printable(r#"key "1" of "a\u{9b}""#),
            r#"key "1" of "a\u{9b}""#
        );
    }

    #[test]
    fn ascii_json_escapes_del_and_everything_beyond_ascii_and_reads_back_the_same() {
        let value =
            serde_json::json!({ "authority_id": "a\u{1b}\u{7f}\u{9b}\u{202e}\u{e9}\u{1f600}\"\\" });
        let text = ascii_json(&value).unwrap();
        assert!(text.is_ascii() && !text.contains('\u{7f}'), "{text}");
        assert!(
            text.contains(r#""a\u001b\u007f\u009b\u202e\u00e9\ud83d\ude00\"\\""#),
            "{text}"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            value
        );
    }
}
