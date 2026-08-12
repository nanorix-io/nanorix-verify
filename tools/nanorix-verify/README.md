# nanorix-verify

> Standalone CLI for verifying Nanorix AuditProofs.
> The literal moment-of-truth artifact when an OCR / Big-4 / sovereign-country
> auditor receives a Nanorix AuditProof and needs to confirm authenticity
> without any Nanorix SaaS dependency.

Per the verifier specification.

## Install

### From source

The verifier builds from this repository with a stock Rust toolchain and no
network access beyond crates.io:

```bash
cargo install --git https://github.com/nanorix-io/nanorix-verify nanorix-verify
nanorix-verify --version
```

Or clone and `cargo build --release -p nanorix-verify`; the binary lands at
`target/release/nanorix-verify`.

### Prebuilt binaries

Tagged releases carry builds for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`,
`x86_64-pc-windows-msvc`, and a `universal-apple-darwin` lipo-merged Mac binary
that runs on both Intel and Apple Silicon — alongside a CycloneDX SBOM
(`nanorix-verify-sbom.cdx.json`) and a `checksums.txt` to check an archive
before extracting it.

```bash
gh release download nanorix-verify-v1.0.0 \
  --repo nanorix-io/nanorix-verify \
  --pattern 'nanorix-verify-x86_64-unknown-linux-gnu.tar.gz' \
  --output nanorix-verify.tar.gz
tar xzf nanorix-verify.tar.gz
./nanorix-verify-x86_64-unknown-linux-gnu/nanorix-verify --version
```

### Package managers

A Homebrew tap, an apt mirror, and a crates.io publish are planned and are not
live yet. Until they are, use one of the two paths above rather than
`brew install` or `apt install`, which will not resolve.

## Usage

```bash
# Verify an AuditProof — human-readable
$ nanorix-verify auditproof.json
✓ Verified · capsule cap_01HXX... · region us-central1
  Signing key version: 7
  Algorithm: Ed25519
  Chain steps: 8 / 8

# Verify with JSON output (for CI / tooling)
$ nanorix-verify auditproof.json --json
{
  "valid": true,
  "failure_reason": null,
  "stage_reached": 4,
  "metadata": { ... }
}

# Reject diagnostic-mode proofs (verifier policy per the specification)
$ nanorix-verify auditproof.json --reject-diagnostic

# Geo-residency check (per the specification G1)
$ nanorix-verify auditproof.json --required-region europe-west1

# Print trust chain
$ nanorix-verify print-trust-chain
```

## Exit codes

- `0` — verified
- `1` — verification failed (see stderr / `--json` for `failure_reason`)
- `2` — usage error

## Verification stages (per the AuditProof specification)

1. Schema validation — required fields present, types correct
2. cdp_version recognized (`1.0` / `2.0` / `2.1`)
3. Chain reproducibility — recompute SHA-512 chain from genesis
4. Final hash binding — `final_hash` matches last step's `chain_hash`
5. Canonical hash binding — `canonical_hash` recompute matches *(V1: stub; ships in trust-chain anchoring with shared crate extraction)*
6. Signing key resolution — `signing_key_version` → public key from trust chain *(V1: stub)*
7. Ed25519 signature verification *(V1: stub)*
8. Authority status — active / revoked / fingerprint stale *(V1: stub)*

V1 (this build) verifies stages 1-4 (schema + chain integrity + final-hash binding). V2 (trust-chain anchoring) wires the shared verification crate from `services/api` for stages 5-8.

## Trust model

The verifier needs ONE thing the customer cannot tamper with: a trusted public
key for the AuditProof's signing authority. Two paths:

1. **Trust-chain manifest** — supplied as a local file via `--trust-chain`,
   pinned with `--identity-fingerprint`. The manifest is itself signed by a
   long-term identity key. The verifier has no HTTP client and retrieves
   nothing; if you obtain a manifest from a published location, you fetch it
   yourself and hand it over.
2. **Direct override** (`--public-key`) — for offline / sovereign-auditor
   use cases where the auditor brings the public key themselves.

## Failure reasons

When verification fails, `--json` returns a typed `failure_reason`. Closed
enum (forever-stable per the Forever-Standard wire discipline):

- `cdp_version_unsupported` — version not recognized
- `required_field_missing` — structural fields absent
- `step_count_invalid` — chain has != 8 steps
- `step_hash_mismatch` — chain step doesn't recompute
- `genesis_hash_mismatch` — first step's prev_hash != SHA-512(empty)
- `final_hash_mismatch` — final_hash doesn't match last chain hash
- `signature_mismatch` — Ed25519 verify failed (sub-reason: malformed / does_not_verify / public_key_malformed / message_format_mismatch)
- `signing_key_version_unknown` — key not in trust chain
- `authority_revoked` — signing authority revoked
- `region_mismatch` — AuditProof region disagrees with required (the specification G1)
- `diagnostic_proof_refused` — verifier policy rejected diagnostic mode (the specification)
- `algorithm_unsupported` — unknown signature algorithm

Each reason carries diagnostic detail (`step_idx`, `subsystem`, `claimed`/`computed`
hashes, etc.) so an auditor can self-diagnose without filing a support ticket.

## Library API

```rust
use nanorix_verify::{verify_auditproof, VerifierPolicy, FailureReason};

let proof: serde_json::Value = serde_json::from_slice(&bytes)?;
let result = verify_auditproof(&proof, &[], &VerifierPolicy::default());

if result.valid {
    println!("verified");
} else {
    match result.failure_reason {
        Some(FailureReason::StepHashMismatch { step_idx, subsystem }) => { ... }
        Some(FailureReason::SignatureMismatch { reason }) => { ... }
        _ => { ... }
    }
}
```

## License

Apache-2.0. Copyright 2026 Nanorix Inc.

This verifier is a released adoption surface: the verification algorithm is
open so that evidence can be checked by parties with no relationship to its
issuer. The runtime that produces a proof, and the trust root that identifies
signing authorities, are not.
