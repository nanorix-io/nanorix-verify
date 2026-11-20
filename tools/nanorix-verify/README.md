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
cargo install --locked --git https://github.com/nanorix-io/nanorix-verify nanorix-verify
nanorix-verify --version
```

`--locked` builds with this repository's `Cargo.lock`, the dependency versions
the release was tested with.

Or clone and `cargo build --release -p nanorix-verify`; the binary lands at
`target/release/nanorix-verify`.

### Prebuilt binaries

No release carries binaries: build from source as above. The SBOM and signing
steps below are planned rather than shipped. If a release does carry binaries,
it is meant to have builds for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`,
`x86_64-pc-windows-msvc`, and a `universal-apple-darwin` lipo-merged Mac binary
that runs on both Intel and Apple Silicon, alongside a CycloneDX SBOM and a
`checksums.txt` to check an archive before extracting it.

### Package managers

A Homebrew tap, an apt mirror, and a crates.io publish are planned and are not
live yet. Until they are, use one of the two paths above rather than
`brew install` or `apt install`, which will not resolve.

## Usage

```bash
# Fetch the published key list and its identity pin once. Neither is fetched
# for you: obtain both through a channel you trust, and archive them. Both
# curls reach the same host, so compare the fingerprint with one you got
# another way before you rely on it. The identity fingerprint published when
# this README was written is
#   sha256:e1386d36fc69fa8165cc9a3bae10f210824534bac54704912ce94f95f115eba0
$ curl -sO https://verify.nanorix.io/.well-known/trust-chain.json
$ FP=$(curl -s https://verify.nanorix.io/.well-known/identity.txt)
$ [ "$FP" = "sha256:e1386d36fc69fa8165cc9a3bae10f210824534bac54704912ce94f95f115eba0" ] \
    && echo "pin matches this README" || echo "pin differs from this README: stop and ask"

# Verify an AuditProof against the key list — human-readable, exit 0
$ nanorix-verify --trust-chain trust-chain.json --identity-fingerprint "$FP" auditproof.json
✓ Verified · capsule cap_01HXX... · region us-central1
  Signing key version: 7
  Algorithm: Ed25519
  Chain steps: 8 / 8

# The same with JSON output (for CI / tooling)
$ nanorix-verify --trust-chain trust-chain.json --identity-fingerprint "$FP" --json auditproof.json
{
  "valid": true,
  "failure_reason": null,
  "stage_reached": 8,
  "metadata": { ... },
  "status": "verified"
}

# Without a key list the signature is checked only against the key the proof
# carries: status not_anchored, exit 4. A proof signed with a fresh key
# reaches the same result, so this is never a pass.
$ nanorix-verify auditproof.json
⚠ Signature valid · key NOT anchored to Nanorix trust root · capsule cap_01HXX... · region us-central1

# Refuse an AuditProof whose signed activity trail records diagnostic mode,
# and every AuditProof whose activity is unsigned, which cannot show that it was
# not run in diagnostic mode: cdp_version 1.0, which signs only final_hash, or
# 2.1 or 2.2 without a signature. A refused proof is not_verified, exit 1. Only
# a verified result (stage 8, with --trust-chain) ties the trail to a Nanorix
# key. bundle verify, boundary verify and pubkey-bundle verify refuse this flag.
$ nanorix-verify auditproof.json --reject-diagnostic

# Geo-residency check
# The region is read from the signed capsule_started activity event. Every
# AuditProof whose region is unsigned is refused: cdp_version 1.0, which signs
# only final_hash, or 2.1 or 2.2 without a signature. Only a verified result
# (stage 8, with --trust-chain) ties the region to a Nanorix key.
$ nanorix-verify auditproof.json --required-region europe-west1

# Check one authority's proofs against its signed heads
$ nanorix-verify --trust-chain trust-chain.json --identity-fingerprint sha256:... \
    population proofs/ --heads heads.json

# Print trust chain
$ nanorix-verify print-trust-chain
```

## Exit codes

For `verify` (and the bare `nanorix-verify <file>` form) and `batch`. With
`--json`, single-file output carries `status`, as each `batch` entry does:
`verified` (exit `0`), `not_anchored` (exit `4`) or `not_verified` (exit `1`
or `3`). The `valid` field is true when the chain and the signature hold under
the key used, and says nothing on its own about who signed: it is true at stage
7, and at stage 4, where no signature was checked. Read `status` or the exit
code, never `valid` alone.

- `0` — verified: the signing key resolved in the `--trust-chain` key list,
  checked against the pinned identity, and the signature verified against
  that key (stage 8). No other proof result exits `0`; `boundary verify` and
  `bundle verify` are the two exceptions, below.
- `1` — verification failed (see stderr, or `--json` for `failure_reason`), or the
  proof or key list could not be read or parsed, the activity record could not
  be read, or `--trust-chain` was given without `--identity-fingerprint`
- `2` — the key list is not signed by the pinned identity, or a usage error
  (`--input` and `--api-key` included: this build refuses both, as it refuses
  `--identity-fingerprint` without `--trust-chain`), or a `batch` directory
  with no matching file; nothing was verified (`population` also exits `2` on
  any setup error, below). `--help`, `-h`, `--version` and `-V` print and exit
  `0` only alone or after subcommand words (`nanorix-verify bundle extract
  --help`); beside any other flag or a file they exit `2` and print nothing on
  stdout, so a gate line cannot read them as a result
- `3` — the chain verified, but this build could check no signature on the
  document, so integrity is not established. Do not accept this in an
  automated gate.
- `4` — not anchored: the signature is valid against the key the proof itself
  carries (stage 7), and no key list anchored that key: none was given, or the
  proof is `cdp_version` `1.0` (below). A proof self-signed
  with a fresh key reaches the same result, so who signed is not established.
  Do not accept this in an automated gate; pass `--trust-chain` and
  `--identity-fingerprint` to reach `0`. A `cdp_version` `1.0` proof never
  reaches `0`: its signature covers `final_hash` alone, which binds
  `destroyed_at` and the two optional Merkle roots. It does not bind the
  capsule_id itself (only through record receipts, which a holder can remove),
  the region or the key id. Under a key list it is checked as a `2.1` proof is
  (key lookup, signature against the listed key, revocation), so the list can
  still refuse it, and where a `2.1` proof would reach `0` it exits `4`; its
  result names no capsule and no region.

`batch <directory>` gives each file one of three results. `verified` means the
signing key chains to the key list given with `--trust-chain`, checked against the
identity pinned with `--identity-fingerprint`, which this build requires with
`--trust-chain`: stage 8. Without `--trust-chain` no file is `verified`, and a `1.0` file never is. `not_anchored`
means the signature is valid against the key the file carries (stage 7), which
establishes integrity and not who signed: a file signed with a fresh key reaches the
same result. `not_verified` means the file is invalid or its chain reproduced with no
signature checked (stage 4 and lower, reason `no_signature_checked (stage 4)`). Put
`--trust-chain` and `--identity-fingerprint` before `batch`. The exit code is `1` when
any file is `not_verified`, otherwise `4` when any file is `not_anchored`, otherwise `0`:
as in single-file mode, `0` means every file is `verified`. A stage 4 proof exits `3`
alone but `1` in a batch; an empty directory exits `2` with a total of `0`, because
nothing was verified.
With `--json`, `batch` prints `summary` with the keys `verified`, `not_anchored`,
`not_verified` and `total`, and each `files[]` entry has `status` set to `verified`,
`not_anchored` or `not_verified`. These replace the earlier summary key names and status
values, which carried the retired verdict word.

**Exceptions: `boundary verify` and `bundle verify` exit `0` on an unanchored key.**
They check a boundary attestation or a record bundle, not an AuditProof, and exit `0`
when its signature holds against the key the document itself carries, where a proof
would exit `4`. A document signed with a fresh key reaches the same exit, so their `0`
is not `verified` and establishes integrity, not who signed. Their success line says
the key was not anchored, and `boundary verify` also prints a note on stderr when it
exits `0` without a key list anchoring every attestation. `bundle verify` refuses
`--trust-chain` with exit `2`; to establish who signed, verify the full AuditProof
with a key list. `bundle verify`, `boundary verify` and `pubkey-bundle verify`
refuse the proof policy flags (`--reject-diagnostic`, `--required-region`,
`--required-authority-id`, `--customer-activity`) with exit `2`, since none of
them reads the AuditProof those flags apply to.

`population` never exits `0`. It exits `1` when a check failed and `3` otherwise,
because the checks that would show the handed heads are every head need a
transparency log. A key list it cannot load or pin exits `2`, as does every other
setup error of `population`; `verify` exits `1` for a key list it cannot load. It prints
which key list it read, by its signed issue time and identity.

## Verification stages

1. Schema validation — required fields present, types correct
2. cdp_version recognized (`1.0` / `2.1` / `2.2` — 2.2 is verified exactly as 2.1; `2.0` is retired and refused with `cdp_version_unsupported`)
3. Chain reproducibility — recompute the SHA-512 chain from genesis
4. Final hash binding — `final_hash` matches the last step's `chain_hash`
5. Canonical hash binding — recomputed `canonical_hash` matches
6. Signing key resolution — `signing_key_version` to a public key
7. Ed25519 signature verification against the embedded key
8. Authority status — the key is anchored to a trust-chain manifest, and the
   authority is active rather than revoked or stale

Stages 1-7 run on every document and establish integrity. Stage 8 establishes
authenticity and runs only when a manifest is supplied with `--trust-chain`
and pinned with `--identity-fingerprint`; without one, stage 7 is the highest
stage reachable, and it exits `4`, not `0`.

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
enum (forever-stable):

- `cdp_version_unsupported` — version not recognized
- `required_field_missing` — structural fields absent
- `step_count_invalid` — chain has != 8 steps
- `step_hash_mismatch` — chain step doesn't recompute
- `genesis_hash_mismatch` — first step's prev_hash != SHA-512(empty)
- `final_hash_mismatch` — final_hash doesn't match last chain hash
- `streaming_merkle_root_mismatch` — a streaming-egress Merkle root disagrees with the chunk leaves disclosed beside it
- `signature_mismatch` — Ed25519 verify failed (sub-reason: malformed / does_not_verify / public_key_malformed / message_format_mismatch)
- `signing_key_version_unknown` — key not in trust chain
- `authority_revoked` — signing authority revoked
- `region_mismatch` — AuditProof region disagrees with required, or its region is unsigned: cdp_version 1.0, or 2.1 or 2.2 without a signature (`actual` is then empty)
- `diagnostic_proof_refused` — `--reject-diagnostic` refused the AuditProof at stage 2: its signed activity trail records diagnostic mode, or its activity is unsigned: cdp_version 1.0, or 2.1 or 2.2 without a signature
- `algorithm_unsupported` — unknown signature algorithm
- `signing_mode_authority_mismatch` — a 2.1 or 2.2 AuditProof says `signing_mode: customer_only` while its `authority_id` is absent or names no customer authority (no `customer-hsm-`, `customer-kms-`, `customer-tee-` or `customer-byo-` segment, matched byte for byte); refused at stage 4; carries `claimed_authority_id`
- `unsigned_field_populated` — a field outside the signed view carries a value (reserved slots; a `customer_declared_activity_root` on a version whose signed message is not the canonical view)
- `field_malformed` — a present field has the wrong shape (e.g. a `customer_declared_activity_root` that is not `sha512:` + 128 lowercase hex; `""` is malformed, not absent)
- `customer_declared_activity_root_mismatch` — the root recomputed from the customer's activity record (`--customer-activity <file>`) disagrees with the signed root; carries `claimed` / `computed`

Each reason carries diagnostic detail (`step_idx`, `subsystem`, `claimed`/`computed`
hashes, etc.) so an auditor can self-diagnose without filing a support ticket.

## Library API

```rust
use nanorix_verify::{verify_auditproof, FailureReason, TrustChainManifest, VerifierPolicy};

let proof: serde_json::Value = serde_json::from_slice(&bytes)?;

// The key list and the identity fingerprint that must have signed it. For
// Nanorix's own authority: https://verify.nanorix.io/.well-known/trust-chain.json
// and https://verify.nanorix.io/.well-known/identity.txt (confirm the
// fingerprint through a channel you trust). Refuse a list the pin did not sign.
let manifest: TrustChainManifest = serde_json::from_slice(&key_list_bytes)?;
manifest.clone().into_verified(&pin)?;
let policy = VerifierPolicy {
    trust_chain: Some(manifest),
    pinned_identity_fingerprint: Some(pin),
    ..VerifierPolicy::default()
};
let result = verify_auditproof(&proof, &[], &policy);

// Gate on `status()` (or `ok()`), never on `valid`: `valid` is also true at
// stage 7 (not_anchored: the signature checks only against the key the proof
// carries, which a proof signed with a fresh key also does) and at stage 4 (no
// signature checked). Only stage 8 is "verified".
if result.ok() {
    println!("verified");
} else if result.failure_reason.is_none() {
    println!("{}: stage {}", result.status(), result.stage_reached);
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
