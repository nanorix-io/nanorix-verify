# auditproof-verifier-go

Go reference implementation of the Nanorix AuditProof verifier.

This is the cross-implementation peer of the Rust verifier at
`tools/nanorix-verify/` and of the TypeScript verifier at
`sdk/typescript/src/verifier/`.
Cross-implementation byte-equivalence is the binding contract: every fixture
in `tools/nanorix-verify/fixtures/corpus/` produces byte-identical
verification output between the Rust verifier and this Go verifier. If a
single language ecosystem suffers a supply-chain compromise or a runtime bug,
the alternate-language verifier provides cross-validation.

This is what makes "evidence outlives Nanorix" structurally real.

## Why a separate Go implementation

Auditors and customers need substrate-independence: the cryptographic chain
that anchors AuditProof verification must be reproducible from the algorithm
spec, not from a single binary distributed by Nanorix. A Go verifier built
in a clean room from the spec, producing byte-identical output to the Rust
verifier on the 100-fixture reference corpus, is the strongest available
proof that the spec is unambiguous and the algorithm is implementable
without insider information.

The AuditProof shape is **forever-stable** per ADR-006 I0. This Go
implementation therefore uses standard-library-only crypto (`crypto/ed25519`,
`crypto/sha512`, `encoding/json`) so it carries zero supply-chain dependence
on third parties for the cryptographic primitives.

## Install

```bash
go install github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go/cmd/auditproof-verifier-go@latest
```

Or import it as a library:

```go
import verifier "github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go"
```

## Build

```bash
cd tools/auditproof-verifier-go
go build ./...
go vet ./...
go test ./...
```

MSRV: Go 1.21.

## Usage

```bash
# Verify a single AuditProof (human-readable)
auditproof-verifier-go path/to/auditproof.json

# Machine-readable JSON output
auditproof-verifier-go --json path/to/auditproof.json

# Walk an entire fixture corpus and report aggregate counts
auditproof-verifier-go --fixture-dir tools/nanorix-verify/fixtures/corpus
```

### Verifier policy flags

```
--reject-diagnostic            Refuse AuditProofs flagged diagnostic_mode (EO-09)
--required-region <region>     Require the AuditProof region to match (e.g. europe-west1)
--required-authority-id <id>   Require a specific signing-authority id (per ADR-031 G7)
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Verified (or all fixtures passed in `--fixture-dir` mode) |
| 1 | Verification failed (or any fixture failure) |
| 2 | Malformed input (file unreadable, not valid JSON, CLI usage error) |
| 3 | The chain verified, but no signature on the document could be checked. Integrity is not established. |

## Cross-implementation byte-equivalence

This Go verifier produces byte-equivalent results to the Rust verifier
(`tools/nanorix-verify/`) on the 100-fixture reference corpus shipped at
commit `ba1d51a` (Wave 6 verification-surface scaffolds). Specifically:

- 100/100 fixtures yield identical verdict (valid/invalid)
- 100/100 fixtures yield identical typed `failure_reason` payload
- 100/100 fixtures yield identical metadata (cdp_version, capsule_id,
  region, signing_key_version, algorithm, step_count)
- JSON wire-form is byte-identical including key ordering (the
  serde-tag-discriminant `"type"` is always emitted first)

The closed-set `FailureReason` enum is forever-stable per ADR-006 I0 and is
mirrored exactly from the canonical Rust definition at
`governance/verify-types/src/lib.rs::FailureReason`. New failure modes ship
as additive variants; existing variants are NEVER renamed, removed, or
repurposed.

To verify cross-impl byte-equivalence locally:

```bash
# Build the Rust verifier
cargo build -p nanorix-verify

# Run the Go test that walks the corpus and compares against Rust
cd tools/auditproof-verifier-go
go test -v -run TestFixtureCorpusByteEquivalentWithRust
```

The test walks all 100 fixtures, runs each through both verifiers, and
fails the build if any fixture diverges.

## Implementation status

This build implements stages 1-7: schema, version, chain reproducibility,
final-hash binding, the policy-pin gate at stage 2, canonical-hash recompute,
and Ed25519 signature verification against the key embedded in the document.
Stage 7 is therefore the terminal success stage here.

Stage 8, anchoring that key to a trust-chain manifest, is not implemented in
this build. A document that requires stage 8 needs the Rust verifier. Corpus
fixtures are verified without a manifest, which is the same path the Rust
verifier takes when none is supplied, so the two agree on the corpus.

When either verifier changes a verdict, the other must change in lockstep. The
cross-impl byte-equivalence test is the structural
backstop that catches drift.

## Testing

```bash
go test ./...           # full suite
go test -v ./...        # with progress output
go test -run TestPropertyFault10kIterations  # 10k-iter fault-injection only
```

The test suite includes:

- 8 happy-path / failure-path tests mirroring the Rust unit tests
- Wire-form lock tests for every variant of the closed-set FailureReason enum
- The `TestFixtureCorpusByteEquivalentWithRust` cross-impl assertion (skips
  cleanly if the Rust binary isn't available at `target/debug/nanorix-verify`)
- `TestPropertyFault10kIterations`: 10,000 iterations of random AuditProof
  bytes (malformed JSON, wrong field types, truncated chains, tampered
  signatures) — every fault path must produce a deterministic failure reason
  from the closed-set enum, no panics, no hangs (per
  `feedback_canonical_hash_under_fault.md`)
- A chain-step anchor test that pins `ComputeStepHash` byte-output against a
  hand-computed reference value

## Disclaimer

This verifier reads an AuditProof JSON file off disk and runs offline
verification. It does not contact Nanorix infrastructure, and nothing leaves
the local machine. No trust-chain manifest ships with this binary and none is
fetched; stage 8 anchoring is not implemented here.

This verifier is a reference implementation for cross-implementation
byte-equivalence verification. It is a peer of the Rust verifier and is not
intended to replace it; auditors and customers should run BOTH verifiers
where adversarial assurance matters, and cross-check the outputs.

## License

Apache-2.0. Copyright 2026 Nanorix Inc. See `LICENSE` at the repository root.

## References

- Rust verifier: `tools/nanorix-verify/`
- Verification result types (Rust source of truth):
  `governance/verify-types/src/lib.rs`
- Fixture corpus: `tools/nanorix-verify/fixtures/corpus/` (100 fixtures, shipped
  from sealed Wave 6 commit `ba1d51a`)
- JSON Schema: `tools/nanorix-verify/schema/audit_proof_v2_1.json`
  (verifier release framing)
