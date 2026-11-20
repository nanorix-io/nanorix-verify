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
verifier on every fixture in the reference corpus, is the strongest available
proof that the spec is unambiguous and the algorithm is implementable
without insider information.

The AuditProof shape is **forever-stable**. This Go
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
# Verify a single AuditProof against the published key list (exit 0, status verified).
# Read the fingerprint in https://verify.nanorix.io/.well-known/identity.txt and
# confirm it through a channel you trust.
curl -fsSLo trust-chain.json https://verify.nanorix.io/.well-known/trust-chain.json
auditproof-verifier-go --trust-chain trust-chain.json \
  --identity-fingerprint sha256:<fingerprint> path/to/auditproof.json

# Machine-readable JSON output: the result followed by "status"
auditproof-verifier-go --json --trust-chain trust-chain.json \
  --identity-fingerprint sha256:<fingerprint> path/to/auditproof.json

# Without a key list the signature is checked only against the key the proof
# carries: the best result is exit 4, status not_anchored, never exit 0
auditproof-verifier-go path/to/auditproof.json

# Verify every fixture in a corpus and compare each verdict with its .expected.json
auditproof-verifier-go --fixture-dir tools/nanorix-verify/fixtures/corpus
```

`--fixture-dir` runs each fixture under the pins its sibling `.expected.json`
declares and compares `valid`, `stage_reached` and `failure_reason` with that
file, as the Rust test `every_corpus_fixture_verifies_to_its_committed_verdict`
in `tools/nanorix-verify/tests/corpus_sweep.rs` does. It does not check for an
`.expected.json` without a fixture or the `index.json` counts, which other Rust
tests check. It prints the counts, then either `N of N match their expected
verdict` or each difference. The policy flags below and a file argument are
refused in this mode, and so is a symlinked subfolder (the Rust sweep follows
folder links) or a symlink whose target cannot be read.

### Version

`auditproof-verifier-go --version` prints the command's own version (0.1.0), which is not the release version of this repository. `-version`, `-help` and `-h` (one dash or two) print and exit 0 only alone or after the subcommand words (`auditproof-verifier-go bundle verify -h`). Beside any other flag or argument they print a usage line on stderr, nothing on stdout, and exit 2, so a gate line that also names a proof cannot read them as a result.

### Verifier policy flags

```
--reject-diagnostic            Refuse an AuditProof whose signed activity trail records diagnostic mode, and every AuditProof whose activity is unsigned (cdp_version 1.0, or 2.1 or 2.2 without a signature)
--required-region <region>     Require the region on the signed capsule_started activity event to match (e.g. europe-west1); every AuditProof whose region is unsigned (cdp_version 1.0, or 2.1 or 2.2 without a signature) is refused
--required-authority-id <id>   Require the top-level authority_id (signed on cdp_version 2.1/2.2 only); a full authority check only together with --trust-chain
--trust-chain <key-list.json>  Anchor the signing key to a signed key list (stage 8); needs --identity-fingerprint
--identity-fingerprint <fp>    The identity fingerprint (sha256:<hex>) the key list must be signed by, from a channel other than the list itself
```

Only a `verified` result (stage 8, with `--trust-chain`) ties the activity
trail, and the region in it, to a Nanorix key; at stage 7 the key is the one
the proof carries.

Flags go before the proof file. Any argument after it, a flag included, is
refused with exit 2 rather than dropped. (`nanorix-verify` accepts flags
after the file; this command does not.) The `bundle` and `pubkey-bundle`
subcommands take their flags before their file too, and refuse anything after
it the same way (`pubkey-bundle build` takes flags only). The verify command's
pin, policy and path flags, and `--publisher-pubkey` of `pubkey-bundle verify`,
are each given once, with a value: a repeated `--trust-chain`,
`--identity-fingerprint`, `--required-region`, `--required-authority-id`,
`--customer-activity`, `--fixture-dir`, `--reject-diagnostic` or
`--publisher-pubkey`, or an empty value for one, is refused with exit 2,
because keeping either value would leave the other unchecked. (The other flags
of `bundle extract` and `pubkey-bundle build` still keep their last value.) `bundle verify` refuses `--trust-chain` in every form, a repeated or
empty one included.

### Anchoring a proof to a key list (stage 8)

A key list names each signing authority and the public keys it has used. The
list is signed by an identity key, and you pin that key's fingerprint. This
checks the list first, then checks the proof against it:

```bash
auditproof-verifier-go \
  --trust-chain key-list.json \
  --identity-fingerprint sha256:<fingerprint you were given> \
  auditproof.json
```

A key list that the pinned identity did not sign is refused with exit 2
before any proof is read. A proof whose authority or key version is not in the
list fails at stage 6, a proof signed by a different key than the list holds
under that version fails at stage 7, and a proof that resolves reaches stage 8.
From Go, `LoadTrustChain(keyList, pinnedFingerprint)` makes the value for
`VerifierPolicy.TrustChain`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Verified (status `verified`): the signing key resolved in the key list given with `--trust-chain` and `--identity-fingerprint`, and the signature verified against it (stage 8). In `--fixture-dir` mode: every fixture's verdict equals its `.expected.json` |
| 1 | Verification failed, including a document that is not JSON as `nanorix-verify` parses it, reported as `required_field_missing` of `json_root` (`nanorix-verify` exits 1 with no verdict): invalid UTF-8, a byte order mark, an escape naming half a surrogate pair, 128 or more nested arrays and objects, `NaN`, or a number beyond the 64-bit float range. In `--fixture-dir` mode: at least one fixture's verdict differs from its `.expected.json` |
| 2 | No verdict was reached: file unreadable, CLI usage error (an argument after the proof file, a pin, policy or path flag given twice or with an empty value, or a policy flag or a file argument with `--fixture-dir`, included), or a key list that cannot be read or parsed or that the pinned identity did not sign. `nanorix-verify` exits 1 instead on an unreadable proof, key list or activity record, an unparseable key list, and `--trust-chain` without `--identity-fingerprint`; it has no `--fixture-dir`. In `--fixture-dir` mode also: the root is not a folder, the folder cannot be walked (a symlinked subfolder or a symlink whose target cannot be read included) or holds no fixture, or a fixture has no readable `.expected.json` with a boolean `valid` and a `stage_reached` written as an unsigned integer (digits alone) |
| 3 | The chain verified, but no signature on the document could be checked. Integrity is not established. |
| 4 | Not anchored (status `not_anchored`): the signature is valid against the key the proof itself carries (stage 7), and no key list anchored that key: none was given, or the proof is `cdp_version` `1.0`. A proof self-signed with a freshly made key reaches the same result, so a gate must not accept it. A `cdp_version` `1.0` proof never exits 0: its signature covers `final_hash` alone, which binds `destroyed_at` and the two optional Merkle roots. It does not bind the capsule_id itself (only through record receipts, which a holder can remove), the region or the key id. Under a key list it is checked as a `2.1` proof is (key lookup, signature against the listed key, revocation), so the list can still refuse it, and where a `2.1` proof would exit 0 it exits 4; its result names no capsule and no region. |

**Exception: `bundle verify` exits 0 on an unanchored key.** It checks a record
bundle, not an AuditProof, and exits 0 when the bundle's signature holds against
the key the bundle itself carries, where a proof would exit 4. A bundle signed
with a fresh key reaches the same exit, so its 0 is not `verified`, and its
success line says the key was not anchored. It refuses `-trust-chain` with exit
2. `nanorix-verify` has the same exception for `bundle verify` and for
`boundary verify`, which this build does not have.

For a proof both can read, exits 0, 1, 3 and 4 are the ones `nanorix-verify`
gives. The single-file `--json` output is the verification result followed by
`status`: `verified` (exit 0), `not_anchored` (exit 4) or `not_verified`
(exit 1 or 3). The `valid` field is true when the chain and the signature hold
under the key used, and says nothing on its own about who signed: it is true at
stage 7, and at stage 4, where no signature was checked. Read `status` or the
exit code, never `valid` alone.

Changed: before this, a proof that reached stage 7 without a key list exited 0,
printed `Verified` and its `--json` output had no `status`. It now exits 4 and
prints `Signature valid · key NOT anchored to a trust root`. A gate that ran
the bare command now needs `--trust-chain` and `--identity-fingerprint`.

## Cross-implementation byte-equivalence

This Go verifier produces byte-equivalent results to the Rust verifier
(`tools/nanorix-verify/`) on every fixture in the reference corpus
(`tools/nanorix-verify/fixtures/corpus/index.json` holds the current count).
Specifically, for every fixture:

- identical verdict (valid/invalid)
- identical typed `failure_reason` payload
- identical metadata (cdp_version, capsule_id,
  region, signing_key_version, algorithm, step_count)
- JSON wire-form is byte-identical including key ordering (the
  serde-tag-discriminant `"type"` is always emitted first)

The closed-set `FailureReason` enum is forever-stable and is
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

The test walks every fixture in the corpus, runs each through both verifiers, and
fails the build if any fixture diverges.

## Implementation status

This build implements stages 1-8: schema, version, chain reproducibility,
final-hash binding, the policy-pin gate at stage 2, the stage-2 refusal
(`unsigned_field_populated`) of a document that carries any of the seven
reserved attestation slots (`customer_attestation`, `policy_attestation`,
`third_party_attestation`, `retention_policy_attestation`, `witness_signatures`,
`pqc_attestation`, `customer_pqc_attestation`) with a value other than null, or a
`customer_declared_activity_root` on a cdp_version whose signature does not
cover it (1.0), canonical-hash recompute,
Ed25519 signature verification against the key embedded in the document, and,
when a key list and a pinned identity fingerprint are given, anchoring that key
to the list (stage 8). Without a key list, stage 7 is as far as a proof gets:
it shows integrity, not authenticity, and the command exits 4 (not anchored).

Stage 8 is checked against shared vectors written by the Rust verifier
(`tools/nanorix-verify/fixtures/trust_chain/`), and a Rust test fails if those
files drift from the Rust reference. Corpus fixtures are verified without a key
list, which is the same path the Rust verifier takes when none is supplied, so
the two agree on the corpus.

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
  an internal design rule)
- A chain-step anchor test that pins `ComputeStepHash` byte-output against a
  hand-computed reference value

## Disclaimer

This verifier reads an AuditProof JSON file off disk and runs offline
verification. It does not contact Nanorix infrastructure, and nothing leaves
the local machine. No key list ships with this binary and none is fetched; for
stage 8 you supply the key list and the fingerprint you pin.

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
- Fixture corpus: `tools/nanorix-verify/fixtures/corpus/` (count in its
  `index.json`)
- JSON Schema: `tools/nanorix-verify/schema/audit_proof_v2_1.json`
  (verifier release framing)
