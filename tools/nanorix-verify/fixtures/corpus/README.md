# AuditProof verifier reference corpus

100 pinned AuditProof documents and their expected verdicts. This is the
artifact a skeptic runs first, and the contract every Nanorix verifier
implementation (Rust, Go, Python, TypeScript) is held to.

## Running it

```bash
cargo test -p nanorix-verify --test corpus_sweep
```

That sweeps all 100 fixtures, asserts each one's `valid`, `stage_reached`, and
full `failure_reason` against its committed verdict, and — importantly —
re-runs the generator into a tempdir and diffs, so the committed bytes cannot
drift away from the code that produced them.

## Layout

Each fixture `NNNN_<descriptor>.json` has a sibling `NNNN_<descriptor>.expected.json`:

```json
{
  "valid": false,
  "failure_reason": { "type": "region_mismatch", "required": "...", "actual": "..." },
  "stage_reached": 2,
  "policy": { "required_region": "europe-west1" },
  "note": "optional prose"
}
```

`policy` is what makes a fixture self-describing. The `05_*` and `06_*`
verdicts are only reachable when the verifier is configured with that pin — a
harness that ignores `policy` will see those fixtures pass as valid and
wrongly conclude the corpus is satisfied. `failure_reason` is the exact wire
form of the `FailureReason` enum in `governance/verify-types`; there are no
invented keys.

Success is `stage_reached: 7` — integrity proven against the key embedded in
the proof. Stage 8 additionally anchors the key to the signed trust-chain
manifest and requires `--trust-chain`, which is an operator artifact rather
than a fixture, so the corpus does not pin it.

## Categories

| Path | n | What it proves |
|---|---|---|
| `01_single_capsule_success` | 10 | A genuinely signed v2.1 AuditProof verifies |
| `02_multi_step_pipeline` | 10 | Parent-linked proofs verify; `parent_audit_proof_id` is canonical-bound |
| `03_failure_chain_mismatch` | 10 | Per-step tampering and wrong step counts are caught at stage 3 |
| `04_failure_signature_invalid` | 10 | Bad, malformed, and unusable-key signatures are rejected at stage 7 |
| `05_failure_region_mismatch` | 10 | The residency pin is enforced, not merely accepted |
| `06_failure_authority_unknown` | 10 | The authority pin rejects unregistered signing authorities |
| `07_failure_version_unsupported` | 10 | Unrecognised `cdp_version` is rejected at stage 2 |
| `08_failure_canonical_hash_drift` | 10 | Mutating any canonical-bound field breaks the signature |
| `09_tamper_patterns/*` | 20 | Byte-flip, step re-order, version downgrade, signature substitution |

## The signed message

A v2.1 `nanorix_only` AuditProof is **not** signed over `final_hash` — that is
the v1.0 message. It is signed over the specification Part-3 canonical-view hash,
`hex(sha512(jcs(canonical_view)))`. Getting this wrong is not a theoretical
concern: the corpus previously shipped with every success fixture signed over
the v1.0 message inside a document stamped `cdp_version: "2.1"`, so every one
of them failed to verify. The 8-step chain still reproduced perfectly, which is
why nothing caught it — chain integrity and signature validity are independent
properties, and only the latter was broken.

| Version | Signed message |
|---|---|
| `1.0` | `final_hash` (hex, prefix stripped) |
| `2.0` | `document_hash` |
| `2.1` + `nanorix_only` | recomputed canonical-view hash |
| `2.1` + `dual_signature` / `tee_attested` | not verifiable by this build |

The signature covers the ASCII hex characters of that hash (128 bytes), not its
64 raw digest bytes.

## Changing the corpus

Fix the generator (`fixtures/generator.rs`) and regenerate:

```bash
cargo run --bin nanorix-verify-fixtures-gen
```

Never hand-edit a fixture, and never edit an `.expected.json` to match a
failing verifier — that converts a defect into a committed expectation, which
is precisely how the signed-message bug survived. The byte-identity test exists
to make that mistake fail loudly.

## Known cross-implementation divergence

The corpus is the contract; the implementations do not all meet it yet. As of
the last sweep the Rust verifier agrees with all 100 fixtures. The Go verifier
(`tools/auditproof-verifier-go`) stops at stage 4 and performs no signature
verification at all, so it accepts tampered proofs the corpus requires to be
rejected. Treat any implementation's disagreement with this corpus as a defect
in that implementation.
