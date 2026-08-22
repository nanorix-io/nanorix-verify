# AuditProof verifier reference corpus

110 pinned AuditProof documents and their expected verdicts. This is the
artifact a skeptic runs first, and the contract every Nanorix verifier
implementation (Rust, Go, Python, TypeScript) is held to.

## Running it

```bash
cargo test -p nanorix-verify --test corpus_sweep
```

That sweeps all 110 fixtures, asserts each one's `valid`, `stage_reached`, and
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
| `10_v2_2` | 10 | CDP 2.2 verifies exactly as 2.1; ADR-053 `policy_denial_summary` and ADR-056 `customer_declared_activity_root` are canonical-bound, so a count or root rewritten after signing breaks the signature. A root on a version that does not sign the canonical view (1.0 / 2.0) is `unsigned_field_populated`; a root that is not a `sha512:` + 128-lowercase-hex string (the empty string, a number) is `field_malformed` — both at stage 2, before the chain walk |

## The signed message

A v2.1 `nanorix_only` AuditProof is **not** signed over `final_hash` — that is
the v1.0 message. It is signed over the ADR-011 Part-3 canonical-view hash,
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
| `2.1` / `2.2` + `nanorix_only` | recomputed canonical-view hash |
| `2.1` / `2.2` + `dual_signature` / `tee_attested` | not verifiable by this build |

`2.2` (ADR-053 + ADR-056) shares the `2.1` arm on purpose: it changed what a
document may carry, not how it is hashed or signed. The canonical view includes
`customer_declared_activity_root` whenever the document carries it, so a root
tampered after signing is a signature failure, not a new verdict. The separate
`customer_declared_activity_root_mismatch` verdict is reached only when the
customer's record is supplied beside a genuine proof and does not reproduce the
signed root; the corpus carries no records, so it does not exercise that path
(the CLI integration tests do).

Two gates run before the chain walk, at stage 2, whenever a document carries a
present non-null root. The root is signed only where the signed message is the
canonical view, so on `1.0` or `2.0` it is `unsigned_field_populated` — the
same verdict the reserved attestation slots get — and is never reported as
checked. On `2.1` / `2.2` the root must be a JSON string of `sha512:` + 128
lowercase hex (bare 128-hex accepted); anything else is `field_malformed` with
`field` and a short `reason`, named before any recompute consumes it. The empty
string is malformed, not absent: the canonical view binds it as a value.

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

## What is checked against this corpus, and by what

The corpus is the contract. Treat any implementation's disagreement with it as a
defect in that implementation, not in the corpus.

Four automated sweeps run against it and live in this repository:
`tools/nanorix-verify/tests/corpus_sweep.rs`,
`tools/auditproof-verifier-go/corpus_sweep_test.go`,
`sdk/python/tests/test_verifier.py` (`test_reference_corpus_agreement`) and
`sdk/typescript/tests/verifier_corpus.test.ts`. All four compare `valid`,
`stage_reached` and the full `failure_reason` object against each fixture's
committed verdict, so a `reason` string that differs by one character in one
port fails that port's sweep.

One difference worth stating so it is not mistaken for a divergence: the Go
build implements stages 1-7 and does not implement stage 8, trust-chain
anchoring. Corpus fixtures are verified without a manifest, which is the same
path the Rust verifier takes when none is supplied, so both agree here. A
document requiring stage 8 needs the Rust verifier.
