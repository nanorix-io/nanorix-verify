# AuditProof verifier reference corpus

163 pinned AuditProof documents and their expected verdicts. This is the
artifact a skeptic runs first, and the contract every Nanorix verifier
implementation (Rust, Go, Python, TypeScript) is held to.

## Running it

```bash
cargo test -p nanorix-verify --test corpus_sweep
```

That sweeps all 163 fixtures, asserts each one's `valid`, `stage_reached`, and
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

`policy` is what makes a fixture self-describing. The `05_*`, `06_*` and
`12_*` verdicts are only reachable when the verifier is configured with that
pin or setting — a harness that ignores `policy` will see those fixtures pass
as valid and wrongly conclude that every verdict reproduces. `failure_reason`
is the exact wire form of the `FailureReason` enum in `governance/verify-types`;
there are no invented keys.

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
| `05_failure_region_mismatch` | 12 | The residency pin is enforced, not merely accepted, and reads only a signed region. It refuses with an empty `actual` an AuditProof whose activity no signature covers, whatever region it states: a signed 1.0 AuditProof with a `capsule_started` region equal to the pin added after signing, which verifies without the pin, and a 2.2 AuditProof without a signature whose region equals the pin |
| `06_failure_authority_unknown` | 15 | The authority pin compares the top-level `authority_id`; an unsigned `signing_authority` that disagrees is refused and cannot match a pin. The signature covers that field only on 2.1 and 2.2: on a signed 1.0 proof an added `authority_id` other than `us-kms-nanorix-v1` is refused at stage 2 and the unlabelled proof matches a pin only on the default |
| `07_failure_version_unsupported` | 15 | Unrecognised `cdp_version`, and the retired `2.0` in five document shapes, is rejected at stage 2 |
| `08_failure_canonical_hash_drift` | 10 | Mutating any canonical-bound field breaks the signature |
| `09_tamper_patterns/*` | 20 | Byte-flip, step re-order, version downgrade, signature substitution |
| `10_v2_2` | 13 | CDP 2.2 verifies exactly as 2.1; `policy_denial_summary` and the customer-declared activity specification `customer_declared_activity_root` are canonical-bound, so a count or root rewritten after signing breaks the signature. A root on a version that does not sign the canonical view (1.0) is `unsigned_field_populated`; a root that is not a `sha512:` + 128-lowercase-hex string (the empty string, a number) is `field_malformed` — both at stage 2, before the chain walk. A run of a declared Capsulefile under an egress allowlist verifies, and its Capsulefile hash changed after signing breaks the signature. A stream stopped on a budget break, with its chunks and one `streaming_policy_violation` and no completed event, verifies |
| `11_json_parse_boundary` | 28 | What the reference verifier's JSON parser accepts, the same in the Rust, Go, Python and TypeScript verifiers (the browser page's test skips the nineteen `json_root` fixtures in this category, because the page is handed JSON its browser already parsed, and sweeps the other nine): 127 nested containers parse, and 128 are refused, as are 20,000; invalid UTF-8, a byte order mark at the start of the document, an escape naming half a surrogate pair, `NaN` and a number past the 64-bit float range (`1e400`, an integer of 401 digits, `1.7976931348623159e308`) are refused, in a field no verifier reads too; for seven of those shapes (a lone high surrogate, a lone low surrogate, a high surrogate followed by text or by another escape, nesting, `1e400` and `NaN`) a fixture also puts them in the earlier copy of a repeated key, which serde_json reads in full before it keeps the last copy; a repeated key is not itself refused, and the last copy is the one that counts (also for `cdp_version`); an escaped backslash before the text `ud800` parses; `1.7976931348623158e308`, the largest 64-bit float, parses; a surrogate pair parses; 200 `[`, a `{` and an escaped quote inside a string are text, not nesting; a top-level array or `null` is not a parse failure, it is a missing `cdp_version` |
| `12_failure_diagnostic_refused` | 4 | Under `reject_diagnostic`, a signed 2.2 AuditProof whose activity trail records diagnostic mode (a `diagnostic_mode_enabled` event) is refused at stage 2 with `diagnostic_proof_refused`, and so is every AuditProof whose activity no signature covers, so that it cannot show the event is absent: a signed 1.0 AuditProof, and a 2.2 AuditProof without a signature and without the event. A signed 2.2 AuditProof whose event was removed after signing still carries its signature, so it passes stage 2 and fails at stage 7 with `signature_mismatch`. The browser page has no diagnostic setting, so its test skips this category |
| `13_customer_only` | 6 | `signing_mode: "customer_only"` (section 4), each signed with the generator's fixed test key: a valid proof under `us-customer-kms-acme-v1`, whose customer segment is not at the start of the id (`not_anchored` at stage 7); the same proof under `us-kms-nanorix-v1` and under `us-Customer-kms-acme-v1`, refused at stage 4 with `signing_mode_authority_mismatch` (`claimed_authority_id` names the id); the valid proof with its mode rewritten to `nanorix_only` after signing (`signature_mismatch`, `does_not_verify`, stage 7); `customer_only` under a Nanorix authority with `attestation.algorithm` `Ed448`, refused at stage 4 with `algorithm_unsupported` because the algorithm check runs first; and the legacy shape, a signed `nanorix_only` under a customer authority, which still verifies (`not_anchored` at stage 7) |

## The signed message

A v2.1 `nanorix_only` AuditProof is **not** signed over `final_hash` — that is
the v1.0 message. It is signed over the canonical-view hash,
`hex(sha512(jcs(canonical_view)))`. Getting this wrong is not a theoretical
concern: the corpus previously shipped with every success fixture signed over
the v1.0 message inside a document stamped `cdp_version: "2.1"`, so every one
of them failed to verify. The 8-step chain still reproduced perfectly, which is
why nothing caught it — chain integrity and signature validity are independent
properties, and only the latter was broken.

| Version | Signed message |
|---|---|
| `1.0` | `final_hash` (hex, prefix stripped) |
| `2.1` / `2.2` + `nanorix_only` or `customer_only` | recomputed canonical-view hash |
| `2.1` / `2.2` + any other mode (`dual_signature`, `tee_attested`, `customer-only`, ...) | not verifiable by this build (`algorithm_unsupported`, `found: "signing_mode=<mode>"`, stage 4) |

`2.0` is retired. Its signature covers a hash that no published rule lets a
verifier recompute from the document (the 2.0 projection carries it only as a
declared `document_hash` string), so no verifier can tie it to the document in
front of it. Every offline verifier that sweeps this corpus (Rust
`nanorix-verify`, Go, the Python SDK, the TypeScript ladder and flat `verify()`,
and the browser engine in `static/verify`) refuses it at the version gate
(stage 2, `cdp_version_unsupported`, `found: "2.0"`) whatever else the document
carries. The hosted route's parity test also sweeps this corpus, except category `11`
(the route is handed JSON its framework already parsed), but compares
validity only, and the hosted route keeps a separate check for 2.0-labelled
documents already delivered. It reaches `valid: false` on four of the five
2.0-labelled shapes in category `07` (a full 2.0 document fails that check's
required-field test, and a populated `customer_declared_activity_root` is refused
first) and `valid: true` on `0011_v2_0_stripped_projection`, which is built to be
well formed for it: every summary field, a complete `destruction.chain`, a
well-formed `destruction.chain_hash`, and a signature over the declared
`document_hash` string. That verdict carries the scope `declared_hash_only`, which
says that string is all the signature covers and that who signed is not
established; the parity test names that fixture as the one expected divergence,
and any other disagreement between the hosted route and the offline verifiers
fails it. Category `07` pins five
2.0-labelled shapes, and `09_tamper_patterns/c_version_downgrade` re-stamps a
2.1 document as `2.0` to show the same refusal.

`2.2` shares the `2.1` arm on purpose: it changed what a
document may carry, not how it is hashed or signed. The canonical view includes
`customer_declared_activity_root` whenever the document carries it, so a root
tampered after signing is a signature failure, not a new verdict. The separate
`customer_declared_activity_root_mismatch` verdict is reached only when the
customer's record is supplied beside a genuine proof and does not reproduce the
signed root; the corpus carries no records, so it does not exercise that path
(the CLI integration tests do).

Two gates run before the chain walk, at stage 2, whenever a document carries a
present non-null root. The root is signed only where the signed message is the
canonical view, so on `1.0` it is `unsigned_field_populated` — the
same verdict the reserved attestation slots get — and is never reported as
checked. On `2.1` / `2.2` the root must be a JSON string of `sha512:` + 128
lowercase hex (bare 128-hex accepted); anything else is `field_malformed` with
`field` and a short `reason`, named before any recompute consumes it. The empty
string is malformed, not absent: the canonical view binds it as a value.

`customer_only` differs from `nanorix_only` only in the mode string the view
carries. A customer authority is one whose `authority_id` contains
`customer-hsm-`, `customer-kms-`, `customer-tee-` or `customer-byo-`, compared
byte for byte (the issuer's rule). `customer_only` under any other authority,
the `us-kms-nanorix-v1` default included, is refused before the signature check;
`nanorix_only` under a customer authority is the shape issued before
`customer_only` existed and still verifies.

The signature covers the ASCII hex characters of that hash (128 bytes), not its
64 raw digest bytes.

## Documents the parser refuses

`nanorix-verify` parses a file with serde_json before it verifies anything, and
refuses what serde_json refuses: exit 1, an error on stderr, and no verdict. The
other verifiers parse with libraries that accept more, so each refuses the same
bytes itself and reports them as `required_field_missing` of `json_root` at
stage 1, the form they already gave a document they could not parse. Category
`11` pins that form in its `.expected.json` files, and the Rust sweep maps a
fixture serde_json refuses to it; a separate test checks that the CLI exits 1 on
it with nothing on stdout. Those fixtures are raw bytes, written by the generator, never
by hand.

serde_json counts depth in containers: the top-level object is one, and 128
nested arrays and objects are refused. A document that parses but is not an
object, such as `[]`, is not a parse failure: it is `required_field_missing` of
`cdp_version`, as in every verifier.

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
`sdk/python/src/nanorix/verifier/corpus_sweep.py` and
`sdk/typescript/src/verifier/corpus-sweep.ts`. All four compare `valid`,
`stage_reached` and the full `failure_reason` object against each fixture's
committed verdict, so a `reason` string that differs by one character in one
port fails that port's sweep.

One point worth stating so it is not mistaken for a divergence: all four
verifiers implement stage 8, trust-chain anchoring, which runs only when a key
list is supplied. None of the four sweeps supplies a key list, so the sweeps
do not exercise stage 8. The shared vectors in
`tools/nanorix-verify/fixtures/trust_chain/` do: their case
`customer_only_corpus_proof_resolves` anchors `13_customer_only/0000` at stage 8
in a key list published for its customer authority, and the Rust, Go, Python
and TypeScript vector tests and the browser verifier's test
(`scripts/test_browser_reference_verifier.mjs`) each check that case.
