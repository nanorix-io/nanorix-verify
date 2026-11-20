# Stage 8 vectors

Key lists, proofs and verdicts for the stage 8 check (a proof's signing key resolved in a signed key list pinned by the list's identity fingerprint). The Rust library is the reference; the Go, Python and TypeScript verifiers replay every case and must give the same `valid`, `stage_reached` and `failure_reason`, or the same refusal. The browser verifier's test (`scripts/test_browser_reference_verifier.mjs`) replays the key-list marker and algorithm cases and `customer_only_corpus_proof_resolves`, which anchors the corpus proof `13_customer_only/0000` under a key list published for its customer authority.

## Layout

- `cases.json` lists every case: `name`, `note`, `key_list`, `proof`, `pin`, `required_authority_id` (null when none) and `expected`.
- `key_lists/` and `proofs/` hold the documents the cases name.
- `expected` is either `{ "valid", "stage_reached", "failure_reason" }` or `{ "refusal": "<kind>" }`. A refusal happens when the key list is loaded, before any proof is read. The kinds are `load_failed`, `malformed`, `fingerprint_mismatch` and `signature_invalid`.

## Regeneration

Everything is built from fixed seeds through `TrustChainManifest::build_and_sign` by `tools/nanorix-verify/tests/trust_chain_vectors.rs`. That test rebuilds the set in memory and fails if a committed file differs, and it checks each computed verdict against a hand-written intent so a change in the reference cannot silently rewrite the expectation. To rewrite the files after a deliberate change:

```
NANORIX_REGEN_TRUST_CHAIN_VECTORS=1 cargo test -p nanorix-verify --test trust_chain_vectors
```

## Known limits

- `algorithm` on a key record is in the signed bytes when it is present. Every hosted key record carries it.
- `emits_population_heads` on an authority is in the signed bytes when it is true. When false, or absent, it is not, so a false marker changes nothing the signature covers (`marker_false_signs_as_absent`). The other verifiers rebuild the same view, and none of them reads the marker for anything else.
- A key list field the reference does not read is outside the signature. The reference re-serializes the list from known fields only, so an added unknown field changes nothing the signature covers. The cases `unknown_fields_are_not_covered` and `pqc_slot_is_not_covered` record this.
- A key list field the reference reads, of the list or of a record, written twice, the marker among them: the reference refuses the list when it loads it (`load_failed`); the Go, Python and TypeScript verifiers keep the last copy, which is the one their signature check covers. An authority id written twice keeps its last copy, as in the other verifiers. No vector uses one.
- Inside a member it does not read, the reference checks only the JSON syntax: it reads such a member without checking that its strings are UTF-8, how large its numbers are or how deep it nests. The other verifiers read the whole list, so each can refuse, as `load_failed`, a list the reference loads: Python and TypeScript refuse invalid UTF-8 there and Go replaces it, Python refuses an integer past its digit limit and very deep nesting, and Go refuses a number past the float64 range. No vector uses one.
- A lone surrogate escape such as `\ud800` in a field the reference reads: the reference refuses the list (`load_failed`). Python and TypeScript read it and write the same escape into the signed view, so the list fails its signature check (`signature_invalid`) unless that escaped text is what was signed; Go reads it as U+FFFD. No vector uses one.
- The Go verifier cannot tell a 32-byte identity key that is not a curve point from a bad signature. The reference reports `malformed` for such a key; Go reports `signature_invalid`. No vector uses one.
- For a proof key that is not a curve point the reference reports `public_key_malformed`; Go reports `does_not_verify`. No vector uses one.
