# Hybrid key-list vectors

Shared vectors for the BYOC hybrid key list. A BYOC
key list has two identity keys, Ed25519 and ML-DSA-87, and a relying party pins both with one value:

```
hybrid1-sha256:<lowercase hex SHA-256 of
  "nanorix-identity-hybrid-v1" 0x00 "Ed25519" 0x00 <32 key bytes> 0x00 "ML-DSA-87" 0x00 <2592 key bytes>>
```

The Ed25519 signature (`manifest_signature`) covers `signed_payload()`: RFC 8785 JCS of the list without its two
signature members. The ML-DSA-87 signature (`pqc_manifest_signature`) is pure ML-DSA with an empty context, over
`nanorix-key-list-pqc-v1`, a 0x00 byte, and the same payload. Every Ed25519 record names its ML-DSA-65 partner, a
record of the same authority, in `pqc_partner_version`.

The Rust library is the reference. `tests/hybrid_key_list_vectors.rs` builds every file here from fixed seeds and
checks it against the reference. Go (`trust_chain_hybrid_vectors_test.go`), Python
(`sdk/python/tests/test_trust_chain_hybrid_vectors.py`), TypeScript
(`sdk/typescript/tests/trust_chain_hybrid_vectors.test.ts`) and the browser page
(`scripts/test_browser_reference_verifier.mjs`) replay every case. The auditor portal
(`scripts/test_auditor_portal_anchor.mjs`) replays five of them, and the hosted verify route's own test one, `ed25519_only_record_under_hybrid_pin`.

## Format

`cases.json` holds `cases`. Each case has a `name`, a `note`, a `kind`, a `pin` and two results:

| `kind` | Files | What a verifier does |
|---|---|---|
| `key_list` | `key_list` | Loads the list under the pin. |
| `record` | `key_list`, `proof` | Loads the list, then verifies the proof against it under the pin. |
| `two_lists` | `earlier`, `later` | Loads both lists under the pin, then compares their records and partners. |

- `expected` is what the Rust reference gives. It is one of:
  - `{"refusal": <kind>}`, with the kind named as `ManifestError::kind` names it, or `load_failed` for bytes that are
    not a key list;
  - `{"loaded": true, "partners": {<authority>: {<Ed25519 version>: <partner version>}}}`;
  - a stage 8 verdict (`valid`, `stage_reached`, `status`, `failure_reason`);
  - `{"same_partners": true}`.
- `expected_without_ml_dsa` is what a verifier without an ML-DSA check gives: `{"refusal": "hybrid_check_unavailable"}`
  for every hybrid pin, and `expected` for every other pin. Such a verifier never checks one half of a hybrid list.
- `expected_by_verifier`, on a few cases only, maps `go`, `python` or `typescript` to the refusal that verifier gives
  where its kind differs from the reference's today. Its replay is held to that result instead of `expected`. Every
  such result is a refusal.

Which verifier is held to which result:

- Go 1.27 and later, Python with `cryptography` 50, and TypeScript are held to `expected`.
- A Go build without `crypto/mldsa` (before Go 1.27, or `GOFIPS140=certified` or `v1.0.0`), the browser page and the
  portal are held to `expected_without_ml_dsa`.
- The browser page and the portal give a signed record under a hybrid pin a typed stage 6 refusal,
  `algorithm_unsupported` with `found` `ML-DSA-87 key list check (hybrid pin)`, because they cannot load the list.
  The browser page refuses an unsigned one at stage 7 (`signature_mismatch`, `signature_or_public_key_missing`)
  before it reads the list.

## Record verdicts under a hybrid pin

No verifier checks a record's ML-DSA-65 half yet. Under a hybrid pin, a record whose key resolves
in the list is refused at stage 8 with `algorithm_unsupported` and `found` `ML-DSA-65 record check (hybrid pin)`.
The case `ed25519_only_record_under_hybrid_pin` pins it. An unsigned record, which without a pin ends valid at stage 4
with its signature not checked, gets the same refusal at stage 4 (`unsigned_record_under_hybrid_pin`). The other two consumers of this gate have no shared vector,
because only the Rust verifier has them:

- version 1 population heads, refused with `head_algorithm_unsupported` and `found` `Ed25519 (hybrid pin)`
  (version 2 heads have both halves checked: `tests/population_head_v2.rs`);
- BoundaryAttestations, refused with `algorithm_unsupported` on `trust_chain_pin`.

Their Rust tests are `a_version_1_head_under_a_hybrid_pin_fails_f_with_the_typed_reason` in
`src/population_head.rs` and `no_boundary_attestation_is_valid_under_a_hybrid_pin` in `tests/boundary_attestation.rs`.

## Regeneration

ML-DSA signing in aws-lc-rs 1.18.1 is hedged and takes no randomness option, so each regeneration writes a new,
equally valid `pqc_manifest_signature`. The Rust test therefore compares every file with that member's value masked,
and it also runs the reference on every committed file and requires the committed `expected`. A committed signature
that does not verify cannot pass for one that does. Every other byte is deterministic.

aws-lc-rs cannot make two signatures:

- one with the tag given as the FIPS 204 context instead of in the message (`tag_as_context`);
- a HashML-DSA one (`hash_mldsa_signature`).

`scripts/gen_hybrid_foreign_signatures.py` makes both with pyca/cryptography over the committed base list's payload
and writes `foreign_signatures.json`, which records the payload's SHA-512. The Rust test refuses a stale file.
Python's replay checks that each signature in that file verifies in its own mode, and the Rust test requires the two
committed lists to carry exactly those signatures, so both cases refuse real signatures, not noise.

To regenerate after an intended change:

```
NANORIX_REGEN_HYBRID_KEY_LIST_VECTORS=1 cargo test -p nanorix-verify --test hybrid_key_list_vectors
python3 scripts/gen_hybrid_foreign_signatures.py   # only when hybrid_v1's payload changed
NANORIX_REGEN_HYBRID_KEY_LIST_VECTORS=1 cargo test -p nanorix-verify --test hybrid_key_list_vectors
cargo test -p nanorix-verify --test hybrid_key_list_vectors
```

The seeds are fixed and public, made for these vectors only. No key here signs anything outside them.
