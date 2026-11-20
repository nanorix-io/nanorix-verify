# Record transcript vectors

`record_transcript.json` holds the shared cases for the bytes a record's ML-DSA-65 signature covers, the record
transcript. The Rust builder is `src/pqc_transcript.rs` and `tests/pqc_transcript_vectors.rs` runs every case
through it. The Go, Python, TypeScript and browser engines are to build the same bytes and give the same refusals on
every case here.

## The rule

The transcript is nine ASCII fields joined by single 0x00 bytes, with no 0x00 at the end:

```text
nanorix-pqc-v1  cdp_version  capsule_id  key_id  signature_algorithm  pqc_algorithm
ed25519_public_key  pqc_public_key_fingerprint  canonical_hash_raw
```

Its source is the specification, as amended by H3 and by the 2026-11-18 sentence on each field's text form. The fields
are:

| Field | Form |
|---|---|
| `nanorix-pqc-v1` | this text, always first |
| `cdp_version` | exactly `2.1` or `2.2` |
| `capsule_id` | the record's capsule id, not empty |
| `key_id` | the Ed25519 attestation's `key_id` as the record carries it, not empty |
| `signature_algorithm` | exactly `Ed25519` |
| `pqc_algorithm` | exactly `ML-DSA-65` |
| `ed25519_public_key` | the attestation's `public_key` text as the record carries it: `base64:` and the standard, padded base64 of the 32 key bytes, which must re-encode to the same text |
| `pqc_public_key_fingerprint` | `sha256:` and the lowercase hex SHA-256 of the 1952 bytes of the ML-DSA-65 public key; the builder computes it from the key bytes |
| `canonical_hash_raw` | the 128 lowercase hex characters the record's Ed25519 signature covers |

The record's `signing_mode` must be exactly `nanorix_only` or `customer_only`. It is checked but is not one of the
nine fields: H3 gives those two modes this last field and gives no other mode or version one.

A builder refuses its inputs, and builds nothing, when:

1. any text field holds a 0x00 byte (`NulByte`, naming the field) or a byte above 0x7F (`NonAsciiByte`, naming the
   field). This check runs first, on every text field (`cdp_version`, `signing_mode`, `capsule_id`, `key_id`,
   `signature_algorithm`, `pqc_algorithm`, `ed25519_public_key`, `canonical_hash_raw`, in that order), before any
   other check; within one field, a 0x00 byte is reported before a byte above 0x7F;
2. `cdp_version` is anything other than `2.1` or `2.2` (`CdpVersionUnsupported`);
3. `signing_mode` is anything other than `nanorix_only` or `customer_only` (`SigningModeUnsupported`);
4. `capsule_id` is empty (`CapsuleIdEmpty`), or `key_id` is empty (`KeyIdEmpty`);
5. `signature_algorithm` is not `Ed25519` (`SignatureAlgorithmUnsupported`), or `pqc_algorithm` is not `ML-DSA-65`
   (`PqcAlgorithmUnsupported`);
6. `ed25519_public_key` is not in the form above (`Ed25519PublicKeyMalformed`);
7. the ML-DSA-65 public key is not 1952 bytes (`PqcPublicKeyLength`);
8. `canonical_hash_raw` is not exactly 128 lowercase hex characters (`CanonicalHashMalformed`).

Each refusal case breaks at most one of rules 2 to 8, so their order does not change any case's answer. Rule 1 runs
first, and 12 of its cases also break their own field's form rule (a 0x00 or a byte above 0x7F in `cdp_version`,
`signing_mode`, `signature_algorithm`, `pqc_algorithm`, `ed25519_public_key` or `canonical_hash_raw`): their answer
is rule 1's because rule 1 runs first. Two cases carry two faults each and pin that order:
`two_faults_cdp_version_1_0_and_capsule_id_holds_nul` expects `NulByte` on `capsule_id`, not
`CdpVersionUnsupported`, and `two_faults_key_id_holds_non_ascii_then_nul` (a byte above 0x7F, then a 0x00, in
`key_id`) expects `NulByte`.

## The file

- `valid`: four cases, one for each of `2.1` and `2.2` with each of `nanorix_only` and `customer_only`. Each gives
  every input (the ML-DSA key as hex in `pqc_public_key_hex`), the expected fingerprint, the expected transcript as
  hex and its length in bytes. Two of them use one ML-DSA key and two the other, so the file holds two fingerprints:
  compute each from the key the case gives.
- `refusals`: each case names a `base` valid case and, in `set`, the inputs it changes. Build the base case's inputs,
  apply `set`, and expect the refusal `expected_error`, with `expected_field` naming the field for `NulByte` and
  `NonAsciiByte` (null otherwise).
- `pqc_public_key_source`: the ML-DSA-65 public keys are groups 0 and 1 of `fixtures/mldsa/acvp_siggen_ml_dsa_65.json`,
  two NIST ACVP keys; `group_by_valid_case` names each valid case's group. A refusal case uses its base case's key
  unless its `set` gives one.

The expected bytes were computed by a separate Python script written from the ADR text, not by the Rust builder.
