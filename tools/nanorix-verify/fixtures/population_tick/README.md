# Population tick vectors

Shared vectors for the population tick of the specification (Amendment 2026-11-16, A4 and A5), whose format is Appendix A.2.1
of `docs/signed-containment-evidence.md`. Every key is derived from a fixed, public, test-only seed and has no relation
to any production or ceremony key.

`population_tick_vectors.json` holds:

- `keys`: two log key versions, `log` and `other`, each an Ed25519 key and its ML-DSA-65 partner (`base64:`).
- `salt_key_hex`: the test-only salt key the ticks' salts are derived from.
- `encoding`: three signed ticks under the `log` key, each with its canonical bytes, both signed messages (the
  ML-DSA-65 one in hex, because it holds a 0x00 byte), the head hash it seals, its salt, its seal and its log key
  pin. Ticks 2 and 3 seal one head, under different salts.
- `cases`: 43 tick texts, each with the key version to check it under and the result a reader gives:
  - `parse`, checked in this order: `not_json`; `{"member_written_twice": <RFC 6901 pointer>}`; `not_canonical`
    (the bytes are not the RFC 8785 form of the JSON they hold: other whitespace, member order or escapes);
    `{"field": <path>}` for a member written `null`; `shape` (a missing or unknown member, or a value of the wrong
    JSON type); `{"field": <path>}`, the first value outside the format; or `ok`;
  - `signatures`, when the text parses: `ok`, `log_key_pin_mismatch`, `ed25519_does_not_verify` or
    `ml_dsa_65_does_not_verify`, checked in that order.

The timestamp token in tick 2 is placeholder bytes: a reader of this format checks a token's form only.

`tests/population_tick_vectors.rs` recomputes every byte string from the primitives, with the tags and separators
written out in the test, and requires the library to give the same values; then it runs the library on every case.
ML-DSA signing is hedged, so a rebuilt file has new ML-DSA signatures; the committed ones are checked by verifying
them. Rewrite the file after an intended change with `NANORIX_REGEN_POPULATION_TICK_VECTORS=1`.
