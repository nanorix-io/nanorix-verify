# Population head vectors (draft)

`population_head_vectors.json` holds the shared vectors for the population
head format and its offline checks, described in Appendix A of
`docs/signed-containment-evidence.md`. `generate_population_head_vectors.py`
writes it with python3 `hashlib` and `cryptography` only, independently of the
Rust code it pins. `tests/population_head_vectors.rs` replays every case
through `verify_population` and compares the whole reported result, except
the free-text `detail` of a `head_malformed` reason.

## Formula

```text
canonical_bytes  = JCS(head)                      (RFC 8785)
head_hash        = "sha512:" + hex(SHA-512(canonical_bytes))
signed_message   = "nanorix-population-head-v1:" + hex(SHA-512(canonical_bytes))
                                                  (155 ASCII bytes)
signature        = "base64:" + b64(Ed25519(signed_message)), verified strictly
genesis link     = "sha512:" + hex(SHA-512(""))   (prev_head_hash at sequence 1)
tip_proof_hash   = "sha512:" + hex(leaf of the named AuditProof)
```

A proof signature is over a 128-character lowercase hex string. The head
message is 155 bytes and starts with the type tag, so neither signature can
stand for the other.

## Leaf rule

The leaf is read the way a transparency log reads it (Appendix A.1): the
attestation's `algorithm`, `key_id`, `public_key` and `signature`, exactly as
written, then an empty fifth field, with only `sha512:` removed from
`final_hash`. A proof has no leaf, so no head can name it, when `final_hash`
is not 128 lowercase hex characters, when `attestation` is not an object, when
one of those four fields is missing, not a string or holds NUL
(`verification_key` never stands in for `public_key`), or when `pqc_signature`,
`pqc_attestation` or `customer_pqc_attestation` is not null, on any
`cdp_version`. A proof carrying PQC has no leaf until verifiers check PQC.

Six pool proofs have no leaf: four copies of `a1`, and the documents
`not_a_proof_empty` and `not_a_proof_authority_only`, which hold no proof at
all. `a1_verification_key_only`
has its key under `verification_key` instead of `public_key`, and
`copy_without_public_key_has_no_leaf` shows a head that names `a1` failing (c)
when only that copy is handed. `a1_pqc_signature_added` carries a top-level
`pqc_signature`, which the signature does not cover, so it verifies with no
second leaf. `a1_customer_pqc_populated` fills a reserved slot and does not
verify. `a1_nul_in_key_id` holds NUL in a field the signature does not cover,
so it verifies with no leaf. Each refusal is also pinned by a unit test in
`src/population_head.rs` or `src/checkpoint.rs`.

## Regeneration

```bash
python3 -I generate_population_head_vectors.py           # rewrite the JSON
python3 -I generate_population_head_vectors.py --check   # exit 1 if stale
```

The output is deterministic: fixed seeds, fixed timestamps, sorted keys.

## Contents

| Key | What it is |
|---|---|
| `key_list` | A trust-chain key list naming fourteen test authorities, signed by the test-only identity. Every customer authority carries `emits_population_heads`; the two hosted authorities do not. |
| `key_list_variants` | The same key list with one or more records or one authority added, signed by the same identity, by case name. A case's `list_variant` names the one it uses. |
| `key_list_texts` | The signed key list as nine texts, none signed again, each with `member`: the first member its bytes hold that the signature does not cover, as `kind` (`repeated` or `not_carried`) and an RFC 6901 `pointer`, or null. `nanorix-verify population` refuses a text with a member as a setup error, exit 2. `genuine`, `defaults_left_out` (B's `revoked` and `archived_versions` left out, which the signature covers at their defaults) and `member_name_written_with_an_escape` (B's `revoked` written with the escape `\u0072`, which reads as the same name) and `pqc_signature_written_null` (`pqc_manifest_signature` written as `null`; neither signature member's value is compared) have none; `members_outside_the_signature` adds `superseded_by_hex` and `retired_at` to B's record and `public_key_hex` to D's; `member_name_escaped_in_the_pointer` adds `retired/at~`, pointed to as `retired~1at~0`; `archived_at_written_null` writes `archived_at` as `null` on B's active record, which the signature leaves out; `marker_written_false` writes a hosted authority's marker as `false`, which the signature leaves out; `authority_written_twice` writes a copy of B, holding B's key retired in hex, before the real one. |
| `head_texts` | The good chain's signed heads as six texts, each with `member`: the first member name it writes twice in one object, as `kind` `repeated` and an RFC 6901 `pointer`, or null. A parser keeps the last copy, so each text reads as the good chain's heads. `nanorix-verify population` refuses a text with a member as a setup error, exit 2. `genuine` has none; `issued_at_written_twice` writes head 1's `issued_at` twice; `head_written_twice` writes head 2's `head` twice, the earlier copy under authority B; `signature_written_twice` writes head 3's `signature` twice, the earlier copy head 1's; `key_version_written_twice` writes head 1's `signing_key_version` twice; `signature_written_twice_once_escaped` writes head 2's `signature` twice, the earlier copy's name with the escape `\u0073`. |
| `key_list_identity_fingerprint` | The pin. `tests/population_head_vectors.rs` verifies the list against it, because `verify_population` takes only a verified key list. |
| `proof_pool` | AuditProofs the cases draw from, by name. |
| `proof_stages` | The verification stage each pool proof that verifies reaches: 8 under the key list for the proofs of authorities A, B, D, E, F, H, L and M and both hosted authorities, and 7 against the embedded key only for the local-signer, revoked-authority, unregistered-key and unlisted-authority proofs, for authority K's proof, whose authority only a variant carries, and for the proofs whose signer an edit or a key the list does not hold leaves unshown. Authority J holds version 1 in both lists and version 2 twice in one list, and its proofs reach 8. `a1_no_signature` stops at 4. |
| `proof_failures` | The stage and failure reason, against the embedded key, of each pool proof that does not verify: `a2_forged`, which keeps `a2`'s leaf with `destruction_state` edited, `a1_customer_pqc_populated`, `a2_authority_set_hosted`, `a2_authority_set_local`, `a2_authority_deleted`, `not_a_proof_empty` and `not_a_proof_authority_only`. |
| `leaves` | The expected `tip_proof_hash` of each pool proof, null for the six proofs under "Leaf rule", which have no leaf. |
| `encoding` | Heads with their canonical bytes, head hash and signed message. |
| `cases` | Pool proof names, heads, whether the key list is supplied, and the exact expected result. |

## Cases

| Case | What it shows |
|---|---|
| `good_chain` | (a), (b), (c), (f) ok; (d), (e) need a transparency log, so the label is set. |
| `withheld_proof` | A head names a proof that was not handed: (c) fails. |
| `withheld_head` | A head was withheld: (a) and (b) fail, its proof is listed as unwitnessed. |
| `sequence_gap` | Correct link, wrong number: (b) fails. |
| `heads_handed_out_of_order` | Three heads handed as 3, 1, 2: nothing fails. |
| `chain_without_head_1` | Heads 2 and 3 alone: (a) holds, (b) fails with `sequence_gap`. |
| `fork` | Two heads at one sequence: (b) fails. |
| `wrong_authority` | Heads under another registered authority over A's proofs: (f) fails at the proofs' authority, before any signature is read. |
| `non_canonical_signature` | S replaced by S + L: (f) fails. Plain verification refuses it too; `small_order_key` proves strictness. |
| `small_order_key` | Identity key, R = identity, S = 0: strict verification refuses it, (f) fails. |
| `forged_authority_claim` | A head claims one authority's key and was signed with another's: (f) fails. |
| `relabelled_authority` | A head signed by A with its `authority_id` changed to B: the signature covers another head, so (f) fails. |
| `authority_switch_mid_chain` | Head 2, correctly linked and validly signed, is under another authority than head 1: (f) fails. |
| `two_authorities_at_sequence_one` | Two heads at sequence 1 under two authorities: the result names the first handed, (b) and (f) fail. |
| `local_signer_and_hosted_proofs_carry_the_label` | Proofs from signers that emit no heads: nothing fails, both listed as unwitnessed. |
| `head_names_local_signer_proof` | A head names a local-signer proof: (f) fails. |
| `head_names_hosted_proof` | A head names a hosted proof: (f) fails. |
| `head_under_hosted_authority_names_customer_proof` | A head under a hosted authority names a customer's proof: (c) holds, (f) fails before any key is read. |
| `head_under_unmarked_authority` | A head under an authority the key list carries without the marker: (f) fails. |
| `head_under_authority_not_in_the_key_list` | A head under an authority the key list does not carry: (f) fails with `head_signing_key_unknown`. |
| `proof_under_authority_not_in_the_key_list` | A proof under such an authority, with no head: listed with no handed head. |
| `no_key_list_knows_only_the_local_signer` | No key list: the local signer is listed as such, the hosted proof with no handed head. |
| `no_key_list` | No key list: (f) is not checked, nothing fails. |
| `proof_without_a_head` | A proof no head names: listed as unwitnessed; a cut tail is found only by (e). |
| `first_head_without_genesis_link` | Sequence 1 without the genesis link: (a) fails. |
| `tip_named_twice` | Two heads name the same proof: (c) fails. |
| `forged_copy_before_genuine` | A copy of proof 2 with a canonical-view field edited keeps the leaf; handed before the genuine proof, (c) and (f) fail on it. |
| `forged_copy_after_genuine` | The same copy handed after the genuine proof: (c) and (f) fail on it all the same. |
| `one_proof_named_twice_through_an_unsigned_field` | Two heads name proof 1 and a copy with `key_id` rewritten: different leaves, one signed document, so (c) fails. |
| `head_key_under_two_authorities` | The head's key is listed under authorities D and E: (f) fails. |
| `copy_without_public_key_has_no_leaf` | The head names proof 1's leaf, but the only copy handed has its key under `verification_key`: the copy has no leaf, so (c) fails and the copy is listed as unwitnessed with no tip. |
| `head_key_archived_under_a_revoked_authority` | The head's key is under authority F and among the archived versions of revoked authority G: (f) fails. |
| `head_key_listed_again_with_a_base64_prefix` | Authority I lists authority H's key with a `base64:` prefix; the prefix is stripped before keys are compared, so (f) fails. |
| `genesis_misplaced` | Head 2 carries the genesis link: (a) fails. |
| `head_links_past_the_head_below_it` | Head 3 carries the hash of head 1, a lower handed head but not the one directly below: (a) fails. |
| `named_proof_not_verified` | The only copy of the named proof does not verify: (c) and (f) fail. |
| `named_proof_has_no_signature` | The named proof is valid only as far as stage 4: (c) and (f) fail. |
| `head_signing_key_unknown` | Head 2 names a key version the key list does not hold: (f) fails. |
| `head_authority_revoked` | Heads under a revoked authority: (f) fails. |
| `head_algorithm_unsupported` | Head 2's key version is recorded as ML-DSA-65: (f) fails. |
| `named_proof_not_anchored` | The named proof verifies under its embedded key but not under the key list: (c) holds, (f) fails. |
| `identical_head_handed_twice` | One head handed twice: (a), (b), (c) read it once, (f) verifies both copies, nothing fails. |
| `identical_copy_with_a_bad_signature` | The second copy is signed with another key: (f) fails. |
| `same_head_under_two_key_versions` | One body under two key versions is two heads: (b) and (c) fail. |
| `chain_continues_across_key_rotation` | Head 1 under version 8 before it was archived, head 2 under version 1: nothing fails. Registration does not produce this shape today; gates marking on the rotation model. |
| `head_after_its_key_was_archived` | Head 2 is issued after its key was archived: (f) fails. |
| `head_before_its_key_took_effect` | Head 2 is issued before its key took effect: (f) fails. |
| `key_list_effective_from_unreadable` | The key's `effective_from` cannot be read: (f) fails. |
| `key_list_effective_from_lower_case` | The key takes effect in lower case `t` and `z`, outside the time grammar: (f) fails. |
| `key_list_effective_from_offset_plus_zero` | The key takes effect with the offset `+00:00`, outside the time grammar: (f) fails. |
| `key_list_effective_from_second_60` | The key takes effect at second 60, outside the time grammar: (f) fails. |
| `key_list_archived_at_unreadable` | The key's `archived_at` cannot be read: (f) fails. |
| `head_issued_before_proof` | The head was issued a second before the proof ended: (c) fails. |
| `head_issued_in_the_second_the_proof_ended` | Proof end 00:06:00.750, head 00:06:00: compared to the second, nothing fails. |
| `proof_end_time_unreadable` | The proof's `destroyed_at` cannot be read: (c) fails. |
| `proof_end_time_milliseconds` | Proof end `2026-10-28T00:30:00.123Z`, a three-digit fraction as the emitter writes it: nothing fails. |
| `proof_end_time_nanoseconds` | Proof end `2026-10-28T00:31:00.123456789Z`, a nine-digit fraction: nothing fails. |
| `proof_end_time_second_60` | Proof end at second 60, outside the time grammar: (c) fails. |
| `proof_end_time_lower_case_t` | Proof end with a lower case `t`, outside the time grammar: (c) fails. |
| `proof_end_time_lower_case_z` | Proof end with a lower case `z`, outside the time grammar: (c) fails. |
| `proof_end_time_space_separator` | Proof end with a space in place of `T`, outside the time grammar: (c) fails. |
| `proof_end_time_offset_plus_zero` | Proof end with the offset `+00:00` in place of `Z`, outside the time grammar: (c) fails. |
| `proof_end_time_offset_minus_zero` | Proof end with the offset `-00:00`, outside the time grammar: (c) fails. |
| `proof_end_time_offset_plus_14` | Proof end with the offset `+14:00`, outside the time grammar: (c) fails. |
| `proof_end_time_year_0000` | Proof end in year 0000, outside the time grammar: (c) fails. |
| `proof_end_time_fraction_13_digits` | Proof end with a thirteen-digit fraction, outside the time grammar: (c) fails. |
| `archived_key_with_no_end` | The key version is archived with no `archived_at`: (f) fails. |
| `head_issued_before_the_head_below_it` | Head 2 was issued a second before head 1: (b) fails. |
| `heads_share_a_second` | Two heads in one second: nothing fails. |
| `retired_key_backdates_a_head` | An archived key extends the chain with a head dated inside its window: its signature and window hold, and (b) fails. |
| `v1_0_proof_named` | A head names a version 1.0 proof, whose signature does not cover its authority: (f) fails. |
| `v1_0_proof_named_no_key_list` | The same head with no key list: (f) needs no key list to refuse it. |
| `v2_2_proof_named` | A head names a version 2.2 proof: nothing fails. |
| `proof_under_a_shared_key_named_by_the_other_authority` | Authority E lists authority D's key, and a head under D names a proof signed under E: (f) fails. |
| `proof_authority_writes_a_line` | A proof's authority holds a newline, a forged check line and a terminal erase sequence: (f) fails. The population CLI tests prove a reader's output escapes it. |
| `unwitnessed_attestation_pointer_claims_local` | A copy of the key version inside the attestation says the local signer, and the key list holds its key: `no_handed_head`. |
| `unwitnessed_attestation_pointer_claims_local_unlisted_key` | The proof names the local signer's authority under a key the list does not hold, with a numeric key version, and a copy of the key version inside the attestation says the local signer. No signature covers the copy, so it is not read: `no_handed_head`. |
| `unwitnessed_authority_set_to_local` | The proof's authority was changed to the local signer's name: `proof_not_verified`. |
| `unwitnessed_authority_set_to_hosted` | The proof's authority was changed to a hosted one: `proof_not_verified`. |
| `unwitnessed_authority_deleted` | The proof's authority was deleted, which reads as the hosted default: `proof_not_verified`. |
| `unwitnessed_empty_document` | An empty document: `proof_not_verified`. |
| `unwitnessed_authority_only_document` | A document holding only a hosted authority: `proof_not_verified`. |
| `unwitnessed_version_0_relabelled_local` | A key version 0 proof relabelled local verifies, and the key list holds its key under version 8: `no_handed_head`. |
| `unwitnessed_version_0_relabelled_local_no_key_list` | The same proof with no key list: its signature covers authority A, so it does not name the local signer: `no_handed_head`. |
| `unwitnessed_version_0_relabelled_local_unlisted_authority` | The same edit under an authority the list does not carry, with a key it does not hold: `no_handed_head`. |
| `unwitnessed_throwaway_key_keeps_a_marked_authority` | A key anyone can mint, the local signer's key version, and an authority that emits heads: `no_handed_head`. |
| `unwitnessed_local_version_on_a_hosted_authority` | The local key version under a hosted name, which the local signer no longer writes: `no_handed_head`. |
| `unwitnessed_local_name_under_a_listed_key` | The signature covers the local signer's name and the proof carries its key version, but the key list holds the key: `no_handed_head`. |
| `unwitnessed_local_name_on_version_1_0` | A version 1.0 proof names the local signer in fields its signature does not cover: `no_handed_head`. |
| `key_version_in_both_lists` | A key version is active and also archived, and the head is dated after the archived record's end: (f) fails. |
| `key_version_twice_in_one_list` | A key version is held twice among the active versions: (f) fails. |
| `key_reused_under_a_later_version` | One key under 1, archived, and 9, active, and a head past the archive end: (f) fails. |
| `key_version_with_two_keys` | Version 1 held twice with two different keys: (f) fails. |
| `key_retired_in_unpadded_base64` | Authority B's key is also retired under version 8 without padding, and the head is past that end: refused at `public_key_b64`. |
| `key_retired_in_hex` | The same record in hex, which decodes as base64 to 48 bytes: refused at `public_key_b64`. |
| `key_retired_with_trailing_bits` | The same record in standard base64 with a trailing bit set: refused at `public_key_b64`. |
| `key_retired_as_spki` | The same record as SPKI text, 16 characters and then the key's own standard text, which decodes to 44 bytes: refused at `public_key_b64`. |
| `key_retired_after_a_zero_byte` | The same record with a zero byte before the key, 33 bytes: refused at `public_key_b64`. |
| `key_retired_one_byte_short` | The same record with the key's last byte cut, 31 bytes: refused at `public_key_b64`. |
| `key_retired_empty` | The same record with an empty key: refused at `public_key_b64`. |
| `ml_dsa_65_record_with_an_ed25519_key` | B's 32-byte key under the label ML-DSA-65, whose keys are 1952 bytes: refused at `public_key_b64`. |
| `ml_dsa_65_key_in_unpadded_base64` | An ML-DSA-65 record of B with its key's text missing its padding: refused at `public_key_b64`. |
| `ml_dsa_65_key_in_hex` | The same key in hex, which decodes as base64 to 2928 bytes: refused at `public_key_b64`. |
| `ml_dsa_65_key_as_spki` | The same key as the base64 of its SPKI, 1974 bytes: refused at `public_key_b64`. |
| `ml_dsa_65_key_after_a_zero_byte` | The same key with a zero byte before it, 1953 bytes: refused at `public_key_b64`. |
| `ml_dsa_65_key_one_byte_short` | The same key with its last byte cut, 1951 bytes: refused at `public_key_b64`. |
| `key_under_another_authority_in_unpadded_base64` | Authority D lists B's key without padding: refused at `public_key_b64`. |
| `key_under_another_authority_in_hex` | Authority D lists B's key in hex: refused at `public_key_b64`. |
| `key_under_another_authority_as_spki_under_eddsa` | Authority D lists B's key as SPKI text under the label `EdDSA`; the label is read first: refused at `algorithm`. |
| `key_retired_under_a_lower_case_label` | B's key retired under version 8 with the label `ed25519`: refused at `algorithm`. |
| `key_retired_under_the_label_eddsa` | The same record with the label `EdDSA`, the JOSE name for Ed25519: refused at `algorithm`. |
| `key_retired_under_a_label_with_a_trailing_space` | The same record with the label `Ed25519` and a trailing space: refused at `algorithm`. |
| `key_retired_under_an_empty_label` | The same record with an empty label: refused at `algorithm`. |
| `record_under_an_unknown_algorithm` | An ML-DSA-87 record of B with a key of that length, 2592 bytes. ML-DSA-87 is not a known label: refused at `algorithm`. |
| `fingerprint_of_another_key` | B holds another key under version 8 with B's own fingerprint: refused at `public_key_fingerprint`. |
| `fingerprint_under_another_authority` | D holds another key with B's fingerprint: refused at `public_key_fingerprint`. |
| `ml_dsa_65_record_with_another_keys_fingerprint` | An ML-DSA-65 record of B, of its length, with B's Ed25519 fingerprint: the fingerprint is read under every label, refused at `public_key_fingerprint`. |
| `fingerprint_in_upper_case_hex` | B's key retired with its fingerprint in upper case hex: refused at `public_key_fingerprint`. |
| `version_with_a_leading_zero` | B holds another key archived under version `01`: refused at `signing_key_version`. |
| `version_with_a_plus_sign` | The same under version `+1`: refused at `signing_key_version`. |
| `version_with_a_leading_space` | The same under version ` 1`: refused at `signing_key_version`. |
| `version_with_an_underscore` | The same under version `1_0`: refused at `signing_key_version`. |
| `version_as_a_decimal_fraction` | The same under version `1.0`: refused at `signing_key_version`. |
| `version_with_a_letter` | The same under version `v8`, which a signature reads as 0: refused at `signing_key_version`. |
| `version_minus_zero` | The same under version `-0`: refused at `signing_key_version`. |
| `version_zero` | The same under version `0`: versions run from 1, refused at `signing_key_version`. |
| `version_minus_one` | The same under version `-1`: refused at `signing_key_version`. |
| `version_past_the_largest_integer` | The same under version 9223372036854775808, one past the largest signed 64-bit integer: refused at `signing_key_version`. |
| `ml_dsa_65_record_under_a_leading_zero_version` | B's ML-DSA-65 key, of its length, under version `01`: the version is read under every label, refused at `signing_key_version`. |
| `key_under_two_spellings_of_a_version` | Authority K holds one key under 1, archived, and 01, active, which a signature reads as 1: refused at `signing_key_version` of 01. |
| `record_of_another_algorithm_and_length` | The ML-DSA-65 key of the rows above, 1952 bytes in standard base64: inside the grammar, so nothing fails. |
| `key_retired_under_no_label` | B's key retired under version 8 with no label, which reads as Ed25519: the record is read, so B holds its key twice and (f) fails with `head_key_record_not_unique`. |
| `largest_version` | B holds another key under version 9223372036854775807, the largest signed 64-bit integer: inside the grammar, so nothing fails. |
| `refused_record_among_the_active_versions` | B holds an active record without padding: active records are read too, refused at `public_key_b64`. |
| `two_refused_records_under_two_authorities` | B holds a refused record under version 8 and D one under version 7. Authorities are read in byte order of `authority_id`, so the result names B's. |
| `two_refused_records_under_one_authority` | B holds a refused archived record under version 8 and a refused active one under version 9. Active records are read first, so the result names 9. |
| `two_refused_records_in_one_list` | B holds two refused archived records, version 9 before version 8. Each list is read in its order, so the result names 9. |
| `authority_id_with_a_cyrillic_letter` | An added authority whose id is B's with the Cyrillic letter U+0435 for the e of example, holding version 1 with another key, archived before the head: refused at `authority_id`, read before its records, so the version named is empty. |
| `authority_id_with_a_zero_width_space` | The same with B's id followed by a zero-width space: refused at `authority_id`. |
| `authority_id_with_a_trailing_space` | The same with B's id followed by a space: refused at `authority_id`. |
| `authority_id_in_upper_case` | The same with B's id in upper case: refused at `authority_id`. |
| `authority_id_empty` | The same with an empty id: refused at `authority_id`. |
| `authority_id_of_129_bytes` | The same with an id of 129 bytes: refused at `authority_id`. |
| `authority_id_in_upper_case_with_no_records` | An added revoked authority whose id is B's in upper case and which holds no record: its id is read all the same, refused at `authority_id`. |
| `authority_id_of_128_bytes_with_a_dot_and_an_underscore` | An added unmarked authority whose id is 128 bytes long and holds `.` and `_`, holding version 1 with a key no other authority lists: inside the alphabet, so nothing fails. |
| `refused_record_at_its_fingerprint_before_its_version` | B holds a record whose fingerprint and version `v8` are both outside the grammar. The fingerprint is read first, so the result names it. |
| `refused_record_beside_a_head_under_an_unlisted_authority` | A head under an authority the list does not carry, which alone fails with `head_signing_key_unknown`, under a list holding a refused record: the refusal is reported. |
| `refused_record_with_no_heads` | No heads, under a list holding a refused record: (f) still fails, and the proof is listed with no handed head. |
| `refused_record_with_a_malformed_head` | A malformed head under a list holding a refused record: (a) fails on the head and (f) on the list. |
| `refused_record_gives_no_signer_reason` | A local-signer proof and a hosted proof with no heads, under a list in which D holds the local signer's key in hex. A refused list gives no reason anything to rest on, so both are listed with no handed head, not `local_signer` and `unmarked_authority`. |
| `unwitnessed_hosted_name_on_an_unlisted_key` | A proof names a hosted authority and verifies only under its embedded key: `no_handed_head`. |
| `malformed_type_of_a_later_version` | A later head type: (a) fails at `head.type`. |
| `malformed_proof_sequence_zero` | `proof_sequence` 0: (a) fails at `head.proof_sequence`. |
| `malformed_proof_sequence_float` | `proof_sequence` 1.0: (a) fails at the head as a whole (empty field). |
| `malformed_proof_sequence_string` | `proof_sequence` "1": (a) fails at the head as a whole. |
| `malformed_proof_sequence_2_pow_53` | `proof_sequence` 2^53: (a) fails at `head.proof_sequence`. |
| `malformed_proof_sequence_negative` | `proof_sequence` -1: (a) fails at the head as a whole. |
| `malformed_unknown_field_in_head` | An extra field inside the signed head: (a) fails at the head as a whole. |
| `malformed_unknown_field_beside_head` | An extra field beside the head, outside the signed bytes: (a) fails at the head as a whole. |
| `malformed_authority_id_empty` | `authority_id` "": (a) fails at `head.authority_id`. |
| `malformed_authority_id_uppercase` | An upper case letter: (a) fails at `head.authority_id`. |
| `malformed_authority_id_129_bytes` | 129 bytes: (a) fails at `head.authority_id`. |
| `malformed_authority_id_non_ascii` | A non-ASCII character: (a) fails at `head.authority_id`. |
| `malformed_authority_id_missing` | No `authority_id`: (a) fails at the head as a whole. |
| `malformed_authority_id_beside_head` | `authority_id` beside the head, outside the signed bytes: (a) fails at the head as a whole. |
| `malformed_signature_without_base64_prefix` | The signature without `base64:`: (a) fails at `signature`. |
| `malformed_issued_at_second_60` | `issued_at` 23:59:60: (a) fails at `head.issued_at`. |
| `malformed_signing_key_version_empty` | An empty `signing_key_version`: (a) fails at `signing_key_version`. |
| `malformed_signing_key_version_writes_a_line` | A `signing_key_version` holding a newline, a forged check line and a terminal erase sequence: (a) fails at `signing_key_version`. |

A row that says "refused at" a field fails (f) with `key_list_record_refused`,
naming the authority, the key version as written and the first field of the
first record read outside the record grammar of Appendix A.3. One such record
refuses the whole key list, whatever the heads.

A malformed head reports its position in the handed list and a field. A head
that does not fit the shape (a missing or unknown field, or a value of the
wrong JSON type) reports the empty field; a value of the right type outside the
format reports its dotted path. The reason's `detail` is free text and is not
part of the expected result.

## Test-only keys

Every key is derived from the public seed
`SHA-256("nanorix-test-only-population-head-<label>")` and has no
relation to any production or ceremony key. The authorities
`customer-kms-example-a-v1`, `-b-v1`, `-d-v1`, `-e-v1`, `-f-v1`, `-g-revoked-v1`,
`-h-v1`, `-i-v1`, `-j-v1`, `-k-v1`, `-l-v1`, `-m-v1`, `customer-kms-example-revoked-v1`,
`us-kms-nanorix-v1` and `eu-kms-nanorix-v1` are fixture names. The three ML-DSA
keys are test bytes, not keys: SHAKE-256 of
`"nanorix-test-only-population-head-ml-dsa-<label>"`, 1952 bytes for
ML-DSA-65 (authority A's version 3 and authority B's version 8 records) and
2592 for ML-DSA-87. The SPKI prefix of `ml_dsa_65_key_as_spki` is the DER of
an ML-DSA-65 SubjectPublicKeyInfo up to the key. On purpose:

- the key list is signed by a test-only identity, and its fingerprint is a test
  pin, not a trust root;
- authority A's key version 8 is archived between heads 1 and 2, version 4
  takes effect after the heads, and versions 5 and 6 hold a time that cannot be
  read, for the key window cases;
- authority A's key version 2 is the identity point, for `small_order_key`;
- authority A's key version 3 is recorded as ML-DSA-65 with 1952 test bytes,
  for `head_algorithm_unsupported`;
- authority A's key version 7 is archived with no `archived_at`, for
  `archived_key_with_no_end`;
- authority E lists authority D's key, for `head_key_under_two_authorities`;
- authority G is revoked, has no active version and lists authority F's key
  as an archived version, for `head_key_archived_under_a_revoked_authority`;
- authority I lists authority H's key with a `base64:` prefix, for
  `head_key_listed_again_with_a_base64_prefix`;
- authority J holds key versions 1 and 2 twice, for `key_version_in_both_lists` and
  `key_version_twice_in_one_list`;
- authority K is carried only by the variant of
  `key_under_two_spellings_of_a_version`, which holds one key under 1 and 01;
- authority B's version 8 records in the variants hold B's own key, or the
  test key `authority-b-v8` where a case needs another key;
- authority L holds one key under 1 and 9, for `key_reused_under_a_later_version`;
- authority M holds version 1 with two keys, for `key_version_with_two_keys`;
- the revoked authority is marked revoked, for `head_authority_revoked`;
- `customer-kms-example-unlisted-v1` is named by proofs and heads and is not in
  the key list;
- `a5_unregistered_key` is signed with a key no authority lists, for
  `named_proof_not_anchored`.
