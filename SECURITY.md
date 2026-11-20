# Security — disclosed verification holes and how to report one

This file exists because a verifier that has never been attacked is not evidence of
anything. Every hole below was found by writing the attack first and confirming the
released verifier returned exit 0 on it. Each entry names the reproducing test, so you can
read the break before you read the fix.

## Disclosed holes, closed in 1.3.0 (fixed 2026-10-15, 2026-10-21 and 2026-10-22, and 2026-10-30 for the hash-anchor part of 8)

All three let a document or a receipt bundle verify that should have failed. Inputs carrying
these shapes verified under 1.2.0 and fail under 1.3.0, which is why that release is a minor
version and not a patch.

| # | Hole | What an outsider could do | Fixed by | Reproducing test |
|---|---|---|---|---|
| 6 | **A retired version accepted** | A document labelled `cdp_version: "2.0"` verified, including a genuine 2.1 proof relabelled 2.0. A 2.0 signature covers a declared `document_hash` string, not the document's content. | Version 2.0 is refused at stage 2 as `cdp_version_unsupported` in all four verifiers. The supported versions are 1.0, 2.1 and 2.2. | `tools/nanorix-verify/src/lib.rs` · `subb_2_0_document_with_anchored_key_is_refused_at_stage_2`; `tests/integration_tests.rs` · `cli_v2_0_proof_under_a_pin_is_refused_at_the_version_gate`; corpus `07_failure_version_unsupported/0010` to `0014`, `09_tamper_patterns/c_version_downgrade/0000` |
| 7 | **An authority pin met by an unsigned label** | `--required-authority-id` was compared with `signing_authority.authority_id`, a field the signature does not cover, so a label added after signing could match the pin. | The pin compares the top-level `authority_id`, which 2.1 and 2.2 sign. An unsigned `signing_authority` that disagrees with it is refused, and a 1.0 document, which signs no authority, matches a pin only on the default `us-kms-nanorix-v1`. | `tools/nanorix-verify/src/lib.rs` · `policy_pin_unsigned_signing_authority_cannot_match_pin`, `policy_pin_unsigned_authority_on_v1_0_and_v2_0_refused_first`; corpus `06_failure_authority_unknown/0010` to `0014` |
| 8 | **A receipt root the signature does not commit to** | `bundle verify` checked a receipt's Merkle inclusion against the root carried in the bundle, and the signature over `step_8_chain_hash`, but never checked that the signed Step 8 value commits to that root. A self-consistent root over other receipts, beside a genuine signature, verified. A bundle signed over `document_canonical_hash` verified with nothing binding its receipt, and the signature was checked over whatever string followed the `sha512:` prefix. | All four verifiers recompute Steps 1 to 8 from the bundle's timestamp and roots and require the result to equal the signed `step_8_chain_hash` (`step_8_mismatch`). A bundle signed over the document's canonical hash reports the signature authentic and the receipt not bound (`receipt_not_bound`), and the CLI exits non-zero. `malformed_canonical_hash_anchor` refuses any `document_canonical_hash` that is not `sha512:` and 128 lowercase hex characters, before the signature is checked. | `tools/nanorix-verify/tests/bundle_cross_impl.rs` · `fixture_corpus_matches_expected_outcomes`; fixtures `fixtures/bundles/d_root_not_committed`, `e_parent_root_removed`, `f_altered_timestamp`, `g_v2_signature_under_legacy_label`, `h_v2_not_bound_idx0`, `h_v2_not_bound_idx1`, and for the anchor `p_population_head_message_as_canonical_hash`, `q_canonical_hash_uppercase`, `r_canonical_hash_too_short`, `s_canonical_hash_trailing_newline`, `t_canonical_hash_prefix_only` |

None let anyone forge a signature. Each was a value the signature does not cover being
trusted, the same class as the five below.

## Disclosed holes, closed in 1.1.0 (fixed 2026-08-19; released 2026-08-22)

All five accepted a document an attacker could edit by hand, holding no key, against a
genuine signed proof. Documents carrying these shapes verified under 1.0.x and fail under
1.1.0, which is why that release is a minor version and not a patch.

| # | Hole | What an outsider could do | Fixed by | Reproducing test |
|---|---|---|---|---|
| 1 | **Unsigned residency** | The region was read from an unsigned top-level field, so an auditor applying a residency pin could be told a proof was pinned to a region it was never pinned to. | Region resolves only from the signed `capsule_started` activity event. | `tools/nanorix-verify/src/lib.rs` · `residency_pin_ignores_unsigned_region_fields` |
| 2 | **Trusted streaming leaves** | `streaming_egress_chunk` leaves were trusted without recomputing their Merkle root, so disclosed chunks could be altered or removed silently. | The root is recomputed whenever the leaves are present; truncation is distinguished from a gap. | `tools/nanorix-verify/src/streaming_merkle.rs` · `altered_chunk_hash_is_caught`, `a_malformed_leaf_cannot_masquerade_as_truncation` |
| 3 | **Injectable reserved slots** | Seven attestation slots sit outside the canonical signed view and no signer populates them, so an outsider could add fabricated `witness_signatures` or residency claims to a genuine proof and the verifier reported it untampered. | A populated reserved slot is rejected. `per_event_attestations`, which also sits outside the signed view, is excluded because genuine proofs carry it. It is accepted unchecked: anyone holding the file can add or change its entries, and they prove nothing about who signed. This part is still open. | `tools/nanorix-verify/src/lib.rs` · `every_populated_reserved_slot_is_rejected`, `empty_array_in_a_reserved_slot_is_rejected` |
| 4 | **Forgeable lineage** | A parent set with no `parent_proofs_merkle_root` returned "no check to run" instead of failing, so lineage could be forged by deleting one field. | Fails closed. | `tools/nanorix-verify/src/lib.rs` · `parent_set_without_root_is_rejected`; `tests/wave_n_fixtures.rs` · `stripping_the_parent_root_from_a_genuine_proof_is_rejected` |
| 5 | **Chain identity by count** | Eight steps was a count, not an identity. The walk hashed whatever subsystem the document declared, so genuine hashes could be relabelled. | The walk hashes the canonical `(subsystem, method)` at each index. | `tools/nanorix-verify/src/lib.rs` · `genuine_hashes_with_a_forged_subsystem_label_are_rejected` |

Earlier material from us said "four holes". It was five. The undercount was ours and this
table is the correction.

What these were not: none of them let anyone forge a signature or alter signed content.
Each one was a field the signature did not cover being read as if it did, or a check that
reported nothing instead of failing. That class is worth naming because it is the class
every canonicalisation-based scheme is exposed to, and it is the class an implementer of
this specification should test for first.

## Reporting a hole

Open an issue, or if you would rather not disclose in public first, email
security@nanorix.io. Include the document that verifies when it should not, and the
command you ran. We will reproduce it, credit you if you want credit, add the reproducing
test here, and cut a release. The fix is not done until the attack is in this table.
