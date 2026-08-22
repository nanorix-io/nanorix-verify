# Security — disclosed verification holes and how to report one

This file exists because a verifier that has never been attacked is not evidence of
anything. Every hole below was found by writing the attack first and confirming the
released verifier returned exit 0 on it. Each entry names the reproducing test, so you can
read the break before you read the fix.

## Disclosed holes, closed in 1.1.0 (2026-08-19)

All five accepted a document an attacker could edit by hand, holding no key, against a
genuine signed proof. Documents carrying these shapes verified under 1.0.x and fail under
1.1.0, which is why that release is a minor version and not a patch.

| # | Hole | What an outsider could do | Fixed by | Reproducing test |
|---|---|---|---|---|
| 1 | **Unsigned residency** | The region was read from an unsigned top-level field, so an auditor applying a residency pin could be told a proof was pinned to a region it was never pinned to. | Region resolves only from the signed `capsule_started` activity event. | `tools/nanorix-verify/src/lib.rs` · `residency_pin_ignores_unsigned_region_fields` |
| 2 | **Trusted streaming leaves** | `streaming_egress_chunk` leaves were trusted without recomputing their Merkle root, so disclosed chunks could be altered or removed silently. | The root is recomputed whenever the leaves are present; truncation is distinguished from a gap. | `tools/nanorix-verify/src/streaming_merkle.rs` · `altered_chunk_hash_is_caught`, `a_malformed_leaf_cannot_masquerade_as_truncation` |
| 3 | **Injectable reserved slots** | Seven attestation slots sit outside the canonical signed view and no signer populates them, so an outsider could add fabricated `witness_signatures` or residency claims to a genuine proof and the verifier reported it untampered. | A populated reserved slot is rejected. `per_event_attestations` is excluded because genuine proofs carry it, signed by the customer's own key. | `tools/nanorix-verify/src/lib.rs` · `every_populated_reserved_slot_is_rejected`, `empty_array_in_a_reserved_slot_is_rejected` |
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
