# Signed Containment Evidence — specification and reference verifiers

An AuditProof is a document that says a compute workload ran in a contained
environment and was destroyed, and carries enough evidence for someone who was
not there to check that claim offline.

This repository holds the specification and four reference verifiers. They are
Apache-2.0 licensed, and they agree with each other byte-for-byte.

Nothing here talks to Nanorix. A verifier reads a document from disk and
answers from the document's own contents plus, optionally, one published trust
anchor. That is the point: evidence a party has to ask its issuer to validate
is not evidence.

## What a proof contains

An eight-step SHA-512 chain over the destruction sequence, each link computed as

```
SHA-512( prev_hash ‖ 0x00 ‖ subsystem ‖ 0x00 ‖ "destroy" ‖ 0x00 ‖ method ‖ 0x00 ‖ timestamp )
```

seeded from `SHA-512("")`, plus an Ed25519 attestation over the canonical form
of the document — a fixed 15-field view serialised under RFC 8785 JCS, hashed
with SHA-512, and signed as its ASCII-hex representation.

The eight steps, their order, their names, and the hash and signature
algorithms do not change. They are fixed by specification, not by policy, and
every implementation here depends on that.

## Two questions, kept apart

A verifier climbs a stage ladder, and where it stops is the answer:

- **Integrity** — is this document internally consistent and unmodified? Answerable
  from the document alone, using the key embedded in it.
- **Authenticity** — does that key belong to the party the document names? Not
  answerable from the document alone. It requires resolving the key against a
  published trust anchor.

A document can have perfect integrity and no authenticity — a self-consistent
proof signed by a key nobody vouches for. Reporting that as "verified" is the
failure this ladder exists to prevent, so the two are reported separately and
the exit code distinguishes them.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The signature was checked and it verified. |
| `1` | Verification failed — a chain link, a canonical hash, or a signature did not agree. |
| `2` | Usage or I/O error. Nothing was verified. |
| `3` | The chain verified, but this build could check no signature on the document. Integrity is **not** established. Do not accept this in an automated gate. |

Exit `3` is deliberate. An earlier design returned a partial verdict for a
document whose signing mode the build did not understand, which let an unknown
mode read as a soft pass — a downgrade an attacker chooses. An unverifiable
document is now rejected rather than partially reported.

## Implementations

| Language | Path | Notes |
|---|---|---|
| Rust | `tools/nanorix-verify` | CLI, and the implementation the corpus is generated from |
| Go | `tools/auditproof-verifier-go` | Library + CLI |
| Python | `sdk/python/src/nanorix/verifier` | Library |
| TypeScript | `sdk/typescript/src/verifier` | Library; runs in a browser |

`governance/verify-types` holds the failure taxonomy the four share. A failure
reason is part of the wire contract: a verifier that rejects a document must say
which of the fixed reasons applies, so two implementations disagreeing is
detectable rather than a matter of prose.

## Conformance

`tools/nanorix-verify/fixtures/corpus` holds 100 cases across nine categories —
successful single and multi-step proofs, chain mismatches, invalid signatures,
region and authority mismatches, unsupported versions, canonical-hash drift, and
a family of targeted tamper patterns. Each case ships with its expected verdict.

An implementation conforms when it returns the expected verdict for all 100. The
corpus is generated, not hand-written; the generator ships with it, so the
expected verdicts can be regenerated and diffed rather than trusted.

## Specification

`docs/signed-containment-evidence.md` is the normative document: scope and
non-goals, chain construction, the canonical view, the downgrade rule, the stage
ladder, conformance requirements, and a mapping to the OWASP Agentic Security
Initiative top-ten risks — including the entries this evidence does **not**
address, which are listed as explicitly as the ones it does.

## Reading the boundary

This repository is the verification algorithm. It is deliberately complete: an
auditor can check a proof with no access to the party that issued it, and a
third party can write a fifth implementation from the specification alone.

It is not the capsule runtime, the destruction mechanism, or the trust root that
identifies signing authorities. Those stay closed. Publishing a verifier is what
makes evidence checkable; publishing the issuer would make it forgeable.

## License

Apache-2.0. Copyright 2026 Nanorix Inc. See `LICENSE`.
