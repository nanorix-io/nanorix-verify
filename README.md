# Signed Containment Evidence — specification and reference verifiers

An AuditProof is a document saying that a compute workload ran in a contained
environment and was then destroyed. It carries enough evidence that someone who
wasn't there can check the claim.

This repository holds the specification and four verifiers that implement it.
Everything here is Apache-2.0. The four agree with each other byte for byte.

None of them contacts Nanorix, or anything else. A verifier reads a file from
disk and answers using what's in the file, plus one published trust anchor if
you supply it. There's no HTTP client in any of the four implementations, so
this isn't a policy we're asking you to trust.

## What a proof contains

Eight steps covering the destruction sequence, chained with SHA-512. Each link
is computed as:

```
SHA-512( prev_hash ‖ 0x00 ‖ subsystem ‖ 0x00 ‖ "destroy" ‖ 0x00 ‖ method ‖ 0x00 ‖ timestamp )
```

starting from `SHA-512("")`.

On top of that sits an Ed25519 attestation. What gets signed is a fixed 15-field
view of the document, serialised with RFC 8785 JCS and hashed with SHA-512. The
signature covers the ASCII-hex form of that hash, not its raw bytes.

The eight steps, their order and names, and the two algorithms don't change.
Every implementation here relies on that.

## Integrity and authenticity are different questions

A verifier answers two things, and where it stops tells you which one it got to.

**Integrity** asks whether the document is internally consistent and hasn't been
modified. You can answer that from the document alone, using the key embedded in
it.

**Authenticity** asks whether that key actually belongs to whoever the document
names. You can't answer it from the document. It needs a trust anchor from
somewhere else.

So a proof can be perfectly self-consistent and still be signed by a key nobody
vouches for. Calling that "verified" is the mistake the stage ladder is built to
avoid, which is why the two are reported separately and why the exit codes tell
them apart.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Signature checked, and it verified. |
| `1` | Verification failed. A chain link, a canonical hash, or a signature didn't agree. |
| `2` | Usage or I/O error. Nothing was verified. |
| `3` | The chain verified, but this build couldn't check any signature on the document. Integrity is **not** established. Don't accept this in an automated gate. |

Code 3 replaced something worse. An earlier version returned a partial verdict
when it met a signing mode it didn't understand, which meant an unknown mode
read as a soft pass. Since the mode is inside the canonical hash and an attacker
can set it, that turned a rejection into an acceptance. Now an unverifiable
document is rejected.

## Implementations

| Language | Path | Notes |
|---|---|---|
| Rust | `tools/nanorix-verify` | CLI, and the implementation the corpus is generated from |
| Go | `tools/auditproof-verifier-go` | Library and CLI |
| Python | `sdk/python/src/nanorix/verifier` | Library |
| TypeScript | `sdk/typescript/src/verifier` | Library, runs in a browser |

`governance/verify-types` holds the failure taxonomy all four share. When a
verifier rejects a document it has to say which of the fixed reasons applied.
That's part of the wire contract, and it's what makes a disagreement between two
implementations something you can detect instead of argue about.

## Conformance

`tools/nanorix-verify/fixtures/corpus` holds 100 cases in nine categories:
single-capsule and multi-step successes, chain mismatches, invalid signatures,
region and authority mismatches, unsupported versions, canonical-hash drift, and
a set of targeted tamper patterns. Every case ships with the verdict it should
produce.

An implementation conforms if it produces the expected verdict on all 100. The
corpus is generated rather than written by hand, and the generator is in the
repository, so you can regenerate the expected verdicts and diff them instead of
taking our word for it.

## Specification

`docs/signed-containment-evidence.md` is the normative document. It covers scope
and non-goals, how the chain is built, the canonical view, the downgrade rule,
the stage ladder, conformance requirements, and a mapping to the OWASP Agentic
Security Initiative top ten. That mapping lists the entries this evidence
doesn't address as explicitly as the ones it does.

## What isn't here

This repository is the verification algorithm, and it's complete on its own. An
auditor can check a proof without any access to whoever issued it, and a third
party can write a fifth implementation from the specification.

It doesn't include the capsule runtime, the destruction mechanism, or the trust
root that identifies signing authorities. Those stay closed. Opening the
verifier is what lets anyone check the evidence; opening the issuer would let
anyone forge it.

## Citing this work

`CITATION.cff` at the root has the machine-readable record. GitHub renders a
"Cite this repository" button from it, and reference managers read it directly.

If you're writing a specification or a paper that incorporates this format, cite
the archived release rather than the repository URL. Repositories move.

## License

Apache-2.0. Copyright 2026 Nanorix Inc. See `LICENSE`.
