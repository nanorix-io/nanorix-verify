# Signed Containment Evidence

**A specification for tamper-evident, offline-verifiable records of what an autonomous
agent did inside a bounded execution environment.**

Version 0.1 (draft) · 2026-08-11 · Nanorix Inc.
Reference implementation and verifier: Apache-2.0.

---

## 0. Why this document exists

Published guidance now names the control. OWASP's *Top 10 for Agentic Applications*
(Version 2026) recommends maintaining **"tamper-evident logs with cryptographic binding to
agent identity for non-repudiation."** NIST's CAISI AI Agent Standards Initiative (launched
2026-02-17) lists **agent action containment** and **chain-of-custody logging for autonomous
operations** among the concerns its SP 800-53 control overlays address.

The control has a name. What it does not have is an implementable specification — a wire
format, a chain construction, and a verification algorithm precise enough that two parties
who do not trust each other can reach the same verdict about the same artifact.

This document supplies one. It is offered as an input, not a product description. Everything
it specifies is implemented and released under Apache-2.0, and the conformance section names
four independent implementations that agree byte-for-byte on a public corpus.

### 0.1 The property that is actually missing

Most agent-logging today is **repudiable by construction**. The record is generated, held,
and attested by the same party it benefits. That is sufficient for debugging and
insufficient for evidence: an auditor cannot distinguish "this is what happened" from "this
is what the operator says happened."

Non-repudiation — the word OWASP chose — requires that the party the record concerns
**cannot** deny it. That requires three properties this specification defines:

1. **Tamper-evidence**: any modification to the record is detectable without reference to
   the operator.
2. **Offline verifiability**: the verdict is reachable with the artifact and a published
   public key alone — no call to the issuer, no account, no vendor dependency, and it must
   still work after the issuer ceases to exist.
3. **Signer attribution**: the record states which key signed it, and the verification
   binds signature to content, not to a display field.

---

## 1. Scope and non-goals

**In scope.** The document format, its canonical serialisation, the hash chain over
lifecycle steps, the signature basis, and the verification algorithm with its ordered
failure modes.

**Explicitly not in scope, and not claimed:**

| Not claimed | Why it matters to state |
|---|---|
| **Event completeness** | The record proves the integrity and ordering of the events *presented*. It cannot prove no event was omitted before signing. |
| **Collector honesty** | A compromised collector can emit a well-formed record of events that did not occur. Signature validity says nothing about observation fidelity. |
| **Host integrity** | The specification assumes the host executing the boundary is not itself compromised. It provides no remote-attestation of that assumption. |
| **Absence of unobserved side effects** | Effects outside the instrumented surface are outside the record. |
| **Regulatory compliance** | The record is structural evidence. Whether it satisfies an obligation is an adjudication, made by an auditor or regulator, never by the format or its issuer. |
| **Prevention** | This is a containment-and-evidence control. It does not prevent an agent from attempting anything. |

A specification that claims less is more useful to a standards author, because citing an
overclaim transfers the overclaim.

---

## 2. Document model

A conforming document has two layers:

- a **full record**, held by the party that ran the workload, carrying the typed event trail;
- a **shareable projection**, safe to hand to a third party, carrying commitments to the full
  record rather than its contents.

Both are bound by a single signature over a canonical view. The projection therefore proves
that a full record with exactly these commitments existed at signing time, without disclosing
its contents — which is what allows evidence to be shared with a party who must not see the
underlying data.

### 2.1 Canonical serialisation

The signed message is computed over a canonical view serialised with **RFC 8785 (JSON
Canonicalisation Scheme)**. Canonicalisation is mandatory and is the whole basis of
cross-implementation agreement: two implementations that serialise differently will disagree
about a document neither has tampered with.

The canonical view is a **fixed field set**. Fields outside it — display strings, human-readable
summaries, post-signing annotations — are not part of the signed message and MUST NOT be
treated as evidence by a verifier. A verifier that reaches a verdict by comparing a
human-readable field is not verifying; it is reading.

### 2.2 Field presence

A field that is present in some documents and absent in others MUST NOT appear in canonical
hash input. Optional semantics are expressed as an always-present nullable slot. This is what
prevents a stripping attack: if absence is representable, an attacker can remove a field and
produce a document that still verifies.

---

## 3. The chain

Lifecycle steps form a hash chain. Each step commits to its predecessor, so any edit to a
step invalidates every subsequent link — the property that makes after-the-fact editing
detectable rather than merely discouraged.

```
step_hash = SHA-512( prev_hash ‖ 0x00 ‖ subsystem ‖ 0x00 ‖ operation ‖ 0x00 ‖ method ‖ 0x00 ‖ timestamp )
genesis   = SHA-512("")
```

Requirements:

- The genesis value is the hash of the empty string, so the first link is not attacker-chosen.
- `method` is a **specification constant** for the step, not a value copied from the document.
  A chain that hashes its own serialised field would validate a document against itself.
- Step count, order and subsystem names are fixed by the profile in use and are not
  negotiable per-document. A verifier MUST reject a document whose chain does not match the
  declared profile.

---

## 4. Signature

- Algorithm: **Ed25519**.
- Message: the canonical view's hash, as defined in §2.1.
- Encoding: the message is signed as its ASCII hexadecimal representation, not as raw bytes.
  This is a wire-format decision and implementations MUST NOT differ on it.
- Private key material MUST NOT persist beyond the run that used it.

### 4.1 Signing-mode declaration and the downgrade rule

A document declares the mode under which it was signed. **A verifier that does not implement
the declared mode MUST reject the document**, and MUST NOT report a partial success.

This rule exists because the declared mode is inside the canonical hash and is
attacker-controllable. If an unrecognised mode yields "chain verified, signature not checked,"
an attacker flips the mode to one the verifier lacks and converts a rejection into a
reassuring partial result. "I lack the key to check with" and "I do not implement the mode you
claim" are different conditions and MUST produce different verdicts — the first may be a
partial result, the second is a rejection.

---

## 5. Verification algorithm

Verification is a **stage ladder**. A verifier reports the highest stage reached and the
ordered reason it stopped. Reporting a boolean loses the information an auditor needs.

| Stage | Establishes |
|---|---|
| 1–3 | Document parses; declared version is supported; required fields present |
| 4 | Chain structure matches the declared profile (count, order, subsystem names) |
| 5–6 | Each step hash recomputes; the chain links |
| 7 | **Integrity** — the signature verifies against the key embedded in the document |
| 8 | **Authenticity** — the signing key is the one a published trust chain attests |

**Stage 7 and stage 8 are different claims and MUST NOT be conflated.** Stage 7 proves the
document was not altered after signing by whoever held that key. Stage 8 proves *which*
party that was. A forgery that ships its own internally consistent key passes stage 7 and
fails stage 8. Any implementation that stops at stage 7 MUST report that it did, and MUST NOT
describe its verdict as authenticity.

Exit conditions SHOULD be distinguishable by a caller: verified-with-signature,
verified-without-signature-checked, and failed are three outcomes, not two.

---

## 6. Conformance

An implementation conforms if, for every document in the public corpus, it produces the same
verdict, the same terminating stage, and the same failure reason as the reference
implementation.

The corpus MUST include documents that are expected to **fail**, one per failure mode, and
each mutation MUST alter a field inside the canonical hash input. A corpus of valid documents
tests parsing, not verification.

The reference deployment reports four independent implementations (Rust, Go, Python,
TypeScript) agreeing on a 100-document corpus, with the browser verifier as a fifth surface.
Cross-implementation agreement is the only practical defence against a specification that is
precise in prose and ambiguous in fact.

### 6.1 A note on test construction

A conformance test that passes when the defect is present proves nothing. Every guard in the
reference implementation is validated by **injection**: the defect is deliberately
reintroduced, the test is confirmed to fail, and the fix is restored. Implementers are
strongly encouraged to do the same — in building this specification's reference
implementation, more than one guard passed with the bug in place on first writing.

---

## 7. Mapping to OWASP Top 10 for Agentic Applications (2026)

Stated honestly, including where it does not apply. This is a containment-and-evidence
control; most entries below are bounded or evidenced, not prevented.

| | Risk | This specification |
|---|---|---|
| ASI01 | Agent Goal Hijack | **Partial** — bounds consequences and evidences them; does not prevent hijack |
| ASI02 | Tool Misuse & Exploitation | **Partial** — the record attributes tool invocations; enforcement is a separate control |
| ASI03 | Identity & Privilege Abuse | **Direct** — per-run ephemeral identity, no persistent identifiers, credential destruction evidenced |
| ASI04 | Agentic Supply Chain | **No** — a content hash evidences *what ran*; it verifies nothing upstream of it |
| ASI05 | Unexpected Code Execution | **Direct** — the bounded environment is the control; the record evidences its limits held |
| ASI06 | Memory & Context Poisoning | **Partial** — no cross-run persistence makes cross-run poisoning structurally unavailable; within-run, no |
| ASI07 | Insecure Inter-Agent Communication | **Weak** — egress bounds it; no inter-agent protocol security |
| ASI08 | Cascading Failures | **Direct on the named control** — non-repudiation and the forensic chain needed to trace a cascade |
| ASI09 | Human-Agent Trust Exploitation | **No** — social and interface layer |
| ASI10 | Rogue Agents | **Detection and containment**, not prevention |

---

## 8. Reference material

- Reference implementation, verifier CLI and shared result types: Apache-2.0.
- Public corpus with expected verdicts, including failure fixtures.
- Threat model and boundary statement: <https://docs.nanorix.io/threat-model/>. It is
  published separately from this repository rather than inside it, and says what the
  evidence does not establish.

### 8.1 Normative references

An implementation of this document depends on the following. Where this document and one of
them appear to disagree, the referenced standard governs.

| | |
|---|---|
| **RFC 8785** | JSON Canonicalization Scheme (JCS). Defines the serialisation of the canonical view in §2.1. Two implementations that canonicalise differently produce different hashes over identical documents, so this reference is load-bearing rather than advisory. |
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (EdDSA), §5.1 Ed25519. The signature algorithm of §4. |
| **FIPS 180-4** | Secure Hash Standard. SHA-512, used for every hash in §2.1 and §3. |
| **RFC 4648** | Base16 and Base64 encodings. Base16 (hex) for the message encoding in §4 and for chain hashes; Base64 for key and signature transport. |

### 8.2 Informative references

| | |
|---|---|
| **OWASP Top 10 for Agentic Applications (2026)** | The risk taxonomy §7 maps against. That mapping is a citation, not a claim of coverage — see the "Partial" and "No" rows. |

---

## 9. Open items in this draft

Stated rather than omitted:

1. **Trust-chain distribution** (stage 8) is specified as a published manifest; a transparency
   log would be stronger and is not specified here.
2. **Multi-signer / dual-signature modes** are declared in the format but not yet verifiable
   end to end in the reference implementation. Per §4.1, a verifier that does not implement a
   mode rejects it.
3. **Version resolution** for any registry embedded in a document requires that historical
   versions resolve permanently; serving only the current version silently rewrites the
   meaning of records already issued.
