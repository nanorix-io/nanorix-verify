# Signed Containment Evidence

**A specification for tamper-evident, offline-verifiable records of what an autonomous
agent did inside a bounded execution environment.**

Version 0.1 (draft) · 2026-08-11, editorially revised 2026-10-14, Appendix A (draft) added 2026-10-28 · Nanorix Inc.
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

1. **Tamper-evidence**: any modification to the record's signed content is detectable without reference to
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
| **Regulatory compliance** | The record is structural evidence. Whether it is acceptable evidence for an obligation is an adjudication, made by an auditor or regulator, never by the format or its issuer. |
| **Prevention** | This is a containment-and-evidence control. It does not prevent an agent from attempting anything. |

A specification that claims less is more useful to a standards author, because citing an
overclaim transfers the overclaim.

---

## 2. Document model

A conforming document has two layers:

- a **full record**, held by the party that ran the workload, carrying the typed event trail;
- a **summary projection** that leaves out the activity detail and carries commitments to the
  full record rather than its contents.

Both are bound by a single signature over a canonical view. The projection therefore proves
that a full record with exactly these commitments existed at signing time, without disclosing
its contents — which is what allows evidence to be shared with a party who must not see the
underlying data. Nanorix's hosted service does not deliver that separation by itself: it serves
the full proof, without authentication, to any party that holds the capsule ID.

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

### 2.3 Media type

A serialised AuditProof is identified by the media type

```
application/vnd.nanorix.auditproof+json
```

The `+json` structured suffix applies: a consumer that does not recognise the type may still
process the payload as JSON under RFC 6839, which is the behaviour a generic tool should have.
Registration is in the vendor tree under RFC 6838 §3.2.

A media type matters here for a reason specific to this format. Evidence is handed between parties
who share no software: an auditor receives a file from a party they do not trust, and the first
question is what the file claims to be. Content-sniffing a document whose whole purpose is
tamper-evidence is the wrong default, so the type travels with it. Implementations SHOULD set it on
HTTP responses carrying a proof and SHOULD accept a proof regardless of the type declared, because
the verdict comes from verification and never from the label.

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
- Strictness: every Ed25519 signature is verified strictly. A verifier MUST reject a non-canonical or
  small-order public key, a small-order or non-canonical `R`, and `S >= L`
  (`tests/vectors/ed25519_strict_negative.json`).
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
document's signed content was not altered after signing by whoever held that key. Stage 8 proves *which*
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
implementation, more than one guard let the bug through on first writing.

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

1. **Trust-chain distribution** (stage 8) is specified as a manifest the verifier is given.
   Nanorix's own list is published; a BYOC customer's list goes to its auditor and its client
   and is never published (amended 2026-11-16). No transparency log for either list is
   specified here.
2. **Multi-signer / dual-signature modes** are declared in the format but not yet verifiable
   end to end in the reference implementation. Per §4.1, a verifier that does not implement a
   mode rejects it.
3. **Version resolution** for any registry embedded in a document requires that historical
   versions resolve permanently; serving only the current version silently rewrites the
   meaning of records already issued.
4. **§2.2 and the shipped optional fields disagree, and CDP 2.2 widens the gap by one field.**
   §2.2 says a field present in some documents and absent in others must not appear in the
   canonical hash input, with optional semantics expressed as an always-present nullable slot.
   The reference implementation ships four canonical fields that do the opposite —
   `parent_audit_proof_id`, `cdp_kind`, `parent_proofs_merkle_root`,
   `record_receipts_merkle_root` are omitted from the canonical bytes when absent, and every
   conforming verifier inserts them only when present. CDP 2.2 adds `customer_declared_activity_root`
   under that same skip-when-absent mechanic, so that a proof which did not opt in hashes exactly as
   it did before the field existed. The stripping concern §2.2 names is answered differently than
   §2.2 says: the signature covers the view *with* the field, so removing a present field changes
   the hash and the signature fails; what cannot be detected is the absence of a field that was
   never there, which is the intended meaning of "did not opt in". This is a wording item for the
   next revision of this specification (tracked as the v1.1 reconciliation), not a change to any
   verifier: following §2.2 literally for a new field would change the hash of every document
   already issued. §2.2 itself is left as published here so that the revision, not this note,
   carries the corrected text.
5. **Population heads (Appendix A) are checked offline only in part.** Checks (a), (b), (c) and
   (f) run on what an auditor is handed. Checks (d) and (e) read the chain's ticks in write-once
   storage (amended 2026-11-16: no public log), whose format this draft does not yet
   specify, so a verifier reports every population as "population not externally witnessed".

---

## Appendix A. Population heads (draft)

A signed document proves that one run happened as recorded. It cannot show that the holder
handed over every document an authority signed: a withheld document leaves no trace in the
documents that are handed over. A **population head chain** makes withholding visible. It is a
separate signed primitive beside the document. The document, its canonical view and its
signature are unchanged.

### A.1 Head

For each document an authority signs, the deployment that signed it emits one head:

```
{ "type":           "nanorix-population-head-v1",
  "authority_id":   1 to 128 bytes of a-z 0-9 . _ -,
  "proof_sequence": integer from 1 to 2^53 − 1,
  "prev_head_hash": "sha512:" + 128 lowercase hex,
  "tip_proof_hash": "sha512:" + 128 lowercase hex,
  "issued_at":      "YYYY-MM-DDTHH:MM:SSZ" }
```

- There is one chain per signing authority, and each head names it in `authority_id`.
  `proof_sequence` counts that authority's documents from 1, one head per document.
- `prev_head_hash` is the `head_hash` (A.2) of the head at the previous sequence. The head at
  sequence 1 carries `sha512:` followed by the hex of `SHA-512("")`, the genesis value of §3.
- `tip_proof_hash` names the document by its leaf:

  ```
  envelope_digest = hex( SHA-512( algorithm ‖ 0x00 ‖ key_id ‖ 0x00 ‖ public_key ‖ 0x00 ‖ signature ‖ 0x00 ) )
  leaf            = SHA-512( 0x00 ‖ final_hash_raw ‖ 0x00 ‖ envelope_digest )
  tip_proof_hash  = "sha512:" ‖ hex( leaf )
  ```

  `final_hash_raw` is the document's `final_hash` with its `sha512:` prefix removed. The
  envelope fields are the attestation's `algorithm`, `key_id`, `public_key` and `signature`,
  each exactly as written, prefixes included, and an empty fifth field. Nothing else is changed:
  no trimming, no re-encoding, no change of case. The specification's checkpoint verifier computes its leaves
  by the same rule (the hosted publication of that log does not ship). A document has no leaf,
  and no head can name it, when any of these holds:

  - `final_hash` is missing, is not a string, or is not exactly 128 lowercase hexadecimal
    characters once `sha512:` is removed;
  - `attestation` is missing or is not an object;
  - `algorithm`, `key_id`, `public_key` or `signature` is missing, is not a string or contains
    NUL. `verification_key` never stands in for `public_key`;
  - the top-level `pqc_signature`, `pqc_attestation` or `customer_pqc_attestation` is present
    and is not null, on any `cdp_version`. A document carrying a post-quantum signature has no
    leaf until verifiers check that signature.

  A head naming such a document fails (c) with `tip_matches_no_proof`. The leaf covers the
  final hash and the signature envelope, never the canonical view, which can carry
  customer-supplied file names and commands.
- A head carries nothing else: no classification, no outcome, no run identifier. A verifier
  MUST reject a head with any other field.
- The bound on `proof_sequence` keeps every sequence exact under RFC 8785, which writes numbers
  as IEEE-754 doubles.
- `issued_at` is a real UTC date and time to the second. Seconds run from 00 to 59 on every
  date: a verifier MUST reject `60`, including on a date with a leap second. It is the time
  grammar of A.3 ("Times") with no fraction, so year 0000 is rejected too.

### A.2 Encoding and signature

```
canonical_bytes = RFC8785( head )
head_hash       = "sha512:" ‖ hex( SHA-512( canonical_bytes ) )
signed_message  = "nanorix-population-head-v1:" ‖ hex( SHA-512( canonical_bytes ) )
```

- The head is signed with Ed25519, over the ASCII bytes of `signed_message`, by the authority
  that signs the deployment's documents, under a key registered for that authority in the
  trust chain the verifier is given (stage 8). That is a customer's list, handed to its auditor
  and its client and never published (amended 2026-11-16). Heads are emitted only where that authority is registered as
  the customer's own: the trust chain marks such an authority with
  `"emits_population_heads": true`, inside the bytes its identity signs. The local signer
  (`signing_key_version` `local-ephemeral`) emits no heads, and neither does an authority the
  trust chain carries without the marker, which includes every hosted authority. When it loads a
  trust chain, this verifier refuses one that writes a field it reads twice, of the list or of a
  record, the marker among them, while the Python, TypeScript, Go and browser verifiers keep the
  last copy, which is the copy their signature check covers, and read the marker only to rebuild
  the signed bytes. An authority id written twice keeps its last copy, as in the other verifiers.
- `signed_message` is 155 ASCII bytes and contains `:` and letters outside hexadecimal. Every
  document signature message (§4) is 128 lowercase hexadecimal characters. Under strict
  verification (A.4) a signature binds one message, so a head signature never verifies as a
  document signature, and a document signature never verifies as a head signature.
- A signed head is carried as
  `{ "head": head, "signing_key_version": "...", "signature": "base64:..." }`.
  The authority is inside the signed bytes, so a head cannot be relabelled to another authority.
  The key version is outside them. It binds a key, not its own text: the signature verifies only
  under the key the version resolves to, and check (f) ties that key to the document's authority.
  `signing_key_version` has the same alphabet and length as `authority_id`.
- **Version 2.** A BYOC chain carries `"type": "nanorix-population-head-v2"` from
  sequence 1. Its members and `head_hash` are those of version 1. Its `signed_message` starts
  `nanorix-population-head-v2:` in place of the version 1 tag, still 155 bytes. The record key signs
  it with both halves: Ed25519 over `signed_message`, as above, and the key version's ML-DSA-65
  partner (amendment H7.2), pure with an empty context, over

  ```
  pqc_signed_message = "nanorix-population-head-pqc-v2" ‖ 0x00 ‖ signed_message
  ```

  The carrier adds two members beside the version 1 ones:
  `"pqc_signing_key_version"`, the partner's version, with the alphabet and length of
  `signing_key_version`, and `"pqc_signature": "base64:..."`, 3309 bytes. A version 2 head
  without either member, or a version 1 head with either, `null` included, fails (a) with
  `head_malformed`, naming the member.
- `head_hash` is also what a tick seals. A tick is a separate signed object, written to
  write-once storage on a timer, that carries a salted SHA-512 fingerprint of the chain's latest
  `head_hash` (amended 2026-11-16, Amendment A4). Its format is in A.2.1. Nothing goes
  to a public log.

### A.2.1 Tick

A tick is an RFC 8785 object with exactly these members, and a reader MUST reject any other. A
reader MUST also reject a tick whose bytes are not the RFC 8785 form of the JSON they hold (other
whitespace, member order or escapes), since a timestamp token's imprint is over a tick's bytes as
stored:

```
{ "type":                  "nanorix-population-tick-v1",
  "log_key_pin":           "log1-sha256:" + 64 lowercase hex,
  "sequence":              integer from 1 to 2^53 − 1,
  "sealed_fingerprint":    "sha512:" + 128 lowercase hex,
  "key_list_fingerprints": [ { "list_version": integer from 1 to 2^53 − 1,
                               "fingerprint":  "sha512:" + 128 lowercase hex } ],   (optional)
  "timestamp_tokens":      [ { "sequence": an earlier tick's sequence,
                               "token":    "base64:" + DER bytes } ],                (optional)
  "final":                 true,                                                     (optional)
  "signature":             "base64:" + 64 Ed25519 signature bytes,
  "pqc_signature":         "base64:" + 3309 ML-DSA-65 signature bytes }
```

```
canonical_bytes    = RFC8785( tick without signature and pqc_signature )
signed_message     = "nanorix-population-tick-v1:" ‖ hex( SHA-512( canonical_bytes ) )
pqc_signed_message = "nanorix-population-tick-pqc-v1" ‖ 0x00 ‖ signed_message
salt(n)            = HMAC-SHA-512( salt_key, "nanorix-tick-salt-v1" ‖ 0x00 ‖ decimal(n) )
sealed_fingerprint = "sha512:" ‖ hex( SHA-512( "nanorix-tick-seal-v1" ‖ 0x00 ‖ salt(sequence) ‖ 0x00 ‖ head_hash ) )
log_key_pin        = "log1-sha256:" ‖ hex( SHA-256( "nanorix-log-hybrid-v1" ‖ 0x00 ‖ "Ed25519" ‖ 0x00 ‖ ed25519_key ‖
                                                   0x00 ‖ "ML-DSA-65" ‖ 0x00 ‖ ml_dsa_65_key ) )
```

- Both signatures are required, by the chain's log key: Ed25519 over the ASCII bytes of
  `signed_message`, and ML-DSA-65, pure with an empty context, over `pqc_signed_message`. The
  tick's `log_key_pin` names that log key version, its 32 Ed25519 bytes and its 1952 ML-DSA-65
  bytes, and a tick checks only under the version its pin names.
- `sequence` counts the chain's ticks from 1, across log key versions.
- `head_hash` is the chain's latest head at the tick's time, written exactly as A.2 writes it,
  `sha512:` included, or the genesis value of A.1 before the first head. `salt_key` is 32 random
  bytes kept with the evidence and handed to the auditor. Each tick has its own salt, so two
  ticks over one head differ. One tick's seal opens with that tick's salt alone, so an offline
  bundle can carry one salt and never the salt key.
- `key_list_fingerprints` is present only in the first tick after one or more new key-list
  versions, one entry per version in ascending order. `fingerprint` is the SHA-512 of that
  version's bytes as handed.
- `timestamp_tokens` is present only when timestamps are on. Each entry names an earlier tick and
  holds an RFC 3161 token whose message imprint is the SHA-512 of that tick's complete bytes. A
  reader of this format checks the entry's form only: an earlier `sequence`, in ascending order,
  and a non-empty `base64:` value.
- `final` is present, as `true`, only in the chain's final tick.
- Absent members are left out, never written as `null` or empty. A reader MUST reject a member
  written `null`, at the top level or in an entry, and a member name written twice in one object.
- The vectors are `tools/nanorix-verify/fixtures/population_tick/population_tick_vectors.json`:
  three signed ticks with every byte string above, and 43 cases with the result a reader gives.

### A.3 Checks

Given documents, their signed heads, the trust chain it is given (every version of it since the
chain's start), and, for (d) and (e), the chain's ticks as read from the box that holds them and
the salt key that opens them (amended 2026-11-16), a verifier runs six checks
and reports each one as `ok`, `failed` with a reason, or `not_checked` with a reason. A
`not_checked` check MUST NOT be reported or read as `ok`.

| Check | Holds when |
|---|---|
| (a) chain links | Every handed head after the first carries the `head_hash` of a handed head at the greatest lower sequence. The head at sequence 1 carries the genesis value, and no other head does. |
| (b) contiguous sequence | Handed sequences run 1, 2, 3 and on, with no gap and no repeat, and no head is issued before the head at the sequence below it. Two heads at one sequence are a fork, and a failure. |
| (c) tips match documents | Each `tip_proof_hash` is the leaf of at least one handed document, every handed document with that leaf verifies to stage 7 and ended no later than the head's `issued_at`, and no two heads name one document. |
| (d) tick coverage | Each head outside the open window is covered: some tick written no later than the head's `issued_at` plus one tick period plus the tolerance opens, under its salt, to that head or to a handed head that descends from it. The head's `issued_at` is not before, and no more than the tolerance after, the destruction time signed in the document it names. A head whose `issued_at` plus one period plus the tolerance falls after the time the auditor reads the box is in the open window and is listed as not yet witnessed, never as covered. The tolerance is the 300 seconds of the emitter's clock rule below; it also bounds the destruction-time half, so every head is issued within 300 seconds of its document's destruction. A head issued after a final tick's write time fails, even inside the open window. The period is the one the trust chain states for the chain's log key, taken from the log key version current at the earlier tick when it changes. A tick's time is the box's write time for the earliest object version under its name; a timestamp token never stands in for it. A missing salt is a failure. |
| (e) tick population | The box's ticks under the chain's log keys run 1, 2, 3 and on, with no gap and no repeat. Over the span from the chain's last tick written before the audit period starts, or its first tick, to the first tick written after the period ends, no two consecutive ticks are written further apart than one period plus the tolerance; when that first tick is in a burst (below), the span runs on to the end of that burst; when no tick follows the period's end, the span runs on to the time the auditor reads the box (the auditor's own clock), and the last tick and that read are no further apart either, unless the chain's final tick came first. Each tick in the span opens to a handed head, and from the span's second tick on that head is the previous tick's head or descends from it; the audited party hands every head up to the head the span's last tick opens to, with the documents those heads name. A tick written after the chain's final tick is a failure, and so is a final tick that carries no fingerprint of a trust-chain version archiving every key version of the chain's authority. The final tick is the first tick after that version. That version's archive date is at or after the `issued_at` of the head the final tick opens to, and no later than the final tick's write time plus the tolerance. The verifier reports every final tick written in the audit period, with its write time. Every handed trust-chain version, whatever it changes, a version that changes only a marker included, has its fingerprint in the box, the box names no version that was not handed, and two fingerprints for one version are a fork. |
| (f) head signatures | Every record of the trust chain is inside the record grammar. Every head is under one authority. The head's authority and its documents' signer both emit heads: neither is the local signer or an authority the trust chain carries without the marker. The head's authority is the authority of every handed document with the named leaf. The head signature verifies strictly under a registered, unrevoked Ed25519 key of that authority, held in one record, that no other authority in the trust chain lists and whose window holds the head's `issued_at`, and every handed document with the named leaf is version 2.1 or 2.2 and verifies to stage 8 under the same authority. Under a trust chain verified under a hybrid pin every head is version 2, its `pqc_signing_key_version` is the partner of its key version, and its ML-DSA-65 signature verifies under that partner's key; under a classical pin every head is version 1. The partner record's own window and status are not read. |

- **Ticks (amended 2026-11-16).** (d) and (e) hold only when the box is
  read directly, or from a copy its holder hands over, never from a copy the audited party hands
  over; the verifier lists every object version under a tick's name. When the box cannot be read,
  both report `not_checked`. A gap longer than one period plus the tolerance that later ticks
  close, as after an outage, is a delayed span. The burst that closes it is the run of ticks from
  the closing one, each written less than one period after the one before, ending no later than
  the closing tick's write time plus the gap's length. (e) is reported `not_checked` over the
  span, and (d) for every head whose deadline falls after the span opens and whose first covering
  tick is in that burst and was written after the head's deadline, naming the span and the
  burst's end; a head the burst covers in time is checked as usual, and (e) still checks every
  tick of the burst. A delayed span is unwitnessed: until its ticks reach the box they are only
  the audited party's. A gap still open at the read, with no final tick, is a failure. A
  backdated head fails (d), unless the delayed-span exemption above applies to it: every tick
  written by its deadline was written before the head existed, so it opens to an earlier head,
  which cannot descend from the backdated one.
- A withheld document leaves a head naming a missing leaf (c), and (f) checks that head's
  signature, then reports `not_checked`. A head withheld between handed heads breaks the chain
  (a, b), and a chain without head 1 fails (b). A cut tail fails neither.
  A head signed by another authority fails (f).
- **Versions 2.1 and 2.2.** A head names a document of version 2.1 or 2.2, whose signature
  covers the canonical view. A version 1.0 signature covers only `final_hash`, and neither the
  capsule identifier nor the authority enters it, so two documents with one destruction timestamp
  and the same step inputs carry the same signed message. A head over a version 1.0 document
  would fix neither the capsule it covers, nor the authority it came from, nor how many documents
  there were. (f) fails with `named_proof_version_unsupported` for any other version, with or
  without a trust chain.
- **Every copy is checked.** The leaf does not cover the canonical view, so a copy of a document
  with a canonical-view field edited keeps the leaf while its signature no longer verifies. (c)
  and (f) check every handed document with the named leaf, so such a copy fails both checks
  whether it is handed before or after the genuine document.
- **Document identity.** Two heads name one document when the documents they name are signed
  over the same message. That message is the canonical view's hash, as defined in §2.1, recomputed
  from the document, and it covers the document's authority, so the authority is not compared
  apart from it. Leaves alone do not decide it, because the leaf covers envelope fields the
  signature does not, such as `key_id`.
  Two copies of one document with different `key_id` values have different leaves; heads naming
  each of them fail (c) with `tip_named_twice`. A document of any other version has no signed
  message of this kind, so it keeps its leaf as its identity, and (f) refuses it. The leaf rule
  of A.1 is unchanged.
- **Copies of one head.** Heads with the same `head_hash` and the same `signing_key_version` are
  one head. (a), (b) and (c) read it once and (f) verifies every copy, so a copy with a bad
  signature fails (f). One head body under two key versions is two heads, and (b) and (c) fail.
- **A member written twice.** A parser keeps one copy of a member name written twice in one
  object, so the checks would read one head while a reader keeping the other copy sees another.
  `nanorix-verify population` refuses a heads file whose text writes a member name twice in one
  object, inside a head or beside it, as a setup error (exit 2) before any check. It names the
  first such member as an RFC 6901 JSON Pointer, reading objects depth first in text order and
  finding a name written twice in an object before any of its members.
- **The record grammar.** (f) compares keys and versions, so before anything else it reads every
  authority in the trust chain and every record it holds: authorities in byte order of
  `authority_id`, and within each, its id first, then the active versions before the archived
  ones, each in list order. Every `authority_id` has the alphabet and length of a head's: 1 to 128
  bytes of `a`-`z`, `0`-`9`, `.`, `_` and `-`. The id is read even when the authority holds no
  record. A lookalike of another authority's id, such as one with a Cyrillic letter, a zero-width
  space, a trailing space or upper case, would otherwise show that authority's version beside its
  own. Byte order of these ids is also their code point and UTF-16 order. A record is inside the
  grammar when, read in this order:

  - its `algorithm` is a known label, compared exactly: absent or `Ed25519`, for a 32-byte key,
    or `ML-DSA-65`, for a 1952-byte key;
  - its `public_key_b64`, after an optional `base64:` prefix, is standard base64 with its padding
    and no stray bits, and decodes to exactly the label's length;
  - its `public_key_fingerprint` is `sha256:` and the lowercase hex SHA-256 of the decoded key;
  - its `signing_key_version` is the decimal text of an integer from 1 to 2^63 − 1, as a signed
    64-bit integer prints it: no `+`, no leading zero, no space or other character. A document's
    signature covers its version only as that integer, so `01` or `+1` would be a second
    spelling of `1`. The canonical view reads a version it cannot parse as 0, so `0` and the
    versions below it are refused; the registry writes versions from 1.

  The first id or record outside the grammar fails (f) with `key_list_record_refused`, which
  names the authority, the record's version as written (empty for an id) and the first field
  outside the grammar. It fails whichever authority holds the id or record and whatever the
  heads: with no heads, with a malformed head, and before any other finding of (f). Every
  authority, key and version in a list (f) reads then has one text, apart from the `base64:`
  prefix. One such id or record refuses the whole list, so it fails every population read under
  that list; the tool that signs the list refuses to sign one.

  (f) reads only the members the list's signature covers. The signature covers the list as this
  verifier parses it, apart from `manifest_signature` and `pqc_manifest_signature`. A member it
  does not read, the earlier copy of a member name written twice in one object, and a member
  written with a value the parsed list does not write back, such as a marker written `false` or
  a `null`, are therefore outside the signature while it still verifies. Once the signature
  verifies, and before any check, `nanorix-verify population` refuses a list whose bytes hold any
  of these, as a setup error (exit 2); a field it reads written twice is refused when the list
  loads, before its signature is checked. It names the first such member as an RFC 6901 JSON
  Pointer, reading objects depth first in text order and finding a name written twice in an
  object before any of its members. A member left out that the parsed list holds at its default,
  such as `revoked` or an empty `archived_versions`, is covered and is not looked for. The values
  of the two signature members are not compared, a `null` `pqc_manifest_signature` among them:
  (f) reads neither, and under a classical pin this verifier does not check
  `pqc_manifest_signature`. The tool that signs the list refuses an authorities file holding a
  member the list would not carry, so a repeated authority or a misspelled `revoked` is never
  signed away, and one holding an `effective_from` or `archived_at` outside the time grammar
  (Times, below), under which no head would be inside the key's window.

  The grammar and the rule on signed members belong to (f) and to the tool that signs the list. Neither is
  a rule of proof verification: stage 8 reads a document's key from the trust chain as it did
  before, and already needs exactly 32 bytes. A list (f) refuses can still anchor a document at
  stage 8.
- **Heads under a hybrid pin.** Under a hybrid pin (f) fails with `head_algorithm_unsupported`,
  `found` `Ed25519 (hybrid pin)`, at the first version 1 head, and under a classical pin with
  `found` `nanorix-population-head-v2 (classical pin)` at the first version 2 head, before any
  other finding of (f) but after the record grammar. A version 2 head's ML-DSA-65 half is checked
  after its Ed25519 half verifies: a `pqc_signing_key_version` that is not the partner of the
  head's key version fails with `head_signing_key_unknown`, naming that version, and a signature
  that does not verify under the partner's key with `head_pqc_signature_invalid`. A document that
  carries `pqc_attestation`, as every BYOC document does, has no leaf (A.1), so a head naming it
  fails (c) with `tip_matches_no_proof` until verifiers read the leaf that covers the ML-DSA half.
- **A hybrid key version.** Each key is a record of its own under its own `signing_key_version`.
  When a version is signed with Ed25519 and ML-DSA-65, the ML-DSA-65 key takes a
  version number of its own beside the Ed25519 key's. One version holding both would be one
  version with two records, which fails every head under it with `head_key_record_not_unique`,
  and stage 8 reads only the first record of a version.
- **One key, one authority.** The head names its authority in its signed bytes, but a key that
  the trust chain lists under more than one authority does not show which of them signed. When
  the head's key, compared as decoded bytes, appears in the active or archived versions of more
  than one authority, revoked authorities included, (f) fails with
  `head_key_under_several_authorities`.
- **One record per key.** When the head's authority holds more than one record of the head's
  `signing_key_version`, or of the head's key compared as decoded bytes, active or archived, the
  trust chain gives that key no one window, and (f) fails with `head_key_record_not_unique`.
- **Times.** Every time a population check compares is read under one grammar: `YYYY-MM-DD`, an
  upper case `T`, `HH:MM:SS`, then optionally a `.` and 1 to 9 digits, then an upper case `Z`. The
  date is a real date from year 0001, and seconds run from 00 to 59. Nothing else is read: no
  offset, `+00:00` and `-00:00` included, no lower case `t` or `z`, no space in place of `T`, and no
  fraction of more than nine digits. The grammar covers a head's `issued_at` (with no fraction,
  A.1), the destruction time of the document a head names, and a key version's `effective_from`
  and `archived_at`. It is a rule of the population checks only: proof verification reads its
  times as before. (c) and (f) compare times to the second, with any fraction dropped. A document that
  ended in the same second a head was issued is not after it. A head is inside its key's window
  when `issued_at` is at or after the key version's `effective_from` and at or before its
  `archived_at`. An archived version with no `archived_at` shows no end, so it holds no head. A
  time that cannot be read fails closed: (c) fails with `head_issued_before_proof`, and (f) fails
  with `head_outside_key_window`.
- **Heads run forward in time.** (b) fails with `head_issued_before_previous` when a head's
  `issued_at` is before that of the head at the sequence below it. Two heads may share a second.
  So a retired key cannot extend a chain that has moved past its window, with a head dated inside
  that window. (b) does not stop a retired key replacing the tail of a chain whose last remaining
  head is inside its window, or starting a chain from sequence 1. Only (d) and (e) find those.
- **An emitter's clock.** A verifier has no clock to hold `issued_at` against, so (b) sets no
  upper bound, and one head dated ahead binds every head after it. An emitter MUST set `issued_at`
  to the latest of its clock, the previous head's `issued_at` and the end of the document the head
  names. It MUST sign nothing when that time is more than 300 seconds ahead of its clock: signing
  would put a false date on the record. A holder of the key who ignores this rule stops the chain
  the same way. A chain stopped this way waits for the repair procedure of the specification question 3.
- **A retry.** An emitter retrying one sequence MUST reuse the same head body and key version.
  Copies with one head hash and one key version count as one head. A retry with a new `issued_at`
  or under a new key version makes two heads at one sequence, and (b) fails whenever both are
  handed.
- **An authority the trust chain does not carry.** Nothing says it emits no heads. A document
  under it is listed as having no handed head, and a head under it fails (f) with
  `head_signing_key_unknown`, unless an earlier finding of (f) comes first: a record outside the
  grammar (`key_list_record_refused`); a chain that another authority started
  (`chain_authority_mismatch`); the local key version, or a named document of a signer the key
  list does not mark for heads (`signer_not_marked_for_heads`); a named document of a version
  other than 2.1 or 2.2 (`named_proof_version_unsupported`); or a named document under another
  authority (`named_proof_authority_mismatch`).
- **Re-encoding fails closed.** A head names the document's envelope exactly as written. If an
  intermediary re-encodes the public key or signature (for example by dropping the `base64:`
  prefix), the leaf changes. If it adds a top-level `pqc_signature`, the document has no leaf.
  Either way (c) fails with `tip_matches_no_proof`. The document has to be handed as it was
  signed.
- Each check reports its first failure in sequence order. There are two exceptions. A head that
  does not parse is reported under (a) by its handed position, and (b) and (c) then report
  `not_checked`, as (f) does unless the trust chain holds a record outside the grammar. That
  record is reported under (f) before any head (see the record grammar above).
- Without a trust chain, (f) checks what needs no key and reports `not_checked` with the reason
  "needs a registered key list", and only the local signer is known to emit no heads.
- (d) and (e) read the chain's ticks (A.2.1) from the box that holds them, which no verifier
  reads yet. A verifier MUST report both as `not_checked` with the reason "needs a transparency log". The
  reason text is the wire value the verifiers emit today, as are the result members
  `d_log_inclusion` and `e_log_population` that carry the two checks; all three are kept until a
  verifier reads ticks. They predate the specification's 2026-11-16 amendment, under which nothing goes to
  a public log. The reason string is the current wire value and is tracked for rename.
- A handed document that no handed head names is listed as unwitnessed, never failed. Its reason
  rests on what the document verified to, because its own fields can be edited with no key:

  - `proof_not_verified`: it does not verify to stage 7, so nothing it says about its signer can
    be read;
  - `local_signer`: it verifies to stage 7, its signature covers an authority naming the local
    signer, it carries that signer's key version, and its key is under no authority in the trust
    chain;
  - `unmarked_authority`: it verifies to stage 8 under an authority the handed trust chain
    carries without the marker. This reports what that list says, not that no head was expected:
    whoever signs the list sets the marker, so an older list or one that drops the marker reads
    the same. The result prints the list's `issued_at` for that reason;
  - `no_handed_head`: anything else, including a document under an authority that emits heads,
    and every document that verifies to stage 7 under a trust chain holding a record outside the
    grammar: that list says nothing a reason could rest on.

  A document signed with a key anyone can mint can report `local_signer`, but only by naming the
  local signer as its authority, under a signature that covers that name. It then claims no
  authority that emits heads. The trust chain marks an authority, not a time, so a document an
  authority signed before its first head reports `no_handed_head`. An authority is marked before
  it signs its first document, and a deployment that starts emitting later takes a new
  `authority_id` and a new key. Without (e), a chain whose last heads were withheld cannot be told apart from a
  chain that ends there.

### A.4 Verdict, label and strictness

- The verdict is `failed` when any check failed, and otherwise `not_externally_witnessed`. This
  draft has no stronger verdict: only (d) and (e) can show that the handed heads are every head.
- Every result carries the label **"population not externally witnessed"**, in those words.
- A result read under a trust chain carries `key_list`: that list's signed `issued_at` and the
  fingerprint of the identity that signed it. Two lists from one identity can disagree on which
  authorities emit heads, so a result says which it read.
- `nanorix-verify population` prints all six checks with their reasons, the list it read and that
  limit. It needs a trust chain verified against a pinned identity, and exits 1 when a check
  failed and 3 otherwise. A trust chain it cannot load or pin, or whose bytes hold a member its
  signature does not cover apart from `manifest_signature` and `pqc_manifest_signature` (A.3),
  and a heads file that writes a member name twice in one object (A.3), exit 2, with nothing
  verified. It never exits 0, so no automated gate can read a population as complete. Text a
  document or the trust chain supplies is printed as printable ASCII. The human output writes
  every other character as `\u{...}`. The `--json` output writes every character beyond ASCII,
  and DEL, as a `\uXXXX` escape, which reads back as the same string; JSON escapes the other
  controls itself.
- Head signatures are verified strictly. A verifier MUST reject a non-canonical or small-order
  public key, a small-order or non-canonical `R`, and a non-canonical `S`. A small-order key
  with `R` the identity and `S = 0` would otherwise verify for every message.

### A.5 Test vectors

`tools/nanorix-verify/fixtures/population_head/population_head_vectors.json`, written by the
generator beside it, holds a test-only trust chain signed by a test-only identity, a pool of
signed documents, encoding vectors and 169 cases, each with the exact result a verifier must
report. The vector test reads that number from this sentence. It also holds the signed trust
chain as nine texts, none signed again, each with the first member its bytes hold that the
signature does not cover: none in the list as written, in one with defaults left out, in one
with a member name written with a `\u` escape and in one with `pqc_manifest_signature` written
as `null`; members added to two records; a member name the pointer escapes; `archived_at`
written as `null`; a marker written as `false`; and an authority written twice, the earlier copy
holding its key retired in hex. It holds the good chain's heads as six texts, each with the first
member name it writes twice in one object: none as written; `issued_at` inside a head; a whole
head; a signature, and a signature whose earlier copy writes its name with a `\u` escape; and a
`signing_key_version`. The cases include:

- a good chain, a withheld document, a withheld head, a sequence gap and a fork;
- a wrong authority, an authority switch within one chain, a head relabelled to another
  authority, a non-canonical signature and a small-order key;
- one head handed twice, a copy with a bad signature and one body under two key versions;
- a chain across a key rotation, a head after its key was archived, a head before its key took
  effect, and key list times that cannot be read;
- an archived key version with no end;
- a head issued before the head below it, two heads in one second, and a retired key backdating
  a head;
- a head issued before the document it names ended, in the same second, and a document end time
  that cannot be read;
- document end times the time grammar reads, with a fraction of three and of nine digits, and
  ones it does not: second 60, a lower case `t`, a lower case `z`, a space for `T`, the offsets
  `+00:00`, `-00:00` and `+14:00`, year 0000 and a fraction of thirteen digits;
- a key version's `effective_from` in lower case, with the offset `+00:00`, and at second 60;
- a head naming a version 1.0 document, with and without a trust chain, and a version 2.2
  document;
- a head under an authority the trust chain carries without the marker, and one under an
  authority it does not carry;
- a forged copy of a document handed before the genuine one, and after it;
- one document named twice through a rewritten `key_id`;
- a head naming a document whose only handed copy carries its key under `verification_key`
  instead of `public_key`, so the copy has no leaf;
- a head key listed under two authorities, a head key among the archived versions of a revoked
  authority, a head key listed again with a `base64:` prefix, and a document under a shared key
  named by the other authority;
- a trust chain record outside the grammar at each of its five fields: an `authority_id` that is
  empty, 129 bytes long, or another's with a Cyrillic letter, a zero-width space, a trailing
  space or in upper case, and one in upper case that holds no record; the labels `ed25519`,
  `EdDSA`, `Ed25519 ` with a trailing space, empty and `ML-DSA-87`; under `Ed25519`, a key in
  unpadded base64, in hex, as SPKI, after a zero byte, one byte short, with a stray bit and
  empty, and under `ML-DSA-65`, a 32-byte key and a key in unpadded base64, in hex, as SPKI,
  after a zero byte and one byte short; a fingerprint of another key, under another authority
  and in upper case, and under `ML-DSA-65` a fingerprint of another key; and the versions `01`,
  `+1`, ` 1`, `1_0`, `1.0`, `v8`, `-0`, 2^63, `0` and `-1`, and `01` under `ML-DSA-65`;
- which record a refusal names when several are outside the grammar, in two authorities, in one
  authority's two lists and in one list, an active record outside
  it, and a refusal with no heads, with a malformed head, beside another finding of (f) and beside
  documents that would otherwise report `local_signer` and `unmarked_authority`;
- records the grammar reads: each label with a key of exactly its length (an Ed25519 key in
  every base record, and the same ML-DSA-65 key the refused forms above carry), a record with no
  label, the version 2^63 − 1, and an `authority_id` of 128 bytes holding `.` and `_`;
- every unwitnessed reason, including documents that claim a signer by an edit that takes no key;
- a document's authority and a head's `signing_key_version` that hold a line of forged output;
- at least one case for every failure reason a check can report;
- eighteen malformed heads: a later version's `type`, `proof_sequence` 0, 1.0, "1", 2^53 and −1, an unknown field inside
  the head and beside it, `authority_id` empty, upper case, 129 bytes long, not ASCII, missing
  and beside the head, a signature without its `base64:` prefix, `issued_at` with second 60,
  and a `signing_key_version` that is empty or outside its alphabet.

A malformed head fails (a) with `head_malformed`, which carries the head's position in the
handed list and the field. A head that does not fit the shape of A.1 and A.2 (a missing or
unknown field, or a value of the wrong JSON type) reports the empty field. A value of the right
type outside the format reports its dotted path, such as `head.proof_sequence`. The reason's
`detail` is free text for a human reader and is not compared. A conforming implementation
reports the same result for every case.
