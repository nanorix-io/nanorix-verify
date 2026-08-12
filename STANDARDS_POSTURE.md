# Standards posture

This document says what a standards body, working group, or another vendor may
do with the material in this repository. It exists because the usual answer —
"ask us" — is the thing that stops a specification from being cited.

## What is published, and why

The verification algorithm is published in full: the specification, four
reference implementations, the failure taxonomy, and the conformance corpus.

A verifier that only its issuer can run is not evidence. The whole argument for
this format is that a party with no relationship to the issuer, and no access to
its systems, can take a document and decide for itself whether it holds. That
argument requires the algorithm to be public and requires a second
implementation to exist. Four exist.

## What is not published

The party that issues a proof, the runtime that produces it, and the trust root
that identifies signing authorities are not in this repository and will not be.

That boundary is not incidental to the standards question — it is the answer to
it. A published verifier makes evidence checkable by anyone. A published issuer
would make evidence forgeable by anyone. A specification that required both to
be open would describe a format with no security property left.

## For a standards body

The specification and this code are Apache-2.0. Within those terms you may:

- cite the specification, by DOI or by URL, in a published document
- quote it, including normative text, with attribution
- incorporate the format, or parts of it, into a broader specification
- implement it, ship the implementation commercially, and say it conforms if it
  returns the expected verdict on all 100 conformance cases
- fork it

None of that needs permission from Nanorix Inc., and none of it needs to be
negotiated first.

Two things to be aware of when incorporating it:

**The wire form is frozen, not versioned-in-place.** The eight steps, the chain
construction, the hash and signature algorithms, and the canonical view do not
change. Evidence retained for years must remain checkable, so a change to any of
them produces a successor format with its own version field rather than a
revision of this one. A specification that incorporates this format can rely on
that; it is a constraint we hold ourselves to, recorded and enforced in our own
codebase, not a roadmap intention.

**The conformance corpus is the interoperability test.** If you need a normative
conformance requirement, "returns the expected verdict for every case in the
published corpus" is a testable one, and the corpus is generated from a
committed generator so its expected verdicts can be reproduced rather than
trusted.

## Scope — what this format does not claim

The specification carries this in its own scope section, and it belongs here
too, because a standards author needs the negative space more than the positive.

An AuditProof is a **structural** claim: these steps ran, in this order, over
this workload, and the result was signed. It is not a claim that any regulation,
control framework, or certification requirement is addressed by that fact. The
format deliberately carries no field that asserts one. The mapping in the
specification to the OWASP Agentic Security Initiative top ten uses
"related_to", lists the entries this evidence does not address alongside those it
does, and stops there — reaching further would substitute our judgement for the
auditor's, which is neither ours to make nor useful to them.

If your document needs to state what an AuditProof means for a particular
obligation, that determination belongs to whoever is accountable for the
obligation. We will happily supply the structural facts underneath it.

## Formal IPR declarations

Apache-2.0 section 3 grants a patent licence on this code under its own terms,
and that grant applies to everything in this repository.

Anything beyond that — a working-group IPR declaration, a royalty-free or RAND
commitment on a specific specification, a letter of assurance to a particular
standards organisation — is a commitment Nanorix Inc. makes deliberately and in
writing, not something this file can grant on its behalf. Write to
`hello@nanorix.io` and it will be answered by someone who can make it.

## Contact

- Specification questions, defects, ambiguities: open an issue here.
- Citation, incorporation, working-group participation, IPR: `hello@nanorix.io`.
- Vulnerabilities in the verification logic: `security@nanorix.io`, not a public issue.
