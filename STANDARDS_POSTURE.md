# Standards posture

This document says what a standards body, a working group, or another vendor can
do with the material in this repository. It exists because the usual answer,
"ask us," is what stops a specification from being cited.

## What's published

The whole verification algorithm: the specification, four reference
implementations, the failure taxonomy, and the conformance corpus.

A verifier only its issuer can run isn't evidence. The argument for this format
rests on a party with no relationship to the issuer, and no access to its
systems, being able to take a document and decide for itself whether the
document holds. That requires the algorithm to be public, and it requires more
than one implementation to exist. There are four.

## What isn't

The party that issues a proof, the runtime that produces it, and the trust root
that identifies signing authorities aren't in this repository and won't be.

That boundary is part of the answer to the standards question rather than an
exception to it. A published verifier means anyone can check the evidence. A
published issuer would mean anyone can forge it. A specification requiring both
to be open would describe a format with no security property left in it.

## For a standards body

The specification and the code are Apache-2.0. Under those terms you can:

- cite the specification, by DOI or URL, in a published document
- quote it, including normative text, with attribution
- incorporate the format or parts of it into a broader specification
- implement it, ship that implementation commercially, and state that it
  conforms if it produces the expected verdict on all 100 conformance cases
- fork it

None of that needs permission from Nanorix Inc., and none of it needs
negotiating first.

Two things to know when incorporating it.

**The wire form is frozen rather than versioned in place.** The eight steps, the
chain construction, the two algorithms, and the canonical view don't change.
Evidence kept for years has to stay checkable, so a change to any of them
produces a successor format with its own version field instead of a revision of
this one. A specification that builds on this format can rely on that. It's a
constraint we hold ourselves to and enforce in our own codebase, not a roadmap
item.

**The conformance corpus is the interoperability test.** If you need a normative
conformance requirement, "produces the expected verdict for every case in the
published corpus" is one you can actually test against. The corpus is generated
from a committed generator, so its expected verdicts can be reproduced rather
than taken on trust.

## What this format doesn't claim

The specification says this in its own scope section. It belongs here too,
because a standards author needs the negative space more than the positive.

An AuditProof makes a structural claim: these steps ran, in this order, over this
workload, and the result was signed. It doesn't claim that any regulation,
control framework, or certification requirement is addressed by that fact, and
the format carries no field that could assert one. The mapping to the OWASP
Agentic Security Initiative top ten uses "related_to", lists the entries this
evidence doesn't address alongside the ones it does, and stops there. Going
further would substitute our judgement for the auditor's, which isn't ours to
make and isn't useful to them.

If your document needs to state what an AuditProof means for a specific
obligation, that determination belongs to whoever is accountable for the
obligation. We'll supply the structural facts underneath it.

## IPR

Apache-2.0 section 3 grants a patent licence on this code under its own terms,
and that applies to everything in this repository.

Anything beyond that — a working-group IPR declaration, a royalty-free or RAND
commitment on a particular specification, a letter of assurance to a specific
standards organisation — is a commitment Nanorix Inc. makes deliberately and in
writing. This file can't grant it. Write to `hello@nanorix.io` and someone who
can make that commitment will answer.

## Contact

- Specification questions, defects, ambiguities: open an issue here.
- Citation, incorporation, working-group participation, IPR: `hello@nanorix.io`
- Vulnerabilities in the verification logic: `security@nanorix.io`, not a public
  issue.
