# Contributing

Contributions are welcome, with one hard boundary described below.

## The wire form does not change

The following are fixed. A pull request that changes any of them will be closed,
regardless of how it improves the code:

- the eight chain steps — their count, their order, and their names
- the chain construction, including the `0x00` separators and the literal
  `"destroy"` operation token
- SHA-512 as the hash, Ed25519 as the signature
- the genesis value `SHA-512("")`
- the 15-field canonical view, its RFC 8785 JCS serialisation, and the fact
  that the signature is over the ASCII-hex form of the digest rather than its
  bytes
- the failure-reason taxonomy in `governance/verify-types` — reasons may be
  added, never renamed or removed

This is not a preference about code style. Proofs already issued are verified by
this algorithm for as long as they are retained, which for regulated records is
measured in years. A change to the wire form does not produce a new version; it
produces a body of evidence nobody can check any more. Anything that would
require such a change belongs in a successor format with its own version field,
proposed as a specification change first and implemented second.

If you believe you have found a case where an implementation deviates from the
specification, that is a bug in the implementation and a very welcome report —
open an issue with the document that reproduces it.

## What is genuinely wanted

- **Additional implementations.** A fifth language is the strongest possible
  evidence that the specification is complete. If you write one, the bar is the
  conformance corpus: all 100 cases, matching verdicts.
- **Conformance cases.** A document that two implementations disagree about is
  more valuable than a feature. Include the document, both verdicts, and what
  you believe the correct verdict is.
- **Specification defects.** Ambiguity, an under-specified edge, a case where
  the prose and the reference implementation diverge.
- **Bug fixes** that bring an implementation back into agreement with the
  specification, with a corpus case that fails before and passes after.
- **Documentation**, particularly anything that makes the integrity/authenticity
  distinction harder to misread.

## Ground rules

- Every behavioural change carries a test that fails without it. A guard that
  has never been observed to fire is a comment.
- Cross-implementation changes land together. If a fix changes a verdict, all
  four implementations change in the same pull request, or the corpus catches it
  and CI fails — which is the corpus working as intended.
- Do not add network calls to a verifier's default path. Offline verification is
  a property of the design, not an optimisation.
- Contributions are accepted under Apache-2.0, including its patent grant in
  section 3. By opening a pull request you are licensing your contribution under
  those terms.

## Security

Do not open a public issue for a vulnerability in the verification logic —
particularly anything that would let a modified document verify. Write to
`security@nanorix.io`. Include the document if you have one.
