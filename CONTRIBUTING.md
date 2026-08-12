# Contributing

Contributions are welcome. There's one hard boundary, described first because
it's the one that gets pull requests closed.

## The wire form doesn't change

These are fixed:

- the eight chain steps, their count, their order, and their names
- how the chain is constructed, including the `0x00` separators and the literal
  `"destroy"` operation token
- SHA-512 as the hash, Ed25519 as the signature
- the genesis value `SHA-512("")`
- the 15-field canonical view, its RFC 8785 serialisation, and the fact that the
  signature covers the ASCII-hex form of the digest rather than its bytes
- the failure reasons in `governance/verify-types`. New reasons can be added.
  Existing ones can't be renamed or removed.

A pull request that changes any of them will be closed, however much it improves
the code otherwise.

This isn't about taste. Proofs that have already been issued get verified by
this algorithm for as long as they're kept, which for regulated records means
years. Changing the wire form doesn't produce a new version of the format, it
produces a pile of evidence nobody can check any more. If something genuinely
needs one of these to change, it belongs in a successor format with its own
version field, proposed as a specification change before any code is written.

If you think an implementation deviates from the specification, that's a bug in
the implementation and we want to hear about it. Open an issue with the document
that reproduces it.

## What's actually wanted

**Another implementation.** A fifth language is the best evidence that the
specification is complete enough to work from. The bar is the conformance
corpus: all 100 cases, matching verdicts.

**Conformance cases.** A document that two implementations disagree about is
worth more than a feature. Include the document, both verdicts, and which one
you think is right.

**Specification defects.** Ambiguity, an under-specified edge case, or a place
where the prose and the reference implementation don't agree.

**Bug fixes** that bring an implementation back in line with the specification.
Include a corpus case that fails before your change and passes after.

**Documentation**, especially anything that makes the integrity/authenticity
distinction harder to misread.

## Ground rules

Every behavioural change needs a test that fails without it. A guard nobody has
watched fire isn't a guard.

Cross-implementation changes land together. If a fix changes a verdict, all four
implementations change in the same pull request. If they don't, the corpus will
catch it and CI will fail, which is the corpus doing its job.

Don't add network calls to a verifier's default path. Offline verification is
part of the design, not an optimisation.

Contributions are accepted under Apache-2.0, including the patent grant in
section 3. Opening a pull request means you're licensing your contribution under
those terms.

## Security

Don't open a public issue for a vulnerability in the verification logic,
particularly anything that would let a modified document verify. Email
`security@nanorix.io`. Include the document if you have one.
