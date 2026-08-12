## What this changes

<!-- One or two sentences. What is different after this lands. -->

## Why

<!-- What was wrong, or what is now possible that wasn't. -->

## Wire form

Tick one. See CONTRIBUTING.md for what "wire form" covers.

- [ ] This does not touch the wire form.
- [ ] This touches the wire form, and I've read why that gets closed.

The wire form is the eight chain steps and their order, the chain construction,
SHA-512 and Ed25519, the genesis value, the 15-field canonical view and its
RFC 8785 serialisation, and the existing failure reasons. Proofs already issued
are verified by this algorithm for as long as they're kept, so a change here
doesn't make a new version of the format, it makes evidence nobody can check.

## Verdict changes

- [ ] No verifier verdict changes.
- [ ] A verdict changes. All four implementations are updated in this PR, and I
      ran the corpus sweeps I could run. Which ones:

<!-- e.g. "cargo test -p nanorix-verify --test corpus_sweep" and/or
     "go test ./... in tools/auditproof-verifier-go" -->

There is no CI in this repository yet, so this check is yours and the
reviewer's.

## Tests

- [ ] A test fails without this change and passes with it. Where:

## Language

- [ ] No output, comment, doc or message added here uses COMPLIANT, SATISFIED,
      PASSED or MEETS to say a regulation or control framework has been met.
      An AuditProof records what happened; whether that discharges an
      obligation is an auditor's call, not the format's.
- [ ] Anything a reader sees uses the public names, AuditProof and AuditRecord.
