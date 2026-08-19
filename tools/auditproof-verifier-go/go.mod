// Module auditproof-verifier-go — Go reference implementation of the Nanorix
// AuditProof verifier, providing cross-implementation byte-equivalence with the
// Rust verifier (`tools/nanorix-verify/`) on the 100-fixture corpus shipped at
// commit ba1d51a (Wave 6 verification-surface scaffolds).
//
// Discipline anchors:
// - ADR-006 I0: Forever-Standard. AuditProof shape is permanent; this module
//   evolves field-additively, never breakingly.
// - ADR-027: trust-chain manifest awareness (capsulefile_content_hash →
//   required_authority_id → customer-attested signing).
// - ADR-031: BYO-HSM customer-attested signing path.
// - ADR-033: verifier release framing.
//
// Cross-implementation byte-equivalence is the binding contract: every fixture
// in `tools/nanorix-verify/fixtures/corpus/` must produce a byte-identical
// `AuditProofVerificationResult` between Rust verifier and Go verifier. If a
// single fixture diverges, that divergence is a P0 finding.
//
// Standard-library-only crypto: this module imports zero third-party packages.
// JCS canonicalization (RFC 8785) is implemented inline (~150 LOC) since
// `encoding/json` does not provide it. Ed25519 is `crypto/ed25519`. SHA-512 is
// `crypto/sha512`.
//
// MSRV: Go 1.21. The module compiles clean on `go build ./...` against
// 1.21+ toolchains.
module github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go

go 1.21
