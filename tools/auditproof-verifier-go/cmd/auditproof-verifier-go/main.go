// Command auditproof-verifier-go — standalone CLI for AuditProof verification.
//
// This is the Go reference implementation, peer to the Rust `nanorix-verify`
// CLI at the Rust verifier. The literal moment-of-truth artifact for an
// auditor receiving a Nanorix AuditProof who needs to confirm authenticity
// without any Nanorix SaaS dependency.
//
// Per the specification (verifier release framing): cross-implementation byte-equivalence
// across Rust + Go (and future browser TS) is the binding contract. If a
// single language ecosystem suffers a supply-chain compromise or a runtime
// bug, the alternate-language verifier provides cross-validation. This is what
// makes "evidence outlives Nanorix" structurally real.
//
// Usage:
//
//   $ auditproof-verifier-go path/to/auditproof.json
//   ✓ Verified · capsule cap_01HXX... · region us-central1
//
//   $ auditproof-verifier-go --json path/to/auditproof.json
//   {"valid":true,"failure_reason":null,"stage_reached":7,"metadata":{...}}
//
//   $ auditproof-verifier-go --fixture-dir the Rust verifierfixtures/corpus
//   100 fixtures · 41 verified · 59 failed
//
// Exit codes:
//   0  — verified: chain walked AND Ed25519 signature checked (stage 7)
//   1  — failed verification (or any fixture failure in --fixture-dir mode).
//        Includes a document that is not parseable JSON: that is reported as
//        the verdict required_field_missing{json_root}, matching nanorix-verify.
//   2  — the CLI could not get as far as a verdict: file unreadable/missing, or
//        a usage error. (nanorix-verify exits 1 on an unreadable file; the
//        divergence is confined to inputs where no AuditProof was ever read.)
//   3  — chain verified but the signature was NOT checked, because the proof
//        carries no signature or uses a signing_mode this build cannot verify
//        (dual_signature, tee_attested). An automated `verify && accept` gate
//        must NOT treat this as acceptance.
//
// Stage 8 — anchoring the signing key to a verified trust-chain manifest, which
// is what rejects a forgery that carries its own self-consistent key — is
// implemented in nanorix-verify and not in this build. Exit 0 here means
// integrity, not authenticity.

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go"
)

const cliVersion = "0.1.0"

func main() {
	args := os.Args[1:]
	// Wave B Items 7+8 bundle subcommands route to dedicated handlers.
	if len(args) > 0 {
		switch args[0] {
		case "bundle":
			runBundleSubcommand(args[1:])
			return
		case "pubkey-bundle":
			runPubkeyBundleSubcommand(args[1:])
			return
		}
	}

	jsonOutput := flag.Bool("json", false, "Output result as JSON instead of human-readable text.")
	rejectDiagnostic := flag.Bool("reject-diagnostic", false, "Refuse AuditProofs in diagnostic mode (the specification).")
	requiredRegion := flag.String("required-region", "", "Required region (e.g., 'europe-west1'). When set, AuditProofs whose region disagrees fail.")
	requiredAuthorityID := flag.String("required-authority-id", "", "Required signing-authority id (e.g., 'customer-hsm-mayo-clinic-v1').")
	fixtureDir := flag.String("fixture-dir", "", "Path to fixture corpus root; runs verification on every fixture and reports pass/fail counts.")
	versionFlag := flag.Bool("version", false, "Print version and exit.")
	helpFlag := flag.Bool("help", false, "Print help and exit.")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("auditproof-verifier-go %s\n", cliVersion)
		os.Exit(0)
	}
	if *helpFlag {
		printHelp()
		os.Exit(0)
	}

	policy := auditproof.VerifierPolicy{
		RejectDiagnostic:    *rejectDiagnostic,
		RequiredRegion:      *requiredRegion,
		RequiredAuthorityID: *requiredAuthorityID,
	}

	if *fixtureDir != "" {
		runFixtureCorpus(*fixtureDir, policy, *jsonOutput)
		return
	}

	args = flag.Args()
	if len(args) == 0 {
		printHelp()
		os.Exit(2)
	}

	verifyFile(args[0], policy, *jsonOutput)
}

// ─────────────────────────────────────────────────────────────────────────────
// Wave B Item 7 — `bundle` subcommand
// ─────────────────────────────────────────────────────────────────────────────

func runBundleSubcommand(args []string) {
	if len(args) == 0 {
		printBundleHelp()
		os.Exit(2)
	}
	switch args[0] {
	case "extract":
		runBundleExtract(args[1:])
	case "verify":
		runBundleVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown bundle subcommand: %s\n", args[0])
		printBundleHelp()
		os.Exit(2)
	}
}

func runBundleExtract(args []string) {
	fs := flag.NewFlagSet("bundle extract", flag.ExitOnError)
	record := fs.Uint("record", 0, "Zero-indexed record position within the AuditProof's record_receipts.")
	output := fs.String("output", "", "Path to write the bundle JSON.")
	jsonOutput := fs.Bool("json", false, "Output status as JSON.")
	fs.Parse(args)
	posArgs := fs.Args()
	if len(posArgs) == 0 || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: auditproof-verifier-go bundle extract <auditproof.json> --record N --output <out.prb.json>")
		os.Exit(2)
	}

	proofBytes, err := os.ReadFile(posArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", posArgs[0], err)
		os.Exit(2)
	}
	bundle, err := auditproof.ExtractReceiptBundle(proofBytes, uint32(*record))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: extract failed: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(bundle, "", "  ")
	if err := os.WriteFile(*output, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write failed: %v\n", err)
		os.Exit(2)
	}
	if *jsonOutput {
		fmt.Printf("{\"status\":\"ok\",\"output_path\":%q,\"record_index\":%d}\n", *output, *record)
	} else {
		fmt.Printf("Extracted record %d bundle → %s\n", *record, *output)
	}
}

func runBundleVerify(args []string) {
	fs := flag.NewFlagSet("bundle verify", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output result as JSON.")
	fs.Parse(args)
	posArgs := fs.Args()
	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: auditproof-verifier-go bundle verify <bundle.prb.json>")
		os.Exit(2)
	}
	bundleBytes, err := os.ReadFile(posArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", posArgs[0], err)
		os.Exit(2)
	}
	var bundle auditproof.PortableReceiptBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid bundle JSON: %v\n", err)
		os.Exit(2)
	}
	if err := auditproof.VerifyReceiptBundle(&bundle); err != nil {
		if *jsonOutput {
			fmt.Printf("{\"valid\":false,\"error\":%q}\n", err.Error())
		} else {
			fmt.Printf("Bundle verification FAILED\n  %v\n", err)
		}
		os.Exit(1)
	}
	signatureTarget := auditproof.SignatureTargetStep8ChainHash
	if bundle.AuditProofAnchors.SignatureTarget != nil {
		signatureTarget = *bundle.AuditProofAnchors.SignatureTarget
	}
	verdict := auditproof.BundleVerdictText(&bundle)
	if *jsonOutput {
		fmt.Printf("{\"valid\":true,\"bundle_version\":%q,\"bundle_type\":%q,\"capsule_id\":%q,\"signature_target\":%q,\"verdict\":%q}\n",
			bundle.BundleVersion, bundle.BundleType, bundle.AuditProofAnchors.CapsuleID, signatureTarget, verdict)
	} else {
		rid, _ := bundle.Receipt["record_id"].(string)
		fmt.Printf("Bundle verifies · capsule %s · record_id %s\n", bundle.AuditProofAnchors.CapsuleID, rid)
		fmt.Printf("  %s\n", verdict)
	}
}

func printBundleHelp() {
	fmt.Fprintln(os.Stderr, "auditproof-verifier-go bundle — Portable Receipt Bundle operations (Wave B Item 7)")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  extract <auditproof.json> --record N --output <out.prb.json>")
	fmt.Fprintln(os.Stderr, "  verify <bundle.prb.json>")
}

// ─────────────────────────────────────────────────────────────────────────────
// Wave B Item 8 — `pubkey-bundle` subcommand
// ─────────────────────────────────────────────────────────────────────────────

func runPubkeyBundleSubcommand(args []string) {
	if len(args) == 0 {
		printPubkeyBundleHelp()
		os.Exit(2)
	}
	switch args[0] {
	case "build":
		runPubkeyBundleBuild(args[1:])
	case "verify":
		runPubkeyBundleVerify(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown pubkey-bundle subcommand: %s\n", args[0])
		printPubkeyBundleHelp()
		os.Exit(2)
	}
}

func runPubkeyBundleBuild(args []string) {
	fs := flag.NewFlagSet("pubkey-bundle build", flag.ExitOnError)
	keys := fs.String("keys", "", "Path to JSON file containing {pubkeys: [...]} or [...].")
	output := fs.String("output", "", "Path to write the bundle JSON.")
	signerSeed := fs.String("signer-seed", "", "Path to raw Ed25519 32-byte signing-key seed.")
	signerKeyID := fs.String("signer-key-id", "", "Authority key identifier of the publisher.")
	issuerOrg := fs.String("issuer-org", "", "Opaque issuer organization tag.")
	jsonOutput := fs.Bool("json", false, "Output status as JSON.")
	fs.Parse(args)
	if *keys == "" || *output == "" || *signerSeed == "" || *signerKeyID == "" || *issuerOrg == "" {
		fmt.Fprintln(os.Stderr, "usage: auditproof-verifier-go pubkey-bundle build --keys <keys.json> --output <out.ppb.json> --signer-seed <seed.bin> --signer-key-id <id> --issuer-org <org>")
		os.Exit(2)
	}

	keysBytes, err := os.ReadFile(*keys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read keys file: %v\n", err)
		os.Exit(2)
	}
	var doc map[string]interface{}
	json.Unmarshal(keysBytes, &doc)
	var entries []auditproof.PubKeyEntry
	if pubkeys, ok := doc["pubkeys"]; ok {
		jb, _ := json.Marshal(pubkeys)
		json.Unmarshal(jb, &entries)
	} else {
		json.Unmarshal(keysBytes, &entries)
	}

	seedBytes, err := os.ReadFile(*signerSeed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read signer seed: %v\n", err)
		os.Exit(2)
	}
	if len(seedBytes) != 32 {
		fmt.Fprintf(os.Stderr, "error: signer seed must be exactly 32 bytes, got %d\n", len(seedBytes))
		os.Exit(2)
	}
	signer := ed25519.NewKeyFromSeed(seedBytes)
	bundle, err := auditproof.BuildPubkeyBundle(entries, signer, *signerKeyID, *issuerOrg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: build failed: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(bundle, "", "  ")
	if err := os.WriteFile(*output, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write failed: %v\n", err)
		os.Exit(2)
	}
	publisherPubB64 := base64.StdEncoding.EncodeToString(signer.Public().(ed25519.PublicKey))
	if *jsonOutput {
		fmt.Printf("{\"status\":\"ok\",\"output_path\":%q,\"key_count\":%d,\"publisher_pubkey_b64\":%q}\n",
			*output, len(bundle.Pubkeys), publisherPubB64)
	} else {
		fmt.Printf("Built pubkey bundle (%d keys) → %s\n", len(bundle.Pubkeys), *output)
		fmt.Printf("  Publisher pubkey (base64): %s\n", publisherPubB64)
	}
}

func runPubkeyBundleVerify(args []string) {
	fs := flag.NewFlagSet("pubkey-bundle verify", flag.ExitOnError)
	publisherPubkey := fs.String("publisher-pubkey", "", "Path to publisher's Ed25519 public key (raw 32-byte file).")
	jsonOutput := fs.Bool("json", false, "Output result as JSON.")
	fs.Parse(args)
	posArgs := fs.Args()
	if len(posArgs) == 0 || *publisherPubkey == "" {
		fmt.Fprintln(os.Stderr, "usage: auditproof-verifier-go pubkey-bundle verify <bundle.ppb.json> --publisher-pubkey <pubkey.bin>")
		os.Exit(2)
	}
	bundleBytes, err := os.ReadFile(posArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read bundle: %v\n", err)
		os.Exit(2)
	}
	var bundle auditproof.PortablePubkeyBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid bundle JSON: %v\n", err)
		os.Exit(2)
	}
	pubBytes, err := os.ReadFile(*publisherPubkey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read publisher pubkey: %v\n", err)
		os.Exit(2)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "error: publisher pubkey must be exactly 32 bytes, got %d\n", len(pubBytes))
		os.Exit(2)
	}
	if err := auditproof.VerifyPubkeyBundle(&bundle, ed25519.PublicKey(pubBytes)); err != nil {
		if *jsonOutput {
			fmt.Printf("{\"valid\":false,\"error\":%q}\n", err.Error())
		} else {
			fmt.Printf("Pubkey bundle verification FAILED\n  %v\n", err)
		}
		os.Exit(1)
	}
	if *jsonOutput {
		fmt.Printf("{\"valid\":true,\"issuer_organization\":%q,\"key_count\":%d}\n",
			bundle.IssuerOrganization, len(bundle.Pubkeys))
	} else {
		fmt.Printf("Pubkey bundle verifies · issuer %s · %d keys\n", bundle.IssuerOrganization, len(bundle.Pubkeys))
	}
}

func printPubkeyBundleHelp() {
	fmt.Fprintln(os.Stderr, "auditproof-verifier-go pubkey-bundle — Portable Pubkey Bundle operations (Wave B Item 8)")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  build --keys <keys.json> --output <out.ppb.json> --signer-seed <seed.bin> --signer-key-id <id> --issuer-org <org>")
	fmt.Fprintln(os.Stderr, "  verify <bundle.ppb.json> --publisher-pubkey <pubkey.bin>")
}

func printHelp() {
	fmt.Fprintln(os.Stderr, "auditproof-verifier-go — verify a Nanorix AuditProof")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  auditproof-verifier-go [flags] <auditproof.json>")
	fmt.Fprintln(os.Stderr, "  auditproof-verifier-go [flags] --fixture-dir <corpus-root>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags:")
	flag.PrintDefaults()
}

func verifyFile(path string, policy auditproof.VerifierPolicy, jsonOutput bool) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", path, err)
		os.Exit(2)
	}

	result := auditproof.Verify(bytes, policy)

	if jsonOutput {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		printHuman(result)
	}

	if !result.Valid {
		os.Exit(1)
	}
	// `Valid` alone is not acceptance. A proof reaches stage 4 when its chain
	// reproduces but there was no signature this build could check — an
	// unsigned partial, or a signing_mode outside {nanorix_only}. Nothing
	// cryptographic was established, so exiting 0 would let an automated
	// `verify && accept` gate accept an unverified document. Mirrors the
	// exit-code ladder in nanorix-verify.
	if result.StageReached < 7 {
		fmt.Fprintln(os.Stderr,
			"note: exiting 3 — the chain verified, but this proof carries no signature "+
				"this build can check, so integrity is not established. Do not treat "+
				"this as an accepted proof in an automated gate.")
		os.Exit(3)
	}
}

func printHuman(r auditproof.AuditProofVerificationResult) {
	if r.Valid {
		cap := "(unknown)"
		if r.Metadata.CapsuleID != nil {
			cap = *r.Metadata.CapsuleID
		}
		region := "(unset)"
		if r.Metadata.Region != nil {
			region = *r.Metadata.Region
		}
		if r.StageReached < 7 {
			// No signature was checked on this proof, so the output must not
			// print the word that implies one was.
			fmt.Printf("Chain verified, signature NOT checked \u00b7 capsule %s \u00b7 region %s\n", cap, region)
		} else {
			fmt.Printf("Verified \u00b7 capsule %s \u00b7 region %s\n", cap, region)
		}
		if r.Metadata.SigningKeyVersion != nil {
			fmt.Printf("  Signing key version: %s\n", *r.Metadata.SigningKeyVersion)
		}
		if r.Metadata.Algorithm != nil {
			fmt.Printf("  Algorithm: %s\n", *r.Metadata.Algorithm)
		}
		if r.Metadata.StepCount != nil {
			fmt.Printf("  Chain steps: %d / 8\n", *r.Metadata.StepCount)
		}
		if r.StageReached < 7 {
			fmt.Printf("  Note: stages 1-%d only. No Ed25519 signature was checked on this\n"+
				"  proof, so tampering since signing would NOT be detected. Treat this as\n"+
				"  an unverified document.\n", r.StageReached)
		} else if r.StageReached < 8 {
			fmt.Printf("  Note: the signature verified against the public key EMBEDDED in\n" +
				"  this proof, which proves it has not been altered since signing. It does\n" +
				"  NOT prove the key is Nanorix's — a forgery carrying its own key also\n" +
				"  reaches this stage. Use nanorix-verify with a trust-chain manifest to\n" +
				"  anchor the key (stage 8).\n")
		}
	} else {
		fmt.Println("Verification FAILED")
		if r.FailureReason != nil {
			fmt.Printf("  Failure: %s\n", r.FailureReason.Type)
			fmt.Printf("  Stage reached: %d / 8\n", r.StageReached)
		}
	}
}

// runFixtureCorpus walks the fixture corpus directory, runs Verify() on every
// `.json` proof file (excluding `.expected.json`), and reports aggregate
// pass/fail counts. This mode is used by CI / cross-impl byte-equivalence
// tests.
func runFixtureCorpus(root string, policy auditproof.VerifierPolicy, jsonOutput bool) {
	type fixtureResult struct {
		Path   string                                  `json:"path"`
		Result auditproof.AuditProofVerificationResult `json:"result"`
	}

	var results []fixtureResult
	verifiedCount := 0
	failedCount := 0
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Skip expected.json fixtures; only walk the.json proof files.
		if strings.HasSuffix(path, ".expected.json") {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		if filepath.Base(path) == "index.json" {
			return nil
		}
		bytes, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		r := auditproof.Verify(bytes, policy)
		results = append(results, fixtureResult{Path: path, Result: r})
		if r.Valid {
			verifiedCount++
		} else {
			failedCount++
		}
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(os.Stderr, "error: fixture walk failed: %v\n", walkErr)
		os.Exit(2)
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Path < results[j].Path })

	if jsonOutput {
		out, _ := json.MarshalIndent(struct {
			Total    int             `json:"total"`
			Verified int             `json:"verified"`
			Failed   int             `json:"failed"`
			Results  []fixtureResult `json:"results"`
		}{
			Total:    len(results),
			Verified: verifiedCount,
			Failed:   failedCount,
			Results:  results,
		}, "", "  ")
		fmt.Println(string(out))
		return
	}

	fmt.Printf("%d fixtures · %d verified · %d failed\n",
		len(results), verifiedCount, failedCount)
}
