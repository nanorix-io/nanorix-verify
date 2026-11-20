// Command auditproof-verifier-go — standalone CLI for AuditProof verification.
//
// This is the Go reference implementation, peer to the Rust `nanorix-verify`
// CLI at `tools/nanorix-verify/`. The literal moment-of-truth artifact for an
// auditor receiving a Nanorix AuditProof who needs to confirm authenticity
// without any Nanorix SaaS dependency.
//
// (verifier release framing): cross-implementation byte-equivalence
// across Rust + Go (and future browser TS) is the binding contract. If a
// single language ecosystem suffers a supply-chain compromise or a runtime
// bug, the alternate-language verifier provides cross-validation. This is what
// makes "evidence outlives Nanorix" structurally real.
//
// Usage:
//
//   $ auditproof-verifier-go -trust-chain trust-chain.json \
//       -identity-fingerprint sha256:... path/to/auditproof.json
//   Verified · capsule cap_01HXX... · region us-central1
//
//   $ auditproof-verifier-go --json path/to/auditproof.json
//   {"valid":true,"failure_reason":null,"stage_reached":7,"metadata":{...},"status":"not_anchored"}
//   (exit 4: without -trust-chain the signature is checked only against the
//   key the proof carries)
//
//   $ auditproof-verifier-go --fixture-dir tools/nanorix-verify/fixtures/corpus
//   163 fixtures · 0 verified · 38 not_anchored · 125 not_verified
//   163 of 163 match their expected verdict
//
// --fixture-dir verifies every fixture under the folder, each under the pins
// its sibling <name>.expected.json declares, and compares valid,
// stage_reached and failure_reason with that file, as the Rust test
// every_corpus_fixture_verifies_to_its_committed_verdict in
// tools/nanorix-verify/tests/corpus_sweep.rs does; that test also compares
// status, which this mode counts but does not compare. It does not check for an
// .expected.json without a fixture or the index.json counts, which other Rust
// tests check. Each difference is printed. The policy flags and a file
// argument are refused in this mode, and so is a symlinked subfolder (the
// Rust sweep follows folder links) or a symlink whose target cannot be read.
//
// Exit codes:
//   0  — verified (status verified): the signing key resolved in the key
//        list given with -trust-chain and -identity-fingerprint, and the
//        signature verified against it (stage 8). In --fixture-dir mode:
//        every fixture's verdict equals its .expected.json.
//   1  — failed verification. Includes a document that is not JSON as
//        nanorix-verify parses it (invalid UTF-8, a byte order mark, half a
//        surrogate pair, 128 or more nested containers, NaN, a number beyond
//        float64): that is reported as the verdict
//        required_field_missing{json_root}; nanorix-verify exits 1 with no
//        verdict. In --fixture-dir mode: at least one
//        fixture's verdict differs from its .expected.json.
//   2  — the CLI could not get as far as a verdict: file unreadable/missing,
//        a usage error (more than one argument after the flags included:
//        flags go before the proof file; a pin, policy or path flag given
//        twice or empty included), or a key list that cannot be read
//        or parsed or is not signed by the pinned identity (-trust-chain).
//        nanorix-verify exits 1 instead on an unreadable proof, key list or
//        activity record, an unparseable key list, and -trust-chain without
//        -identity-fingerprint; it has no --fixture-dir. In --fixture-dir
//        mode also: a policy flag was given, the folder is not a folder,
//        cannot be walked (a symlinked subfolder or a symlink whose target
//        cannot be read included) or holds no fixture, or a fixture has no
//        readable .expected.json with a boolean valid and a stage_reached
//        written as an unsigned integer (digits alone, as serde_json's as_u64
//        reads it).
//   3  — chain verified but the signature was NOT checked, because the proof
//        carries no signature. (A signing_mode this build cannot verify, such
//        as dual_signature or tee_attested, exits 1 with algorithm_unsupported.)
//        An automated `verify && accept` gate must NOT treat this as
//        acceptance.
//   4  — not anchored (status not_anchored): the signature is valid against
//        the key the proof itself carries (stage 7), and no key list anchored
//        that key: none was given, or the proof is cdp_version 1.0. A proof
//        self-signed with a freshly made key reaches the same result, so an
//        automated gate must NOT accept it either. For a proof both can read,
//        exits 0, 1, 3 and 4 are the ones nanorix-verify gives.
//
// The single-file --json output is the verification result followed by a
// status member: verified (exit 0), not_anchored (exit 4) or not_verified
// (exit 1 or 3). The valid field is true when the chain and the signature
// hold under the key used, and says nothing on its own about who signed: it
// is true at stage 7, and at stage 4, where no signature was checked. Read
// status or the exit code, never valid alone.
//
// Stage 8 — anchoring the signing key to a signed key list, which is what
// rejects a forgery that carries its own self-consistent key — runs when the
// flags -trust-chain <key-list.json> and -identity-fingerprint <sha256:...> are
// given. The key list is checked against the pinned fingerprint before any
// proof is read; a list that is not signed by the pinned identity ends the run
// with exit 2. Without them no proof exits 0: the best result is exit 4.

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/nanorix-io/nanorix-verify/tools/auditproof-verifier-go"
)

const cliVersion = "0.1.0"

// onceString is a string flag that refuses a second value and an empty one.
// Keeping either of two values would leave the other pin or policy unchecked,
// and an empty one would apply nothing, while the caller believes it ran.
type onceString struct {
	value string
	set   bool
}

func (v *onceString) String() string {
	if v == nil {
		return ""
	}
	return v.value
}

func (v *onceString) Set(s string) error {
	if v.set {
		return errors.New("given twice")
	}
	if s == "" {
		return errors.New("needs a value")
	}
	v.value, v.set = s, true
	return nil
}

// onceBool is a boolean flag that refuses a second use, so a later
// -flag=false cannot undo a policy given earlier on the same line.
type onceBool struct {
	value bool
	set   bool
}

func (v *onceBool) String() string {
	if v == nil {
		return "false"
	}
	return strconv.FormatBool(v.value)
}

func (v *onceBool) Set(s string) error {
	if v.set {
		return errors.New("given twice")
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	v.value, v.set = b, true
	return nil
}

func (v *onceBool) IsBoolFlag() bool { return true }

func onceStringFlag(fs *flag.FlagSet, name, usage string) *string {
	v := &onceString{}
	fs.Var(v, name, usage)
	return &v.value
}

func onceBoolFlag(fs *flag.FlagSet, name, usage string) *bool {
	v := &onceBool{}
	fs.Var(v, name, usage)
	return &v.value
}

// subcommandWords lists the words that name a subcommand after each command.
var subcommandWords = map[string][]string{
	"":              {"bundle", "pubkey-bundle"},
	"bundle":        {"extract", "verify"},
	"pubkey-bundle": {"build", "verify"},
}

// asksHelpOrVersion reports whether arg is -h, -help or -version, with one or
// two dashes and with or without a value.
func asksHelpOrVersion(arg string) bool {
	name := strings.TrimPrefix(arg, "-")
	if name == arg {
		return false
	}
	name = strings.TrimPrefix(name, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	switch name {
	case "h", "help", "version":
		return true
	}
	return false
}

// besideHelpOrVersion returns the first argument that is neither a help or
// version flag nor a subcommand word, when the line asks for help or the
// version. Help and the version exit 0 without reading anything, so beside a
// flag or a file they would turn a gate's refusal into exit 0 with no verdict.
func besideHelpOrVersion(args []string) (string, bool) {
	asked := false
	for _, a := range args {
		if asksHelpOrVersion(a) {
			asked = true
			break
		}
	}
	if !asked {
		return "", false
	}
	command := ""
	for _, a := range args {
		if asksHelpOrVersion(a) {
			continue
		}
		found := false
		for _, word := range subcommandWords[command] {
			if a == word {
				found = true
				break
			}
		}
		if !found {
			return a, true
		}
		command = strings.TrimSpace(command + " " + a)
	}
	return "", false
}

func main() {
	args := os.Args[1:]
	if other, refused := besideHelpOrVersion(args); refused {
		fmt.Fprintf(os.Stderr, "usage: -help, -h and -version are given alone, after the subcommand words; this run also got %s\n",
			strconv.Quote(other))
		os.Exit(2)
	}
	// The bundle subcommands route to dedicated handlers.
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
	rejectDiagnostic := onceBoolFlag(flag.CommandLine, "reject-diagnostic", "Refuse an AuditProof whose signed activity trail records diagnostic mode (a diagnostic_mode_enabled event), and every AuditProof that cannot show it does not, whose activity is unsigned: cdp_version 1.0, or 2.1 or 2.2 without a signature. Only a verified result (stage 8, with -trust-chain) ties the trail to a Nanorix key. bundle verify and pubkey-bundle verify do not take this flag.")
	requiredRegion := onceStringFlag(flag.CommandLine, "required-region", "Required region (e.g., 'europe-west1'), compared with the region on the signed capsule_started activity event. When set, an AuditProof whose region disagrees fails, and so does every AuditProof whose region is unsigned: cdp_version 1.0, or 2.1 or 2.2 without a signature. Only a verified result (stage 8, with -trust-chain) ties the region to a Nanorix key.")
	requiredAuthorityID := onceStringFlag(flag.CommandLine, "required-authority-id", "Required signing-authority id (e.g., 'customer-hsm-example-org-v1'), compared with the proof's top-level authority_id. The signature covers that field only on cdp_version 2.1 and 2.2; on 1.0 a pin accepts only us-kms-nanorix-v1, and 2.0 is refused before the pin is read. A pin is a full authority check only together with -trust-chain.")
	trustChain := onceStringFlag(flag.CommandLine, "trust-chain", "Path to a signed key list (trust-chain manifest) to anchor the proof's signing key against (stage 8). Needs -identity-fingerprint. The list is refused, with exit 2 and before any proof is read, unless the pinned identity signed it.")
	identityFingerprint := onceStringFlag(flag.CommandLine, "identity-fingerprint", "The identity fingerprint to pin for -trust-chain, obtained from the key list's publisher by a channel other than the list itself and never computed from it: sha256:<hex of SHA-256 over the identity public key> for the hosted service, or hybrid1-sha256:<hex> for a BYOC install, from its contract. A hybrid1-sha256: pin needs a build with crypto/mldsa (Go 1.27 or later, without GOFIPS140=certified or v1.0.0); any other build refuses it.")
	fixtureDir := onceStringFlag(flag.CommandLine, "fixture-dir", "Path to a fixture corpus root laid out as tools/nanorix-verify/fixtures/corpus. Verifies every fixture under the pins its sibling .expected.json declares, compares valid, stage_reached and failure_reason with that file, prints each difference, and exits 1 if any differs. The policy flags, a file argument, a symlinked subfolder (the Rust sweep follows folder links) and a symlink whose target cannot be read are refused in this mode.")
	customerActivity := onceStringFlag(flag.CommandLine, "customer-activity", "Path to the customer's activity record (activity_events.jsonl) for a proof carrying customer_declared_activity_root. The root is recomputed from the file's raw bytes and compared; a mismatch fails. Single-proof verification only.")
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

	// Each fixture carries its own pins, so a policy flag here would either be
	// ignored or change every verdict the corpus records.
	if *fixtureDir != "" && (*rejectDiagnostic || *requiredRegion != "" || *requiredAuthorityID != "" ||
		*trustChain != "" || *identityFingerprint != "") {
		fmt.Fprintln(os.Stderr, "usage: --fixture-dir runs each fixture under the policy its .expected.json declares; -reject-diagnostic, -required-region, -required-authority-id, -trust-chain and -identity-fingerprint are refused in this mode.")
		os.Exit(2)
	}

	if *fixtureDir != "" && flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "usage: --fixture-dir takes no file argument; it verifies every fixture under the folder.")
		os.Exit(2)
	}

	// flag.Parse stops at the first argument that is not a flag, so a flag
	// written after the proof file arrives here as a second argument; running
	// without it would drop a pin the user asked for.
	if *fixtureDir == "" && flag.NArg() > 1 {
		fmt.Fprintf(os.Stderr, "usage: auditproof-verifier-go [flags] <auditproof.json>: flags go before the proof file, and one file is verified per run; after the flags this run got %d arguments: %s\n",
			flag.NArg(), strings.Join(flag.Args(), " "))
		os.Exit(2)
	}

	policy := auditproof.VerifierPolicy{
		RejectDiagnostic:    *rejectDiagnostic,
		RequiredRegion:      *requiredRegion,
		RequiredAuthorityID: *requiredAuthorityID,
	}

	// Stage 8: the key list is checked against the pin before any proof is
	// read. A list that is not the pinned identity's is a setup error, never a
	// verdict, and never silently falls back to stage 7.
	if *trustChain != "" || *identityFingerprint != "" {
		if *trustChain == "" || *identityFingerprint == "" {
			fmt.Fprintln(os.Stderr, "usage: -trust-chain and -identity-fingerprint go together: the key list is only as good as the pin it is checked against.")
			os.Exit(2)
		}
		list, err := os.ReadFile(*trustChain)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read key list %s: %v\n", *trustChain, err)
			os.Exit(2)
		}
		chain, err := auditproof.LoadTrustChain(list, *identityFingerprint)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trust-chain key list verification FAILED: %v\n  The supplied key list is not the pinned identity's - refusing to verify any proof against it.\n", err)
			os.Exit(2)
		}
		policy.TrustChain = chain
	}

	// The record is read as raw bytes — never parsed — and handed to
	// the verifier. A record belongs to exactly one proof, so corpus mode
	// refuses it rather than applying one file to every document.
	if *customerActivity != "" {
		if *fixtureDir != "" {
			fmt.Fprintln(os.Stderr, "usage: -customer-activity applies to exactly one proof (the record is committed per-capsule); verify each proof with its own record.")
			os.Exit(2)
		}
		record, err := os.ReadFile(*customerActivity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read customer activity record %s: %v\n", *customerActivity, err)
			os.Exit(2)
		}
		policy.CustomerActivity = record
	}

	if *fixtureDir != "" {
		os.Exit(runFixtureCorpus(*fixtureDir, *jsonOutput, os.Stdout, os.Stderr))
	}

	args = flag.Args()
	if len(args) == 0 {
		printHelp()
		os.Exit(2)
	}

	verifyFile(args[0], policy, *jsonOutput)
}

// ─────────────────────────────────────────────────────────────────────────────
// `bundle` subcommand
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
		fmt.Fprintln(os.Stderr, "usage: auditproof-verifier-go bundle extract --record N --output <out.prb.json> <auditproof.json>")
		os.Exit(2)
	}
	// A flag written after the proof file arrives as an extra argument; running
	// would ignore it (a -record 3 there would extract record 0).
	if len(posArgs) != 1 {
		fmt.Fprintf(os.Stderr, "usage: auditproof-verifier-go bundle extract [flags] <auditproof.json>: flags go before the proof file, and one file is read per run; after the flags this run got %d arguments: %s\n",
			len(posArgs), strings.Join(posArgs, " "))
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
	trustChain := onceStringFlag(fs, "trust-chain", "Refused: bundle verify reads no key list yet.")
	fs.Parse(args)
	if *trustChain != "" {
		fmt.Fprintln(os.Stderr, "usage: bundle verify does not read -trust-chain yet. It checks a bundle "+
			"against the key the bundle carries, so a key list would be ignored. To resolve the signer, "+
			"verify the full AuditProof: auditproof-verifier-go -trust-chain <key-list.json> "+
			"-identity-fingerprint <sha256:...> <auditproof.json>")
		os.Exit(2)
	}
	posArgs := fs.Args()
	if len(posArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: auditproof-verifier-go bundle verify <bundle.prb.json>")
		os.Exit(2)
	}
	// fs.Parse stops at the first argument that is not a flag, so a flag
	// written after the bundle file (a -trust-chain the user expects to be
	// refused) arrives here as an extra argument; running would ignore it.
	if len(posArgs) != 1 {
		fmt.Fprintf(os.Stderr, "usage: auditproof-verifier-go bundle verify [flags] <bundle.prb.json>: flags go before the bundle file, and one file is verified per run; after the flags this run got %d arguments: %s\n",
			len(posArgs), strings.Join(posArgs, " "))
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
	result, err := auditproof.VerifyReceiptBundleDetailed(&bundle)
	if err != nil {
		kind := "error"
		var be *auditproof.BundleError
		if errors.As(err, &be) {
			kind = be.Kind
		}
		if *jsonOutput {
			fmt.Printf("{\"valid\":false,\"receipt_bound\":false,\"signature_authentic\":false,\"error_kind\":%q,\"error\":%q}\n", kind, err.Error())
		} else {
			fmt.Printf("Bundle verification FAILED\n  %v\n", err)
		}
		os.Exit(1)
	}
	verdict := auditproof.BundleVerdictText(&bundle)
	valid := result.Valid()
	if *jsonOutput {
		fmt.Printf("{\"valid\":%t,\"receipt_bound\":%t,\"signature_authentic\":%t,\"bundle_version\":%q,\"bundle_type\":%q,\"capsule_id\":%q,\"signature_target\":%q,\"verdict\":%q}\n",
			valid, result.ReceiptBound, result.SignatureAuthentic, bundle.BundleVersion, bundle.BundleType, bundle.AuditProofAnchors.CapsuleID, result.SignatureTarget, verdict)
	} else {
		rid, _ := bundle.Receipt["record_id"].(string)
		if valid {
			fmt.Printf("Bundle verifies (signature checked against the key carried in the bundle, which was not anchored to a trust chain, so who signed is not established; exit 0 here is not the verified exit of a proof) · capsule %s · record_id %s\n", bundle.AuditProofAnchors.CapsuleID, rid)
		} else {
			fmt.Printf("Signature authentic, receipt NOT bound · capsule %s · record_id %s\n", bundle.AuditProofAnchors.CapsuleID, rid)
		}
		fmt.Printf("  %s\n", verdict)
	}
	if !valid {
		os.Exit(1)
	}
}

func printBundleHelp() {
	fmt.Fprintln(os.Stderr, "auditproof-verifier-go bundle — Portable Receipt Bundle operations")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  extract --record N --output <out.prb.json> <auditproof.json>")
	fmt.Fprintln(os.Stderr, "  verify <bundle.prb.json>")
	fmt.Fprintln(os.Stderr, "Flags go before the file; an argument after it exits 2.")
}

// ─────────────────────────────────────────────────────────────────────────────
// `pubkey-bundle` subcommand
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
	// The command takes no file argument; one stops flag parsing, so a flag
	// after it would be ignored.
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "usage: auditproof-verifier-go pubkey-bundle build takes flags only; after the flags this run got %d arguments: %s\n",
			fs.NArg(), strings.Join(fs.Args(), " "))
		os.Exit(2)
	}
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
	publisherPubkey := onceStringFlag(fs, "publisher-pubkey", "Path to publisher's Ed25519 public key (raw 32-byte file).")
	jsonOutput := fs.Bool("json", false, "Output result as JSON.")
	fs.Parse(args)
	posArgs := fs.Args()
	if len(posArgs) == 0 || *publisherPubkey == "" {
		fmt.Fprintln(os.Stderr, "usage: auditproof-verifier-go pubkey-bundle verify --publisher-pubkey <pubkey.bin> <bundle.ppb.json>")
		os.Exit(2)
	}
	// A second -publisher-pubkey written after the bundle file arrives as an
	// extra argument; running would ignore it and check only the first key.
	if len(posArgs) != 1 {
		fmt.Fprintf(os.Stderr, "usage: auditproof-verifier-go pubkey-bundle verify [flags] <bundle.ppb.json>: flags go before the bundle file, and one file is verified per run; after the flags this run got %d arguments: %s\n",
			len(posArgs), strings.Join(posArgs, " "))
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
	fmt.Fprintln(os.Stderr, "auditproof-verifier-go pubkey-bundle — Portable Pubkey Bundle operations")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  build --keys <keys.json> --output <out.ppb.json> --signer-seed <seed.bin> --signer-key-id <id> --issuer-org <org>")
	fmt.Fprintln(os.Stderr, "  verify --publisher-pubkey <pubkey.bin> <bundle.ppb.json>")
	fmt.Fprintln(os.Stderr, "verify takes its flags before the file and exits 2 on an argument after it; build takes flags only.")
}

func printHelp() {
	fmt.Fprintln(os.Stderr, "auditproof-verifier-go — verify a Nanorix AuditProof")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  auditproof-verifier-go [flags] <auditproof.json>")
	fmt.Fprintln(os.Stderr, "  auditproof-verifier-go [flags] --fixture-dir <corpus-root>")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Flags (each pin, policy and path flag once, with a value; a repeat or an empty value exits 2):")
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
		out, _ := json.MarshalIndent(singleFileJSON{result, verificationStatus(result)}, "", "  ")
		fmt.Println(string(out))
	} else {
		printHuman(result, bytes)
		if result.Valid {
			printSigner(os.Stdout, result, bytes, policy.TrustChain)
		}
	}

	if !result.Valid {
		os.Exit(1)
	}
	// `Valid` alone is not acceptance. A proof reaches stage 4 when its chain
	// reproduces but there was no signature this build could check — an
	// unsigned partial. Nothing cryptographic was established, so exiting 0
	// would let an automated
	// `verify && accept` gate accept an unverified document. Mirrors the
	// exit-code ladder in nanorix-verify.
	if result.StageReached < 7 {
		fmt.Fprintln(os.Stderr,
			"note: exiting 3 — the chain verified, but this proof carries no signature "+
				"this build can check, so integrity is not established. Do not treat "+
				"this as an accepted proof in an automated gate.")
		os.Exit(3)
	}
	if result.StageReached < 8 {
		if result.Metadata.CdpVersion != nil && *result.Metadata.CdpVersion == "1.0" {
			fmt.Fprintln(os.Stderr, v10Exit4Note)
		} else {
			fmt.Fprintln(os.Stderr,
				"note: exiting 4 — the signature is valid against the key this document "+
					"carries, and no trust chain resolved that key, so who signed it is not "+
					"established. Pass -trust-chain <key-list.json> -identity-fingerprint "+
					"<sha256:...> to resolve it.")
		}
		os.Exit(4)
	}
}

// verificationStatus is the status nanorix-verify and the SDKs give a result:
// verified only at stage 8, not_anchored for a signature valid against the key
// the proof carries (stage 7), not_verified otherwise.
func verificationStatus(r auditproof.AuditProofVerificationResult) string {
	return r.Status()
}

// singleFileJSON is the single-file --json output: the verification result,
// then its status, as nanorix-verify prints it.
type singleFileJSON struct {
	auditproof.AuditProofVerificationResult
	Status string `json:"status"`
}

// v10NotCovered is shown where a capsule id or region would be, on a 1.0 proof.
const v10NotCovered = "not named (a 1.0 signature does not cover it)"

// v10Exit4Note is printed on stderr when a 1.0 proof exits 4. No key list
// changes that exit, so the note names none. The words nanorix-verify prints.
const v10Exit4Note = "note: exiting 4 — a 1.0 proof is never anchored; no key list " +
	"changes this. Its signature covers final_hash alone, so it does not tie the signing key " +
	"to a capsule."

// v10Scope says what a valid 1.0 verdict establishes, in the words
// nanorix-verify prints.
const v10Scope = "The 8-step chain reproduced and the Ed25519 signature over " +
	"final_hash verified against the key embedded in this 1.0 proof. A 1.0 signature covers " +
	"final_hash alone, which binds destroyed_at and the two optional Merkle roots " +
	"(record_receipts_merkle_root and parent_proofs_merkle_root). It does not bind the " +
	"capsule_id itself (only through record receipts, which a holder can remove), the " +
	"region or the key id, so this verdict names no capsule. A 1.0 proof is " +
	"never anchored to a key list (stage 7, not stage 8), with or without a trust-chain " +
	"manifest."

func printHuman(r auditproof.AuditProofVerificationResult, raw []byte) {
	if r.Valid {
		v10 := r.Metadata.CdpVersion != nil && *r.Metadata.CdpVersion == "1.0"
		cap := "(unknown)"
		if r.Metadata.CapsuleID != nil {
			cap = *r.Metadata.CapsuleID
		} else if v10 {
			cap = v10NotCovered
		}
		region := "(unset)"
		if r.Metadata.Region != nil {
			region = *r.Metadata.Region
		} else if v10 {
			region = v10NotCovered
		} else if r.StageReached < 7 {
			region = "(unsigned)"
		}
		if r.StageReached >= 7 && v10 {
			fmt.Println("Signature valid \u00b7 AuditProof 1.0 binds its time and two Merkle roots only \u00b7 never anchored to a key list")
			fmt.Printf("  %s\n", v10Scope)
		} else if r.StageReached < 7 {
			// No signature was checked on this proof, so the output must not
			// print the word that implies one was.
			fmt.Printf("Chain verified, signature NOT checked \u00b7 capsule %s \u00b7 region %s\n", cap, region)
		} else if r.StageReached < 8 {
			// The key came from the proof itself, which a forgery also carries.
			fmt.Printf("Signature valid \u00b7 key NOT anchored to a trust root \u00b7 capsule %s \u00b7 region %s\n", cap, region)
		} else {
			fmt.Printf("Verified \u00b7 capsule %s \u00b7 region %s\n", cap, region)
		}
		if r.Metadata.SigningKeyVersion != nil {
			// The metadata value is the attestation's when it carries one, and
			// the signature does not cover that field. Only the top-level value
			// is in the signed view, and only on 2.1 and 2.2: a 1.0 signature
			// covers final_hash alone.
			if v10 {
				fmt.Printf("  Signing key version (not covered by a 1.0 signature): %s\n", *r.Metadata.SigningKeyVersion)
			} else if attestationKeyVersion(raw) {
				fmt.Printf("  Signing key version (attestation, not covered by the signature): %s\n", *r.Metadata.SigningKeyVersion)
			} else {
				fmt.Printf("  Signing key version: %s\n", *r.Metadata.SigningKeyVersion)
			}
		}
		if r.Metadata.Algorithm != nil {
			fmt.Printf("  Algorithm: %s\n", *r.Metadata.Algorithm)
		}
		if r.Metadata.StepCount != nil {
			fmt.Printf("  Chain steps: %d / 8\n", *r.Metadata.StepCount)
		}
		// Say what was and was not established about a declared
		// customer activity root. Silence here would let "Verified" be read as
		// covering a record this build never saw.
		if r.Metadata.CustomerDeclaredActivityRoot != nil {
			root := *r.Metadata.CustomerDeclaredActivityRoot
			if r.Metadata.CustomerDeclaredActivityChecked != nil && *r.Metadata.CustomerDeclaredActivityChecked {
				fmt.Printf("  Customer-declared activity root: %s\n", root)
				fmt.Println("  Recomputed from the supplied -customer-activity record and matched. The root commits to the record's raw bytes; Nanorix did not read or validate their content, and this check does not either.")
			} else {
				fmt.Printf("  Customer-declared activity root: %s — declared, NOT checked\n", root)
				fmt.Println("  The proof commits to the customer's activity record, but no record was supplied. Pass -customer-activity <activity_events.jsonl> to recompute the root and compare. The signature covers the root either way.")
			}
		}
		if r.StageReached < 7 {
			fmt.Printf("  Note: stages 1-%d only. No Ed25519 signature was checked on this\n"+
				"  proof, so tampering since signing would NOT be detected. Treat this as\n"+
				"  an unverified document.\n", r.StageReached)
		} else if r.StageReached < 8 && !v10 {
			fmt.Printf("  Note: the signature verified against the public key EMBEDDED in\n" +
				"  this proof, which shows no signed byte has changed since signing (fields\n" +
				"  outside the signed view, such as metadata, are not checked). It does\n" +
				"  NOT prove the key is the authority's — a forgery carrying its own key\n" +
				"  also reaches this stage. Pass -trust-chain <key-list.json> and\n" +
				"  -identity-fingerprint <sha256:...> to anchor the key (stage 8).\n")
		} else {
			fmt.Printf("  Anchored (stage 8): the signing key was resolved in the key list signed\n" +
				"  by the pinned identity, and the signature verified against that key.\n")
		}
	} else {
		fmt.Println("Verification FAILED")
		if r.FailureReason != nil {
			fmt.Printf("  Failure: %s\n", failureLine(r.FailureReason))
			fmt.Printf("  Stage reached: %d / 8\n", r.StageReached)
		}
	}
}

// customerKeyAdvice is printed at stage 7 when the proof's signed labels name
// a customer authority. It states the label and the action only: the label
// does not establish who holds the key.
func customerKeyAdvice(authority string) string {
	return "This proof's signed labels name a customer authority (" + printable(authority) +
		"). To anchor its key, supply the key list and identity fingerprint published for that authority."
}

// notEstablished is printed once under a stage-8 verdict: what anchoring the
// key does not show.
var notEstablished = [4]string{
	"It does not say who the legal person behind the fingerprint is.",
	"It does not say the key is non-exportable or HSM-held.",
	"It does not say Nanorix's software could not have requested the signature.",
	"It makes no regulatory statement.",
}

// legacyModeLine is the legacy customer shape, a signed nanorix_only under a
// customer-classified authority, before stage 8 ("Legacy
// proofs"); legacyModeLineAnchored is the same line once stage 8 resolved it.
const legacyModeLine = "signing_mode predates customer_only; this proof names a customer-classified authority, which only stage 8 (the customer's key list) anchors to the key that signed."
const legacyModeLineAnchored = "signing_mode predates customer_only; this proof names a customer-classified authority, and stage 8 resolved its key in the key list below, so the signer is the customer authority named above."

// printable keeps a proof's or key list's text from driving the terminal:
// ASCII graphic characters and space pass, every other rune is written as
// \u{..}, as the Rust CLI writes it.
func printable(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r == ' ' || (r > ' ' && r < 0x7f) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "\\u{%x}", r)
		}
	}
	return b.String()
}

// coverage is what the result says about the signature over the labels: the
// three forms of Metadata.AuthoritySigned.
type coverage int

const (
	coverageUnchecked coverage = iota
	coverageNotCovered
	coverageCovered
)

func coverageOf(r auditproof.AuditProofVerificationResult) coverage {
	switch {
	case r.Metadata.AuthoritySigned == nil:
		return coverageUnchecked
	case *r.Metadata.AuthoritySigned:
		return coverageCovered
	default:
		return coverageNotCovered
	}
}

func (c coverage) phrase() string {
	switch c {
	case coverageUnchecked:
		return "no signature was checked"
	case coverageCovered:
		return "covered by the signature"
	default:
		return "not covered by the signature"
	}
}

// labelText is a string label as printed: the proof's own string, or the
// issuer's default with a note saying it is a default and what the signature
// binds instead (the canonical view binds the raw value, null when absent).
func labelText(proof map[string]interface{}, key, def string, c coverage) (string, string) {
	v, present := proof[key]
	if s, ok := v.(string); ok {
		return printable(s), ""
	}
	how, binds := "absent from the proof", "its absence"
	if present {
		how, binds = "not a string in the proof", "the value "+printable(jsonText(v))
	}
	tail := c.phrase()
	if c == coverageCovered {
		tail = "the signature covers " + binds
	}
	return def, "default: " + how + "; " + tail
}

// keyVersionText is the top-level key version as printed. Under the signature
// it is the integer the canonical view binds (the string's int64 parse, 0 when
// it does not parse); unsigned, it is the string as written.
func keyVersionText(r auditproof.AuditProofVerificationResult, proof map[string]interface{}, c coverage) (string, string) {
	v, present := proof["signing_key_version"]
	s, isString := v.(string)
	if c != coverageCovered {
		switch {
		case isString:
			return printable(s), ""
		case r.Metadata.SigningKeyVersion != nil:
			return printable(*r.Metadata.SigningKeyVersion), ""
		default:
			return "(none)", ""
		}
	}
	switch {
	case isString:
		n, err := strconv.ParseInt(s, 10, 64)
		switch {
		case err != nil:
			return printable(s), "not a number; the signature covers 0"
		case strconv.FormatInt(n, 10) == s:
			return s, ""
		default:
			return strconv.FormatInt(n, 10), "written " + printable(s) + " in the proof; the signature covers " + strconv.FormatInt(n, 10)
		}
	case !present:
		return "none", "absent from the proof; the signature covers 0"
	default:
		return printable(jsonText(v)), "not a string; the signature covers 0"
	}
}

// attestationKeyVersion reports whether the proof carries a string
// `attestation.signing_key_version`, the value the metadata reads first.
func attestationKeyVersion(raw []byte) bool {
	var proof map[string]interface{}
	if json.Unmarshal(raw, &proof) != nil || proof == nil {
		return false
	}
	attestation, ok := proof["attestation"].(map[string]interface{})
	if !ok {
		return false
	}
	_, isString := attestation["signing_key_version"].(string)
	return isString
}

// printSigner prints the signer the proof's own labels claim and what the
// signature covers of them, and at stage 8 the key list the key resolved in.
func printSigner(w io.Writer, r auditproof.AuditProofVerificationResult, raw []byte, tc *auditproof.TrustChain) {
	var proof map[string]interface{}
	if json.Unmarshal(raw, &proof) != nil || proof == nil {
		return
	}
	c := coverageOf(r)
	authority, authorityNote := labelText(proof, "authority_id", auditproof.DefaultAuthorityID, c)
	keyVersion, versionNote := keyVersionText(r, proof, c)
	if authorityNote == "" && versionNote == "" {
		fmt.Fprintf(w, "  Signer: authority %s, key version %s (%s)\n", authority, keyVersion, c.phrase())
	} else {
		if authorityNote == "" {
			authorityNote = c.phrase()
		}
		if versionNote == "" {
			versionNote = c.phrase()
		}
		fmt.Fprintf(w, "  Signer: authority %s (%s), key version %s (%s)\n", authority, authorityNote, keyVersion, versionNote)
	}
	version, _ := proof["cdp_version"].(string)
	modeString, modeIsString := proof["signing_mode"].(string)
	if modeIsString || version == "2.1" || version == "2.2" {
		mode, modeNote := labelText(proof, "signing_mode", "nanorix_only", c)
		if modeNote == "" {
			modeNote = c.phrase()
		}
		fmt.Fprintf(w, "  Signing mode: %s (%s)\n", mode, modeNote)
	}
	if !modeIsString {
		modeString = "nanorix_only"
	}
	effective, ok := proof["authority_id"].(string)
	if !ok {
		effective = auditproof.DefaultAuthorityID
	}
	customerAuthority := auditproof.IsCustomerAuthority(effective)
	signed := c == coverageCovered && r.StageReached >= 7
	if signed && modeString == "nanorix_only" && customerAuthority {
		if r.StageReached >= 8 {
			fmt.Fprintf(w, "  %s\n", legacyModeLineAnchored)
		} else {
			fmt.Fprintf(w, "  %s\n", legacyModeLine)
		}
	}
	if r.StageReached >= 8 && tc != nil {
		fmt.Fprintf(w, "  Key list: issued %s, identity %s (the fingerprint you pinned)\n", printable(tc.IssuedAt()), printable(tc.PinnedIdentityFingerprint()))
		if attestation, ok := proof["attestation"].(map[string]interface{}); ok {
			resolved, isString := attestation["signing_key_version"].(string)
			top, topIsString := proof["signing_key_version"].(string)
			if isString && (!topIsString || resolved != top) {
				fmt.Fprintf(w, "  Key list resolved key version %s (read from attestation.signing_key_version, which the signature does not cover)\n", printable(resolved))
			}
		}
		fmt.Fprintln(w, "  Not established by this check:")
		for _, line := range notEstablished {
			fmt.Fprintf(w, "    %s\n", line)
		}
	} else if r.StageReached == 7 && signed && (modeIsString && modeString == auditproof.SigningModeCustomerOnly || customerAuthority) {
		fmt.Fprintf(w, "  %s\n", customerKeyAdvice(effective))
	}
}

// failureLine names the failure and, when the reason carries one, the field
// it is about, in the Rust CLI's form: `unsigned_field_populated (field:
// witness_signatures)`, `field_malformed (field: X, reason: Y)`.
func failureLine(f *auditproof.FailureReason) string {
	switch {
	case f.Type == auditproof.ReasonSigningModeAuthorityMismatch:
		claimed := "absent or not a string, so the Nanorix default applies"
		if f.ClaimedAuthorityID != nil {
			claimed = printable(*f.ClaimedAuthorityID)
		}
		return fmt.Sprintf("%s (signing_mode: customer_only, claimed_authority_id: %s)", f.Type, claimed)
	case f.Field != "" && f.Reason != "":
		return fmt.Sprintf("%s (field: %s, reason: %s)", f.Type, f.Field, f.Reason)
	case f.Field != "":
		return fmt.Sprintf("%s (field: %s)", f.Type, f.Field)
	default:
		return string(f.Type)
	}
}

// runFixtureCorpus verifies every fixture under root and compares its verdict
// with the fixture's sibling <name>.expected.json, the corpus's own verdict
// file (tools/nanorix-verify/fixtures/corpus/README.md), the way
// every_corpus_fixture_verifies_to_its_committed_verdict in
// tools/nanorix-verify/tests/corpus_sweep.rs does. It returns the exit code:
// 0 when every fixture matches, 1 when any differs, 2 when the corpus cannot
// be compared.
func runFixtureCorpus(root string, jsonOutput bool, stdout, stderr io.Writer) int {
	type fixtureResult struct {
		Path       string                                  `json:"path"`
		Result     auditproof.AuditProofVerificationResult `json:"result"`
		Mismatches []string                                `json:"mismatches,omitempty"`
	}

	rootInfo, err := os.Stat(root)
	if err != nil {
		fmt.Fprintf(stderr, "error: fixture walk failed: %v\n", err)
		return 2
	}
	if !rootInfo.IsDir() {
		fmt.Fprintf(stderr, "error: %s is not a folder\n", root)
		return 2
	}
	// Walk does not follow a link, so a symlinked root is resolved once here;
	// every path printed stays under the root the user gave.
	given := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	shown := func(path string) string {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return path
		}
		return filepath.Join(given, rel)
	}

	var paths []string
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			var pathErr *os.PathError
			if errors.As(err, &pathErr) {
				pathErr.Path = shown(pathErr.Path)
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, statErr := os.Stat(path)
			if statErr != nil {
				return fmt.Errorf("%s is a symlink whose target cannot be read, so what it holds cannot be compared: %v", shown(path), statErr)
			}
			if target.IsDir() {
				return fmt.Errorf("%s is a symlinked folder, which this mode does not follow", shown(path))
			}
		}
		name := filepath.Base(path)
		if info.IsDir() || !strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".expected.json") || name == "index.json" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(stderr, "error: fixture walk failed: %v\n", walkErr)
		return 2
	}
	if len(paths) == 0 {
		fmt.Fprintf(stderr, "error: no fixture under %s (a fixture is a .json file other than *.expected.json and index.json)\n", given)
		return 2
	}
	sort.Strings(paths)

	results := make([]fixtureResult, 0, len(paths))
	var mismatches []string
	verifiedCount, notAnchoredCount, notVerifiedCount, mismatchedCount := 0, 0, 0, 0
	for _, path := range paths {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "error: cannot read %s: %v\n", shown(path), err)
			return 2
		}
		expected, err := readExpectedVerdict(strings.TrimSuffix(path, ".json") + ".expected.json")
		if err != nil {
			fmt.Fprintf(stderr, "error: fixture %s: %v\n", rel, err)
			return 2
		}
		r := auditproof.Verify(raw, expected.policy)
		diffs, err := expected.differences(r)
		if err != nil {
			fmt.Fprintf(stderr, "error: fixture %s: %v\n", rel, err)
			return 2
		}
		results = append(results, fixtureResult{Path: shown(path), Result: r, Mismatches: diffs})
		switch r.Status() {
		case "verified":
			verifiedCount++
		case "not_anchored":
			notAnchoredCount++
		default:
			notVerifiedCount++
		}
		if len(diffs) > 0 {
			mismatchedCount++
			for _, d := range diffs {
				mismatches = append(mismatches, rel+": "+d)
			}
		}
	}

	code := 0
	if mismatchedCount > 0 {
		code = 1
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(struct {
			Total       int             `json:"total"`
			Verified    int             `json:"verified"`
			NotAnchored int             `json:"not_anchored"`
			NotVerified int             `json:"not_verified"`
			Mismatched  int             `json:"mismatched"`
			Results     []fixtureResult `json:"results"`
		}{
			Total:       len(results),
			Verified:    verifiedCount,
			NotAnchored: notAnchoredCount,
			NotVerified: notVerifiedCount,
			Mismatched:  mismatchedCount,
			Results:     results,
		}, "", "  ")
		fmt.Fprintln(stdout, string(out))
		return code
	}

	fmt.Fprintf(stdout, "%d fixtures · %d verified · %d not_anchored · %d not_verified\n",
		len(results), verifiedCount, notAnchoredCount, notVerifiedCount)
	if code == 0 {
		fmt.Fprintf(stdout, "%d of %d match their expected verdict\n", len(results), len(results))
		return 0
	}
	fmt.Fprintf(stdout, "%d of %d differ from their expected verdict:\n", mismatchedCount, len(results))
	for _, m := range mismatches {
		fmt.Fprintf(stdout, "  %s\n", m)
	}
	return code
}

// expectedVerdict is one fixture's .expected.json, in the shape index.json's
// expected_verdict_schema gives.
type expectedVerdict struct {
	valid         bool
	stageReached  uint64
	failureReason interface{}
	policy        auditproof.VerifierPolicy
}

// decodeJSONNumbers reads one JSON value, keeping each number as written so
// that 7 and 7.0 stay distinct, as serde_json keeps them.
func decodeJSONNumbers(raw []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the first JSON value")
	}
	return nil
}

func readExpectedVerdict(path string) (expectedVerdict, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return expectedVerdict{}, fmt.Errorf("no readable .expected.json sibling: %v", err)
	}
	var doc map[string]interface{}
	if err := decodeJSONNumbers(raw, &doc); err != nil {
		return expectedVerdict{}, fmt.Errorf("%s is not a JSON object: %v", filepath.Base(path), err)
	}
	valid, ok := doc["valid"].(bool)
	if !ok {
		return expectedVerdict{}, fmt.Errorf("%s has no boolean \"valid\"", filepath.Base(path))
	}
	number, ok := doc["stage_reached"].(json.Number)
	if !ok {
		return expectedVerdict{}, fmt.Errorf("%s has no numeric \"stage_reached\"", filepath.Base(path))
	}
	// The Rust sweep reads the stage with as_u64, which takes digits alone.
	stage, err := strconv.ParseUint(number.String(), 10, 64)
	if errors.Is(err, strconv.ErrRange) {
		return expectedVerdict{}, fmt.Errorf("%s has \"stage_reached\": %s, which is above 18446744073709551615, the largest unsigned 64-bit integer", filepath.Base(path), number)
	}
	if err != nil {
		return expectedVerdict{}, fmt.Errorf("%s has \"stage_reached\": %s, which is not an unsigned integer written as digits alone (no sign, fraction or exponent)", filepath.Base(path), number)
	}
	pins, _ := doc["policy"].(map[string]interface{})
	pin := func(key string) string {
		s, _ := pins[key].(string)
		return s
	}
	rejectDiagnostic, _ := pins["reject_diagnostic"].(bool)
	return expectedVerdict{
		valid:         valid,
		stageReached:  stage,
		failureReason: doc["failure_reason"],
		policy: auditproof.VerifierPolicy{
			RejectDiagnostic:    rejectDiagnostic,
			RequiredRegion:      pin("required_region"),
			RequiredAuthorityID: pin("required_authority_id"),
		},
	}, nil
}

// differences lists each field of r that differs from e. failure_reason is
// compared as its wire JSON value.
func (e expectedVerdict) differences(r auditproof.AuditProofVerificationResult) ([]string, error) {
	var out []string
	if r.Valid != e.valid {
		out = append(out, fmt.Sprintf("valid — expected %t, got %t", e.valid, r.Valid))
	}
	if uint64(r.StageReached) != e.stageReached {
		out = append(out, fmt.Sprintf("stage_reached — expected %d, got %d", e.stageReached, r.StageReached))
	}
	wire, err := r.FailureReason.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("cannot render failure_reason: %v", err)
	}
	var got interface{}
	if err := decodeJSONNumbers(wire, &got); err != nil {
		return nil, fmt.Errorf("cannot re-read failure_reason %s: %v", wire, err)
	}
	if !reflect.DeepEqual(got, e.failureReason) {
		out = append(out, fmt.Sprintf("failure_reason — expected %s, got %s", jsonText(e.failureReason), jsonText(got)))
	}
	return out, nil
}

// jsonText renders v as compact JSON with <, > and & as they are, the way
// serde_json prints a value.
func jsonText(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprintf("(cannot render: %v)", err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}
