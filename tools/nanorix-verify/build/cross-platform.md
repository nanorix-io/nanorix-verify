# Cross-platform binary recipe — `nanorix-verify`

> Reproducible-build recipe for the standalone AuditProof verifier CLI.
> Audience: release engineers, distribution maintainers, sovereign-auditor
> deployments needing a build they can self-verify.

## Target matrix

The verifier ships as a static-or-near-static binary for the platforms an
auditor's machine is most likely to be:

| Triple | Platform | Notes |
|--------|----------|-------|
| `x86_64-unknown-linux-gnu` | Debian / Ubuntu / RHEL | Most-common cloud + workstation |
| `aarch64-unknown-linux-gnu` | ARM Linux servers + Pi | Cloud ARM hosts (Graviton, Ampere) |
| `x86_64-apple-darwin` | Intel Macs | Still common in regulated industries |
| `aarch64-apple-darwin` | Apple Silicon Macs | Required for current-generation laptops |
| `x86_64-pc-windows-msvc` | Windows audit workstations | Big-4 + healthcare workstations |

A future expansion adds `aarch64-pc-windows-msvc` (Windows on ARM) once
GitHub Actions runners support it natively.

## Toolchain pin

The release builds against **Rust 1.93 stable** to match the production
Cloud Build constraint (per `feedback_cargo_msrv_ceiling.md`). Newer
compilers may produce more efficient binaries but introduce reproducibility
variance — pinning to 1.93 keeps every release binary identical across
regenerations and aligned with the production API container.

The release workflow (`.github/workflows/release-nanorix-verify.yml`) sets
`RUST_TOOLCHAIN: "1.93"` at the env level and feeds that to
`dtolnay/rust-toolchain@master` via the `toolchain:` input on every job.
The Dockerfile's `lukemathwalker/cargo-chef:latest-rust-1.93-bookworm` base
image is the matching production anchor; verifier binary and API binary
build against the same compiler.

## Reproducible-build pattern

Reproducibility goal: any release engineer with the same Rust toolchain,
same `Cargo.lock`, and same source tree produces a byte-identical binary.

Three pillars:

1. **Cargo.lock pinned** — every dependency version is locked. The release
   build uses `cargo build --locked` so a stale `Cargo.lock` fails the build
   rather than silently picking up a new patch version.
2. **Strip symbols** — `RUSTFLAGS="-C strip=symbols"` removes debug info
   and source-path strings that vary per machine.
3. **No timestamp embedding** — the build uses `--frozen` and explicitly
   omits `vergen`-style build-time injection. The binary's only embedded
   version string is the crate's `Cargo.toml` version.

```bash
# Reproducible build invocation
RUSTFLAGS="-C strip=symbols" \
  cargo build \
    --release \
    --locked \
    --frozen \
    --target x86_64-unknown-linux-gnu \
    -p nanorix-verify \
    --bin nanorix-verify
```

Verify reproducibility by building twice on different machines and
comparing SHA-256 of the binary; the hashes must match.

## Cross-compilation

Cross-compilation uses `cross` for Linux ARM (handles glibc / linker
toolchain) and native runners for Apple targets and Windows.

### Linux x86_64 + ARM64 (via `cross`)

```bash
cargo install cross --version 0.2.5 --locked

cross build --release --locked \
  --target x86_64-unknown-linux-gnu \
  -p nanorix-verify

cross build --release --locked \
  --target aarch64-unknown-linux-gnu \
  -p nanorix-verify
```

`cross` runs the build inside a pinned Docker image (`cross-rs/cross:rust-stable`)
which itself is a reproducibility anchor — the same `cross` version produces
the same binary across host machines.

### macOS Intel + Apple Silicon (native)

Apple targets build natively on a macOS GitHub Actions runner. The runner
has both targets installed:

```bash
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin

cargo build --release --locked \
  --target x86_64-apple-darwin \
  -p nanorix-verify

cargo build --release --locked \
  --target aarch64-apple-darwin \
  -p nanorix-verify
```

A future enhancement produces a Mac universal binary via `lipo` so a
single `nanorix-verify` artifact runs on both architectures:

```bash
lipo -create \
  -output nanorix-verify-universal \
  target/x86_64-apple-darwin/release/nanorix-verify \
  target/aarch64-apple-darwin/release/nanorix-verify
```

### Windows x86_64 (native)

```bash
cargo build --release --locked \
  --target x86_64-pc-windows-msvc \
  -p nanorix-verify
```

Built on a `windows-latest` runner. Output is `nanorix-verify.exe`.

## Packaging

Each target produces a tarball (or zip on Windows) containing:

- The binary (`nanorix-verify` or `nanorix-verify.exe`).
- The `README.md` (verifier usage doc).
- The `LICENSE` file (proprietary terms).
- A `SHA256SUMS` file with the SHA-256 of the binary.

Naming pattern: `nanorix-verify-<version>-<target>.tar.gz` (or `.zip` on
Windows). Example: `nanorix-verify-0.1.0-x86_64-unknown-linux-gnu.tar.gz`.

A top-level `checksums.txt` file in the GitHub Release lists SHA-256 of
every tarball, which an auditor can verify before extracting.

## Distribution channels (planned)

The actual release event is gated. The recipe below documents the planned
distribution channels for the post-release moment.

### `cargo install` (planned)

Once the crate is published to a public registry, the install becomes:

```bash
cargo install nanorix-verify --version 0.1.0 --locked
```

The `--locked` flag forces use of the published `Cargo.lock`, preserving
reproducibility for any auditor who builds the verifier from source.

### Homebrew tap (planned)

The Homebrew tap formula references the GitHub Release tarballs directly
and verifies their SHA-256 against the published `SHA256SUMS`:

```ruby
class NanorixVerify < Formula
  desc "Standalone AuditProof verifier — auditor moment-of-truth artifact"
  homepage "https://nanorix.io"
  version "0.1.0"

  on_macos do
    on_arm do
      url "https://github.com/<org>/<repo>/releases/download/nanorix-verify-v0.1.0/nanorix-verify-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "<sha256>"
    end
    on_intel do
      url "https://github.com/<org>/<repo>/releases/download/nanorix-verify-v0.1.0/nanorix-verify-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "<sha256>"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/<org>/<repo>/releases/download/nanorix-verify-v0.1.0/nanorix-verify-0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "<sha256>"
    end
    on_intel do
      url "https://github.com/<org>/<repo>/releases/download/nanorix-verify-v0.1.0/nanorix-verify-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "<sha256>"
    end
  end

  def install
    bin.install "nanorix-verify"
  end

  test do
    system "#{bin}/nanorix-verify", "--version"
  end
end
```

Tap repository: separate public repo (e.g., `<org>/homebrew-nanorix`); the
formula above lives at `Formula/nanorix-verify.rb`. Auditor install:

```bash
brew tap <org>/nanorix
brew install nanorix-verify
```

### apt repository (planned)

A signed apt repository at `apt.nanorix.io` (or a Cloudsmith mirror) will
serve `.deb` packages built from the Linux release tarballs. The
repository is signed with a long-term identity key whose fingerprint is
published statically (release notes, well-known URL).

```bash
# Auditor-side install (planned)
curl -fsSL https://apt.nanorix.io/keyring.gpg | sudo tee /etc/apt/keyrings/nanorix.gpg
echo "deb [signed-by=/etc/apt/keyrings/nanorix.gpg] https://apt.nanorix.io stable main" \
  | sudo tee /etc/apt/sources.list.d/nanorix.list
sudo apt update
sudo apt install nanorix-verify
```

## Binary signing (planned)

For the post-release distribution event, every binary is signed by a
dedicated code-signing key held in a hardware security module:

- **macOS** — Developer ID signature + notarization via Apple's notary
  service. Required for Gatekeeper acceptance on user machines.
- **Windows** — Authenticode signature with an EV certificate. Required
  for SmartScreen reputation building.
- **Linux** — Detached GPG signature alongside each tarball. The signing
  key fingerprint is published at the same well-known URL as the
  trust-chain manifest's identity key.

Signing happens in the release CI in a sealed environment with the HSM
accessed via short-lived credential. The signing step is **after** the
build step so the signed binary's contents (sans signature) are
byte-identical to the unsigned reproducible build.

Auditor-side signature verification:

```bash
# Linux (GPG detached signature)
gpg --verify nanorix-verify-0.1.0-x86_64-unknown-linux-gnu.tar.gz.asc \
            nanorix-verify-0.1.0-x86_64-unknown-linux-gnu.tar.gz

# macOS (codesign)
codesign --verify --verbose nanorix-verify
spctl --assess --verbose nanorix-verify

# Windows (signtool)
signtool verify /pa nanorix-verify.exe
```

## SBOM (planned)

A Software Bill of Materials in CycloneDX format ships alongside each
release tarball. Auditors can inspect the dependency graph without
network access; supply-chain provenance is auditable post-hoc.

```bash
cargo install cargo-cyclonedx --locked
cargo cyclonedx -p nanorix-verify -f json --output sbom.json
```

The SBOM is referenced from the GitHub Release notes and signed
alongside the binary.

## Verification of the verifier

The auditor moment-of-truth has a recursive question: how do you trust
the verifier? The answer is layered:

1. **Open source** — the verifier source is available; an auditor reviews
   it before trusting it.
2. **Reproducible build** — the auditor builds from source with `cargo
   build --locked` and compares the binary's SHA-256 to the published
   release. Match → the published binary corresponds to the public source.
3. **Signed release** — the published binary carries a code signature
   from a key whose fingerprint is published statically. Signature
   verification confirms the binary came from the official release
   pipeline.
4. **Cross-implementation parity** — the verifier produces byte-identical
   verdicts to the Python and TypeScript reference implementations on
   the published fixture corpus. An auditor can run all three and assert
   identical output, confirming the algorithm is consistent.

Layered trust: any layer alone is sufficient for some threat models;
all four together are sufficient for the most paranoid sovereign-auditor
deployment.

## Release cadence

The verifier follows the Forever-Standard discipline: new versions are
strictly additive. A v0.2.0 verifier verifies every v0.1.0 AuditProof
identically. The cross-platform release event is gated on the broader
schema-publishing event (release-event-gated); when the gate clears,
the recipe above produces the binaries and the distribution channels go
live.

