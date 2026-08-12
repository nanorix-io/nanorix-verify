"""
Portable Pubkey Bundle (.ppb.json) — Wave B Item 8 surface, Python port.

Pure Python port of `the Rust verifiersrc/pubkey_bundle.rs``. Cross-impl
byte-equivalence with Rust/Go/TypeScript on the canonical reference vectors.

Per feedback_open_verifier_bounded_manifest.md: the bundle algorithm is open
+ portable; the trust root (publisher pubkey) is bounded out-of-band by the
verifier.

Workflow:

1. Bundle producer (Nanorix-managed publisher OR customer-signed) collects N
   pubkeys for cross-org parent verification.
2. Producer calls ``build_pubkey_bundle(...)`` with the keys + a signing key +
   issuer org tag. Output: signed .ppb.json.
3. Consumer calls ``verify_pubkey_bundle(bundle, publisher_pubkey)`` to
   confirm bundle publisher integrity.
4. Consumer calls ``resolve_parent_key(bundle, key_id, at_timestamp)`` per
   parent_proof_link being verified to look up the parent's pubkey.

Forever-Standard discipline: bundles are append-only — key rotation = new
bundle generation. Old AuditProofs signed under rotated keys must remain
verifiable in perpetuity (healthcare 7-30 year retention).
"""
from __future__ import annotations

import base64
import datetime
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Mandatory disclaimer — factual language only.
PORTABLE_PUBKEY_BUNDLE_DISCLAIMER = (
    "This Portable Pubkey Bundle is a key-discovery aid for cross-org chain "
    "verification. The bundle_signature confirms publisher integrity. The "
    "bundle issuer attests that the listed pubkeys were valid as of "
    "generated_at; subsequent key rotation or revocation MUST be verified "
    "out-of-band by the consuming party."
)


@dataclass
class PubKeyEntry:
    """Single pubkey entry within a Portable Pubkey Bundle."""

    key_id: str
    algorithm: str
    public_key: str
    valid_from: str
    issued_by_org: str
    valid_until: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key": self.public_key,
            "valid_from": self.valid_from,
            "issued_by_org": self.issued_by_org,
        }
        if self.valid_until is not None:
            out["valid_until"] = self.valid_until
        return out

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> "PubKeyEntry":
        return cls(
            key_id=str(doc.get("key_id", "")),
            algorithm=str(doc.get("algorithm", "")),
            public_key=str(doc.get("public_key", "")),
            valid_from=str(doc.get("valid_from", "")),
            issued_by_org=str(doc.get("issued_by_org", "")),
            valid_until=doc.get("valid_until"),
        )


@dataclass
class BundleSignature:
    """Bundle self-signature attestation."""

    algorithm: str
    signed_by_key_id: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "signed_by_key_id": self.signed_by_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> "BundleSignature":
        return cls(
            algorithm=str(doc.get("algorithm", "")),
            signed_by_key_id=str(doc.get("signed_by_key_id", "")),
            signature=str(doc.get("signature", "")),
        )


@dataclass
class PortablePubkeyBundle:
    """Wave B Item 8 wire shape mirroring Rust ``PortablePubkeyBundle``."""

    bundle_version: str
    bundle_type: str
    generated_at: str
    issuer_organization: str
    pubkeys: List[PubKeyEntry]
    bundle_signature: BundleSignature
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_version": self.bundle_version,
            "bundle_type": self.bundle_type,
            "generated_at": self.generated_at,
            "issuer_organization": self.issuer_organization,
            "pubkeys": [p.to_dict() for p in self.pubkeys],
            "bundle_signature": self.bundle_signature.to_dict(),
            "disclaimer": self.disclaimer,
        }

    def to_json(self, *, pretty: bool = False) -> str:
        if pretty:
            return json.dumps(self.to_dict(), indent=2)
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> "PortablePubkeyBundle":
        return cls(
            bundle_version=str(doc.get("bundle_version", "")),
            bundle_type=str(doc.get("bundle_type", "")),
            generated_at=str(doc.get("generated_at", "")),
            issuer_organization=str(doc.get("issuer_organization", "")),
            pubkeys=[PubKeyEntry.from_dict(p) for p in (doc.get("pubkeys") or [])],
            bundle_signature=BundleSignature.from_dict(doc.get("bundle_signature") or {}),
            disclaimer=str(doc.get("disclaimer", "")),
        )


class PubkeyBundleError(Exception):
    """Pubkey bundle operation error."""

    def __init__(self, kind: str, reason: str = "") -> None:
        self.kind = kind
        self.reason = reason
        super().__init__(f"[{kind}] {reason}" if reason else kind)


# Error kinds — match Rust PubkeyBundleError variants.
PUBKEY_BUNDLE_ERR_UNSUPPORTED_VERSION = "unsupported_version"
PUBKEY_BUNDLE_ERR_WRONG_BUNDLE_TYPE = "wrong_bundle_type"
PUBKEY_BUNDLE_ERR_BUNDLE_SIGNATURE_FAILED = "bundle_signature_failed"
PUBKEY_BUNDLE_ERR_INVALID_PUBLISHER_KEY = "invalid_publisher_key"
PUBKEY_BUNDLE_ERR_BASE64_DECODE = "base64_decode"
PUBKEY_BUNDLE_ERR_CANONICALIZATION = "canonicalization"
PUBKEY_BUNDLE_ERR_INVALID_ENTRY = "invalid_entry"
PUBKEY_BUNDLE_ERR_EMPTY_BUNDLE = "empty_bundle"


def _strip_base64_prefix(s: str) -> str:
    if isinstance(s, str) and s.startswith("base64:"):
        return s[len("base64:"):]
    return s


def _now_iso8601() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_entry(entry: PubKeyEntry, idx: int) -> None:
    if entry.algorithm != "Ed25519":
        raise PubkeyBundleError(
            PUBKEY_BUNDLE_ERR_INVALID_ENTRY,
            f"idx {idx}: unsupported algorithm {entry.algorithm}",
        )
    try:
        pub_bytes = base64.b64decode(_strip_base64_prefix(entry.public_key))
    except (ValueError, TypeError) as e:
        raise PubkeyBundleError(
            PUBKEY_BUNDLE_ERR_INVALID_ENTRY, f"idx {idx}: base64 decode failed: {e}"
        ) from e
    if len(pub_bytes) != 32:
        raise PubkeyBundleError(
            PUBKEY_BUNDLE_ERR_INVALID_ENTRY,
            f"idx {idx}: public_key wrong size: got {len(pub_bytes)}, want 32",
        )
    if not entry.key_id.strip():
        raise PubkeyBundleError(PUBKEY_BUNDLE_ERR_INVALID_ENTRY, f"idx {idx}: key_id empty")


def _canonical_bytes_for_signing(bundle: PortablePubkeyBundle) -> bytes:
    """RFC 8785 canonical bytes with signature field cleared."""
    from nanorix.verifier.wave_n import _jcs_canonicalize

    payload = bundle.to_dict()
    # Clear signature for deterministic sign/verify.
    payload["bundle_signature"]["signature"] = ""
    try:
        return _jcs_canonicalize(payload)
    except Exception as e:  # pragma: no cover - JCS failures are P0
        raise PubkeyBundleError(PUBKEY_BUNDLE_ERR_CANONICALIZATION, str(e)) from e


def build_pubkey_bundle(
    keys: Sequence[PubKeyEntry],
    signer_key: Ed25519PrivateKey,
    signer_key_id: str,
    issuer_organization: str,
) -> PortablePubkeyBundle:
    """Construct and sign a Portable Pubkey Bundle.

    Args:
        keys: Pubkey entries to include in the bundle.
        signer_key: Ed25519 private key for the publisher self-signature.
        signer_key_id: Authority key identifier of the publisher.
        issuer_organization: Opaque issuer organization tag.

    Returns:
        A signed ``PortablePubkeyBundle``.

    Raises:
        PubkeyBundleError: With kind ``empty_bundle`` if keys is empty,
            ``invalid_entry`` if a pubkey entry is malformed.
    """
    if not keys:
        raise PubkeyBundleError(PUBKEY_BUNDLE_ERR_EMPTY_BUNDLE)
    for i, entry in enumerate(keys):
        _validate_entry(entry, i)

    bundle = PortablePubkeyBundle(
        bundle_version="1.0",
        bundle_type="pubkey",
        generated_at=_now_iso8601(),
        issuer_organization=issuer_organization,
        pubkeys=list(keys),
        bundle_signature=BundleSignature(
            algorithm="Ed25519",
            signed_by_key_id=signer_key_id,
            signature="",
        ),
        disclaimer=PORTABLE_PUBKEY_BUNDLE_DISCLAIMER,
    )

    canonical = _canonical_bytes_for_signing(bundle)
    sig = signer_key.sign(canonical)
    bundle.bundle_signature.signature = base64.b64encode(sig).decode("ascii")
    return bundle


def verify_pubkey_bundle(
    bundle: PortablePubkeyBundle, publisher_pubkey: Ed25519PublicKey
) -> None:
    """Verify a Portable Pubkey Bundle's publisher signature.

    Args:
        bundle: The bundle to verify.
        publisher_pubkey: Trust-anchor Ed25519 public key (delivered
            out-of-band by trust-chain manifest / direct override /
            pre-shared with auditor).

    Raises:
        PubkeyBundleError: On verification failure.
    """
    if bundle.bundle_version != "1.0":
        raise PubkeyBundleError(PUBKEY_BUNDLE_ERR_UNSUPPORTED_VERSION, bundle.bundle_version)
    if bundle.bundle_type != "pubkey":
        raise PubkeyBundleError(PUBKEY_BUNDLE_ERR_WRONG_BUNDLE_TYPE, bundle.bundle_type)
    if not bundle.pubkeys:
        raise PubkeyBundleError(PUBKEY_BUNDLE_ERR_EMPTY_BUNDLE)
    for i, entry in enumerate(bundle.pubkeys):
        _validate_entry(entry, i)

    try:
        sig_bytes = base64.b64decode(_strip_base64_prefix(bundle.bundle_signature.signature))
    except (ValueError, TypeError) as e:
        raise PubkeyBundleError(
            PUBKEY_BUNDLE_ERR_BASE64_DECODE, f"bundle_signature.signature: {e}"
        ) from e
    if len(sig_bytes) != 64:
        raise PubkeyBundleError(
            PUBKEY_BUNDLE_ERR_BUNDLE_SIGNATURE_FAILED,
            f"signature wrong size: {len(sig_bytes)}",
        )

    canonical = _canonical_bytes_for_signing(bundle)
    try:
        publisher_pubkey.verify(sig_bytes, canonical)
    except InvalidSignature as e:
        raise PubkeyBundleError(PUBKEY_BUNDLE_ERR_BUNDLE_SIGNATURE_FAILED) from e


def resolve_parent_key(
    bundle: PortablePubkeyBundle,
    key_id: str,
    at_timestamp: datetime.datetime,
) -> Optional[PubKeyEntry]:
    """Resolve a pubkey by key_id with validity-window check.

    Returns:
        The pubkey entry whose key_id matches AND whose validity window
        contains ``at_timestamp``; None otherwise.

    Note:
        "Outside validity window" does NOT mean "untrusted for historical
        verification". Use ``resolve_parent_key_forever`` for historical
        AuditProof verification.
    """
    for entry in bundle.pubkeys:
        if entry.key_id != key_id:
            continue
        try:
            valid_from = datetime.datetime.fromisoformat(entry.valid_from.replace("Z", "+00:00"))
        except ValueError:
            continue
        if at_timestamp < valid_from:
            continue
        if entry.valid_until is not None:
            try:
                valid_until = datetime.datetime.fromisoformat(
                    entry.valid_until.replace("Z", "+00:00")
                )
            except ValueError:
                continue
            if at_timestamp > valid_until:
                continue
        return entry
    return None


def resolve_parent_key_forever(
    bundle: PortablePubkeyBundle, key_id: str
) -> Optional[PubKeyEntry]:
    """Resolve a pubkey by key_id regardless of validity window.

    Used for historical AuditProof verification (forever-archive). Returns
    the first matching key_id.
    """
    for entry in bundle.pubkeys:
        if entry.key_id == key_id:
            return entry
    return None


__all__ = [
    "PORTABLE_PUBKEY_BUNDLE_DISCLAIMER",
    "BundleSignature",
    "PortablePubkeyBundle",
    "PubKeyEntry",
    "PubkeyBundleError",
    "PUBKEY_BUNDLE_ERR_UNSUPPORTED_VERSION",
    "PUBKEY_BUNDLE_ERR_WRONG_BUNDLE_TYPE",
    "PUBKEY_BUNDLE_ERR_BUNDLE_SIGNATURE_FAILED",
    "PUBKEY_BUNDLE_ERR_INVALID_PUBLISHER_KEY",
    "PUBKEY_BUNDLE_ERR_BASE64_DECODE",
    "PUBKEY_BUNDLE_ERR_CANONICALIZATION",
    "PUBKEY_BUNDLE_ERR_INVALID_ENTRY",
    "PUBKEY_BUNDLE_ERR_EMPTY_BUNDLE",
    "build_pubkey_bundle",
    "verify_pubkey_bundle",
    "resolve_parent_key",
    "resolve_parent_key_forever",
]
