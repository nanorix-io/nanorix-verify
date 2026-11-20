"""Strict Ed25519 verification.

``cryptography`` (OpenSSL) verifies like RFC 8032 and accepts a small-order
public key or a small-order ``R``; under such a key one signature verifies for
many messages. :func:`verify_strict` adds the ed25519-dalek ``verify_strict``
checks: reject a small-order public key and a small-order ``R``. Canonical
``S`` is already enforced by OpenSSL.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: Every 32-byte encoding of a point whose order divides 8, including the
#: non-canonical y+p forms. Mirrors tests/vectors/ed25519_strict_negative.json.
SMALL_ORDER_ENCODINGS = frozenset(
    [
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000080"),
        bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),
        bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000080"),
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
        bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ]
)


def _is_rejected_point(enc: bytes) -> bool:
    """Small-order encoding, or a non-canonical one (255-bit y >= p = 2^255-19)."""
    if enc in SMALL_ORDER_ENCODINGS:
        return True
    return len(enc) == 32 and enc[31] & 0x7F == 0x7F and enc[0] >= 0xED and all(b == 0xFF for b in enc[1:31])


def verify_strict(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> None:
    """Verify ``signature`` over ``data``; raise ``InvalidSignature`` on failure
    or when the public key or the signature's ``R`` is a small-order point."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if _is_rejected_point(raw) or _is_rejected_point(bytes(signature[:32])):
        raise InvalidSignature("small-order or non-canonical Ed25519 public key or R")
    public_key.verify(signature, data)
