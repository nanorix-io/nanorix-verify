# BoundaryAttestation fixtures (the boundary-attestation specification)

`0001_single_signed.json` — a fully signed BoundaryAttestation v1.0 (index 1,
genesis `prev_attestation_hash`, activity commitment over 2 disclosed events),
generated **by hand** from the boundary-attestation specification D2 formula with python3 hashlib +
`cryptography` — independently of the Rust code it pins. The verifier-side
recompute (`src/boundary.rs`) must reproduce these bytes; the pinned constants
live in `tests/boundary_attestation.rs`.

## Formula (the boundary-attestation specification D2 + the reference chain implementation)

```text
genesis              = SHA-512("")  (the CDP/the per-record receipt specification genesis constant)
event_hash           = SHA-512(JCS(event)).hex()
activity_commitment  = fold: prev = SHA-512(prev ‖ 0x00 ‖ event_hash).hex(), from genesis
canonical_hash       = SHA-512(JCS(document minus `attestation` minus `canonical_hash`)).hex()
signature            = Ed25519 over the 128-char lowercase-hex canonical_hash (ASCII bytes)
```

## Regeneration (deterministic — fixed seed, fixed timestamps)

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# All keys/values are ASCII with integer numbers only, so compact
# sort_keys json.dumps IS the RFC 8785 JCS byte form for this domain.
jcs = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":")).encode("ascii")

GENESIS = hashlib.sha512(b"").hexdigest()
events = [{"event": "exec", "seq": 1}, {"event": "output_read", "seq": 2}]
prev = GENESIS
for e in events:
    eh = hashlib.sha512(jcs(e)).hexdigest()
    prev = hashlib.sha512(prev.encode() + b"\x00" + eh.encode()).hexdigest()

doc = { ... }  # every field of 0001_single_signed.json EXCEPT attestation + canonical_hash
canonical_hash = hashlib.sha512(jcs(doc)).hexdigest()

sk = Ed25519PrivateKey.from_private_bytes(bytes([42] * 32))   # test vector seed, never production
sig = sk.sign(canonical_hash.encode("ascii"))
pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
```

## Hand-computed values pinned by the tests

| Quantity | Value |
|---|---|
| activity_commitment | `ed11da07af53a9c2477595f1390f5c41cabffa2db3e720644802a346b2f9e27cab4008556fd7b81374063c997bc3effab7c67f3f7f3e47ffd2056091638157ba` |
| canonical JCS byte length | 1040 |
| canonical_hash | `7f8bc8f0cae035fffa2bf405495789ddbfa06216ae7284db319be3446fb42770f97d75a7d881c58a1f09cbe8d4d73c2e74468ef051b0e0c7a7c86af631ced975` |
| public_key (b64) | `GX9rI+FshTLGq8g4+s1ep4m+DHaykgM0A5v6iz02jWE=` |
| signature (b64) | `lEbb59ju+432q7LGCYlgl2vA4+ylBeca8MtpMuxUACMuXxjYybNYqW1+dzPkHHRb7HVPw7qAiMBPAN9ut13yBw==` |

The Ed25519 seed (32 × `0x2a`) has RFC 8032 seed semantics in both python
`cryptography` and `ed25519_dalek`, so `tests/boundary_attestation.rs`
reproduces the same keypair to build chain successors.
