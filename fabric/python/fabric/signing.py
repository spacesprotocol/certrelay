"""Optional BIP-340 Schnorr signing with the Spaces signed-message prefix.

Requires the ``coincurve`` package::

    pip install fabric-resolver[signing]
"""

from __future__ import annotations

import hashlib

try:
    from coincurve import PrivateKey
    from coincurve.keys import PublicKeyXOnly
except ImportError:
    raise ImportError(
        "The 'coincurve' package is required for signing. "
        "Install it with: pip install fabric-resolver[signing]"
    )

_SPACES_SIGNED_MSG_PREFIX = b"\x17Spaces Signed Message:\n"


def _hash_signable(msg: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_SPACES_SIGNED_MSG_PREFIX)
    h.update(msg)
    return h.digest()


def sign_message(msg: bytes, secret_key: bytes) -> bytes:
    """Sign a message using BIP-340 Schnorr with the Spaces signed-message prefix.

    Takes raw message bytes (e.g. ``record_set.to_bytes()``) and a 32-byte secret key.
    Returns a 64-byte signature.
    """
    if len(secret_key) != 32:
        raise ValueError(f"secret key must be 32 bytes, got {len(secret_key)}")
    digest = _hash_signable(msg)
    pk = PrivateKey(secret_key)
    return pk.sign_schnorr(digest)


def verify_message(msg: bytes, signature: bytes, pubkey: bytes) -> bool:
    """Verify a BIP-340 Schnorr signature over a message with the Spaces signed-message prefix."""
    if len(signature) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(signature)}")
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes (x-only), got {len(pubkey)}")
    digest = _hash_signable(msg)
    xonly = PublicKeyXOnly(pubkey)
    return xonly.verify(signature, digest)
