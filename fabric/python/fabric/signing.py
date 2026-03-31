"""BIP-340 Schnorr signing helpers.

These are thin wrappers around ``libveritas.sign_schnorr`` and
``libveritas.verify_schnorr``.  They exist so callers can import from
``fabric.signing`` without reaching into ``libveritas`` directly.
"""

from __future__ import annotations

import libveritas as lv


def sign_schnorr(signing_id: bytes, secret_key: bytes) -> bytes:
    """Sign a 32-byte signing ID with a 32-byte secret key.

    Returns a 64-byte BIP-340 Schnorr signature.
    """
    if len(secret_key) != 32:
        raise ValueError(f"secret key must be 32 bytes, got {len(secret_key)}")
    if len(signing_id) != 32:
        raise ValueError(f"signing_id must be 32 bytes, got {len(signing_id)}")
    return lv.sign_schnorr(signing_id, secret_key)


def verify_schnorr(signing_id: bytes, signature: bytes, pubkey: bytes) -> bool:
    """Verify a 64-byte BIP-340 Schnorr signature over a 32-byte signing ID."""
    if len(signature) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(signature)}")
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes (x-only), got {len(pubkey)}")
    if len(signing_id) != 32:
        raise ValueError(f"signing_id must be 32 bytes, got {len(signing_id)}")
    return lv.verify_schnorr(signing_id, signature, pubkey)
