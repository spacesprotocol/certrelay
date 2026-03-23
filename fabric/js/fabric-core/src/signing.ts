/**
 * Optional BIP-340 Schnorr signing with the Spaces signed-message prefix.
 *
 * Requires the `@noble/curves` package:
 *   npm install @noble/curves
 */

import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";

const SPACES_SIGNED_MSG_PREFIX = new TextEncoder().encode(
  "\x17Spaces Signed Message:\n",
);

function hashSignable(msg: Uint8Array): Uint8Array {
  const combined = new Uint8Array(
    SPACES_SIGNED_MSG_PREFIX.length + msg.length,
  );
  combined.set(SPACES_SIGNED_MSG_PREFIX);
  combined.set(msg, SPACES_SIGNED_MSG_PREFIX.length);
  return sha256(combined);
}

/**
 * Sign a message using BIP-340 Schnorr with the Spaces signed-message prefix.
 *
 * Takes raw message bytes (e.g. `recordSet.toBytes()`) and a 32-byte secret key.
 * Returns a 64-byte signature.
 */
export function signMessage(
  msg: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  const hash = hashSignable(msg);
  return schnorr.sign(hash, secretKey);
}

/**
 * Verify a BIP-340 Schnorr signature over a message with the Spaces signed-message prefix.
 */
export function verifyMessage(
  msg: Uint8Array,
  signature: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  const hash = hashSignable(msg);
  return schnorr.verify(signature, hash, pubkey);
}
