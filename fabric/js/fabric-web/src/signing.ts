import { schnorr } from "@noble/curves/secp256k1";

/**
 * Sign a 32-byte digest using BIP-340 Schnorr.
 *
 * @param digest - 32-byte signing ID (e.g. from unsigned entry's signingId)
 * @param secretKey - 32-byte BIP-340 secret key
 * @returns 64-byte Schnorr signature
 */
export function signSchnorr(
  digest: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array {
  return schnorr.sign(digest, secretKey);
}

/**
 * Verify a BIP-340 Schnorr signature over a 32-byte digest.
 */
export function verifySchnorr(
  digest: Uint8Array,
  signature: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  return schnorr.verify(signature, digest, pubkey);
}