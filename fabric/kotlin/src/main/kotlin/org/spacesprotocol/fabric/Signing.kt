package org.spacesprotocol.fabric

import fr.acinq.secp256k1.Secp256k1
import java.security.MessageDigest
import java.security.SecureRandom

private val SPACES_SIGNED_MSG_PREFIX = "\u0017Spaces Signed Message:\n".toByteArray()

private fun hashSignable(msg: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(SPACES_SIGNED_MSG_PREFIX)
    digest.update(msg)
    return digest.digest()
}

/**
 * Sign a message using BIP-340 Schnorr with the Spaces signed-message prefix.
 *
 * Takes raw message bytes (e.g. `recordSet.toBytes()`) and a 32-byte secret key.
 * Returns a 64-byte signature.
 */
fun signMessage(msg: ByteArray, secretKey: ByteArray): ByteArray {
    require(secretKey.size == 32) { "secret key must be 32 bytes, got ${secretKey.size}" }
    val hash = hashSignable(msg)
    val auxRand = ByteArray(32).also { SecureRandom().nextBytes(it) }
    return Secp256k1.signSchnorr(hash, secretKey, auxRand)
}

/**
 * Verify a BIP-340 Schnorr signature over a message with the Spaces signed-message prefix.
 */
fun verifyMessage(msg: ByteArray, signature: ByteArray, pubkey: ByteArray): Boolean {
    require(signature.size == 64) { "signature must be 64 bytes, got ${signature.size}" }
    require(pubkey.size == 32) { "pubkey must be 32 bytes (x-only), got ${pubkey.size}" }
    val hash = hashSignable(msg)
    return Secp256k1.verifySchnorr(signature, hash, pubkey)
}
