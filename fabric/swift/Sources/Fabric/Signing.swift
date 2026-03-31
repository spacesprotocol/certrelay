import Foundation
import secp256k1

/// Sign a digest using BIP-340 Schnorr.
///
/// Takes a 32-byte digest and a 32-byte secret key.
/// Returns a 64-byte signature.
public func signSchnorr(digest: Data, secretKey: Data) throws -> Data {
    var hash = Array(digest)
    let privateKey = try secp256k1.Schnorr.PrivateKey(dataRepresentation: secretKey)
    let auxKey = try secp256k1.Schnorr.PrivateKey()
    var auxRand = Array(auxKey.dataRepresentation)
    let signature = try privateKey.signature(message: &hash, auxiliaryRand: &auxRand)
    return signature.dataRepresentation
}

/// Verify a BIP-340 Schnorr signature over a digest.
public func verifySchnorr(digest: Data, signature: Data, pubkey: Data) throws -> Bool {
    var hash = Array(digest)
    let xonly = secp256k1.Schnorr.XonlyKey(dataRepresentation: pubkey)
    let sig = try secp256k1.Schnorr.SchnorrSignature(dataRepresentation: signature)
    return xonly.isValid(sig, for: &hash)
}
