import Foundation
import secp256k1
import CommonCrypto

private let spacesSignedMsgPrefix = Array("\u{17}Spaces Signed Message:\n".utf8)

private func hashSignable(_ msg: Data) -> [UInt8] {
    var ctx = CC_SHA256_CTX()
    CC_SHA256_Init(&ctx)
    spacesSignedMsgPrefix.withUnsafeBufferPointer { ptr in
        CC_SHA256_Update(&ctx, ptr.baseAddress, CC_LONG(ptr.count))
    }
    msg.withUnsafeBytes { ptr in
        CC_SHA256_Update(&ctx, ptr.baseAddress, CC_LONG(ptr.count))
    }
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CC_SHA256_Final(&digest, &ctx)
    return digest
}

/// Sign a message using BIP-340 Schnorr with the Spaces signed-message prefix.
///
/// Takes raw message bytes (e.g. `recordSet.toBytes()`) and a 32-byte secret key.
/// Returns a 64-byte signature.
public func signMessage(msg: Data, secretKey: Data) throws -> Data {
    var hash = hashSignable(msg)
    let privateKey = try secp256k1.Schnorr.PrivateKey(dataRepresentation: secretKey)
    let auxKey = try secp256k1.Schnorr.PrivateKey()
    var auxRand = Array(auxKey.dataRepresentation)
    let signature = try privateKey.signature(message: &hash, auxiliaryRand: &auxRand)
    return signature.dataRepresentation
}

/// Verify a BIP-340 Schnorr signature over a message with the Spaces signed-message prefix.
public func verifyMessage(msg: Data, signature: Data, pubkey: Data) throws -> Bool {
    var hash = hashSignable(msg)
    let xonly = secp256k1.Schnorr.XonlyKey(dataRepresentation: pubkey)
    let sig = try secp256k1.Schnorr.SchnorrSignature(dataRepresentation: signature)
    return xonly.isValid(sig, for: &hash)
}
