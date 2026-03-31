use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};

/// Sign a 32-byte digest using BIP-340 Schnorr.
///
/// Takes a 32-byte signing ID (e.g. from `unsigned.signing_id`) and a 32-byte secret key.
/// Returns a 64-byte signature.
pub fn sign_schnorr(digest: &[u8; 32], secret_key: &[u8; 32]) -> Result<[u8; 64], secp256k1::Error> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, secret_key)?;
    let message = Message::from_digest(*digest);
    let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    Ok(sig.serialize())
}

/// Verify a BIP-340 Schnorr signature over a 32-byte digest.
pub fn verify_schnorr(
    digest: &[u8; 32],
    signature: &[u8; 64],
    pubkey: &[u8; 32],
) -> Result<(), secp256k1::Error> {
    let secp = Secp256k1::new();
    let sig = secp256k1::schnorr::Signature::from_slice(signature)?;
    let xonly = XOnlyPublicKey::from_slice(pubkey)?;
    let message = Message::from_digest(*digest);
    secp.verify_schnorr(&sig, &message, &xonly)
}
