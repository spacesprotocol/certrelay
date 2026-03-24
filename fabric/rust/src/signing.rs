use libveritas::cert::Signature;
use libveritas::msg::OffchainRecords;
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

const SPACES_SIGNED_MSG_PREFIX: &[u8] = b"\x17Spaces Signed Message:\n";

fn hash_signable(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SPACES_SIGNED_MSG_PREFIX);
    hasher.update(msg);
    hasher.finalize().into()
}

/// Sign a message using BIP-340 Schnorr with the Spaces signed-message prefix.
///
/// Takes raw message bytes (e.g. `record_set.to_bytes()`) and a 32-byte secret key.
/// Returns a 64-byte signature.
pub fn sign_message(msg: &[u8], secret_key: &[u8; 32]) -> Result<[u8; 64], secp256k1::Error> {
    let hash = hash_signable(msg);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, secret_key)?;
    let message = Message::from_digest(hash);
    let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    Ok(sig.serialize())
}

/// Sign a record set and return OffchainRecords ready for publishing.
///
/// Combines `sign_message` + `OffchainRecords::new` in a single call.
pub fn sign_records(
    record_set: &sip7::RecordSet,
    secret_key: &[u8; 32],
) -> Result<OffchainRecords, secp256k1::Error> {
    let sig = sign_message(record_set.as_slice(), secret_key)?;
    Ok(OffchainRecords::new(record_set.clone(), Signature(sig)))
}

/// Verify a BIP-340 Schnorr signature over a message with the Spaces signed-message prefix.
pub fn verify_message(
    msg: &[u8],
    signature: &[u8; 64],
    pubkey: &[u8; 32],
) -> Result<(), secp256k1::Error> {
    let hash = hash_signable(msg);
    let secp = Secp256k1::new();
    let sig = secp256k1::schnorr::Signature::from_slice(signature)?;
    let xonly = XOnlyPublicKey::from_slice(pubkey)?;
    let message = Message::from_digest(hash);
    secp.verify_schnorr(&sig, &message, &xonly)
}
