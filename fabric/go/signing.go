package fabric

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// SignSchnorr signs a 32-byte digest using raw BIP-340 Schnorr.
// Takes a 32-byte digest (e.g. signing ID from BuildResult.Unsigned) and a 32-byte secret key.
// Returns a 64-byte signature.
func SignSchnorr(digest []byte, secretKey []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	if len(secretKey) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(secretKey))
	}
	privKey, _ := btcec.PrivKeyFromBytes(secretKey)
	sig, err := schnorr.Sign(privKey, digest)
	if err != nil {
		return nil, fmt.Errorf("schnorr sign: %w", err)
	}
	return sig.Serialize(), nil
}

// VerifySchnorr verifies a raw BIP-340 Schnorr signature over a 32-byte digest.
func VerifySchnorr(digest []byte, signature []byte, pubkey []byte) error {
	if len(digest) != 32 {
		return fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	if len(signature) != 64 {
		return fmt.Errorf("signature must be 64 bytes, got %d", len(signature))
	}
	if len(pubkey) != 32 {
		return fmt.Errorf("pubkey must be 32 bytes, got %d", len(pubkey))
	}
	sig, err := schnorr.ParseSignature(signature)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	pk, err := schnorr.ParsePubKey(pubkey)
	if err != nil {
		return fmt.Errorf("parse pubkey: %w", err)
	}
	if !sig.Verify(digest, pk) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
