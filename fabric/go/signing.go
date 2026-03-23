package fabric

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var spacesSignedMsgPrefix = []byte("\x17Spaces Signed Message:\n")

func hashSignable(msg []byte) [32]byte {
	h := sha256.New()
	h.Write(spacesSignedMsgPrefix)
	h.Write(msg)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// SignMessage signs a message using BIP-340 Schnorr with the Spaces signed-message prefix.
// Takes raw message bytes (e.g. recordSet.ToBytes()) and a 32-byte secret key.
// Returns a 64-byte signature.
func SignMessage(msg []byte, secretKey []byte) ([]byte, error) {
	if len(secretKey) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(secretKey))
	}
	privKey, _ := btcec.PrivKeyFromBytes(secretKey)
	hash := hashSignable(msg)
	sig, err := schnorr.Sign(privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("schnorr sign: %w", err)
	}
	return sig.Serialize(), nil
}

// VerifyMessage verifies a BIP-340 Schnorr signature over a message with the Spaces signed-message prefix.
func VerifyMessage(msg []byte, signature []byte, pubkey []byte) error {
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
	hash := hashSignable(msg)
	if !sig.Verify(hash[:], pk) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
