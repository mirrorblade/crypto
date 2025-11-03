package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/mirrorblade/crypto/core"
)

func (ap *AsymmetricProvider) encryptRSA(plaintext []byte) ([]byte, error) {
	publicKey, ok := ap.publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, core.ErrInvalidPublicKey
	}

	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
}

func (ap *AsymmetricProvider) decryptRSA(ciphertext []byte) ([]byte, error) {
	privateKey, ok := ap.privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, core.ErrInvalidPrivateKey
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}
