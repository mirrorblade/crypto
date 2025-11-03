package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/mirrorblade/crypto/core"
)

func (ap *AsymmetricProvider) encryptRSA(plaintext []byte) ([]byte, error) {
	publicKey, err := ap.publicKeyToRSA()
	if err != nil {
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext)
}

func (ap *AsymmetricProvider) decryptRSA(ciphertext []byte) ([]byte, error) {
	privateKey, err := ap.privateKeyToRSA()
	if err != nil {
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
}

func (ap *AsymmetricProvider) publicKeyToRSA() (*rsa.PublicKey, error) {
	block, _ := pem.Decode(ap.publicKey)
	if block == nil {
		return nil, core.ErrFailedPEMBlockParsing
	}

	untypedPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, core.ErrInvalidPKIXKey
	}

	publicKey, ok := untypedPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, core.ErrInvalidPublicKey
	}

	return publicKey, nil
}

func (ap *AsymmetricProvider) privateKeyToRSA() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(ap.privateKey)
	if block == nil {
		return nil, core.ErrFailedPEMBlockParsing
	}

	untypedPrivateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, core.ErrInvalidPKIXKey
	}

	privateKey, ok := untypedPrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, core.ErrInvalidPrivateKey
	}

	return privateKey, nil
}
