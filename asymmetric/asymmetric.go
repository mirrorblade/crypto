package asymmetric

import (
	"github.com/mirrorblade/crypto/core"
)

type Provider interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type AsymmetricProvider struct {
	algorithmType AlgorithmType

	publicKey  any
	privateKey any
}

func NewProvider(algorithmType AlgorithmType, publicKey, privateKey any) (*AsymmetricProvider, error) {
	switch algorithmType {
	case RSA1024, RSA2048, RSA3072, RSA4096, RSA8192,
		P224, P256, P384, P521:
	default:
		return nil, core.ErrUnknownAlgorithmType
	}

	return &AsymmetricProvider{
		algorithmType: algorithmType,
		publicKey:     publicKey,
		privateKey:    privateKey,
	}, nil
}

func (ap *AsymmetricProvider) Encrypt(plaintext []byte) ([]byte, error) {
	switch ap.algorithmType {
	case RSA1024, RSA2048, RSA3072, RSA4096, RSA8192:
		return ap.encryptRSA(plaintext)
	case P224, P256, P384, P521:
		return ap.encryptEC(plaintext)
	default:
		return nil, core.ErrUnknownAlgorithmType
	}
}

func (ap *AsymmetricProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	switch ap.algorithmType {
	case RSA1024, RSA2048, RSA3072, RSA4096, RSA8192:
		return ap.decryptRSA(ciphertext)
	case P224, P256, P384, P521:
		return ap.decryptEC(ciphertext)
	default:
		return nil, core.ErrUnknownAlgorithmType
	}
}
