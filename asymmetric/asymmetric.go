package asymmetric

import "github.com/mirrorblade/crypto/core"

type AlgorithmType string

const (
	RSA1024 AlgorithmType = "rsa-1024"
	RSA2048 AlgorithmType = "rsa-2048"
	RSA3072 AlgorithmType = "rsa-3072"
	RSA4096 AlgorithmType = "rsa-4096"
	RSA8192 AlgorithmType = "rsa-8192"

	P224 AlgorithmType = "p-224"
	P256 AlgorithmType = "p-256"
	P384 AlgorithmType = "p-384"
	P521 AlgorithmType = "p-521"
)

func (al AlgorithmType) Size() int {
	switch al {
	case RSA1024:
		return 128
	case RSA2048:
		return 256
	case RSA3072:
		return 384
	case RSA4096:
		return 512
	case RSA8192:
		return 1024
	case P224:
		return 28
	case P256:
		return 32
	case P384:
		return 48
	case P521:
		return 66
	default:
		return 0
	}
}

func (al AlgorithmType) Type() string {
	return string(al)
}

type Provider interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type AsymmetricProvider struct {
	algorithmType AlgorithmType

	publicKey  []byte
	privateKey []byte
}

func NewProvider(algorithmType AlgorithmType, publicKey, privateKey []byte) (*AsymmetricProvider, error) {
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
