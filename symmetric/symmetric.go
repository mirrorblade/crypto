package symmetric

import "github.com/mirrorblade/crypto/core"

type Provider interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type SymmetricProvider struct {
	algorithmType AlgorithmType

	secretKey []byte
}

func NewProvider(algorithmType AlgorithmType, secretKey []byte) (*SymmetricProvider, error) {
	switch algorithmType {
	case AES128, AES192, AES256,
		ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
	default:
		return nil, core.ErrUnknownAlgorithmType
	}

	return &SymmetricProvider{
		algorithmType: algorithmType,
		secretKey:     secretKey,
	}, nil
}

func (sp *SymmetricProvider) Encrypt(plaintext []byte) ([]byte, error) {
	switch sp.algorithmType {
	case AES128, AES192, AES256:
		return sp.encryptAES(plaintext)
	case ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
		return sp.encryptChaCha(plaintext)
	default:
		return nil, core.ErrUnknownAlgorithmType
	}
}

func (sp *SymmetricProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	switch sp.algorithmType {
	case AES128, AES192, AES256:
		return sp.decryptAES(ciphertext)
	case ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
		return sp.decryptChaCha(ciphertext)
	default:
		return nil, core.ErrUnknownAlgorithmType
	}
}
