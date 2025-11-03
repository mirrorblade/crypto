package symmetric

import (
	"crypto/cipher"
	"crypto/rand"

	"github.com/mirrorblade/crypto/core"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

func (sp *SymmetricProvider) encryptChaCha(plaintext []byte) ([]byte, error) {
	var nonceSize int

	switch sp.algorithmType {
	case ChaCha20:
		nonceSize = chacha20.NonceSize
	case XChaCha20:
		nonceSize = chacha20.NonceSizeX
	case ChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSize
	case XChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSizeX
	default:
		return nil, core.ErrUnknownAlgorithmType
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	var ciphertext []byte

	switch sp.algorithmType {
	case ChaCha20, XChaCha20:
		ciphertext := make([]byte, len(plaintext))
		cipher, err := chacha20.NewUnauthenticatedCipher(sp.secretKey, nonce)
		if err != nil {
			return nil, err
		}

		cipher.XORKeyStream(ciphertext, plaintext)

	case ChaCha20Poly1305, XChaCha20Poly1305:
		var (
			aead cipher.AEAD
			err  error
		)

		switch sp.algorithmType {
		case ChaCha20Poly1305:
			aead, err = chacha20poly1305.New(sp.secretKey)
		case XChaCha20Poly1305:
			aead, err = chacha20poly1305.NewX(sp.secretKey)
		}

		if err != nil {
			return nil, err
		}

		ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	}

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

func (sp *SymmetricProvider) decryptChaCha(data []byte) ([]byte, error) {
	var nonceSize int

	switch sp.algorithmType {
	case ChaCha20:
		nonceSize = chacha20.NonceSize
	case XChaCha20:
		nonceSize = chacha20.NonceSizeX
	case ChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSize
	case XChaCha20Poly1305:
		nonceSize = chacha20poly1305.NonceSizeX
	default:
		return nil, core.ErrUnknownAlgorithmType
	}

	if len(data) < nonceSize {
		return nil, core.ErrCipherTextInvalidLength
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	var plaintext []byte

	switch sp.algorithmType {
	case ChaCha20, XChaCha20:
		plaintext := make([]byte, len(ciphertext))
		cipher, err := chacha20.NewUnauthenticatedCipher(sp.secretKey, nonce)
		if err != nil {
			return nil, err
		}

		cipher.XORKeyStream(plaintext, ciphertext)

	case ChaCha20Poly1305, XChaCha20Poly1305:
		var (
			aead cipher.AEAD
			err  error
		)

		switch sp.algorithmType {
		case ChaCha20Poly1305:
			aead, err = chacha20poly1305.New(sp.secretKey)
		case XChaCha20Poly1305:
			aead, err = chacha20poly1305.NewX(sp.secretKey)
		}

		if err != nil {
			return nil, err
		}

		plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}
