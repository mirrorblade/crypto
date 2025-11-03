package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/mirrorblade/crypto/core"
)

func (sp *SymmetricProvider) encryptAES(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sp.secretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (sp *SymmetricProvider) decryptAES(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sp.secretKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, core.ErrCipherTextInvalidLength
	}

	nonce, ciphertextOnly := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertextOnly, nil)
}
