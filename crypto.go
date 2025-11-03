package crypto

import (
	"github.com/mirrorblade/crypto/asymmetric"
	"github.com/mirrorblade/crypto/core"
	"github.com/mirrorblade/crypto/hashing"
	"github.com/mirrorblade/crypto/symmetric"
)

type Provider interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Hash(data, salt []byte) ([]byte, error)
	VerifyHash(data, salt, expectedHash []byte) (bool, error)
}

type Callbacks struct {
	EncryptFunc func(plaintext []byte) ([]byte, error)
	DecryptFunc func(ciphertext []byte) ([]byte, error)

	HashFunc       func(data, salt []byte) ([]byte, error)
	VerifyHashFunc func(data, salt, expectedHash []byte) (bool, error)
}

type CryptoProvider struct {
	symmetricProvider  symmetric.Provider
	asymmetricProvider asymmetric.Provider
	hashingProvider    hashing.Provider
	callbacks          Callbacks
}

func NewProvider(
	symmetricProvider symmetric.Provider,
	asymmetricProvider asymmetric.Provider,
	hashingProvider hashing.Provider,
	callbacks Callbacks,
) (*CryptoProvider, error) {
	if (symmetricProvider == nil &&
		asymmetricProvider == nil &&
		callbacks.EncryptFunc == nil &&
		callbacks.DecryptFunc == nil) &&

		(hashingProvider == nil &&
			callbacks.HashFunc == nil &&
			callbacks.VerifyHashFunc == nil) {

		return nil, core.ErrNoProviderDefined
	}

	if symmetricProvider != nil && asymmetricProvider != nil {
		if callbacks.EncryptFunc == nil || callbacks.DecryptFunc == nil {
			return nil, core.ErrNoCallbackFunctionsDefined
		}
	}

	if (callbacks.EncryptFunc == nil) != (callbacks.DecryptFunc == nil) {
		return nil, core.ErrNoCallbackFunctionsDefined
	}

	if (callbacks.HashFunc == nil) != (callbacks.VerifyHashFunc == nil) {
		return nil, core.ErrNoCallbackFunctionsDefined
	}

	return &CryptoProvider{
		symmetricProvider:  symmetricProvider,
		asymmetricProvider: asymmetricProvider,
		hashingProvider:    hashingProvider,
		callbacks:          callbacks,
	}, nil
}

func (cp *CryptoProvider) Encrypt(plaintext []byte) ([]byte, error) {
	var (
		ciphertext []byte
		err        error
	)

	if cp.callbacks.EncryptFunc == nil {
		if cp.symmetricProvider == nil && cp.asymmetricProvider == nil {
			return nil, core.ErrNoProviderDefined
		}

		if cp.symmetricProvider != nil {
			ciphertext, err = cp.symmetricProvider.Encrypt(plaintext)
		} else {
			ciphertext, err = cp.asymmetricProvider.Encrypt(plaintext)
		}
	} else {
		ciphertext, err = cp.callbacks.EncryptFunc(plaintext)
	}

	return ciphertext, err
}

func (cp *CryptoProvider) Decrypt(ciphertext []byte) ([]byte, error) {
	var (
		plaintext []byte
		err       error
	)

	if cp.callbacks.DecryptFunc == nil {
		if cp.symmetricProvider == nil && cp.asymmetricProvider == nil {
			return nil, core.ErrNoProviderDefined
		}

		if cp.symmetricProvider != nil {
			plaintext, err = cp.symmetricProvider.Decrypt(ciphertext)
		} else {
			plaintext, err = cp.asymmetricProvider.Decrypt(ciphertext)
		}

	} else {
		plaintext, err = cp.callbacks.DecryptFunc(ciphertext)
	}

	return plaintext, err
}

func (cp *CryptoProvider) Hash(data, salt []byte) ([]byte, error) {
	var (
		hash []byte
		err  error
	)

	if cp.callbacks.HashFunc == nil {
		if cp.hashingProvider == nil {
			return nil, core.ErrNoProviderDefined
		}

		hash, err = cp.hashingProvider.Hash(data, salt)

	} else {
		hash, err = cp.callbacks.HashFunc(data, salt)
	}

	return hash, err
}

func (cp *CryptoProvider) VerifyHash(data, salt, expectedHash []byte) (bool, error) {
	var (
		isVerified bool
		err        error
	)

	if cp.callbacks.VerifyHashFunc == nil {
		if cp.hashingProvider == nil {
			return false, core.ErrNoProviderDefined
		}

		isVerified, err = cp.hashingProvider.VerifyHash(data, salt, expectedHash)

	} else {
		isVerified, err = cp.callbacks.VerifyHashFunc(data, salt, expectedHash)
	}

	return isVerified, err
}

// func (cp *CryptoProvider) Sign(data []byte) ([]byte, error) {
// }
//
// func (cp *CryptoProvider) VerifySign(data, expectedSign []byte) ([]byte, error) {
// }
