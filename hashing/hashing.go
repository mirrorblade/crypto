package hashing

import (
	"github.com/mirrorblade/crypto/core"
)

type Provider interface {
	Hash(data, salt []byte) ([]byte, error)
	VerifyHash(data, salt, expectedHash []byte) (bool, error)
}

type HashingProvider struct {
	algorithmType AlgorithmType

	argon2Config Argon2Config
}

func NewProvider(algorithmType AlgorithmType) (*HashingProvider, error) {
	switch algorithmType {
	case SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256,
		SHA3_224, SHA3_256, SHA3_384, SHA3_512,
		Bcrypt, BcryptMin, BcryptMax,
		Argon2Interactive, Argon2Moderate, Argon2Sensitive:
	default:
		return nil, core.ErrUnknownAlgorithmType
	}

	hp := &HashingProvider{
		algorithmType: algorithmType,
	}

	switch algorithmType {
	case Argon2Interactive, Argon2Moderate, Argon2Sensitive:
		argon2Config, err := hp.getDefaultArgon2Config()
		if err != nil {
			return nil, err
		}

		hp.argon2Config = argon2Config
	}

	return hp, nil
}

func (hp *HashingProvider) Hash(data, salt []byte) ([]byte, error) {
	switch hp.algorithmType {
	case SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256,
		SHA3_224, SHA3_256, SHA3_384, SHA3_512:
		return hp.hashSHA(data, salt)
	case Bcrypt, BcryptMin, BcryptMax:
		return hp.hashBcrypt(data, salt)
	case Argon2Interactive, Argon2Moderate, Argon2Sensitive:
		return hp.hashArgon2(data, salt)
	default:
		return nil, core.ErrUnknownAlgorithmType
	}
}

func (hp *HashingProvider) VerifyHash(data, salt, expectedHash []byte) (bool, error) {
	switch hp.algorithmType {
	case SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256,
		SHA3_224, SHA3_256, SHA3_384, SHA3_512:
		return hp.verifySHA(data, salt, expectedHash)
	case Bcrypt, BcryptMin, BcryptMax:
		return hp.verifyBcrypt(data, salt, expectedHash)
	case Argon2Interactive, Argon2Moderate, Argon2Sensitive:
		return hp.verifyArgon2(data, salt, expectedHash)
	default:
		return false, core.ErrUnknownAlgorithmType
	}
}
