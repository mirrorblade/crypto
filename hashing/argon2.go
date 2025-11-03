package hashing

import (
	"crypto/subtle"

	"github.com/mirrorblade/crypto/core"
	"golang.org/x/crypto/argon2"
)

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
	SaltLength  uint32
}

func (hp *HashingProvider) getDefaultArgon2Config() (Argon2Config, error) {
	switch hp.algorithmType {
	case Argon2Interactive:
		return Argon2Config{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 4,
			KeyLength:   32,
			SaltLength:  16,
		}, nil
	case Argon2Moderate:
		return Argon2Config{
			Memory:      256 * 1024,
			Iterations:  6,
			Parallelism: 4,
			KeyLength:   32,
			SaltLength:  16,
		}, nil
	case Argon2Sensitive:
		return Argon2Config{
			Memory:      512 * 1024,
			Iterations:  12,
			Parallelism: 4,
			KeyLength:   32,
			SaltLength:  16,
		}, nil
	default:
		return Argon2Config{}, core.ErrUnknownAlgorithmType
	}
}

func (hp *HashingProvider) hashArgon2(data []byte, salt []byte) ([]byte, error) {
	if len(salt) != 0 && len(salt) < int(hp.argon2Config.SaltLength) {
		return nil, core.ErrArgon2SaltLengthShort
	}

	if len(salt) == 0 {
		salt = []byte{}
	}

	usedSalt := salt
	if len(usedSalt) > int(hp.argon2Config.SaltLength) {
		usedSalt = usedSalt[:hp.argon2Config.SaltLength]
	}

	hash := argon2.IDKey(
		data,
		usedSalt,
		hp.argon2Config.Iterations,
		hp.argon2Config.Memory,
		hp.argon2Config.Parallelism,
		hp.argon2Config.KeyLength,
	)

	return hash, nil
}

func (hp *HashingProvider) verifyArgon2(data, salt, expectedHash []byte) (bool, error) {
	hash, err := hp.hashArgon2(data, salt)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(hash, expectedHash) == 1, nil
}
