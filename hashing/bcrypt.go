package hashing

import (
	"github.com/mirrorblade/crypto/core"
	"golang.org/x/crypto/bcrypt"
)

func (hp *HashingProvider) hashBcrypt(data []byte, salt []byte) ([]byte, error) {
	var cost int

	switch hp.algorithmType {
	case Bcrypt:
		cost = 12
	case BcryptMin:
		cost = 4
	case BcryptMax:
		cost = 31
	default:
		return nil, core.ErrUnknownAlgorithmType
	}

	updatedData := data

	if len(salt) > 0 {
		updatedData = append(salt, data...)
	}

	hash, err := bcrypt.GenerateFromPassword(updatedData, cost)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

func (hp *HashingProvider) verifyBcrypt(data []byte, salt []byte, expectedHash []byte) (bool, error) {
	updatedData := data

	if len(salt) > 0 {
		updatedData = append(salt, data...)
	}

	if err := bcrypt.CompareHashAndPassword(expectedHash, updatedData); err != nil {
		return false, err
	}

	return true, nil
}
