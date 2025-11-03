package keymanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"

	"github.com/mirrorblade/crypto/asymmetric"
	"github.com/mirrorblade/crypto/core"
	"github.com/mirrorblade/crypto/symmetric"
)

func LoadKeyPair(privateFilename, publicFilename string) (privateKey, publicKey []byte, err error) {
	privateKey, err = os.ReadFile(privateFilename)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err = os.ReadFile(publicFilename)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func LoadSecretKey(filename string) (secretKey []byte, err error) {
	return os.ReadFile(filename)
}

func MarshalPrivateKey(key any, keyFormat core.KeyFormat) ([]byte, error) {
	var (
		privateKey []byte
		keyType    string
		err        error
	)

	switch keyFormat {
	case core.PKCS8Format:
		privateKey, err = x509.MarshalPKCS8PrivateKey(key)

	case core.PKCS1Format:
		if parsedKey, ok := key.(*rsa.PrivateKey); ok {
			privateKey = x509.MarshalPKCS1PrivateKey(parsedKey)
			keyType = "RSA "
		} else {
			err = core.ErrUnknownKeyFormat
		}

	case core.SEC1Format:
		if parsedKey, ok := key.(*ecdsa.PrivateKey); ok {
			privateKey, err = x509.MarshalECPrivateKey(parsedKey)
			keyType = "EC "
		} else {
			err = core.ErrUnknownKeyFormat
		}

	default:
		return nil, core.ErrUnknownKeyFormat
	}

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  keyType + "PRIVATE KEY",
		Bytes: privateKey,
	}), nil
}

func MarshalPublicKey(key any, keyFormat core.KeyFormat) ([]byte, error) {
	var (
		publicKey []byte
		keyType   string
		err       error
	)

	switch keyFormat {
	case core.PKCS1Format:
		if parsedKey, ok := key.(*rsa.PublicKey); ok {
			publicKey = x509.MarshalPKCS1PublicKey(parsedKey)
			keyType = "RSA "
		} else {
			err = core.ErrUnknownKeyFormat
		}

	case core.PKIXFormat:
		publicKey, err = x509.MarshalPKIXPublicKey(key)

	default:
		return nil, core.ErrUnknownKeyFormat
	}

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  keyType + "PUBLIC KEY",
		Bytes: publicKey,
	}), nil
}

func UnmarshalPrivateKey(key []byte, keyFormat core.KeyFormat) (any, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, core.ErrFailedPEMBlockParsing
	}

	switch keyFormat {
	case core.PKCS8Format:
		return x509.ParsePKCS8PrivateKey(block.Bytes)

	case core.PKCS1Format:
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case core.SEC1Format:
		return x509.ParseECPrivateKey(block.Bytes)

	default:
		return nil, core.ErrUnknownKeyFormat
	}
}

func UnmarshalPublicKey(key []byte, keyFormat core.KeyFormat) (any, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, core.ErrFailedPEMBlockParsing
	}

	switch keyFormat {
	case core.PKCS1Format:
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case core.PKIXFormat:
		return x509.ParsePKIXPublicKey(block.Bytes)

	default:
		return nil, core.ErrUnknownKeyFormat
	}
}

func GenerateKeyPair(algorithmType asymmetric.AlgorithmType) (privateKey, publicKey any, err error) {
	switch algorithmType {
	case asymmetric.RSA1024,
		asymmetric.RSA2048,
		asymmetric.RSA3072,
		asymmetric.RSA4096,
		asymmetric.RSA8192:
		return generateRSAKeyPair(algorithmType.Size() * 8)

	case asymmetric.P224,
		asymmetric.P256,
		asymmetric.P384,
		asymmetric.P521:
		return generateECKeyPair(algorithmType.Size())

	default:
		return nil, nil, core.ErrUnknownAlgorithmType
	}
}

func GenerateSecretKey(algorithmType symmetric.AlgorithmType) (secretKey []byte, err error) {
	switch algorithmType {
	case symmetric.AES128, symmetric.AES192, symmetric.AES256, symmetric.ChaCha20, symmetric.ChaCha20Poly1305, symmetric.XChaCha20, symmetric.XChaCha20Poly1305:
	default:
		return nil, core.ErrUnknownAlgorithmType
	}

	key := make([]byte, algorithmType.Size())
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, core.ErrFailedKeyGeneration
	}

	return key, nil
}

func generateRSAKeyPair(bits int) (privateKey, publicKey any, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, core.ErrFailedKeyGeneration
	}

	if err := priv.Validate(); err != nil {
		return nil, nil, core.ErrFailedKeyGeneration
	}

	return priv, &priv.PublicKey, nil
}

func generateECKeyPair(bits int) (privateKey, publicKey any, err error) {
	var curve elliptic.Curve

	switch bits {
	case 28:
		curve = elliptic.P224()
	case 32:
		curve = elliptic.P256()
	case 48:
		curve = elliptic.P384()
	case 66:
		curve = elliptic.P521()
	default:
		return nil, nil, core.ErrUnknownKeySize
	}

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return priv, &priv.PublicKey, nil
}

func SaveKeyPair(privateFilename, publicFilename string, privateKey, publicKey []byte) error {
	if err := os.WriteFile(privateFilename, privateKey, 0600); err != nil {
		return err
	}

	if err := os.WriteFile(publicFilename, privateKey, 0600); err != nil {
		return os.Remove(privateFilename)
	}

	return nil
}

func SaveSecretKey(filename string, secretKey []byte) error {
	return os.WriteFile(filename, secretKey, 0600)
}
