package hashing

type AlgorithmType string

const (
	SHA224     AlgorithmType = "sha224"
	SHA256     AlgorithmType = "sha256"
	SHA384     AlgorithmType = "sha384"
	SHA512     AlgorithmType = "sha512"
	SHA512_224 AlgorithmType = "sha512_224"
	SHA512_256 AlgorithmType = "sha512_256"

	SHA3_224 AlgorithmType = "sha3_224"
	SHA3_256 AlgorithmType = "sha3_256"
	SHA3_384 AlgorithmType = "sha3_384"
	SHA3_512 AlgorithmType = "sha3_512"

	Bcrypt    AlgorithmType = "bcrypt"
	BcryptMin AlgorithmType = "bcrypt-min"
	BcryptMax AlgorithmType = "bcrypt-max"

	Argon2Interactive AlgorithmType = "argon2-interactive"
	Argon2Moderate    AlgorithmType = "argon2-moderate"
	Argon2Sensitive   AlgorithmType = "argon2-sensitive"
)

func (at AlgorithmType) Size() int {
	switch at {
	case SHA224, SHA3_224:
		return 28
	case SHA256, SHA3_256:
		return 32
	case SHA384, SHA3_384:
		return 48
	case SHA512, SHA3_512:
		return 64
	case SHA512_224:
		return 28
	case SHA512_256:
		return 32
	case Bcrypt, BcryptMin, BcryptMax:
		return 60
	case Argon2Interactive, Argon2Moderate, Argon2Sensitive:
		return 32
	default:
		return 0
	}
}

func (al AlgorithmType) Type() string {
	return string(al)
}
