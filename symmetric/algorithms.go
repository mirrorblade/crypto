package symmetric

type AlgorithmType string

const (
	AES128 AlgorithmType = "aes-128"
	AES192 AlgorithmType = "aes-192"
	AES256 AlgorithmType = "aes-256"

	ChaCha20          AlgorithmType = "chacha20"
	ChaCha20Poly1305  AlgorithmType = "chacha20-poly1305"
	XChaCha20         AlgorithmType = "xchacha20"
	XChaCha20Poly1305 AlgorithmType = "xchacha20-poly1305"
)

func (al AlgorithmType) Size() int {
	switch al {
	case AES128:
		return 16
	case AES192:
		return 24
	case AES256:
		return 32
	case ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305:
		return 32
	default:
		return 0
	}
}

func (al AlgorithmType) Type() string {
	return string(al)
}
