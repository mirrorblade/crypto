package asymmetric

type AlgorithmType string

const (
	RSA1024 AlgorithmType = "rsa-1024"
	RSA2048 AlgorithmType = "rsa-2048"
	RSA3072 AlgorithmType = "rsa-3072"
	RSA4096 AlgorithmType = "rsa-4096"
	RSA8192 AlgorithmType = "rsa-8192"

	P224 AlgorithmType = "p-224"
	P256 AlgorithmType = "p-256"
	P384 AlgorithmType = "p-384"
	P521 AlgorithmType = "p-521"
)

func (al AlgorithmType) Size() int {
	switch al {
	case RSA1024:
		return 128
	case RSA2048:
		return 256
	case RSA3072:
		return 384
	case RSA4096:
		return 512
	case RSA8192:
		return 1024
	case P224:
		return 28
	case P256:
		return 32
	case P384:
		return 48
	case P521:
		return 66
	default:
		return 0
	}
}

func (al AlgorithmType) Type() string {
	return string(al)
}
