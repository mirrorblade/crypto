package core

type KeyFormat string

const (
	PKCS8Format KeyFormat = "pkcs8"
	PKCS1Format KeyFormat = "pkcs1"
	SEC1Format  KeyFormat = "sec1"
	PKIXFormat  KeyFormat = "pkix"
)
