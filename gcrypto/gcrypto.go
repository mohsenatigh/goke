package gcrypto

//---------------------------------------------------------------------------------------
const (
	GCRYPTO_HASH_TYPE_MD5    = 0
	GCRYPTO_HASH_TYPE_SHA1   = 1
	GCRYPTO_HASH_TYPE_SHA256 = 2
	GCRYPTO_HASH_TYPE_SHA512 = 3
)

//---------------------------------------------------------------------------------------
const (
	GCRYPTO_HMAC_TYPE_MD5    = 0
	GCRYPTO_HMAC_TYPE_SHA1   = 1
	GCRYPTO_HMAC_TYPE_SHA256 = 2
	GCRYPTO_HMAC_TYPE_SHA512 = 3
)

//---------------------------------------------------------------------------------------
const (
	GCRYPTO_CIPHER_AES128 = 0
	GCRYPTO_CIPHER_AES192 = 1
	GCRYPTO_CIPHER_AES256 = 2
)

//---------------------------------------------------------------------------------------
type IGCryptoCipher interface {
	Encrypt(in []byte, out []byte, iv []byte) error
	Decrypt(in []byte, out []byte, iv []byte) error
	GetIVLen() int
	GetBlockLen() int
	GetKeyLen() int
	GetPadLen(bufferSize int) int
	GetIV() []byte
	SetKey([]byte)
}

//---------------------------------------------------------------------------------------
type IGCryptoHash interface {
	Start() error
	Write(buffer []byte) error
	Final() []byte
	GetHash(in []byte) []byte
}

//---------------------------------------------------------------------------------------
type IGCryptoHMAC interface {
	Start() error
	Write(buffer []byte) error
	Final() []byte
	GetHMAC(buffer []byte) ([]byte, error)
	SetKey(key []byte)
	GetLen() int
}

//---------------------------------------------------------------------------------------
type IGCryptoDH interface {
	ComputeKey(peerPublicKey []byte) ([]byte, error)
	GetPublicKey() ([]byte, error)
	GetGroup() int
}

//---------------------------------------------------------------------------------------
type IGCryptoRSA interface {
	GetDER() []byte
	Sign([]byte) ([]byte, error)
	Verify(msg []byte, sig []byte) error
	GetCertSubjectKeyID() []byte
	GetCertSubjectInfoKeyID() []byte
}

//---------------------------------------------------------------------------------------
type IGCryptoCAInfo interface {
	ValidateCert(cert string) bool
	ValidateDer(cert []byte) bool
}

//---------------------------------------------------------------------------------------
type IGCrypto interface {
	GetHash(htype int) IGCryptoHash
	GetHMAC(htype int, key []byte) IGCryptoHMAC
	GetCipher(stype int, key []byte) IGCryptoCipher
	GetDH(group int) IGCryptoDH
	GetCA(cert string) IGCryptoCAInfo
	GetRSA(cert string, key string) IGCryptoRSA
	GetRSAByDer(der []byte) IGCryptoRSA
	CalculatePRFPlus(body []byte, hmacObj IGCryptoHMAC) []byte
}
