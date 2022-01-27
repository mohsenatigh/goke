package gcrypto

//https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml
//---------------------------------------------------------------------------------------
type GCryptoParseResult struct {
	EncAlg    GCryptCipherAlg
	EncKeyLen int
	IntAlg    GCryptAuthAlg
	Prf       GCryptHmacAlg
	DhGroup   GCryptoDH
}

//---------------------------------------------------------------------------------------
type IGCryptoCipher interface {
	Encrypt(in []byte, out []byte, iv []byte) error
	Decrypt(in []byte, out []byte, iv []byte) error
	GetKeyLen() int
	GetPadLen(bufferSize int) int
	GetIV() []byte
	SetKey([]byte)
	GetAlg() GCryptCipherAlg
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
type IGCryptoAuth interface {
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
	GetHash(htype GCryptHashAlg) IGCryptoHash
	GetHMAC(htype GCryptHmacAlg, key []byte) IGCryptoHMAC
	GetAuth(htype GCryptAuthAlg, key []byte) IGCryptoAuth
	GetCipher(stype GCryptCipherAlg, key []byte) IGCryptoCipher
	GetDH(group GCryptoDH) IGCryptoDH
	GetCA(cert string) IGCryptoCAInfo
	GetRSA(cert string, key string) IGCryptoRSA
	GetRSAByDer(der []byte) IGCryptoRSA
	CalculatePRFPlus(body []byte, hmacObj IGCryptoHMAC) []byte
	GenerateRandom(int) []byte
}

//---------------------------------------------------------------------------------------
