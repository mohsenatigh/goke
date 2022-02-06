package gcrypto

//---------------------------------------------------------------------------------------
type GCryptAuthAlg int

//---------------------------------------------------------------------------------------
const (
	IANA_AUTH_HMAC_INVALID      GCryptAuthAlg = 0
	IANA_AUTH_HMAC_MD5_96       GCryptAuthAlg = 1
	IANA_AUTH_HMAC_SHA1_96      GCryptAuthAlg = 2
	IANA_AUTH_HMAC_SHA2_256_128 GCryptAuthAlg = 12
	IANA_AUTH_HMAC_SHA2_512_256 GCryptAuthAlg = 14
)

//---------------------------------------------------------------------------------------
type gCryptoAuthAlgInfo struct {
	alg     GCryptAuthAlg
	name    string
	size    int
	keySize int
}

var gCryptoAuthAlgList = map[GCryptAuthAlg]gCryptoAuthAlgInfo{
	IANA_AUTH_HMAC_MD5_96:       {alg: IANA_AUTH_HMAC_MD5_96, name: "hmac_md5_96", size: 12, keySize: 16},
	IANA_AUTH_HMAC_SHA1_96:      {alg: IANA_AUTH_HMAC_SHA1_96, name: "hmac_sha1_96", size: 12, keySize: 20},
	IANA_AUTH_HMAC_SHA2_256_128: {alg: IANA_AUTH_HMAC_SHA2_256_128, name: "hmac_sha2_256_128", size: 16, keySize: 32},
	IANA_AUTH_HMAC_SHA2_512_256: {alg: IANA_AUTH_HMAC_SHA2_512_256, name: "hmac_sha2_512_256", size: 32, keySize: 64},
}

//---------------------------------------------------------------------------------------
func (alg GCryptAuthAlg) String() string {
	if info, fnd := gCryptoAuthAlgList[alg]; fnd {
		return info.name
	}
	return ""
}

//---------------------------------------------------------------------------------------
func (alg GCryptAuthAlg) FromString(str string) GCryptAuthAlg {
	for key, value := range gCryptoAuthAlgList {
		if value.name == str {
			return key
		}
	}
	return IANA_AUTH_HMAC_INVALID
}

//---------------------------------------------------------------------------------------
func (alg GCryptAuthAlg) Size() int {
	if info, fnd := gCryptoAuthAlgList[alg]; fnd {
		return info.size
	}
	return 0
}

//---------------------------------------------------------------------------------------
func (alg GCryptAuthAlg) KeySize() int {
	if info, fnd := gCryptoAuthAlgList[alg]; fnd {
		return info.keySize
	}
	return 0
}

//---------------------------------------------------------------------------------------
func (alg GCryptAuthAlg) Validate() bool {
	_, fnd := gCryptoAuthAlgList[alg]
	return fnd
}
