package gcrypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

//---------------------------------------------------------------------------------------
type GCryptHmacAlg int

//---------------------------------------------------------------------------------------
const (
	IANA_PRF_HMAC_INVALID  GCryptHmacAlg = 0
	IANA_PRF_HMAC_MD5      GCryptHmacAlg = 1
	IANA_PRF_HMAC_SHA1     GCryptHmacAlg = 2
	IANA_PRF_HMAC_SHA2_256 GCryptHmacAlg = 5
	IANA_PRF_HMAC_SHA2_512 GCryptHmacAlg = 7
)

//---------------------------------------------------------------------------------------
type gCryptoHMACAlgInfo struct {
	alg  GCryptHmacAlg
	name string
	size int
}

var gCryptoHMACAlgList = map[GCryptHmacAlg]gCryptoHMACAlgInfo{
	IANA_PRF_HMAC_MD5:      {alg: IANA_PRF_HMAC_MD5, name: "hmac_md5", size: md5.Size},
	IANA_PRF_HMAC_SHA1:     {alg: IANA_PRF_HMAC_SHA1, name: "hmac_sha1", size: sha1.Size},
	IANA_PRF_HMAC_SHA2_256: {alg: IANA_PRF_HMAC_SHA2_256, name: "hmac_sha2_256", size: sha256.Size},
	IANA_PRF_HMAC_SHA2_512: {alg: IANA_PRF_HMAC_SHA2_512, name: "hmac_sha2_512", size: sha512.Size},
}

//---------------------------------------------------------------------------------------
func (alg GCryptHmacAlg) String() string {
	if info, fnd := gCryptoHMACAlgList[alg]; fnd {
		return info.name
	}
	return ""
}

//---------------------------------------------------------------------------------------
func (alg GCryptHmacAlg) FromString(str string) GCryptHmacAlg {
	for key, value := range gCryptoHMACAlgList {
		if value.name == str {
			return key
		}
	}
	return IANA_PRF_HMAC_INVALID
}

//---------------------------------------------------------------------------------------
func (alg GCryptHmacAlg) Validate() bool {
	_, fnd := gCryptoHMACAlgList[alg]
	return fnd
}

//---------------------------------------------------------------------------------------
func (alg GCryptHmacAlg) Size() int {
	if info, fnd := gCryptoHMACAlgList[alg]; fnd {
		return info.size
	}
	return 0
}

//---------------------------------------------------------------------------------------
