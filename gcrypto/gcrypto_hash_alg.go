package gcrypto

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

//---------------------------------------------------------------------------------------
type GCryptHashAlg int

//---------------------------------------------------------------------------------------
const (
	IANA_HASH_INVALID  GCryptHashAlg = 0
	IANA_HASH_SHA1     GCryptHashAlg = 1
	IANA_HASH_SHA2_256 GCryptHashAlg = 2
	IANA_HASH_SHA2_512 GCryptHashAlg = 4
)

//---------------------------------------------------------------------------------------
type gCryptoHashAlgInfo struct {
	alg  GCryptHashAlg
	name string
	size int
}

var gCryptoHashAlgList = map[GCryptHashAlg]gCryptoHashAlgInfo{
	IANA_HASH_SHA1:     {alg: IANA_HASH_SHA1, name: "sha1", size: sha1.Size},
	IANA_HASH_SHA2_256: {alg: IANA_HASH_SHA2_256, name: "sha256", size: sha256.Size},
	IANA_HASH_SHA2_512: {alg: IANA_HASH_SHA2_512, name: "sha512", size: sha512.Size},
}

//---------------------------------------------------------------------------------------
func (alg GCryptHashAlg) String() string {
	if info, fnd := gCryptoHashAlgList[alg]; fnd {
		return info.name
	}
	return ""
}

//---------------------------------------------------------------------------------------
func (alg GCryptHashAlg) FromString(str string) GCryptHashAlg {
	for key, val := range gCryptoHashAlgList {
		if val.name == str {
			return key
		}
	}
	return IANA_HASH_INVALID
}

//---------------------------------------------------------------------------------------
func (alg GCryptHashAlg) Validate() bool {
	_, fnd := gCryptoHashAlgList[alg]
	return fnd
}

//---------------------------------------------------------------------------------------
func (alg GCryptHashAlg) Size() int {
	if info, fnd := gCryptoHashAlgList[alg]; fnd {
		return info.size
	}
	return 0
}
