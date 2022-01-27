package gcrypto

import "crypto/aes"

//---------------------------------------------------------------------------------------
type GCryptCipherAlg int

//---------------------------------------------------------------------------------------
const (
	IANA_ENCR_INVALID GCryptCipherAlg = 0
	IANA_ENCR_AES_CBC GCryptCipherAlg = 12
)

//---------------------------------------------------------------------------------------
type gCryptoCipherAlgInfo struct {
	alg         GCryptCipherAlg
	name        string
	keySizeList []int
	blockSize   int
}

var gCryptoCipherAlgList = map[GCryptCipherAlg]gCryptoCipherAlgInfo{
	IANA_ENCR_AES_CBC: {alg: IANA_ENCR_AES_CBC, name: "aes", keySizeList: []int{16, 24, 32}, blockSize: aes.BlockSize},
}

//---------------------------------------------------------------------------------------
func (alg GCryptCipherAlg) String() string {
	if info, fnd := gCryptoCipherAlgList[alg]; fnd {
		return info.name
	}
	return ""
}

//---------------------------------------------------------------------------------------
func (alg GCryptCipherAlg) FromString(str string) GCryptCipherAlg {
	for key, value := range gCryptoCipherAlgList {
		if value.name == str {
			return key
		}
	}
	return IANA_ENCR_INVALID
}

//---------------------------------------------------------------------------------------
func (alg GCryptCipherAlg) BlockSize() int {
	if info, fnd := gCryptoCipherAlgList[alg]; fnd {
		return info.blockSize
	}
	return 0
}

//---------------------------------------------------------------------------------------
func (alg GCryptCipherAlg) Validate(keySize int) bool {
	info, fnd := gCryptoCipherAlgList[alg]
	if !fnd {
		return false
	}
	for _, kl := range info.keySizeList {
		if kl == keySize {
			return false
		}
	}
	return true
}

//---------------------------------------------------------------------------------------
