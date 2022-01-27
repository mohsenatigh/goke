package gcrypto

//---------------------------------------------------------------------------------------
type GCryptoDH int

//---------------------------------------------------------------------------------------
const (
	IANA_DH_GROUP_INVALID GCryptoDH = 0
	IANA_DH_GROUP_19      GCryptoDH = 19
	IANA_DH_GROUP_20      GCryptoDH = 20
	IANA_DH_GROUP_21      GCryptoDH = 21
	IANA_DH_GROUP_27      GCryptoDH = 27
	IANA_DH_GROUP_28      GCryptoDH = 28
	IANA_DH_GROUP_29      GCryptoDH = 29
	IANA_DH_GROUP_30      GCryptoDH = 30
)

//---------------------------------------------------------------------------------------
type gCryptoSHAlgInfo struct {
	alg  GCryptoDH
	name string
}

//---------------------------------------------------------------------------------------
//I Love Sara :)
var gCryptoDHList = map[GCryptoDH]gCryptoSHAlgInfo{
	IANA_DH_GROUP_19: {alg: IANA_DH_GROUP_19, name: "dh_group_19"},
	IANA_DH_GROUP_20: {alg: IANA_DH_GROUP_20, name: "dh_group_20"},
	IANA_DH_GROUP_21: {alg: IANA_DH_GROUP_21, name: "dh_group_21"},
	IANA_DH_GROUP_27: {alg: IANA_DH_GROUP_27, name: "dh_group_27"},
	IANA_DH_GROUP_28: {alg: IANA_DH_GROUP_28, name: "dh_group_28"},
	IANA_DH_GROUP_29: {alg: IANA_DH_GROUP_29, name: "dh_group_29"},
	IANA_DH_GROUP_30: {alg: IANA_DH_GROUP_30, name: "dh_group_30"},
}

//---------------------------------------------------------------------------------------
func (alg GCryptoDH) String() string {
	if info, fnd := gCryptoDHList[alg]; fnd {
		return info.name
	}
	return ""
}

//---------------------------------------------------------------------------------------
func (alg GCryptoDH) FromString(str string) GCryptoDH {
	for key, val := range gCryptoDHList {
		if val.name == str {
			return key
		}
	}
	return IANA_DH_GROUP_INVALID
}

//---------------------------------------------------------------------------------------
func (alg GCryptoDH) Validate() bool {
	_, fnd := gCryptoDHList[alg]
	return fnd
}
