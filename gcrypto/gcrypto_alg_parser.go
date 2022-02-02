package gcrypto

import (
	"errors"
	"strconv"
	"strings"
)

//sample format enc:aes-128,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh:group20

//---------------------------------------------------------------------------------------
func GetDefaultESPAlgorithmString() string {
	return "enc:aes-128,auth:hmac_sha2_256_128"
}

//---------------------------------------------------------------------------------------
func GetDefaultIKEAlgorithmString() string {
	return "enc:aes-128,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh:group27"
}

//---------------------------------------------------------------------------------------
func ParseAlgorithm(in string) (GCryptoParseResult, error) {
	out := GCryptoParseResult{
		DhGroup:   IANA_DH_GROUP_27,
		EncAlg:    IANA_ENCR_AES_CBC,
		IntAlg:    IANA_AUTH_HMAC_SHA1_96,
		Prf:       IANA_PRF_HMAC_SHA1,
		EncKeyLen: 16,
	}

	items := strings.Split(in, ",")

	if len(items) < 2 {
		return out, errors.New("invalid algorithm string")
	}

	//parse values
	for _, item := range items {
		//
		pair := strings.Split(item, ":")
		if len(pair) != 2 {
			return out, errors.New("invalid algorithm string")
		}

		//
		switch pair[0] {
		case "enc": //parse encryption
			{
				encInfo := strings.Split(pair[1], "-")
				if len(encInfo) != 2 {
					return out, errors.New("invalid encryption algorithm")
				}

				out.EncKeyLen, _ = strconv.Atoi(encInfo[1])
				out.EncKeyLen /= 8
				if out.EncAlg = out.EncAlg.FromString(encInfo[0]); out.EncAlg == IANA_ENCR_INVALID {
					return out, errors.New("invalid encryption algorithm")
				}

				if !out.EncAlg.Validate(out.EncKeyLen) {
					return out, errors.New("invalid encryption algorithm")
				}
			}

		case "auth":
			{
				if out.IntAlg = out.IntAlg.FromString(pair[1]); out.IntAlg == IANA_AUTH_HMAC_INVALID {
					return out, errors.New("invalid authentication algorithm")
				}
			}

		case "prf":
			{
				if out.Prf = out.Prf.FromString(pair[1]); out.Prf == IANA_PRF_HMAC_INVALID {
					return out, errors.New("invalid PRF algorithm")
				}
			}

		case "dh":
			{
				if out.DhGroup = out.DhGroup.FromString(pair[1]); out.DhGroup == IANA_DH_GROUP_INVALID {
					return out, errors.New("invalid DH group")
				}
			}
		default:
			{
				return out, errors.New("invalid algorithm item")
			}
		}
	}

	return out, nil
}
