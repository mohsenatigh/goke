package gcrypto

import (
	"crypto/rand"
	"log"
	"testing"
)

func TestGCryptoHMACFunctionality(t *testing.T) {

	//
	type testCase struct {
		hmac   GCryptHmacAlg
		result bool
	}

	//
	key := make([]byte, 64)
	rand.Read(key)
	data := "hello this is a data"

	//
	cases := []testCase{
		{
			hmac:   IANA_PRF_HMAC_MD5,
			result: true,
		},
		{
			hmac:   IANA_PRF_HMAC_SHA1,
			result: true,
		},
		{
			hmac:   IANA_PRF_HMAC_SHA2_256,
			result: true,
		},
		{
			hmac:   IANA_PRF_HMAC_SHA2_512,
			result: true,
		},
		{
			hmac:   IANA_PRF_HMAC_INVALID,
			result: false,
		},
	}

	//
	for _, c := range cases {
		hmac := createCryptoHMAC(c.hmac, key)
		hmac.SetKey(key)

		res, err := hmac.GetHMAC([]byte(data))
		if (err == nil) != c.result {
			t.FailNow()
		}

		if c.result {
			if len(res) != c.hmac.Size() || len(res) != hmac.GetLen() {
				t.FailNow()
			}

			log.Printf("%v", res)
		}
	}

}
