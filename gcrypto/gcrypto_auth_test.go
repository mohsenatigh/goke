package gcrypto

import (
	"crypto/rand"
	"log"
	"testing"
)

func TestGCryptoAuthFunctionality(t *testing.T) {

	//
	type testCase struct {
		hmac   GCryptAuthAlg
		result bool
	}

	//
	key := make([]byte, 128)
	rand.Read(key)
	data := "hello this is a data"

	//
	cases := []testCase{
		{
			hmac:   IANA_AUTH_HMAC_MD5_96,
			result: true,
		},
		{
			hmac:   IANA_AUTH_HMAC_SHA1_96,
			result: true,
		},
		{
			hmac:   IANA_AUTH_HMAC_SHA2_256_128,
			result: true,
		},
		{
			hmac:   IANA_AUTH_HMAC_SHA2_512_256,
			result: true,
		},
		{
			hmac:   IANA_AUTH_HMAC_INVALID,
			result: false,
		},
	}

	//
	for _, c := range cases {
		hmac := createCryptoAuth(c.hmac, key)
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
