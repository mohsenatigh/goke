package gcrypto

import "testing"

func TestGCryptoAlgParser(t *testing.T) {

	type testInputs struct {
		pattern string
		result  bool
	}

	//check result
	checkResult := func(val string) bool {
		res, err := ParseAlgorithm(val)
		if err != nil {
			return false
		}
		if !res.DhGroup.Validate() ||
			!res.EncAlg.Validate(res.EncKeyLen) ||
			!res.IntAlg.Validate() ||
			!res.Prf.Validate() {
			return false
		}
		return true
	}

	testCases := []testInputs{
		{GetDefaultIKEAlgorithmString(), true},
		{GetDefaultESPAlgorithmString(), true},

		//invalid pattern
		{"", false},
		{"invalid", false},
		{"enc:aes-128,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh", false},
		{"enc:aes-128,auth:hmac_sha2_256_128,prf:hmac_sha2_256,ch:group20", false},

		//invalid  test
		{"enc:aes-100,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh:group20", false},
		{"enc:aes,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh:group20", false},
		{"enc:des-64,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh:group20", false},

		//invalid auth
		{"enc:aes-128,auth:hmac_sha2_256_256,prf:hmac_sha2_256,dh:group20", false},
		{"enc:aes-128,auth:hmac_sha2_256,prf:hmac_sha2_256,dh:group20", false},

		//invalid hmac
		{"enc:aes-128,auth:hmac_sha2_256_128,prf:hmac_sha3,dh:group20", false},

		//invalid dh
		{"enc:aes-128,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh:group10", false},
	}

	for _, c := range testCases {
		if checkResult(c.pattern) != c.result {
			t.FailNow()
		}
	}
}
