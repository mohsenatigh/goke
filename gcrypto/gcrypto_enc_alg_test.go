package gcrypto

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestGCryptoEncFunctionality(t *testing.T) {

	//
	type testCase struct {
		Alg            GCryptCipherAlg
		KeySize        int
		expectedResult bool
	}

	//
	testCases := []testCase{
		{IANA_ENCR_AES_CBC, 16, true},
		{IANA_ENCR_AES_CBC, 24, true},
		{IANA_ENCR_AES_CBC, 32, true},
		{IANA_ENCR_INVALID, 0, false},
	}

	//
	str := "hello this is a test"

	//
	for _, c := range testCases {

		//create key
		key := make([]byte, c.KeySize)
		rand.Read(key)

		encObj := createCryptoCipher(c.Alg, key)
		if encObj == nil {
			if c.expectedResult {
				t.FailNow()
			}
			continue
		}

		buffer := bytes.NewBuffer(nil)
		buffer.WriteString(str)
		buffer.Write(make([]byte, encObj.GetPadLen(buffer.Len())))

		//make IV
		iv := make([]byte, c.Alg.BlockSize())
		rand.Read(iv)

		//
		out := make([]byte, buffer.Len())
		if encObj.Encrypt(buffer.Bytes(), out, iv) != nil {
			t.FailNow()
		}

		//
		dOut := make([]byte, buffer.Len())
		if encObj.Decrypt(out, dOut, iv) != nil {
			t.FailNow()
		}

		//
		res := string(dOut[:len(str)])
		if res != str {
			t.FailNow()
		}
	}
}
