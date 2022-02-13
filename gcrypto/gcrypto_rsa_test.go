package gcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestGCryptoRSAFunctionality(t *testing.T) {

	//test signing
	testBuffer := make([]byte, 256)
	rand.Read(testBuffer)

	rsaPrivate := cryptoCreateRSA(TEST_CLIENT_PRIVATE_KEY, "")
	sOut, err := rsaPrivate.Sign(testBuffer)
	if err != nil {
		t.FailNow()
	}

	rsaPublic := cryptoCreateRSA("", TEST_CLIENT_CERTIFCATE)
	if rsaPublic.Verify(testBuffer, sOut) != nil {
		t.FailNow()
	}

	//test der formating
	derData := rsaPublic.GetDER()
	if rsaPublic = cryptoCreateRSAByDER(derData); rsaPublic == nil {
		t.FailNow()
	}

	//check ID
	id := rsaPublic.GetCertSubjectInfoKeyID()
	if hex.EncodeToString(id) != "59d2b000eeaec6c8bcca45fb429e26b303cc096d" {
		t.FailNow()
	}

	if rsaPublic.Verify(testBuffer, sOut) != nil {
		t.FailNow()
	}

	//check for malformed certs
	if cryptoCreateRSA("GARBAGE", "") != nil {
		t.FailNow()
	}

	if cryptoCreateRSA("", "GARBAGE") != nil {
		t.FailNow()
	}

}
