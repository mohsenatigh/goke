package gcrypto

import "testing"

func TestGCryptoCAInfoFunctionality(t *testing.T) {

	if cryptoCreateCAInfo("GARBAGE") != nil {
		t.FailNow()
	}

	caInfo := cryptoCreateCAInfo(TEST_CA_CERTIFICATE)
	if caInfo == nil {
		t.FailNow()
	}

	if !caInfo.ValidateCert(TEST_SERVER_CERTIFICATE) {
		t.FailNow()
	}

	if !caInfo.ValidateCert(TEST_CLIENT_CERTIFCATE) {
		t.FailNow()
	}

	if caInfo.ValidateCert(TEST_CA2_CERTIFICATE) {
		t.FailNow()
	}
}
