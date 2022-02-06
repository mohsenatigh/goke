package gcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestGCryptoDHSerialization(t *testing.T) {

	pubStrExp := "651f95203bbad3d8ead39b8bbfe9254a681a525afc23c0ae2820c2c0bd1f4a99bd62e1b115e6b1a641e71807d75bdcce6c821ce993750f70"
	pKeyData := []byte{
		0x83, 0x0b, 0x92, 0xf4, 0x55, 0x37, 0x8f, 0x06, 0xfe, 0x73,
		0xea, 0x2d, 0x62, 0x3f, 0x30, 0x87, 0x80, 0x78, 0x25, 0xc4,
		0x89, 0xc5, 0x39, 0x6a, 0xde, 0x94, 0xb6, 0x52,
	}

	dh := createCryptoDH(IANA_DH_GROUP_27, pKeyData)
	pub, err := dh.GetPublicKey()
	if err != nil {
		t.FailNow()
	}
	pubStr := hex.EncodeToString(pub)
	if pubStr != pubStrExp {
		t.FailNow()
	}
}

func TestGCryptoDHFunctionality(t *testing.T) {

	//
	type testCase struct {
		group          GCryptoDH
		expectedResult bool
	}

	//test group functions
	testGroup := func(g GCryptoDH) error {
		dh1 := createCryptoDH(g, nil)
		dh2 := createCryptoDH(g, nil)

		pub1, err := dh1.GetPublicKey()
		if err != nil {
			return err
		}

		pub2, err := dh2.GetPublicKey()
		if err != nil {
			return err
		}

		key1, err := dh1.ComputeKey(pub2)
		if err != nil {
			return err
		}

		key2, err := dh2.ComputeKey(pub1)
		if err != nil {
			return err
		}

		if !bytes.Equal(key1, key2) {
			return errors.New("compare failed")
		}

		return nil
	}

	//
	testCases := []testCase{
		{IANA_DH_GROUP_19, true},
		{IANA_DH_GROUP_20, true},
		{IANA_DH_GROUP_27, true},
		{IANA_DH_GROUP_28, true},
		{IANA_DH_GROUP_29, true},
		{IANA_DH_GROUP_30, true},
		{IANA_DH_GROUP_INVALID, false},
	}

	//
	for _, c := range testCases {
		if err := testGroup(c.group); (err == nil) != c.expectedResult {
			t.FailNow()
		}
	}
}
