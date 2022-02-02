package gcrypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestGCryptoDHFunctionality(t *testing.T) {

	//
	type testCase struct {
		group          GCryptoDH
		expectedResult bool
	}

	//test group functions
	testGroup := func(g GCryptoDH) error {
		dh1 := createCryptoDH(g)
		dh2 := createCryptoDH(g)

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
