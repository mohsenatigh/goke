package gcrypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

type cryptoAuth struct {
	hmacType GCryptAuthAlg
	key      []byte
	hmac     hash.Hash
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoAuth) getHashFunc() func() hash.Hash {
	switch thisPt.hmacType {
	case IANA_AUTH_HMAC_MD5_96:
		return md5.New
	case IANA_AUTH_HMAC_SHA1_96:
		return sha1.New
	case IANA_AUTH_HMAC_SHA2_256_128:
		return sha256.New
	case IANA_AUTH_HMAC_SHA2_512_256:
		return sha512.New
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoAuth) Start() error {
	fnc := thisPt.getHashFunc()
	if fnc == nil {
		return errors.New("invalid Authentication function")
	}
	thisPt.hmac = hmac.New(fnc, thisPt.key)
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoAuth) Write(buffer []byte) error {
	if _, err := thisPt.hmac.Write(buffer); err != nil {
		return err
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoAuth) Final() []byte {
	return thisPt.hmac.Sum(nil)[0:thisPt.hmacType.Size()]
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoAuth) GetHMAC(buffer []byte) ([]byte, error) {
	if err := thisPt.Start(); err != nil {
		return nil, err
	}
	if err := thisPt.Write(buffer); err != nil {
		return nil, err
	}
	return thisPt.Final(), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoAuth) GetLen() int {
	return thisPt.hmacType.Size()
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoAuth) SetKey(key []byte) {
	thisPt.key = make([]byte, len(key))
	copy(thisPt.key, key)
}

//---------------------------------------------------------------------------------------

func createCryptoAuth(hType GCryptAuthAlg, key []byte) IGCryptoAuth {
	h := &cryptoAuth{
		hmacType: hType,
	}

	if key != nil {
		h.SetKey(key)
	}

	return h
}
