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

type cryptoHmac struct {
	hmacType GCryptHmacAlg
	key      []byte
	hmac     hash.Hash
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) getHashFunc() func() hash.Hash {
	switch thisPt.hmacType {
	case IANA_PRF_HMAC_MD5:
		return md5.New
	case IANA_PRF_HMAC_SHA1:
		return sha1.New
	case IANA_PRF_HMAC_SHA2_256:
		return sha256.New
	case IANA_PRF_HMAC_SHA2_512:
		return sha512.New
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) Start() error {
	fnc := thisPt.getHashFunc()
	if fnc == nil {
		return errors.New("invalid HMAC function")
	}
	thisPt.hmac = hmac.New(fnc, thisPt.key)
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) Write(buffer []byte) error {
	if _, err := thisPt.hmac.Write(buffer); err != nil {
		return err
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) Final() []byte {
	return thisPt.hmac.Sum(nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) GetHMAC(buffer []byte) ([]byte, error) {
	if err := thisPt.Start(); err != nil {
		return nil, err
	}
	if err := thisPt.Write(buffer); err != nil {
		return nil, err
	}
	return thisPt.Final(), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) GetLen() int {
	return thisPt.hmac.Size()
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) SetKey(key []byte) {
	thisPt.key = make([]byte, len(key))
	copy(thisPt.key, key)
}

//---------------------------------------------------------------------------------------

func createCryptoHMAC(hType GCryptHmacAlg, key []byte) IGCryptoHMAC {
	h := &cryptoHmac{
		hmacType: hType,
	}

	if key != nil {
		h.SetKey(key)
	}

	return h
}
