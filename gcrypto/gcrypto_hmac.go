package gcrypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"log"
)

type cryptoHmac struct {
	hmacType int
	key      []byte
	hmac     hash.Hash
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) getHashFunc() func() hash.Hash {
	switch thisPt.hmacType {
	case GCRYPTO_HMAC_TYPE_MD5:
		return md5.New
	case GCRYPTO_HMAC_TYPE_SHA1:
		return sha1.New
	case GCRYPTO_HMAC_TYPE_SHA256:
		return sha256.New
	case GCRYPTO_HMAC_TYPE_SHA512:
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
	out := make([]byte, 64)
	return thisPt.hmac.Sum(out)
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
	fnc := thisPt.getHashFunc()
	if fnc == nil {
		log.Printf("invalid HMAC function \n")
		return 0
	}
	return fnc().Size()
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHmac) SetKey(key []byte) {
	thisPt.key = make([]byte, len(key))
	copy(thisPt.key, key)
}

//---------------------------------------------------------------------------------------

func createCryptoHMAC(hType int, key []byte) IGCryptoHMAC {
	h := &cryptoHmac{
		hmacType: hType,
	}

	if key != nil {
		h.SetKey(key)
	}

	return h
}
