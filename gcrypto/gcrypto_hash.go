package gcrypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

//---------------------------------------------------------------------------------------
type cryptoHash struct {
	hashType int
	hash     hash.Hash
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHash) getHasher() hash.Hash {
	switch thisPt.hashType {
	case GCRYPTO_HASH_TYPE_MD5:
		return md5.New()
	case GCRYPTO_HASH_TYPE_SHA1:
		return sha1.New()
	case GCRYPTO_HASH_TYPE_SHA256:
		return sha256.New()
	case GCRYPTO_HASH_TYPE_SHA512:
		return sha512.New()
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHash) Start() error {
	thisPt.hash = thisPt.getHasher()
	if thisPt.hash == nil {
		return errors.New("invalid hash function")
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHash) Write(buffer []byte) error {
	if _, err := thisPt.hash.Write(buffer); err != nil {
		return err
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHash) Final() []byte {
	out := make([]byte, 64)
	res := thisPt.hash.Sum(nil)
	copy(out, res[:])
	return out[:thisPt.hash.Size()]
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoHash) GetHash(in []byte) []byte {
	if thisPt.Start() != nil {
		return nil
	}
	thisPt.Write(in)
	return thisPt.Final()
}

//---------------------------------------------------------------------------------------
func createCryptoHash(hType int) IGCryptoHash {
	h := &cryptoHash{
		hashType: hType,
	}
	return h
}

//---------------------------------------------------------------------------------------
