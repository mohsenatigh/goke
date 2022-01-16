package gcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"errors"
)

type cryptoCipher struct {
	cipherType int
	iv         [32]byte
	key        []byte
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) getCipher(key []byte) (cipher.Block, error) {
	switch thisPt.cipherType {
	case GCRYPTO_CIPHER_AES128:
	case GCRYPTO_CIPHER_AES192:
	case GCRYPTO_CIPHER_AES256:
		return aes.NewCipher(key)
	}
	return nil, errors.New("invalid cipher")
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) Encrypt(in []byte, out []byte, iv []byte) error {
	c, err := thisPt.getCipher(thisPt.key)
	if err != nil {
		return err
	}
	blockMode := cipher.NewCBCEncrypter(c, iv)
	blockMode.CryptBlocks(out, in)

	//update iv
	blockSize := thisPt.GetIVLen()
	copy(thisPt.iv[:blockSize], out[:blockSize])
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) Decrypt(in []byte, out []byte, iv []byte) error {
	c, err := thisPt.getCipher(thisPt.key)
	if err != nil {
		return err
	}
	blockMode := cipher.NewCBCDecrypter(c, iv)
	blockMode.CryptBlocks(out, in)
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetIVLen() int {
	switch thisPt.cipherType {
	case GCRYPTO_CIPHER_AES128:
	case GCRYPTO_CIPHER_AES192:
	case GCRYPTO_CIPHER_AES256:
		return aes.BlockSize
	}
	return 0
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetKeyLen() int {
	switch thisPt.cipherType {
	case GCRYPTO_CIPHER_AES128:
		return 16
	case GCRYPTO_CIPHER_AES192:
		return 24
	case GCRYPTO_CIPHER_AES256:
		return 32
	}
	return 0
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetBlockLen() int {
	return thisPt.GetIVLen()
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetPadLen(bufferSize int) int {
	blockSize := thisPt.GetBlockLen()
	return (blockSize - (bufferSize % blockSize))
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetIV() []byte {
	blockSize := thisPt.GetBlockLen()
	return thisPt.iv[:blockSize]
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) SetKey(key []byte) {
	thisPt.key = make([]byte, len(key))
	copy(thisPt.key, key)
}

//---------------------------------------------------------------------------------------
func createCryptoCipher(cType int, key []byte) IGCryptoCipher {
	h := &cryptoCipher{
		cipherType: cType,
	}
	crand.Read(h.iv[:])
	if key != nil {
		h.SetKey(key)
	}
	return h
}
