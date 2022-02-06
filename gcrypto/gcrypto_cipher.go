package gcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type cryptoCipher struct {
	cipherType GCryptCipherAlg
	key        []byte
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) getCipher(key []byte) (cipher.Block, error) {
	switch thisPt.cipherType {
	case IANA_ENCR_AES_CBC:
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
func (thisPt *cryptoCipher) GetKeyLen() int {
	return len(thisPt.key)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetPadLen(bufferSize int) int {
	blockSize := thisPt.cipherType.BlockSize()
	return (blockSize - (bufferSize % blockSize))
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) SetKey(key []byte) {
	thisPt.key = make([]byte, len(key))
	copy(thisPt.key, key)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetType() GCryptCipherAlg {
	return thisPt.cipherType
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCipher) GetAlg() GCryptCipherAlg {
	return thisPt.cipherType
}

//---------------------------------------------------------------------------------------
func createCryptoCipher(cType GCryptCipherAlg, key []byte) IGCryptoCipher {
	h := &cryptoCipher{
		cipherType: cType,
	}

	if key != nil {
		h.SetKey(key)
	}

	if _, err := h.getCipher(key); err != nil {
		return nil
	}
	return h
}
