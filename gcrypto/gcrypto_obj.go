package gcrypto

import (
	"bytes"
	"crypto/rand"
)

//---------------------------------------------------------------------------------------
type cryptoObj struct {
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetHMAC(hType GCryptHmacAlg, key []byte) IGCryptoHMAC {
	return createCryptoHMAC(hType, key)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetHash(hType GCryptHashAlg) IGCryptoHash {
	return createCryptoHash(hType)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetAuth(hType GCryptAuthAlg, key []byte) IGCryptoAuth {
	return createCryptoAuth(hType, key)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetCipher(sType GCryptCipherAlg, key []byte) IGCryptoCipher {
	return createCryptoCipher(sType, key)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetDH(group GCryptoDH) IGCryptoDH {
	return createCryptoDH(group, nil)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetCA(cert string) IGCryptoCAInfo {
	return cryptoCreateCAInfo(cert)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetRSA(privateKey string, cert string) IGCryptoRSA {
	return cryptoCreateRSA(privateKey, cert)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GetRSAByDer(der []byte) IGCryptoRSA {
	return cryptoCreateRSAByDER(der)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) CalculatePRFPlus(body []byte, hmacObj IGCryptoHMAC) []byte {
	const round = 128
	out := bytes.NewBuffer(nil)
	t := bytes.NewBuffer(nil)
	for i := 1; i <= round; i++ {
		tempBuffer := bytes.NewBuffer(nil)
		tempBuffer.Write(t.Bytes())
		tempBuffer.Write(body)
		tempBuffer.WriteByte(byte(i))
		hmacRes, _ := hmacObj.GetHMAC(tempBuffer.Bytes())
		t.Reset()
		t.Write(hmacRes)
		out.Write(hmacRes)
	}
	return out.Bytes()
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoObj) GenerateRandom(len int) []byte {
	rBuf := make([]byte, len)
	rand.Read(rBuf)
	return rBuf
}

//---------------------------------------------------------------------------------------
func CreateCryptoObject() IGCrypto {
	return &cryptoObj{}
}
