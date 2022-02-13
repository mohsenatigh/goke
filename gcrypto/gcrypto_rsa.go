package gcrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"strings"
)

//---------------------------------------------------------------------------------------
type cryptoRSA struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) loadCertDer(data []byte) error {
	der, err := x509.ParseCertificate(data)
	if err != nil {
		log.Println(err)
		return err
	}
	thisPt.certificate = der
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) loadCertData(keyValue []byte) error {
	block, _ := pem.Decode(keyValue)
	return thisPt.loadCertDer(block.Bytes)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) loadCert(fName string) error {
	if strings.Contains(fName, "-----BEGIN CERTIFICATE-----") {
		return thisPt.loadCertData([]byte(fName))
	}

	keyValue, err := ioutil.ReadFile(fName)
	if err != nil {
		return err
	}
	return thisPt.loadCertData(keyValue)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) loadPrivateKeyData(keyValue []byte) error {
	block, _ := pem.Decode(keyValue)
	der, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	thisPt.privateKey = der
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) loadPrivateKey(fName string) error {
	//first try to read from the file
	if strings.Contains(fName, "-----BEGIN RSA PRIVATE KEY-----") {
		return thisPt.loadPrivateKeyData([]byte(fName))
	}

	//load from file
	keyValue, err := ioutil.ReadFile(fName)
	if err != nil {
		return err
	}
	return thisPt.loadPrivateKeyData(keyValue)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) GetDER() []byte {
	return thisPt.certificate.Raw
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) Sign(data []byte) ([]byte, error) {
	//sha result
	shaRes := sha1.Sum(data)
	bodyHash, err := rsa.SignPKCS1v15(rand.Reader, thisPt.privateKey, crypto.SHA1, shaRes[:])
	if err != nil {
		return nil, err
	}
	return bodyHash, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) Verify(msg []byte, sig []byte) error {
	shaRes := sha1.Sum(msg)
	return rsa.VerifyPKCS1v15(thisPt.certificate.PublicKey.(*rsa.PublicKey), crypto.SHA1, shaRes[:], sig)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) GetCertSubjectInfoKeyID() []byte {
	res := sha1.Sum(thisPt.certificate.RawSubjectPublicKeyInfo)
	return res[:]
}

//---------------------------------------------------------------------------------------

func cryptoCreateRSA(pkey string, publicKey string) IGCryptoRSA {
	k := &cryptoRSA{}

	if len(pkey) > 0 && k.loadPrivateKey(pkey) != nil {
		return nil
	}

	if len(publicKey) > 0 && k.loadCert(publicKey) != nil {
		return nil
	}

	return k
}

//---------------------------------------------------------------------------------------

func cryptoCreateRSAByDER(publicKey []byte) IGCryptoRSA {
	k := &cryptoRSA{}
	if err := k.loadCertDer(publicKey); err != nil {
		return nil
	}
	return k
}
