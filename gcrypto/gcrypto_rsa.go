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
		return nil
	}
	thisPt.certificate = der
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) loadCert(fName string) error {
	keyValue, err := ioutil.ReadFile(fName)
	if err != nil {
		log.Println(err)
		return nil
	}
	block, _ := pem.Decode(keyValue)
	return thisPt.loadCertDer(block.Bytes)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) loadPrivateKey(fName string) error {
	keyValue, err := ioutil.ReadFile(fName)
	if err != nil {
		log.Println(err)
		return nil
	}
	block, _ := pem.Decode(keyValue)
	der, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Println(err)
		return nil
	}
	thisPt.privateKey = der
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) GetDER() []byte {
	return x509.MarshalPKCS1PublicKey(thisPt.certificate.PublicKey.(*rsa.PublicKey))
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
func (thisPt *cryptoRSA) GetCertSubjectKeyID() []byte {
	return thisPt.certificate.SubjectKeyId
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoRSA) GetCertSubjectInfoKeyID() []byte {
	return thisPt.certificate.RawSubjectPublicKeyInfo
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
