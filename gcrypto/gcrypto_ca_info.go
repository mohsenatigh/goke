package gcrypto

import (
	"crypto/x509"
	"encoding/pem"
)

//---------------------------------------------------------------------------------------
type cryptoCAInfo struct {
	certPool *x509.CertPool
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCAInfo) ValidateCert(cert string) bool {
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	return thisPt.ValidateDer(block.Bytes)
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoCAInfo) ValidateDer(der []byte) bool {

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}

	opts := x509.VerifyOptions{
		Roots:         thisPt.certPool,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return false
	}

	return true
}

//---------------------------------------------------------------------------------------
func cryptoCreateCAInfo(rootCa string) IGCryptoCAInfo {
	caInfo := &cryptoCAInfo{certPool: x509.NewCertPool()}
	if !caInfo.certPool.AppendCertsFromPEM([]byte(rootCa)) {
		return nil
	}
	return caInfo
}
