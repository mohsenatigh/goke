package gcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/ebfe/brainpool"
)

//---------------------------------------------------------------------------------------
type cryptoDH struct {
	group      GCryptoDH
	privateKey *ecdsa.PrivateKey
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoDH) generatePrivateKey() error {
	c, _ := thisPt.getCurve()
	if thisPt.privateKey == nil {
		//get curve
		if c == nil {
			return fmt.Errorf("invalid DH group %d ", thisPt.group)
		}

		//serialize public key and keep private key
		key, err := ecdsa.GenerateKey(c, crand.Reader)
		if err != nil {
			return err
		}
		thisPt.privateKey = key
	}
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoDH) getCurve() (elliptic.Curve, int) {
	switch thisPt.group {
	case IANA_DH_GROUP_19:
		return elliptic.P256(), 32
	case IANA_DH_GROUP_20:
		return elliptic.P384(), 48
	case IANA_DH_GROUP_27:
		return brainpool.P224r1(), 28
	case IANA_DH_GROUP_28:
		return brainpool.P256r1(), 32
	case IANA_DH_GROUP_29:
		return brainpool.P384r1(), 48
	case IANA_DH_GROUP_30:
		return brainpool.P512r1(), 64
	}
	return nil, 0
}

//---------------------------------------------------------------------------------------
//
func (thisPt *cryptoDH) ComputeKey(peerPublicKey []byte) ([]byte, error) {

	pubKey := ecdsa.PublicKey{}
	curve, keyLen := thisPt.getCurve()
	if curve == nil {
		return nil, errors.New("invalid peer public key")
	}

	//read
	reader := bytes.NewReader(peerPublicKey)

	x := make([]byte, keyLen)
	y := make([]byte, keyLen)

	if n, err := reader.Read(x); err != nil || n != len(x) {
		return nil, errors.New("invalid public key")
	}

	if n, err := reader.Read(y); err != nil || n != len(y) {
		return nil, errors.New("invalid public key")
	}

	pubKey.Curve = curve
	pubKey.X = new(big.Int).SetBytes(x)
	pubKey.Y = new(big.Int).SetBytes(y)

	//recheck private key
	if err := thisPt.generatePrivateKey(); err != nil {
		return nil, err
	}

	key, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, thisPt.privateKey.D.Bytes())
	return key.Bytes(), nil
}

//---------------------------------------------------------------------------------------
//
func (thisPt *cryptoDH) GetPublicKey() ([]byte, error) {

	//
	if err := thisPt.generatePrivateKey(); err != nil {
		return nil, err
	}

	//
	outBuf := bytes.NewBuffer(nil)
	outBuf.Write(thisPt.privateKey.PublicKey.X.Bytes())
	outBuf.Write(thisPt.privateKey.PublicKey.Y.Bytes())

	return outBuf.Bytes(), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoDH) GetGroup() int {
	return int(thisPt.group)
}

//---------------------------------------------------------------------------------------
func createCryptoDH(hType GCryptoDH) IGCryptoDH {
	h := &cryptoDH{group: hType}
	return h
}
