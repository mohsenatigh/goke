package gcrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/ebfe/brainpool"
)

//---------------------------------------------------------------------------------------
type cryptoDH struct {
	group      GCryptoDH
	privateKey []byte
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoDH) generatePrivateKey(key []byte) error {
	//get curve
	c, keyLen := thisPt.getCurve()
	if c == nil {
		return fmt.Errorf("invalid DH group %d ", thisPt.group)
	}

	if thisPt.privateKey == nil {
		thisPt.privateKey = make([]byte, keyLen)
		if key == nil {
			rand.Read(thisPt.privateKey)
		} else {
			copy(thisPt.privateKey, key)
		}

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
		return nil, errors.New("invalid DH group")
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
	key, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, thisPt.privateKey)
	return key.Bytes(), nil
}

//---------------------------------------------------------------------------------------
//
func (thisPt *cryptoDH) GetPublicKey() ([]byte, error) {
	c, _ := thisPt.getCurve()
	if c == nil {
		return nil, errors.New("invalid DH group")
	}
	//
	outBuf := bytes.NewBuffer(nil)
	x, y := c.ScalarBaseMult(thisPt.privateKey)
	outBuf.Write(x.Bytes())
	outBuf.Write(y.Bytes())
	return outBuf.Bytes(), nil
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoDH) GetGroup() int {
	return int(thisPt.group)
}

//---------------------------------------------------------------------------------------
func createCryptoDH(hType GCryptoDH, key []byte) IGCryptoDH {
	h := &cryptoDH{group: hType}
	h.generatePrivateKey(key)
	return h
}
