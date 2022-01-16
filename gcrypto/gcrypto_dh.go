package gcrypto

import (
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
	group      int
	privateKey *ecdsa.PrivateKey
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoDH) getCurve() (elliptic.Curve, int) {
	switch thisPt.group {
	case 19:
		return elliptic.P256(), 32
	case 20:
		return elliptic.P384(), 48
	case 21:
		return elliptic.P521(), 65
	case 27:
		return brainpool.P224r1(), 28
	case 28:
		return brainpool.P256r1(), 32
	case 29:
		return brainpool.P384r1(), 48
	case 30:
		return brainpool.P512r1(), 64
	}
	return nil, 0
}

//---------------------------------------------------------------------------------------
func (thisPt *cryptoDH) GetGroup() int {
	return thisPt.group
}

//---------------------------------------------------------------------------------------
//
func (thisPt *cryptoDH) ComputeKey(peerPublicKey []byte) ([]byte, error) {

	pubKey := ecdsa.PublicKey{}
	curve, keyLen := thisPt.getCurve()
	if curve == nil {
		return nil, nil
	}

	//validate input
	if len(peerPublicKey) != ((keyLen * 2) + 1) {
		return nil, errors.New("invalid peer public key")
	}

	if peerPublicKey[0] != 0x04 {
		return nil, errors.New("invalid peer public key")
	}

	pubKey.Curve = curve
	pubKey.X = new(big.Int).SetBytes(peerPublicKey[1:keyLen])
	pubKey.Y = new(big.Int).SetBytes(peerPublicKey[keyLen+1:])

	x, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, thisPt.privateKey.D.Bytes())
	return x.Bytes(), nil
}

//---------------------------------------------------------------------------------------
//
func (thisPt *cryptoDH) GetPublicKey() ([]byte, error) {
	var c elliptic.Curve
	var keyLen int = 0
	if thisPt.privateKey == nil {
		//get curve
		c, keyLen = thisPt.getCurve()
		if c == nil {
			return nil, fmt.Errorf("invalid DH group %d ", thisPt.group)
		}

		//serialize public key and keep private key
		key, err := ecdsa.GenerateKey(c, crand.Reader)
		if err != nil {
			return nil, err
		}
		thisPt.privateKey = key
	}

	//serialize public key {0x04,x,y}
	xBytes := thisPt.privateKey.PublicKey.X.Bytes()
	yBytes := thisPt.privateKey.PublicKey.Y.Bytes()
	outBuf := make([]byte, (keyLen*2)+1)

	outBuf[0] = 0x04
	copy(outBuf[1:], xBytes)
	copy(outBuf[keyLen+1:], yBytes)

	return outBuf, nil
}

//---------------------------------------------------------------------------------------
func createCryptoDH(hType int) IGCryptoDH {
	h := &cryptoDH{group: hType}
	if _, err := h.GetPublicKey(); err != nil {
		return nil
	}
	return h
}
