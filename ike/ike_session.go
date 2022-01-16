package ike

import (
	"time"

	"github.com/mohsenatigh/goke/gcrypto"
)

type IKESessionInitParameters struct {
	id        uint64
	iSpi      []byte
	rSpi      []byte
	initiator bool
}

//---------------------------------------------------------------------------------------
type ikeSession struct {
	initParams   IKESessionInitParameters
	removed      bool
	removeTime   int64
	creationTime int64
	accessTime   int64
	localNonce   []byte
	remoteNonce  []byte
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetId() uint64 {
	return thisPT.initParams.id
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) IsInitiator() bool {
	return thisPT.initParams.initiator
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) Remove() {
	thisPT.removeTime = time.Now().Unix()
	thisPT.removed = true
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) IsActive() bool {
	return thisPT.removed
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) IsHalfOpen() bool {
	return thisPT.initParams.rSpi == nil
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetCreationTime() int64 {
	return thisPT.creationTime
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetAccessTime() int64 {
	return thisPT.accessTime
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetLocalNonce(nonce []byte) {
	thisPT.localNonce = make([]byte, len(nonce))
	copy(thisPT.localNonce, nonce)
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetRemoteNonce(nonce []byte) {
	thisPT.remoteNonce = make([]byte, len(nonce))
	copy(thisPT.remoteNonce, nonce)
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetInitiatorNonce() []byte {
	if thisPT.IsInitiator() {
		return thisPT.localNonce
	}
	return thisPT.remoteNonce
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetResponderNonce() []byte

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetMyNonce() []byte

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPeerNonce() []byte

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetDHInfo() gcrypto.IGCryptoDH

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetDHInfo(gcrypto.IGCryptoDH)

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetInitiatorSPI() []byte

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetResponderSPI() []byte

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPhase1KeyInfo() *IKEPhase1KeyInfo

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPhase2KeyInfo() *IKEPhase2KeyInfo

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetFlag(int)

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) HaveFlag(int) bool

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPrevPacket() []byte

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetPrevPacket([]byte)

//---------------------------------------------------------------------------------------
func createIKESession(params *IKESessionInitParameters) IIKESession {
	session := &ikeSession{
		initParams: *params,
	}
	return session
}

//---------------------------------------------------------------------------------------
