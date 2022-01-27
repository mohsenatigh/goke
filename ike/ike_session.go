package ike

import (
	"net"
	"sync"
	"time"

	"github.com/mohsenatigh/goke/gcrypto"
)

type ikeSessionInitParameters struct {
	id         uint64
	iSpi       []byte
	rSpi       []byte
	initiator  bool
	localAddr  net.UDPAddr
	remoteAddr net.UDPAddr
}

//---------------------------------------------------------------------------------------
type ikeSession struct {
	initParams    ikeSessionInitParameters
	removed       bool
	removeTime    int64
	creationTime  int64
	accessTime    int64
	localNonce    []byte
	remoteNonce   []byte
	dhInfo        gcrypto.IGCryptoDH
	phase1KeyInfo IKEPhase1KeyInfo
	phase2KeyInfo IKEPhase2KeyInfo
	flags         uint64
	pPacket       []byte
	state         int
	authenticated bool
	lock          sync.Mutex
	localNatAddr  net.UDPAddr
	remoteNatAddr net.UDPAddr
	expectedSeq   uint32
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
func (thisPT *ikeSession) updateAccessTime() {
	thisPT.accessTime = time.Now().Unix()
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
func (thisPT *ikeSession) GetResponderNonce() []byte {
	if thisPT.IsInitiator() {
		return thisPT.remoteNonce
	}
	return thisPT.localNonce
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetMyNonce() []byte {
	return thisPT.localNonce
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPeerNonce() []byte {
	return thisPT.remoteNonce
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetDHInfo() gcrypto.IGCryptoDH {
	return thisPT.dhInfo
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetDHInfo(dh gcrypto.IGCryptoDH) {
	thisPT.dhInfo = dh
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetInitiatorSPI() []byte {
	return thisPT.initParams.iSpi
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetResponderSPI() []byte {
	return thisPT.initParams.rSpi
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPhase1KeyInfo() *IKEPhase1KeyInfo {
	return &thisPT.phase1KeyInfo
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPhase2KeyInfo() *IKEPhase2KeyInfo {
	return &thisPT.phase2KeyInfo
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetFlag(flag uint64) {
	thisPT.flags |= flag
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) HaveFlag(flag uint64) bool {
	return ((thisPT.flags & flag) != 0)
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetPrevPacket() []byte {
	return thisPT.pPacket
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetPrevPacket(pPacket []byte) {
	thisPT.pPacket = make([]byte, len(pPacket))
	copy(thisPT.pPacket, pPacket)
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) Lock() {
	thisPT.lock.Lock()
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) UnLock() {
	thisPT.lock.Unlock()
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetState() int {
	return thisPT.state
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) UpdateState(state int) {
	thisPT.state = state
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetAddr() (*net.UDPAddr, *net.UDPAddr) {
	return &thisPT.initParams.localAddr, &thisPT.initParams.remoteAddr
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetNATAddr() (*net.UDPAddr, *net.UDPAddr) {
	return &thisPT.localNatAddr, &thisPT.remoteNatAddr
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetNATAddr(local *net.UDPAddr, remote *net.UDPAddr) {
	thisPT.localNatAddr = *local
	thisPT.remoteNatAddr = *remote
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) IsEncrypted() bool {
	return thisPT.authenticated
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) SetEncrypted(val bool) {
	thisPT.authenticated = val
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetLocalPhase1Key() *IKEPhase1Key {
	if thisPT.IsInitiator() {
		return &thisPT.phase1KeyInfo.IKey
	}
	return &thisPT.phase1KeyInfo.RKey
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetRemotePhase1Key() *IKEPhase1Key {
	if thisPT.IsInitiator() {
		return &thisPT.phase1KeyInfo.RKey
	}
	return &thisPT.phase1KeyInfo.IKey
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) GetExpectedSeq() uint32 {
	return thisPT.expectedSeq
}

//---------------------------------------------------------------------------------------
func (thisPT *ikeSession) AddExpectedSeq() {
	thisPT.expectedSeq++
}

//---------------------------------------------------------------------------------------
func createIKESession(params *ikeSessionInitParameters) *ikeSession {
	session := &ikeSession{
		initParams:   *params,
		creationTime: time.Now().Unix(),
		accessTime:   time.Now().Unix(),
	}
	return session
}

//---------------------------------------------------------------------------------------
