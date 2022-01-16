package ike

import (
	"encoding/binary"
	"sync"
	"time"
)

//---------------------------------------------------------------------------------------

type IKESessionManagerConfig struct {
	halfOpenSessionsLifeTime int64
	inactiveSessionsLifeTime int64
	removedSessionsLifeTime  int64
}

//---------------------------------------------------------------------------------------

type IKESessionManager struct {
	sessions   map[uint64]IIKESession
	accessLock sync.RWMutex
	config     IKESessionManagerConfig
}

//---------------------------------------------------------------------------------------
func (thisPt *IKESessionManager) createRemoveList(cTime int64) []uint64 {
	removeList := []uint64{}

	thisPt.accessLock.RLock()
	defer thisPt.accessLock.Unlock()

	for k, v := range thisPt.sessions {

		if !v.IsActive() && (cTime-v.GetAccessTime()) > thisPt.config.removedSessionsLifeTime {
			removeList = append(removeList, k)
			continue
		}

		if v.IsHalfOpen() && (cTime-v.GetCreationTime()) > thisPt.config.halfOpenSessionsLifeTime {
			removeList = append(removeList, k)
			continue
		}

		if (cTime - v.GetAccessTime()) > thisPt.config.inactiveSessionsLifeTime {
			removeList = append(removeList, k)
			continue
		}
	}
	return removeList
}

//---------------------------------------------------------------------------------------
func (thisPt *IKESessionManager) getSessionKey(spi []byte, spr []byte) uint64 {
	k1, _ := binary.Uvarint(spi[0:8])
	k2 := uint64(0)
	if spr != nil {
		k2, _ = binary.Uvarint(spr[0:8])
	}
	return (k1 ^ k2)
}

//---------------------------------------------------------------------------------------
func (thisPt *IKESessionManager) Find(spi []byte, spr []byte) IIKESession {
	thisPt.accessLock.RLock()
	defer thisPt.accessLock.RUnlock()

	key := thisPt.getSessionKey(spi, spr)

	if session, fnd := thisPt.sessions[key]; fnd && session.IsActive() {
		return session
	}

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKESessionManager) New(spi []byte, spr []byte) (IIKESession, error) {
	return nil, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *IKESessionManager) Timer(cTime int64) int {
	if cTime == 0 {
		cTime = time.Now().Unix()
	}

	//create remove list
	list := thisPt.createRemoveList(cTime)
	if len(list) == 0 {
		return 0
	}

	//remove items
	thisPt.accessLock.Lock()
	for _, k := range list {
		delete(thisPt.sessions, k)
	}
	thisPt.accessLock.Unlock()
	return len(list)
}

//---------------------------------------------------------------------------------------
