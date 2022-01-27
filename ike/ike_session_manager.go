package ike

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

//---------------------------------------------------------------------------------------

type ikeSessionManagerConfig struct {
	halfOpenSessionsLifeTime int64
	inactiveSessionsLifeTime int64
	removedSessionsLifeTime  int64
}

//---------------------------------------------------------------------------------------

type ikeSessionManager struct {
	sessions   map[uint64]*ikeSession
	accessLock sync.RWMutex
	config     ikeSessionManagerConfig
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeSessionManager) createRemoveList(cTime int64) []uint64 {
	removeList := []uint64{}

	thisPt.accessLock.RLock()
	defer thisPt.accessLock.RUnlock()

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
func (thisPt *ikeSessionManager) getSessionKey(spi []byte, spr []byte) uint64 {
	k1, _ := binary.Uvarint(spi[0:8])
	k2 := uint64(0)
	if spr != nil {
		k2, _ = binary.Uvarint(spr[0:8])
	}
	return (k1 ^ k2)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeSessionManager) Find(spi []byte, spr []byte) IIKESession {
	thisPt.accessLock.RLock()
	defer thisPt.accessLock.RUnlock()

	key := thisPt.getSessionKey(spi, spr)

	if session, fnd := thisPt.sessions[key]; fnd && session.IsActive() {
		session.updateAccessTime()
		return session
	}

	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeSessionManager) New(initiator bool, ispi []byte, rspi []byte) (IIKESession, error) {
	thisPt.accessLock.Lock()
	defer thisPt.accessLock.Unlock()

	//check for duplicate SPI
	key := thisPt.getSessionKey(ispi, rspi)
	if _, fnd := thisPt.sessions[key]; fnd {
		return nil, errors.New("duplicate spi")
	}

	//
	params := ikeSessionInitParameters{
		id:        key,
		iSpi:      ispi,
		rSpi:      rspi,
		initiator: initiator,
	}
	session := createIKESession(&params)
	thisPt.sessions[key] = session
	return nil, nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeSessionManager) Timer(cTime int64) int {
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
func createIKESessionManager(conf *ikeSessionManagerConfig) IIKESessionManager {
	sMan := &ikeSessionManager{
		sessions: make(map[uint64]*ikeSession),
		config:   *conf,
	}
	return sMan
}
