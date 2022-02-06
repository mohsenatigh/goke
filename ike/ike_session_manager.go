package ike

import (
	"bytes"
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
func (thisPt *ikeSessionManager) checkSPI(ispi []byte, rspi []byte) error {
	if len(ispi) != 8 || (rspi != nil && len(rspi) != 8) {
		return errors.New("invalid spi")
	}
	return nil
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
	var k1 uint64
	var k2 uint64
	binary.Read(bytes.NewBuffer(spi), binary.LittleEndian, &k1)
	if spr != nil {
		binary.Read(bytes.NewBuffer(spr), binary.LittleEndian, &k2)
	}
	return (k1 ^ k2)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeSessionManager) GetSessionsCount() int {
	return len(thisPt.sessions)
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeSessionManager) Find(spi []byte, spr []byte) IIKESession {

	if err := thisPt.checkSPI(spi, spr); err != nil {
		return nil
	}

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
func (thisPt *ikeSessionManager) ReIndexSession(session IIKESession, ispi []byte, rspi []byte) error {
	sessionObj := session.(*ikeSession)
	key := thisPt.getSessionKey(ispi, rspi)

	thisPt.accessLock.Lock()
	defer thisPt.accessLock.Unlock()

	if _, fnd := thisPt.sessions[key]; fnd {
		return errors.New("duplicate spi")
	}

	delete(thisPt.sessions, session.GetId())
	sessionObj.initParams.id = key
	thisPt.sessions[key] = sessionObj
	return nil
}

//---------------------------------------------------------------------------------------
func (thisPt *ikeSessionManager) New(initiator bool, ispi []byte, rspi []byte) (IIKESession, error) {

	//
	if err := thisPt.checkSPI(ispi, rspi); err != nil {
		return nil, err
	}

	//
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
	return session, nil
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
	defer thisPt.accessLock.Unlock()

	for _, k := range list {
		delete(thisPt.sessions, k)
	}
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
