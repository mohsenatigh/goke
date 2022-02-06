package ike

import (
	"testing"
	"time"
)

func TestIKESessionManagerFunctionality(t *testing.T) {

	iSPI := [8]byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
	rSPI := [8]byte{0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x11}
	nullSpi := [8]byte{}

	//
	const (
		removedSessionsLifeTime  = 5
		halfOpenSessionsLifeTime = 10
		inactiveSessionsLifeTime = 20
	)

	//check configuration
	conf := ikeSessionManagerConfig{
		halfOpenSessionsLifeTime: halfOpenSessionsLifeTime,
		inactiveSessionsLifeTime: inactiveSessionsLifeTime,
		removedSessionsLifeTime:  removedSessionsLifeTime,
	}

	//create s
	sm := createIKESessionManager(&conf)

	//create new half open session
	_, err := sm.New(true, iSPI[:], nullSpi[:])
	if err != nil || sm.GetSessionsCount() != 1 {
		t.FailNow()
	}

	//check for duplicate session
	_, err = sm.New(true, iSPI[:], nullSpi[:])
	if err == nil {
		t.FailNow()
	}

	//
	checkSessionRemove := func(elTime int64) {
		if sm.Timer(time.Now().Unix()+elTime+1) != 1 || sm.GetSessionsCount() != 0 {
			t.FailNow()
		}
	}

	//find session
	session := sm.Find(iSPI[:], nullSpi[:])
	if session == nil {
		t.FailNow()
	}

	//
	if sm.ReIndexSession(session, iSPI[:], nullSpi[:]) == nil {
		t.FailNow()
	}

	//check for re-indexing
	if sm.ReIndexSession(session, iSPI[:], rSPI[:]) != nil {
		t.FailNow()
	}

	session = sm.Find(iSPI[:], rSPI[:])
	if session == nil {
		t.FailNow()
	}

	//check for half open sessions remove
	checkSessionRemove(halfOpenSessionsLifeTime)

	//check for full SPI
	session, err = sm.New(true, iSPI[:], rSPI[:])
	if err != nil {
		t.FailNow()
	}
	session.Remove()
	checkSessionRemove(removedSessionsLifeTime)

	//check for inactive sessions remove
	_, err = sm.New(true, iSPI[:], rSPI[:])
	if err != nil {
		t.FailNow()
	}
	checkSessionRemove(inactiveSessionsLifeTime)

	//check for invalid SPI
	if _, err = sm.New(true, nil, nil); err == nil {
		t.FailNow()
	}

	//check for unknown SPI
	if s := sm.Find(rSPI[:], iSPI[:]); s != nil {
		t.FailNow()
	}

	//check for invalid SPI
	if s := sm.Find(nil, nil); s != nil {
		t.FailNow()
	}

	//check dummy remove
	if sm.New(false, iSPI[:], rSPI[:]); sm.Timer(0) != 0 {
		t.FailNow()
	}

}
