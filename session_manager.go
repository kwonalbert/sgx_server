package sgx_server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"sync"
)

// SessionManager basically implements the AttestationServer interface,
// and higher level codes can use it to quickly instantiate an AttestationServer.
type SessionManager struct {
	sessions map[uint64]*Session
	sLock    *sync.RWMutex

	mrenclaves  [][32]byte
	spid        []byte
	longTermKey *ecdsa.PrivateKey
	ias         *IAS
}

func NewSessionManager(release bool, subscription string, mrenclaves [][32]byte, spid []byte, longTermKey *ecdsa.PrivateKey) *SessionManager {
	sessions := make(map[uint64]*Session)
	sessions[0] = nil

	as := &SessionManager{
		sessions: sessions,
		sLock:    new(sync.RWMutex),

		mrenclaves:  mrenclaves,
		spid:        spid,
		longTermKey: longTermKey,
		ias:         NewIAS(release, subscription),
	}
	return as
}

func (as *SessionManager) GetSession(id uint64) (*Session, bool) {
	as.sLock.RLock()
	defer as.sLock.RUnlock()
	session, ok := as.sessions[id]
	return session, ok
}

func (as *SessionManager) NewSession(in *Request) (*Challenge, error) {
	var challenge [32]byte
	n, err := rand.Read(challenge[:])
	if err != nil {
		return nil, err
	} else if n != 32 {
		return nil, errors.New("Could not generate a challenge")
	}

	// generate a unique id for the session
	id := uint64(0)
	var bytes [8]byte
	for true {
		n, err := rand.Read(bytes[:])
		if err != nil {
			return nil, err
		} else if n != 8 {
			return nil, errors.New("Could not generate a session id")
		}

		id = binary.BigEndian.Uint64(bytes[:])
		if _, ok := as.GetSession(id); !ok {
			break
		}
	}
	log.Println("Creating new session:", id)

	as.sLock.Lock()
	as.sessions[id] = NewSession(as.mrenclaves, id, as.spid, as.longTermKey, as.ias)
	as.sLock.Unlock()

	return &Challenge{
		SessionId: id,
		Challenge: challenge[:],
	}, nil
}

func (as *SessionManager) Msg1ToMsg2(msg1 *Msg1) (*Msg2, error) {
	session, ok := as.GetSession(msg1.SessionId)
	if !ok {
		return nil, errors.New("Session not found")
	}

	err := session.ProcessMsg1(msg1)
	if err != nil {
		return nil, err
	}
	return session.CreateMsg2()
}

func (as *SessionManager) Msg3ToMsg4(msg3 *Msg3) (*Msg4, error) {
	session, ok := as.GetSession(msg3.SessionId)
	if !ok {
		return nil, errors.New("Session not found")
	}

	// TODO: generate a proper Msg4 if an error happens during msg3
	err := session.ProcessMsg3(msg3)
	if err != nil {
		return nil, err
	}
	return session.CreateMsg4()
}
