package sgx_server

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"sync"
)

// SessionManager basically implements (though not exactly) the
// AttestationServer interface, and higher level codes can use it to
// quickly instantiate an AttestationServer. See the server in
// cmd/server for examples on how to do this.
type SessionManager struct {
	configuration

	sessions map[uint64]*Session
	sLock    *sync.RWMutex

	ias *IAS
}

func NewSessionManager(config *configuration) *SessionManager {
	sessions := make(map[uint64]*Session)
	sessions[0] = nil

	sm := &SessionManager{
		configuration: *config,

		sessions: sessions,
		sLock:    new(sync.RWMutex),

		ias: NewIAS(config.release, config.subscription, config.allowedAdvisories),
	}
	return sm
}

func (sm *SessionManager) GetSession(id uint64) (*Session, bool) {
	sm.sLock.RLock()
	defer sm.sLock.RUnlock()
	session, ok := sm.sessions[id]
	return session, ok
}

func (sm *SessionManager) NewSession(in *Request) (*Challenge, error) {
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
		if _, ok := sm.GetSession(id); !ok {
			break
		}
	}
	log.Println("Creating new session:", id)

	sm.sLock.Lock()
	sm.sessions[id] = NewSession(id, sm.ias, sm.mrenclaves, sm.spid, sm.longTermKey)
	sm.sLock.Unlock()

	return &Challenge{
		SessionId: id,
		Challenge: challenge[:],
	}, nil
}

func (sm *SessionManager) Msg1ToMsg2(msg1 *Msg1) (*Msg2, error) {
	session, ok := sm.GetSession(msg1.SessionId)
	if !ok {
		return nil, errors.New("Session not found")
	}

	err := session.ProcessMsg1(msg1)
	if err != nil {
		return nil, err
	}
	return session.CreateMsg2()
}

func (sm *SessionManager) Msg3ToMsg4(msg3 *Msg3) (*Msg4, error) {
	session, ok := sm.GetSession(msg3.SessionId)
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
