package sgx_server

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
)

// SessionManager basically implements (though not exactly) the
// AttestationServer interface, and higher level codes can use it to
// quickly instantiate an AttestationServer. See the server in
// cmd/server for examples on how to do this.
type SessionManager interface {
	GetSession(id uint64) (Session, bool)

	NewSession(in *Request) (*Challenge, error)

	Msg1ToMsg2(msg1 *Msg1) (*Msg2, error)

	Msg3ToMsg4(msg3 *Msg3) (*Msg4, error)
}

type sessionManager struct {
	configuration

	sessions Cache

	ias IAS
}

func NewSessionManager(config *Configuration) SessionManager {
	sessions := make(map[uint64]Session)
	sessions[0] = nil

	configInternal := *parseConfiguration(config)

	sm := &sessionManager{
		configuration: configInternal,

		sessions: NewCache(configInternal.maxSessions),

		ias: NewIAS(configInternal.release, configInternal.subscription, configInternal.allowedAdvisories),
	}

	return sm
}

func (sm *sessionManager) GetSession(id uint64) (Session, bool) {
	return sm.sessions.Get(id)
}

func (sm *sessionManager) NewSession(in *Request) (*Challenge, error) {
	var challenge [32]byte
	n, err := rand.Read(challenge[:])
	if err != nil {
		return nil, err
	} else if n != 32 {
		return nil, errors.New("Could not generate a challenge")
	}

	// Generate a non-zero unique id for the session. 0 is reserved.
	id := uint64(0)
	var bytes [8]byte
	for true {
		_, err := rand.Read(bytes[:])
		if err != nil {
			return nil, err
		}

		id = binary.BigEndian.Uint64(bytes[:])
		if id == 0 {
			continue
		}
		if _, ok := sm.GetSession(id); !ok {
			// Found an unused id for the session.
			break
		}
	}
	log.Println("Creating new session:", id)

	sm.sessions.Set(id, NewSession(id, sm.ias, sm.timeout, sm.mrenclaves, sm.spid, sm.longTermKey))

	return &Challenge{
		SessionId: id,
		Challenge: challenge[:],
	}, nil
}

func (sm *sessionManager) Msg1ToMsg2(msg1 *Msg1) (*Msg2, error) {
	session, ok := sm.GetSession(msg1.SessionId)
	if !ok {
		return nil, errors.New("Session not found")
	}

	// If msgs are invalid, or if we fail to create the message
	// (e.g., due to timeout), then the session is removed from
	// the list.
	err := session.ProcessMsg1(msg1)
	if err != nil {
		sm.sessions.Delete(msg1.SessionId)
		return nil, err
	}

	msg2, err := session.CreateMsg2()
	if err != nil {
		sm.sessions.Delete(msg1.SessionId)
	}

	return msg2, err
}

func (sm *sessionManager) Msg3ToMsg4(msg3 *Msg3) (*Msg4, error) {
	session, ok := sm.GetSession(msg3.SessionId)
	if !ok {
		return nil, errors.New("Session not found")
	}

	// TODO: generate a proper Msg4 if an error happens during msg3.
	err := session.ProcessMsg3(msg3)
	if err != nil {
		sm.sessions.Delete(msg3.SessionId)
		return nil, err
	}

	msg4, err := session.CreateMsg4()
	if err != nil {
		sm.sessions.Delete(msg3.SessionId)
	}

	return msg4, err
}
