package sgx_server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// SessionManager keeps records of different SGX sessions with
// different clients using session ids. Note that even though
// NewSession returns the user the session ID, it is *NOT* included in
// the client's subsequent messages to the server. This is because the
// clients are expected to include the ID in the metadata of the gRPC
// call. The AttestationServer interface, which this interface almost
// implements, is reponsible for parsing the metadata. See the server
// in cmd/example_server on how to do this.
type SessionManager interface {
	// GetSession returns (Session, true) if there exists a
	// session that matches id. Otherwise, it returns
	// (nil, false).
	GetSession(id string) (Session, bool)

	// NewSession creates a new session. This generates a new
	// unique session id for the session, and returns the id
	// and a random challenge.
	NewSession(in *Request) (*Challenge, error)

	// Msg1ToMsg3 processes SGX message 1 and generates SGX
	// message 2 for the session matching id.
	Msg1ToMsg2(id string, msg1 *Msg1) (*Msg2, error)

	// Msg3ToMsg4 processes SGX message 3 and generates SGX
	// message 4 for the session matching id.
	Msg3ToMsg4(id string, msg3 *Msg3) (*Msg4, error)
}

type sessionManager struct {
	configuration
	sessions Cache
	ias      IAS
}

// NewSessionManager creates a simple SessionManager with LRU cache
// policy using the configuration.
func NewSessionManager(config *Configuration) SessionManager {
	configInternal := *parseConfiguration(config)
	sm := &sessionManager{
		configuration: configInternal,
		sessions:      NewSimpleLRUCache(configInternal.maxSessions),
		ias:           NewIAS(configInternal.release, configInternal.subscription, configInternal.allowedAdvisories),
	}

	return sm
}

func (sm *sessionManager) GetSession(id string) (Session, bool) {
	return sm.sessions.Get(id)
}

func (sm *sessionManager) NewSession(in *Request) (*Challenge, error) {
	// With 16 byte random ids, we should never run into collisions in IDs.
	var bytes [16]byte
	_, err := rand.Read(bytes[:])
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(bytes[:])

	sm.sessions.Set(id, NewSession(id, sm.release, sm.timeout, sm.ias, sm.mrenclaves, sm.mrsigners, sm.spid, sm.longTermKey, sm.prodID, sm.prodSVN))

	return &Challenge{
		SessionId: id,
	}, nil
}

func (sm *sessionManager) Msg1ToMsg2(id string, msg1 *Msg1) (*Msg2, error) {
	session, ok := sm.GetSession(id)
	if !ok {
		return nil, errors.New("Session not found")
	}

	// If msgs are invalid, or if we fail to create the message
	// (e.g., due to timeout), then the session is removed from
	// the list.
	err := session.ProcessMsg1(msg1)
	if err != nil {
		sm.sessions.Delete(id)
		return nil, err
	}

	msg2, err := session.CreateMsg2()
	if err != nil {
		sm.sessions.Delete(id)
	}

	return msg2, err
}

func (sm *sessionManager) Msg3ToMsg4(id string, msg3 *Msg3) (*Msg4, error) {
	session, ok := sm.GetSession(id)
	if !ok {
		return nil, errors.New("Session not found")
	}

	// TODO: generate a proper Msg4 if an error happens during msg3.
	err := session.ProcessMsg3(msg3)
	if err != nil {
		sm.sessions.Delete(id)
		return nil, err
	}

	msg4, err := session.CreateMsg4()
	if err != nil || !session.Authenticated() {
		sm.sessions.Delete(id)
	}
	return msg4, err
}
