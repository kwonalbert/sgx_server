package sgx_server

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path"
)

type Configuration struct {
	// If true, the session manager will start in release mode,
	// meaning it will connect to the production version of IAS.
	Release bool

	// The subscription key for IAS API. This can be found at
	// https://api.portal.trustedservices.intel.com
	Subscription string

	// The directory that contains all the MREnclave files
	// that are acceptable for this session manager.
	Mrenclaves string

	// Hex encoded SPID for IAS API. This can be found at
	// https://api.portal.trustedservices.intel.com
	Spid string

	// The file that contains a PEM encoded long-term ECDSA P-256
	// (SECP256R1) private key for establishing the session. The
	// public key component of this key should be built-in to the
	// client enclave.
	LongTermKey string

	// If True, then it will either prompt the user to type in the
	// password, or use LongTermKeyPassword field to decrypt the
	// long term key.
	LongTermKeyEncrypted bool

	// If LongTermKeyEncrypted is true, and this password is set
	// to an empty string, the program will prompt user for
	// input. Otherwise, LongTermKeyPassword is used as the
	// password.
	LongTermKeyPassword string

	// AllowedAdvisories maps an error during quote verification
	// to which advisories we are allowed to ignore. Current valid
	// keys are: ["CONFIGURATION_NEEDED", "GROUP_OUT_OF_DATE"].
	// Be careful to not set this too liberally.
	AllowedAdvisories map[string][]string

	// The maximum number of concurrent sessions the session
	// manager will keep alive. If MaxSessions is -1, then we
	// allow unlimited number of sessions.
	MaxSessions int

	// A session times out after Timeout minutes.
	// If there is no activity for this session within the past
	// Timeout minutes, the manager will remove the session,
	// and the client will have to reauthenticate itself.
	// If Timeout is -1, then a session will never expire.
	// except if there are more than MaxSessions sessions,
	// then the oldest ones will be removed.
	Timeout int
}

// Internal configuration used to create a session manager.
type configuration struct {
	release           bool
	subscription      string
	mrenclaves        [][MRENCLAVE_SIZE]byte
	spid              []byte
	longTermKey       *ecdsa.PrivateKey
	allowedAdvisories map[string][]string
	maxSessions       int
	timeout           int
}

func readMREnclaves(dir string) [][MRENCLAVE_SIZE]byte {
	mrs, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal("Could not read mrenclaves directory:", err)
	}

	mrenclaves := make([][MRENCLAVE_SIZE]byte, len(mrs))
	for i, mr := range mrs {
		if mr.Name() == ".gitignore" {
			continue
		}

		mhex, err := ioutil.ReadFile(path.Join(dir, mr.Name()))
		if err != nil {
			log.Fatal("Could not read the mrenclave.")
		}
		mrenclave := make([]byte, hex.DecodedLen(len(mhex)))
		l, err := hex.Decode(mrenclave, mhex)
		if err != nil {
			log.Fatal("Could not parse the hex mrenclave.")
		}
		if l != MRENCLAVE_SIZE {
			log.Fatal("MREnclave file should contain 32 bytes, but instead got", l)
		}

		copy(mrenclaves[i][:], mrenclave[:])
	}
	return mrenclaves
}

func readSPID(shex string) []byte {
	spid := make([]byte, hex.DecodedLen(len(shex)))
	l, err := hex.Decode(spid, []byte(shex))
	if err != nil {
		log.Fatal("Could not parse the hex spid:", err)
	} else if l != 16 {
		log.Fatal("SPID files should contain 16 bytes, but instead got", l)
	}
	return spid
}

func parseConfiguration(config *Configuration) *configuration {
	passwd := ""
	if config.LongTermKeyEncrypted {
		if config.LongTermKeyPassword != "" {
			passwd = config.LongTermKeyPassword
		} else {
			// TODO: read the password
		}
	}

	return &configuration{
		release:           config.Release,
		subscription:      config.Subscription,
		mrenclaves:        readMREnclaves(config.Mrenclaves),
		spid:              readSPID(config.Spid),
		longTermKey:       loadPrivateKey(config.LongTermKey, passwd),
		allowedAdvisories: config.AllowedAdvisories,
		maxSessions:       config.MaxSessions,
		timeout:           config.Timeout,
	}
}

// ReadConfiguration parses the configuration file, and generates the
// internal configuration to initialize the session manager.
// It will fail with log.Fatal if it could not parse the config.
func ReadConfiguration(fileName string) *Configuration {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal("Could not open configuration file:", err)
	}
	defer file.Close()

	config := &Configuration{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		log.Fatal("Could not json decode the config file:", err)
	}

	return config
}
