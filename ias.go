package sgx_server

import (
	"encoding/hex"
	"net/http"
)

type IAS struct {
	release      bool
	host         string
	subscription string
	client       *http.Client
}

// dev
const DEBUG_IAS_HOST = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3/sigrl/"

// prod
const IAS_HOST = "https://api.trustedservices.intel.com/sgx/attestation/v3/sigrl/"

func NewIAS(release bool, subscription string) *IAS {
	host := DEBUG_IAS_HOST
	if release {
		host = IAS_HOST
	}

	client := &http.Client{}

	ias := &IAS{
		release:      release,
		host:         host,
		subscription: subscription,
		client:       client,
	}
	return ias
}

func (ias *IAS) GetRevocationList(gid []byte) (int, []byte, error) {
	// sgx gives gid in little endian, but we need big endian
	reverse(gid)
	url := ias.host + hex.EncodeToString(gid)
	reverse(gid)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return -1, nil, err
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", ias.subscription)

	_, err = ias.client.Do(req)
	if err != nil {
		return -1, nil, err
	}

	return 0, []byte{}, nil
}

func (ias *IAS) VerifyQuote(quote []byte) (bool, error) {
	return true, nil
}
