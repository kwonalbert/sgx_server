package sgx_server

import "net/http"

type IAS struct {
	release bool
	host    string
	client  *http.Client
}

const DEBUG_IAS_HOST = "test-as.sgx.trustedservices.intel.com" // dev
const IAS_HOST = "as.sgx.trustedservices.intel.com"            // production

func NewIAS(release bool, iasKey, iasPub string) *IAS {
	host := DEBUG_IAS_HOST
	if release {
		host = IAS_HOST
	}
	ias := &IAS{
		release: release,
		host:    host,
	}
	return ias
}

func (ias *IAS) GetRevocationList(gid []byte) (int, []byte, error) {
	return 0, []byte{}, nil
}

func (ias *IAS) VerifyQuote(quote []byte) (bool, error) {
	return true, nil
}
