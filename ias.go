package sgx_server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	fmt "fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	MIN_IAS_VERSION_NUMBER = 3
)

type IAS interface {
	// GetRevocationList takes in the gid from Msg1 of the SGX
	// attestation, and talks to the IAS to fetch and return the
	// corresponding revocation list.
	GetRevocationList(gid []byte) ([]byte, error)

	// VerifyQuote takes in the SGX platform security property
	// descruotor and the attestation quote from Msg3 of the SGX
	// attestation, and talks to the IAS to request the quote
	// verification. The IAS can return many advisories
	// depending on the quote, which is included in the error
	// returned. Returns if the PSE can be trusted, the platform
	// information blob, and any error during quote verification.
	VerifyQuoteAndPSE(quote, pse []byte) (bool, []byte, error)
}

type ias struct {
	release           bool
	host              string
	subscription      string
	allowedAdvisories map[string][]string
	client            *http.Client
}

// NewIAS creates a service that talks to the Intel Attestation
// Service to download revocation lists and verify quotes. Depending
// on the value of release parameter, the code will talk to the
// development or the production version of IAS. You must also
// provide the subscription string for the correct mode (which can
// be found at https://api.portal.trustedservices.intel.com).
// allowedAdvisories paramter specifies which error-advisory
// combinations are allowed when verifying quotes. This can be
// useful, for example, when trying to allow hyperthreading in SGX,
// which automatically yields misconfigured error.
func NewIAS(release bool, subscription string, allowedAdvisories map[string][]string) IAS {
	host := DEBUG_IAS_HOST
	if release {
		host = IAS_HOST
	}

	client := &http.Client{}

	ias := &ias{
		release:           release,
		host:              host,
		subscription:      subscription,
		allowedAdvisories: allowedAdvisories,
		client:            client,
	}
	return ias
}

func (ias *ias) GetRevocationList(gid []byte) ([]byte, error) {
	// SGX gives gid in little endian, but we need big endian.
	reverse(gid)
	url := ias.host + "/sigrl/" + hex.EncodeToString(gid)
	reverse(gid)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HEADER_SUBSCRIPTION_KEY, ias.subscription)

	resp, err := ias.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("Could not fetch revocation list: %d.", resp.StatusCode))
	}

	dec := base64.NewDecoder(base64.StdEncoding, resp.Body)
	rl, err := ioutil.ReadAll(dec)

	if err != nil {
		return nil, err
	}

	log.Println("Downloaded the revocation list")
	return rl, nil
}

func (ias *ias) verifyResponseSignature(resp *http.Response, body []byte) error {
	// Passing in the body separately, since resp.Body is a Reader
	// which behaves like a stream. if we wanted to pass a Reader type,
	// we'd have to create a new one.
	sig, err := base64.StdEncoding.DecodeString(resp.Header.Get("x-iasreport-signature"))
	if err != nil {
		return err
	}

	unescaped, err := url.QueryUnescape(resp.Header.Get("x-iasreport-signing-certificate"))
	if err != nil {
		return err
	}

	// the first block is the key used to verify the signature.
	// this currently assumes that Intel always returns the right cert,
	// and that we verify Intel's identity when we connect to it via TLS.
	block, _ := pem.Decode([]byte(unescaped))
	if block == nil {
		return errors.New("Failed to get the IAS certificate for signature verification.")
	}
	certs, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	return certs.CheckSignature(x509.SHA256WithRSA, body, sig)
}

// Check if the advisories we got from Intel are allowed.
func (ias *ias) errorAllowed(status string, advisories string) error {
	if status == ISV_OK {
		return nil
	}

	if _, ok := ias.allowedAdvisories[status]; !ok {
		return errors.New(fmt.Sprintf(quoteErr, status))
	}

	// find the list of advisories that we consider critical
	advs := strings.Split(advisories, ",")
	var notAllowed []string
	allowed := ias.allowedAdvisories[status]
	for _, adv := range advs {
		found := false
		for _, good := range allowed {
			if adv == good {
				found = true
			}
		}

		if !found {
			notAllowed = append(notAllowed, adv)
		}
	}

	if len(notAllowed) == 0 {
		// no bad advisories found
		return nil
	} else {
		return errors.New(fmt.Sprintf(quoteErrWithAdvisory, status, strings.Join(notAllowed, ", ")))
	}
}

func (ias *ias) processReport(hexNonce string, quote, pse []byte, resp *http.Response) (bool, []byte, error) {
	if resp.StatusCode != 200 {
		return false, nil, errors.New(fmt.Sprintf("Could not fetch the report: Error code [%d].", resp.StatusCode))
	}

	reportBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}
	report := make(map[string]interface{})
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return false, nil, err
	}

	if int(report["version"].(float64)) < MIN_IAS_VERSION_NUMBER {
		return false, nil, errors.New("IAS version is too old.")
	}

	if hexNonce != report[ISV_NONCE].(string) {
		return false, nil, errors.New("Incorrect nonce from IAS.")
	}

	if err := ias.verifyResponseSignature(resp, reportBytes); err != nil {
		return false, nil, err
	}

	pseHash := sha256.Sum256(pse)
	retPSEHash, err := hex.DecodeString(report[PSE_MANIFEST_HASH].(string))
	if err != nil {
		return false, nil, err
	}
	if !bytes.Equal(pseHash[:], retPSEHash) {
		return false, nil, errors.New("PSE hash mismatch.")
	}

	retQuote, err := base64.StdEncoding.DecodeString(report[ISV_QUOTE_BODY].(string))
	if err != nil {
		return false, nil, err
	}

	// 432 bytes for everything in the quote structure, except for
	// the signature fields.
	if len(retQuote) != 432 || !bytes.Equal(retQuote, quote[:432]) {
		return false, nil, errors.New("Incorrect quote returned from IAS.")
	}

	isvStatus := report[ISV_QUOTE_STATUS].(string)
	pseStatus := report[PSE_MANIFEST_STATUS].(string)

	// Platform information blob is only set on specific errors.
	var pib []byte
	if isvStatus == ISV_GROUP_REVOKED ||
		isvStatus == ISV_GROUP_OUT_OF_DATE ||
		isvStatus == ISV_CONFIGURATION_NEEDED ||
		pseStatus == PSE_OUT_OF_DATE ||
		pseStatus == PSE_REVOKED ||
		pseStatus == PSE_RL_VERSION_MISMATCH {
		pib, err = hex.DecodeString(report[PLATFORM_INFO_BLOB].(string))
		if err != nil {
			return false, nil, err
		}
	}

	err = ias.errorAllowed(isvStatus, resp.Header.Get("advisory-ids"))
	if err != nil {
		return false, pib, err
	}

	switch pseStatus {
	case PSE_OK:
		return true, pib, nil
	default:
		// Currently returns if PSE is trusted or not, but does
		// not throw an error if it's not.
		// TODO: Different errors for different PSE status.
		return false, pib, nil
	}
}

func (ias *ias) VerifyQuoteAndPSE(quote, pse []byte) (bool, []byte, error) {
	url := ias.host + "/report"

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, nil, err
	}

	bodyMap := make(map[string]string)
	hexQuote := base64.StdEncoding.EncodeToString(quote)
	bodyMap[ISV_QUOTE] = hexQuote
	if len(pse) > 0 {
		bodyMap[PSE_MANIFEST] = base64.StdEncoding.EncodeToString(pse)
	}

	hexNonce := hex.EncodeToString(nonce[:])
	bodyMap[ISV_NONCE] = hexNonce

	body := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(bodyMap)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return false, nil, err
	}

	req.Header.Set(HEADER_SUBSCRIPTION_KEY, ias.subscription)
	// need to manually set it to json content type!
	req.Header.Set("Content-Type", "application/json")

	resp, err := ias.client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	return ias.processReport(hexNonce, quote, pse, resp)
}

// URL for the IAS attestation API
const (
	// dev
	DEBUG_IAS_HOST = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3"
	// prod
	IAS_HOST = "https://api.trustedservices.intel.com/sgx/attestation/v3"
)

const (
	HEADER_SUBSCRIPTION_KEY = "Ocp-Apim-Subscription-Key"
)

// fields of the isv returns
const (
	ISV_NONCE      = "nonce"
	ISV_QUOTE      = "isvEnclaveQuote"
	ISV_QUOTE_BODY = "isvEnclaveQuoteBody"
)

// possible errors from quote verification
const (
	ISV_QUOTE_STATUS           = "isvEnclaveQuoteStatus"
	ISV_OK                     = "OK"
	ISV_SIGNATURE_INVALID      = "SIGNATURE_INVALID"
	ISV_GROUP_REVOKED          = "GROUP_REVOKED"
	ISV_KEY_REVOKED            = "KEY_REVOKED"
	ISV_SIGRL_VERSION_MISMATCH = "SIGRL_VERSION_MISMATCH"
	ISV_CONFIGURATION_NEEDED   = "CONFIGURATION_NEEDED"
	ISV_GROUP_OUT_OF_DATE      = "GROUP_OUT_OF_DATE"
)

// fields of pse related things
const (
	PSE_MANIFEST      = "pseManifest"
	PSE_MANIFEST_HASH = "pseManifestHash"

	PSE_MANIFEST_STATUS     = "pseManifestStatus"
	PSE_OK                  = "OK"
	PSE_UNKNOWN             = "UNKNOWN"
	PSE_INVALID             = "INVALID"
	PSE_OUT_OF_DATE         = "OUT_OF_DATE"
	PSE_REVOKED             = "REVOKED"
	PSE_RL_VERSION_MISMATCH = "RL_VERSION_MISMATCH"
)

const (
	PLATFORM_INFO_BLOB = "platformInfoBlob"
)

// possible error strings from ias
const (
	quoteErr             = "Quote verification returned unallowed error [%s]."
	quoteErrWithAdvisory = "Quote verification returned [%s] with unallowed advisories [%s]."
)
