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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// Intel Attestation Server parameteres.
const (
	// Mininum Intel Attestation Server in the report.
	MIN_IAS_VERSION_NUMBER = 3
)

// IAS communicates with the Intel Attestation Service to provide
// the caller with the revocation list, or the result of verifying
// the enclave quote.
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
	// information blob, a list of security advisories from Intel,
	// and any error during quote verification.
	VerifyQuoteAndPSE(quote, pse []byte) (bool, []byte, []string, error)
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
	reverse(gid) // reverse is an inplace reverse, so reverse it back.
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

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(fmt.Sprintf("Could not fetch revocation list: %d.", resp.StatusCode))
	}

	dec := base64.NewDecoder(base64.StdEncoding, resp.Body)
	rl, err := ioutil.ReadAll(dec)

	if err != nil {
		return nil, err
	}
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

	// The first block is the key used to verify the signature.
	// this currently assumes that Intel always returns the right cert,
	// and that we verified Intel's identity when we connect to it via TLS.
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
func (ias *ias) errorAllowed(status string, advisories []string) error {
	if status == ISV_OK {
		return nil
	}

	if _, ok := ias.allowedAdvisories[status]; !ok {
		return errors.New(fmt.Sprintf(quoteErr, status))
	}

	// find the list of advisories that we consider critical
	var notAllowed []string
	allowed := ias.allowedAdvisories[status]
	for _, adv := range advisories {
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
		// No unallowed advisories found.
		return nil
	} else {
		return errors.New(fmt.Sprintf(quoteErrWithAdvisory, status, strings.Join(notAllowed, ", ")))
	}
}

func (ias *ias) processReport(hexNonce string, quote, pse []byte, resp *http.Response) (bool, []byte, []string, error) {
	if resp.StatusCode != http.StatusOK {
		return false, nil, nil, errors.New(fmt.Sprintf("Could not fetch the report: Error code [%d].", resp.StatusCode))
	}

	reportBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, nil, nil, err
	}
	report := make(map[string]interface{})
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return false, nil, nil, err
	}

	if int(report["version"].(float64)) < MIN_IAS_VERSION_NUMBER {
		return false, nil, nil, errors.New("IAS version is too old.")
	}

	if hexNonce != report[ISV_NONCE].(string) {
		return false, nil, nil, errors.New("Incorrect nonce from IAS.")
	}

	if err := ias.verifyResponseSignature(resp, reportBytes); err != nil {
		return false, nil, nil, err
	}

	isvStatus := report[ISV_QUOTE_STATUS].(string)
	pseStatus := ""
	if len(pse) > 0 {
		pseHash := sha256.Sum256(pse)
		if retPSEHash, err := hex.DecodeString(report[PSE_MANIFEST_HASH].(string)); err != nil {
			return false, nil, nil, err
		} else if !bytes.Equal(pseHash[:], retPSEHash) {
			return false, nil, nil, errors.New("PSE hash mismatch.")
		}
		pseStatus = report[PSE_MANIFEST_STATUS].(string)
	}

	retQuote, err := base64.StdEncoding.DecodeString(report[ISV_QUOTE_BODY].(string))
	if err != nil {
		return false, nil, nil, err
	}

	if len(retQuote) != NO_SIG_QUOTE_LEN || !bytes.Equal(retQuote, quote[:NO_SIG_QUOTE_LEN]) {
		return false, nil, nil, errors.New("Incorrect quote returned from IAS.")
	}

	// Platform information blob is only set on specific errors.
	isvBad := isvStatus == ISV_GROUP_REVOKED ||
		isvStatus == ISV_GROUP_OUT_OF_DATE ||
		isvStatus == ISV_CONFIGURATION_NEEDED
	pseBad := pseStatus == PSE_OUT_OF_DATE ||
		pseStatus == PSE_REVOKED ||
		pseStatus == PSE_RL_VERSION_MISMATCH
	var pib []byte
	if isvBad || pseBad {
		pib, err = hex.DecodeString(report[PLATFORM_INFO_BLOB].(string))
		if err != nil {
			return false, nil, nil, err
		}
		// pib[0] is type, pib[1] is version, pib[2:4] is size
		pib = pib[4:]
	}

	advisories := strings.Split(resp.Header.Get("advisory-ids"), ",")
	err = ias.errorAllowed(isvStatus, advisories)
	if err != nil {
		return false, pib, advisories, err
	}

	switch pseStatus {
	case PSE_OK:
		return true, pib, advisories, nil
	default:
		// Currently returns if PSE is trusted or not, but does
		// not throw an error if it's not.
		// TODO: Different errors for different PSE status.
		return false, pib, advisories, nil
	}
}

func (ias *ias) VerifyQuoteAndPSE(quote, pse []byte) (bool, []byte, []string, error) {
	url := ias.host + "/report"

	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, nil, nil, err
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
		return false, nil, nil, err
	}

	req.Header.Set(HEADER_SUBSCRIPTION_KEY, ias.subscription)
	// need to manually set it to json content type!
	req.Header.Set("Content-Type", "application/json")

	resp, err := ias.client.Do(req)
	if err != nil {
		return false, nil, nil, err
	}
	defer resp.Body.Close()

	return ias.processReport(hexNonce, quote, pse, resp)
}

// URL for the IAS attestation API.
const (
	// dev
	DEBUG_IAS_HOST = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3"
	// prod
	IAS_HOST = "https://api.trustedservices.intel.com/sgx/attestation/v3"
)

// Fields of the header we set for the IAS.
const (
	HEADER_SUBSCRIPTION_KEY = "Ocp-Apim-Subscription-Key"
)

// Fields of the report body.
const (
	ISV_NONCE        = "nonce"
	ISV_QUOTE        = "isvEnclaveQuote"
	ISV_QUOTE_BODY   = "isvEnclaveQuoteBody"
	ISV_QUOTE_STATUS = "isvEnclaveQuoteStatus"

	// 432 bytes for everything in the quote structure, except for
	// the signature fields.
	NO_SIG_QUOTE_LEN = 432

	PSE_MANIFEST        = "pseManifest"
	PSE_MANIFEST_HASH   = "pseManifestHash"
	PSE_MANIFEST_STATUS = "pseManifestStatus"

	PLATFORM_INFO_BLOB = "platformInfoBlob"
)

// Possible errors from quote verification.
const (
	ISV_OK                     = "OK"
	ISV_SIGNATURE_INVALID      = "SIGNATURE_INVALID"
	ISV_GROUP_REVOKED          = "GROUP_REVOKED"
	ISV_KEY_REVOKED            = "KEY_REVOKED"
	ISV_SIGRL_VERSION_MISMATCH = "SIGRL_VERSION_MISMATCH"
	ISV_CONFIGURATION_NEEDED   = "CONFIGURATION_NEEDED"
	ISV_GROUP_OUT_OF_DATE      = "GROUP_OUT_OF_DATE"
)

// Possible errors from platform services.
const (
	PSE_OK                  = "OK"
	PSE_UNKNOWN             = "UNKNOWN"
	PSE_INVALID             = "INVALID"
	PSE_OUT_OF_DATE         = "OUT_OF_DATE"
	PSE_REVOKED             = "REVOKED"
	PSE_RL_VERSION_MISMATCH = "RL_VERSION_MISMATCH"
)

// Possible error strings from ias.
const (
	quoteErr             = "Quote verification returned unallowed error [%s]."
	quoteErrWithAdvisory = "Quote verification returned [%s] with unallowed advisories [%s]."
)
