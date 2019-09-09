package sgx_server

import (
	"bytes"
	"crypto/rand"
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
	ISV_NONCE        = "nonce"
	ISV_QUOTE        = "isvEnclaveQuote"
	ISV_QUOTE_BODY   = "isvEnclaveQuoteBody"
	ISV_QUOTE_STATUS = "isvEnclaveQuoteStatus"
)

// possible errors from quote verification
const (
	OK                   = "OK"
	CONFIGURATION_NEEDED = "CONFIGURATION_NEEDED"
	GROUP_OUT_OF_DATE    = "GROUP_OUT_OF_DATE"
)

// possible error strings from ias
const (
	quoteErr             = "Quote verification returned unallowed error [%s]."
	quoteErrWithAdvisory = "Quote verification returned [%s] with unallowed advisories [%s]."
)

type IAS struct {
	release           bool
	host              string
	subscription      string
	allowedAdvisories map[string][]string
	client            *http.Client
}

func NewIAS(release bool, subscription string, allowedAdvisories map[string][]string) *IAS {
	host := DEBUG_IAS_HOST
	if release {
		host = IAS_HOST
	}

	client := &http.Client{}

	ias := &IAS{
		release:           release,
		host:              host,
		subscription:      subscription,
		allowedAdvisories: allowedAdvisories,
		client:            client,
	}
	return ias
}

func (ias *IAS) GetRevocationList(gid []byte) ([]byte, error) {
	// sgx gives gid in little endian, but we need big endian
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

// passing in the body separately, since resp.Body is a Reader
// which behaves like a stream. if we wanted to pass a Reader type,
// we'd have to create a new one.
func (ias *IAS) verifyResponseSignature(resp *http.Response, body []byte) error {
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

func (ias *IAS) errorAllowed(status string, advisories string) error {
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

func (ias *IAS) VerifyQuote(quote []byte) error {
	url := ias.host + "/report"

	var nonce [16]byte
	if n, err := rand.Read(nonce[:]); err != nil {
		return err
	} else if n != 16 {
		return errors.New("Could not generate random bytes for nonce")
	}

	bodyMap := make(map[string]string)
	hexQuote := base64.StdEncoding.EncodeToString(quote)
	bodyMap[ISV_QUOTE] = hexQuote
	//bodyMap["pseManifest"]
	hexNonce := hex.EncodeToString(nonce[:])
	bodyMap[ISV_NONCE] = hexNonce

	body := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(bodyMap)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}

	req.Header.Set(HEADER_SUBSCRIPTION_KEY, ias.subscription)
	// need to manually set it to json content type!
	req.Header.Set("Content-Type", "application/json")

	resp, err := ias.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Could not fetch the report: Error code [%d].", resp.StatusCode))
	}

	reportBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	report := make(map[string]interface{})
	err = json.Unmarshal(reportBytes, &report)
	if err != nil {
		return err
	}

	if hexNonce != report[ISV_NONCE].(string) {
		return errors.New("Incorrect nonce from IAS.")
	}

	if err := ias.verifyResponseSignature(resp, reportBytes); err != nil {
		return err
	}

	retQuote := report[ISV_QUOTE_BODY].(string)
	if len(retQuote) < 432 || hexQuote[:len(retQuote)] != retQuote {
		return errors.New("Incorrect quote returned from IAS.")
	}

	status := report[ISV_QUOTE_STATUS].(string)
	if status != OK {
		return ias.errorAllowed(status, resp.Header.Get("advisory-ids"))
	}

	return nil
}
