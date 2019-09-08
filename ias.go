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
)

type IAS struct {
	release      bool
	host         string
	subscription string
	client       *http.Client
}

// dev
const DEBUG_IAS_HOST = "https://api.trustedservices.intel.com/sgx/dev/attestation/v3"

// prod
const IAS_HOST = "https://api.trustedservices.intel.com/sgx/attestation/v3"

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

func (ias *IAS) GetRevocationList(gid []byte) ([]byte, error) {
	// sgx gives gid in little endian, but we need big endian
	reverse(gid)
	url := ias.host + "/sigrl/" + hex.EncodeToString(gid)
	reverse(gid)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", ias.subscription)

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
// which behaves like a stream
func (ias *IAS) verifyResponseSignature(resp *http.Response, body []byte) error {
	sig, err := base64.StdEncoding.DecodeString(resp.Header.Get("x-iasreport-signature"))
	if err != nil {
		return err
	}

	unescaped, err := url.QueryUnescape(resp.Header.Get("x-iasreport-signing-certificate"))
	if err != nil {
		return err
	}

	// the first block is the key used to verify the signature
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
	bodyMap["isvEnclaveQuote"] = hexQuote
	//bodyMap["pseManifest"]
	hexNonce := hex.EncodeToString(nonce[:])
	bodyMap["nonce"] = hexNonce

	body := bytes.NewBuffer(nil)
	encoder := json.NewEncoder(body)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(bodyMap)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return err
	}

	req.Header.Set("Ocp-Apim-Subscription-Key", ias.subscription)
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

	if hexNonce != report["nonce"].(string) {
		return errors.New("Incorrect nonce from IAS.")
	}

	retQuote := report["isvEnclaveQuoteBody"].(string)
	if len(retQuote) < 432 || hexQuote[:len(retQuote)] != retQuote {
		return errors.New("Incorrect quote returned from IAS.")
	}

	if report["isvEnclaveQuoteStatus"].(string) != "OK" {
		if report["isvEnclaveQuoteStatus"].(string) == "CONFIGURATION_NEEDED" {
			log.Println("Requires client configuration (likely due to hyperthreading).")
		} else if report["isvEnclaveQuoteStatus"].(string) == "GROUP_OUT_OF_DATE" {
			// parse the advisory code and report
			log.Println("Client processor is too old.")
		} else {
			return errors.New("Unknown enclave status.")
		}
	}

	if err := ias.verifyResponseSignature(resp, reportBytes); err != nil {
		return err
	}

	return nil
}
