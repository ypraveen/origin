package avi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"log"
	"reflect"

	"github.com/golang/glog"
)

type aviResult struct {
	// Code should match the HTTP status code.
	Code int `json:"code"`

	// Message should contain a short description of the result of the requested
	// operation.
	Message *string `json:"message"`
}

// AviError represents an error resulting from a request to the Avi Controller
type AviError struct {
	// aviresult holds the standard header (code and message) that is included in
	// responses from Avi.
	aviResult

	// verb is the HTTP verb (GET, POST, PUT, PATCH, or DELETE) that was
	// used in the request that resulted in the error.
	verb string

	// url is the URL that was used in the request that resulted in the error.
	url string

	// httpStatusCode is the HTTP response status code (e.g., 200, 404, etc.).
	httpStatusCode int

	// err contains a descriptive error object for error cases other than HTTP
	// errors (i.e., non-2xx responses), such as socket errors or malformed JSON.
	err error
}

// Error implements the error interface.
func (err AviError) Error() string {
	var msg string

	if err.err != nil {
		msg = fmt.Sprintf("error: %v", err.err)
	} else if err.Message != nil {
		msg = fmt.Sprintf("HTTP code: %d; error from Avi: %s",
			err.httpStatusCode, *err.Message)
	} else {
		msg = fmt.Sprintf("HTTP code: %d.", err.httpStatusCode)
	}

	return fmt.Sprintf("Encountered an error on %s request to URL %s: %s",
		err.verb, err.url, msg)
}

type AviSession struct {
	// host specifies the hostname or IP address of the Avi Controller
	host string

	// username specifies the username with which we should authenticate with the
	// Avi Controller.
	username string

	// password specifies the password with which we should authenticate with the
	// Avi Controller.
	password string

	// insecure specifies whether we should perform strict certificate validation
	// for connections to the Avi Controller.
	insecure bool

	// optional tenant string to use for API request
	Tenant string

	sessionid string
	csrf_token string
	prefix string
}

func NewAviSession(host string, username string, password string, insecure bool) *AviSession {
	avisess := &AviSession{
		host: host,
		username: username,
		password: password,
		insecure: insecure,
	}
	avisess.sessionid = ""
	avisess.csrf_token = ""
	avisess.prefix = "https://" + avisess.host + "/"
	avisess.Tenant = ""
	return avisess
}

func (avisession *AviSession) InitiateSession() error {
	if avisession.insecure == true {
		glog.Warning("Strict certificate verification is *DISABLED*")
	}

	// initiate http session here
	res, rerror := avisession.rest_request("GET", "", nil)
	// above sets the csrf token

	// now login to get session_id
	cred := make(map[string]string)
	cred["username"] = avisession.username
	cred["password"] = avisession.password

	res, rerror = avisession.rest_request_payload("POST", "login", cred)

	log.Println("response: ", res)
	if (res != nil && reflect.TypeOf(res).Kind() != reflect.String) {
		println("results: ", res.(map[string]interface{}), " error: ", rerror)
	}

	return nil
}

//
// Helper routines for REST calls.
//

// rest_request makes a REST request to the Avi Controller's REST
// API.
//
// One of three things can happen as a result of a request:
//
// (1) The request succeeds and Avi returns an HTTP 200 response, possibly with
//     a result payload, which should have the fields defined in the
//     result argument.  In this case, rest_request decodes the payload into
//     the result argument and returns nil.
//
// (2) The request fails and Avi returns an HTTP 4xx or 5xx response with a
//     response payload containing a code (which should be the same as the
//     HTTP response code) and a string message.  In this case, rest_request
//     decodes the response payload and returns an AviError with the URL, HTTP
//     verb, HTTP status code, and error information from the response payload.
//
// (3) The REST call fails in some other way, such as a socket error or an
//     error decoding the result payload.  In this case, rest_request returns
//     an AviError with the URL, HTTP verb, HTTP status code (if any), and error
//     value.
func (avi *AviSession) rest_request(verb string, url string, payload io.Reader) (interface{}, error) {
	var result interface{}
	url = avi.prefix + url

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: avi.insecure},
	}

	errorResult := AviError{verb: verb, url: url}

	req, err := http.NewRequest(verb, url, payload)
	if err != nil {
		errorResult.err = fmt.Errorf("http.NewRequest failed: %v", err)
		return result, errorResult
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if avi.csrf_token != "" {
		req.Header.Set("X-CSRFToken", avi.csrf_token)
	}
	if avi.prefix != "" {
		req.Header.Set("Referer", avi.prefix)
	}
	if avi.Tenant != "" {
		req.Header.Set("X-Avi-Tenant", avi.Tenant)
	}
	if avi.sessionid != "" {
		req.AddCookie(&http.Cookie{Name: "sessionid", Value: avi.sessionid,})
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		errorResult.err = fmt.Errorf("client.Do failed: %v", err)
		return result, errorResult
	}

	defer resp.Body.Close()

	errorResult.httpStatusCode = resp.StatusCode

	// collect cookies from the resp
	for _, cookie := range resp.Cookies() {
		log.Println("cookie: ", cookie)
		if cookie.Name == "csrftoken" {
			avi.csrf_token = cookie.Value
		}
		if cookie.Name == "sessionid" {
			avi.sessionid = cookie.Value
		}
	}
	resbytes, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(resbytes, &result)
	if err != nil {
		log.Println(err)
		// non json response
		result = string(resbytes)
	}

	return result, nil
}

// rest_request_payload is a helper for avi operations that take
// a payload.
func (avi *AviSession) rest_request_payload(verb string, url string,
	payload interface{}) (interface{}, error) {
	jsonStr, err := json.Marshal(payload)
	if err != nil {
		return "", AviError{verb: verb, url: url, err: err}
	}

	encodedPayload := bytes.NewBuffer(jsonStr)

	return avi.rest_request(verb, url, encodedPayload)
}

// get issues a GET request against the avi REST API.
func (avi *AviSession) Get(url string) (interface{}, error) {
	return avi.rest_request("GET", url, nil)
}

/*
// post issues a POST request against the avi REST API.
func (avi *AviSession) post(url string, payload interface{}, result interface{}) error {
	return avi.rest_request_payload("POST", url, payload, result)
}

// patch issues a PATCH request against the avi REST API.
func (avi *AviSession) patch(url string, payload interface{}, result interface{}) error {
	return avi.rest_request_payload("PATCH", url, payload, result)
}

// delete issues a DELETE request against the avi REST API.
func (avi *AviSession) delete(url string, result interface{}) error {
	return avi.rest_request("DELETE", url, nil, result)
}
*/