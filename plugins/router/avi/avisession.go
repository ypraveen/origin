package avi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
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

	// internal: session id for this session
	sessionid string

	// internal: csrf_token for this session
	csrf_token string

	// internal: referer field string to use in requests
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
	res, rerror = avisession.Post("login", cred)
	// now session id is set too

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
// Returns a json response (map[string]interface{} type) or string in case of non-json reponse from Avi Controller
func (avi *AviSession) rest_request(verb string, uri string, payload io.Reader) (interface{}, error) {
	var result interface{}
	url := avi.prefix + uri

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
		req.Header["X-CSRFToken"] = []string{ avi.csrf_token }
		req.AddCookie(&http.Cookie{Name: "csrftoken", Value: avi.csrf_token,})
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

	dump, err := httputil.DumpRequestOut(req, true)
	log.Println("Request headers: ", req.Header)
	debug(dump, err)
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
			log.Println("Set the csrf token to ", avi.csrf_token)
		}
		if cookie.Name == "sessionid" {
			avi.sessionid = cookie.Value
		}
	}
	log.Println("Response code: ", resp.StatusCode)

	if resp.StatusCode == 419 {
		// session got reset; try again
		return avi.rest_request(verb, uri, payload)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return result, errorResult
	}

	if resp.StatusCode == 204 {
		// no content in the response
		return result, nil
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

func debug(data []byte, err error) {
    if err == nil {
        fmt.Printf("%s\n\n", data)
    } else {
        log.Fatalf("%s\n\n", err)
    }
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
func (avi *AviSession) Get(uri string) (interface{}, error) {
	return avi.rest_request("GET", uri, nil)
}

// post issues a POST request against the avi REST API.
func (avi *AviSession) Post(uri string, payload interface{}) (interface{}, error) {
	return avi.rest_request_payload("POST", uri, payload)
}

// delete issues a DELETE request against the avi REST API.
func (avi *AviSession) Delete(uri string) (interface{}, error) {
	return avi.rest_request("DELETE", uri, nil)
}
