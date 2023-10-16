package webauthn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gorilla/mux"
	"io"
	"net/http"
	"net/http/httptest"
	"webauthndemo/pkg/db"
	"webauthndemo/pkg/model"
)

type MockWebauthnRP struct {
	contact       *model.Contact
	rp            *virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
}

type MockWebauthnService struct {
	dbsvc *db.DBService
	svr   *Server
	ts    *httptest.Server

	MockWebauthnRP
}

func (tsvc *MockWebauthnService) GetContact() *model.Contact {
	return tsvc.contact
}

// create a registered webauthn user in the test database
func (tsvc *MockWebauthnService) registerWebauthnUser() error {
	if tsvc.contact != nil {
		// already created for this test session
		return nil
	}

	regid := "1234"
	contact := model.Contact{
		CustomerID:     0,
		FullName:       "Trusted User",
		Email:          "tuser@testdomain.com",
		RegistrationID: regid,
		APIKey:         "",
		Credentials:    nil,
	}
	if _, err := tsvc.dbsvc.CreateContact(&contact); err != nil {
		return err
	}

	// **** webauthn RP mock setup
	// The relying party settings should mirror those on the actual WebAuthn server
	rp := virtualwebauthn.RelyingParty{
		Name:   "Testco",
		ID:     tsvc.svr.cfg.RPID,
		Origin: "http://localhost",
	}
	tsvc.rp = &rp

	// A mock authenticator that represents a security key or biometrics module
	tsvc.authenticator = virtualwebauthn.NewAuthenticator()

	// Create a new credential that we'll try to register with the relying party
	tsvc.credential = virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	// **** register/begin
	req, _ := http.NewRequest(http.MethodGet, tsvc.ts.URL+"/register/begin/"+contact.Email+"?regid="+regid, http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	// Parses the attestation options we got from the relying party to ensure they're valid
	parsedAttestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(body))
	if err != nil {
		return err
	}

	// parse them as the struct to test more
	credOpts := protocol.CredentialCreation{}
	err = json.Unmarshal(body, &credOpts)
	if err != nil {
		return err
	}

	// to be added to req to /registration/finish
	webauthnSessionCookie := GetResponseSessionCookie(resp)

	// **** register/finish
	// like what the javascript does to POST to /register/finish
	// Creates an attestation response that we can send to the relying party as if it came from
	// an actual browser and authenticator.
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, tsvc.authenticator, tsvc.credential, *parsedAttestationOptions)

	bodyFin := io.NopCloser(bytes.NewReader([]byte(attestationResponse)))

	req, _ = http.NewRequest(http.MethodPost, tsvc.ts.URL+"/register/finish/"+contact.Email, bodyFin)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(webauthnSessionCookie)

	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return err
	}

	tsvc.authenticator.AddCredential(tsvc.credential)

	tsvc.contact = &contact
	return nil
}

func (tsvc *MockWebauthnService) loginUser() (*http.Cookie, error) {
	req, _ := http.NewRequest(http.MethodGet, tsvc.ts.URL+"/login/begin/"+tsvc.contact.Email, http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parses the assertion options we got from the relying party to ensure they're valid
	parsedAssertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(body))
	if err != nil {
		return nil, err
	}

	// to be added to req to /login/finish
	webauthnSessionCookie := GetResponseSessionCookie(resp)

	//*** login finish
	// Creates an assertion response that we can send to the relying party as if it came from
	// an actual browser and authenticator.
	attestationResponse := virtualwebauthn.CreateAssertionResponse(*tsvc.rp, tsvc.authenticator, tsvc.credential, *parsedAssertionOptions)
	attBody := io.NopCloser(bytes.NewReader([]byte(attestationResponse)))

	req, _ = http.NewRequest(http.MethodPost, tsvc.ts.URL+"/login/finish/"+tsvc.contact.Email, attBody)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(webauthnSessionCookie)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(resp.Status)
	}

	tsvc.authenticator.AddCredential(tsvc.credential)

	// this login auth token can be used to req.AddCookie(sessionCookie) in future requests
	sessionCookie := GetResponseSessionCookie(resp)

	return sessionCookie, nil
}

// NewLoggedInUser register and login a new user, returning the cookie that would be added to subsequent REST calls that validate auth.
// Ex. req.AddCookie(sessionCookie)
func (tsvc *MockWebauthnService) NewLoggedInUser() (*http.Cookie, error) {
	if err := tsvc.registerWebauthnUser(); err != nil {
		return nil, err
	}

	return tsvc.loginUser()
}

// NewMockWebauthnService create a mock webauthnService with a httptest server.
// If webauthnService is nil, one will be created, but you may not have luck using the returned session token if your tests use a different one.
func NewMockWebauthnService(dbsvc *db.DBService, webauthnService *Server) (*MockWebauthnService, error) {
	svc := &MockWebauthnService{dbsvc: dbsvc}

	var err error

	if webauthnService != nil {
		svc.svr = webauthnService
	} else {
		svc.svr, err = NewServer(&WebauthnConfig{
			WebsiteURL:    "http://localhost",
			Router:        mux.NewRouter(),
			UserDB:        svc.dbsvc,
			RPDisplayName: "Test Co.",
			RPID:          "http://localhost",
			RPOrigins:     nil,
		})
		if err != nil {
			return nil, err
		}
	}

	svc.ts = httptest.NewServer(svc.svr.mux)

	return svc, nil
}

func GetResponseSessionCookie(resp *http.Response) *http.Cookie {
	for _, ck := range resp.Cookies() {
		if ck.Name == WebauthnSession {
			return ck
		}
	}
	return nil
}
