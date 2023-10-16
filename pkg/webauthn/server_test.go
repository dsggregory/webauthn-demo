package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"gorm.io/gorm"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"webauthndemo/pkg/db"
	"webauthndemo/pkg/model"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	testDBPath = "./test_db.db"
)

// createTestDB Remember to defer db.DropTestDB(testDBPath)
func createTestDB() (*gorm.DB, error) {
	_ = os.Setenv("DB_LOG_SILENT", "1")
	_ = db.DropTestDB(testDBPath)
	dbase := db.TestDB(testDBPath)
	if err := db.AutoMigrate(dbase); err != nil {
		return nil, err
	}

	return dbase, nil
}

func (svc *MockWebauthnService) Close() {
	svc.ts.Close()
	_ = db.DropTestDB(testDBPath)
}

func createTestService() (*MockWebauthnService, error) {
	dbase, err := createTestDB()
	if err != nil {
		return nil, err
	}
	dbsvc := &db.DBService{}
	dbsvc.SetDb(dbase)

	return NewMockWebauthnService(dbsvc, nil)
}

func testLogin(c C, tsvc *MockWebauthnService) *http.Cookie {
	var webauthnSessionCookie *http.Cookie

	//**** login/begin
	req, _ := http.NewRequest(http.MethodGet, tsvc.ts.URL+"/login/begin/"+tsvc.contact.Email, http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	So(err, ShouldBeNil)
	_ = resp.Body.Close()

	// Parses the assertion options we got from the relying party to ensure they're valid
	parsedAssertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(body))
	So(err, ShouldBeNil)

	// parse them as the struct to test more
	credOpts := protocol.CredentialCreation{}
	err = json.Unmarshal(body, &credOpts)
	So(credOpts.Response.Challenge, ShouldNotBeNil)

	// to be added to req to /registration/finalize
	webauthnSessionCookie = GetResponseSessionCookie(resp)
	So(webauthnSessionCookie, ShouldNotBeNil)

	//**** login/finish
	// Creates an assertion response that we can send to the relying party as if it came from
	// an actual browser and authenticator.
	tsvc.credential.Counter++ // an authenticator (yubi, et.al. but not passkeys) would do this
	attestationResponse := virtualwebauthn.CreateAssertionResponse(*tsvc.rp, tsvc.authenticator, tsvc.credential, *parsedAssertionOptions)
	arBody := io.NopCloser(bytes.NewReader([]byte(attestationResponse)))

	req, _ = http.NewRequest(http.MethodPost, tsvc.ts.URL+"/login/finish/"+tsvc.contact.Email, arBody)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(webauthnSessionCookie)

	resp, err = http.DefaultClient.Do(req)
	So(err, ShouldBeNil)
	So(resp.StatusCode, ShouldEqual, http.StatusOK)

	var contact *model.Contact
	credIDb64 := base64.StdEncoding.EncodeToString(tsvc.credential.ID)
	contact, err = tsvc.dbsvc.GetContactByCredentialID(credIDb64)
	So(err, ShouldBeNil)
	So(contact, ShouldNotBeNil)
	So(contact.Email, ShouldEqual, tsvc.contact.Email)

	tsvc.authenticator.AddCredential(tsvc.credential)
	webauthnSessionCookie = GetResponseSessionCookie(resp)

	return webauthnSessionCookie
}

func TestWebauthn(t *testing.T) {
	tsvc, err := createTestService()
	if err != nil {
		t.Error(err)
	}
	defer tsvc.Close()

	Convey("Test webauthn registration", t, func() {

		// The relying party settings should mirror those on the actual WebAuthn server
		rp := virtualwebauthn.RelyingParty{
			Name:   "Testco",
			ID:     tsvc.svr.cfg.RPID,
			Origin: "http://localhost",
		}

		// A mock authenticator that represents a security key or biometrics module
		authenticator := virtualwebauthn.NewAuthenticator()

		// Create a new credential that we'll try to register with the relying party
		credential := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

		Convey("should begin registration with no users", func() {
			username := "test@test.domain.com"
			req, _ := http.NewRequest(http.MethodGet, tsvc.ts.URL+"/register/begin/"+username, http.NoBody)
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			body, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			resp.Body.Close()

			// Parses the attestation options we got from the relying party to ensure they're valid
			parsedAttestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(body))
			So(err, ShouldBeNil)

			// parse them as the struct to test more
			credOpts := protocol.CredentialCreation{}
			err = json.Unmarshal(body, &credOpts)
			So(credOpts.Response.User.Name, ShouldEqual, username)

			// to be added to req to /registration/finalize
			var webauthnSessionCookie *http.Cookie
			webauthnSessionCookie = GetResponseSessionCookie(resp)
			So(webauthnSessionCookie, ShouldNotBeNil)

			Convey("should finish registration", func() {
				// like what the javascript does to POST to /register/finish
				// Creates an attestation response that we can send to the relying party as if it came from
				// an actual browser and authenticator.
				attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedAttestationOptions)

				body := io.NopCloser(bytes.NewReader([]byte(attestationResponse)))

				req, _ := http.NewRequest(http.MethodPost, tsvc.ts.URL+"/register/finish/"+username, body)
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(webauthnSessionCookie)

				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				//So(resp, ShouldNotBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)

				var c *model.Contact
				credIDb64 := base64.StdEncoding.EncodeToString(credential.ID)
				c, err = tsvc.dbsvc.GetContactByCredentialID(credIDb64)
				So(err, ShouldBeNil)
				So(c, ShouldNotBeNil)
				So(c.Email, ShouldEqual, username)

				authenticator.AddCredential(credential)
			})
		})

		Convey("register 2nd user", func() {
			// create the next user having a registration invite
			regid := "12345"
			c := model.Contact{
				CustomerID:     0,
				FullName:       "User Two",
				Email:          "u2@testco.com",
				RegistrationID: regid,
				APIKey:         "",
				Credentials:    nil,
			}
			contact, err := tsvc.dbsvc.CreateContact(&c)
			So(err, ShouldBeNil)

			// in terms of the web UI, the user has received an invite to click on the link
			//   * /signin?username=u2@testco.com&regid=12345
			req, _ := http.NewRequest(http.MethodGet,
				tsvc.ts.URL+"/register/begin/"+contact.Email+"?regid="+regid,
				http.NoBody)
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			body, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			resp.Body.Close()

			// Parses the attestation options we got from the relying party to ensure they're valid
			parsedAttestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(body))
			So(err, ShouldBeNil)
			// parse them as the struct to test more
			credOpts := protocol.CredentialCreation{}
			err = json.Unmarshal(body, &credOpts)
			So(credOpts.Response.User.Name, ShouldEqual, contact.Email)

			// to be added to req to /registration/finalize
			webauthnSessionCookie := GetResponseSessionCookie(resp)
			So(webauthnSessionCookie, ShouldNotBeNil)

			Convey("should finish 2nd user registration", func() {
				// like what the javascript does to POST to /register/finish
				// Creates an attestation response that we can send to the relying party as if it came from
				// an actual browser and authenticator.
				attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedAttestationOptions)

				body := io.NopCloser(bytes.NewReader([]byte(attestationResponse)))

				req, _ := http.NewRequest(http.MethodPost, tsvc.ts.URL+"/register/finish/"+contact.Email, body)
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(webauthnSessionCookie)

				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				//So(resp, ShouldNotBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)

				var c *model.Contact
				credIDb64 := base64.StdEncoding.EncodeToString(credential.ID)
				c, err = tsvc.dbsvc.GetContactByCredentialID(credIDb64)
				So(err, ShouldBeNil)
				So(c, ShouldNotBeNil)
				So(c.Email, ShouldEqual, contact.Email)

				authenticator.AddCredential(credential)
			})
		})

		Convey("Should not register without invite", func() {
			contact, err := tsvc.dbsvc.GetContact(1)
			So(err, ShouldBeNil)
			So(contact.RegistrationID, ShouldBeBlank)

			req, _ := http.NewRequest(http.MethodGet,
				tsvc.ts.URL+"/register/begin/"+contact.Email,
				http.NoBody)
			resp, err := http.DefaultClient.Do(req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusForbidden)
		})
	})

	Convey("Test webauthn login", t, func() {
		// creates the first registered user and sets up webauthn RP
		err := tsvc.registerWebauthnUser()
		So(err, ShouldBeNil)

		Convey("test login", func() {
			Convey("should fail login with non-existing user", func() {
				req, _ := http.NewRequest(http.MethodGet, tsvc.ts.URL+"/login/begin/"+"nouser@domain.com", http.NoBody)
				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
			})
			Convey("should login", func(c C) {
				webauthnSessionCookie := testLogin(c, tsvc)

				//Convey("session should authenticate", func() {
				lts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// initially what an authentication middleware would do
					u := tsvc.svr.GetSessionUser(w, r)
					if u == nil {
						w.WriteHeader(http.StatusUnauthorized)
					}
				}))
				req, _ := http.NewRequest(http.MethodPost, lts.URL+"/", http.NoBody)
				req.Header.Set("Content-Type", "application/json")
				req.AddCookie(webauthnSessionCookie)

				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				//})

				// Convey("should login a 2nd time and update cred sign count")
				webauthnSessionCookie = testLogin(c, tsvc)
				So(webauthnSessionCookie, ShouldNotBeNil)
			})
		})
	})
}
