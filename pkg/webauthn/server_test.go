package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"thsapi/pkg/db"
	"thsapi/pkg/model"

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

type TestWebauthnRP struct {
	contact       *model.Contact
	rp            *virtualwebauthn.RelyingParty
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
}

type TestService struct {
	dbase *gorm.DB
	dbsvc *db.DBService
	svr   *Server
	ts    *httptest.Server

	TestWebauthnRP
}

func (svc *TestService) Close() {
	svc.ts.Close()
	_ = db.DropTestDB(testDBPath)
}

// create a registered webauthn user in the test database
func (tsvc *TestService) createWebauthnUser() error {
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
	var webauthnSessionCookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == WebauthnSession {
			webauthnSessionCookie = ck
			break
		}
	}

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

func createTestService() (*TestService, error) {
	svc := &TestService{}
	var err error

	svc.dbase, err = createTestDB()
	if err != nil {
		return nil, err
	}

	svc.dbsvc = &db.DBService{}
	svc.dbsvc.SetDb(svc.dbase)

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

	svc.ts = httptest.NewServer(svc.svr.mux)

	return svc, nil
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
			for _, ck := range resp.Cookies() {
				if ck.Name == WebauthnSession {
					webauthnSessionCookie = ck
					break
				}
			}
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
			var webauthnSessionCookie *http.Cookie
			for _, ck := range resp.Cookies() {
				if ck.Name == WebauthnSession {
					webauthnSessionCookie = ck
					break
				}
			}
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
		err := tsvc.createWebauthnUser()
		So(err, ShouldBeNil)

		Convey("test login", func() {
			Convey("should fail login with non-existing user", func() {
				req, _ := http.NewRequest(http.MethodGet, tsvc.ts.URL+"/register/begin/"+tsvc.contact.Email, http.NoBody)
				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusForbidden)
			})
			Convey("should login/begin", func() {
				req, _ := http.NewRequest(http.MethodGet, tsvc.ts.URL+"/login/begin/"+tsvc.contact.Email, http.NoBody)
				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)

				body, err := io.ReadAll(resp.Body)
				So(err, ShouldBeNil)
				resp.Body.Close()

				// Parses the assertion options we got from the relying party to ensure they're valid
				parsedAssertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(body))
				So(err, ShouldBeNil)

				// parse them as the struct to test more
				credOpts := protocol.CredentialCreation{}
				err = json.Unmarshal(body, &credOpts)
				So(credOpts.Response.Challenge, ShouldNotBeNil)

				// to be added to req to /registration/finalize
				var webauthnSessionCookie *http.Cookie
				for _, ck := range resp.Cookies() {
					if ck.Name == WebauthnSession {
						webauthnSessionCookie = ck
						break
					}
				}
				So(webauthnSessionCookie, ShouldNotBeNil)

				Convey("should login/finish", func() {

					// Creates an assertion response that we can send to the relying party as if it came from
					// an actual browser and authenticator.
					attestationResponse := virtualwebauthn.CreateAssertionResponse(*tsvc.rp, tsvc.authenticator, tsvc.credential, *parsedAssertionOptions)
					body := io.NopCloser(bytes.NewReader([]byte(attestationResponse)))

					req, _ := http.NewRequest(http.MethodPost, tsvc.ts.URL+"/login/finish/"+tsvc.contact.Email, body)
					req.Header.Set("Content-Type", "application/json")
					req.AddCookie(webauthnSessionCookie)

					resp, err := http.DefaultClient.Do(req)
					So(err, ShouldBeNil)
					So(resp.StatusCode, ShouldEqual, http.StatusOK)

					var c *model.Contact
					credIDb64 := base64.StdEncoding.EncodeToString(tsvc.credential.ID)
					c, err = tsvc.dbsvc.GetContactByCredentialID(credIDb64)
					So(err, ShouldBeNil)
					So(c, ShouldNotBeNil)
					So(c.Email, ShouldEqual, tsvc.contact.Email)

					tsvc.authenticator.AddCredential(tsvc.credential)
				})
			})
		})
	})

}
