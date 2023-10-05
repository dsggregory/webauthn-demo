package webauthn

import (
	"encoding/json"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"webauthndemo/pkg/db"

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

type TestService struct {
	dbase *gorm.DB
	dbsvc *db.DBService
	svr   *Server
	ts    *httptest.Server
}

func (svc *TestService) Close() {
	svc.ts.Close()
	_ = db.DropTestDB(testDBPath)
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
		RPID:          "http://test.domain.com",
		RPOrigins:     nil,
	})
	if err != nil {
		return nil, err
	}

	svc.ts = httptest.NewServer(svc.svr.mux)

	return svc, nil
}

func TestWebauthnServer(t *testing.T) {
	Convey("Test routes", t, func() {
		tsvc, err := createTestService()
		So(err, ShouldBeNil)
		defer tsvc.Close()

		Convey("should begin registration with no users", func() {
			username := "test@test.domain.com"
			resp, err := http.Get(tsvc.ts.URL + "/register/begin/" + username)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			opts := protocol.CredentialCreation{}
			err = json.NewDecoder(resp.Body).Decode(&opts)
			So(opts.Response.User.Name, ShouldEqual, username)

			user, err := tsvc.svr.userDB.GetFirstContact()
			So(err, ShouldBeNil)
			creds := webauthn.Credential{
				ID:              []byte("1"),
				PublicKey:       []byte("deadbeef"),
				AttestationType: "public",
				Transport:       nil,
				Flags:           webauthn.CredentialFlags{},
				Authenticator:   webauthn.Authenticator{},
			}
			user.AddCredential(creds)
			err = tsvc.dbsvc.PutUserCredentials(user)
			So(err, ShouldBeNil)

			// try to register again, and we should receive the creds we stored earlier. The browser will decline to call finish.
			resp, err = http.Get(tsvc.ts.URL + "/register/begin/" + username)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			opts = protocol.CredentialCreation{}
			err = json.NewDecoder(resp.Body).Decode(&opts)
			So(opts.Response.User.Name, ShouldEqual, username)
			So(len(opts.Response.CredentialExcludeList), ShouldBeGreaterThan, 0)
			So(string(opts.Response.CredentialExcludeList[0].CredentialID), ShouldEqual, string(creds.ID))

			Convey("should finish registration", func() {
				// TODO a lot of struct to send to this...
				resp, err := http.Post(tsvc.ts.URL+"/register/finish/"+username, "application/json", http.NoBody)
				So(err, ShouldBeNil)
				//So(resp, ShouldNotBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)
			})
		})
	})
}
