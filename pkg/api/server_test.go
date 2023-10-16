package api

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"webauthndemo/pkg/config"
	"webauthndemo/pkg/db"
	"webauthndemo/pkg/model"
	webauthnapi "webauthndemo/pkg/webauthn"
)

type MockResponseWriter struct {
	body       []byte
	statusCode int
	header     http.Header
}

func NewMockResponseWriter() *MockResponseWriter {
	return &MockResponseWriter{
		header: http.Header{},
	}
}

func (w *MockResponseWriter) Header() http.Header {
	return w.header
}

func (w *MockResponseWriter) Write(b []byte) (int, error) {
	w.body = b
	// implement it as per your requirement
	return 0, nil
}

func (w *MockResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

var (
	testDBPath = "./test_db.db"
)

const SeedAPIKey = "deadbeef"

func seedDB(db *gorm.DB) error {
	customers := []string{"TestCo", "ACME Corp."}
	for _, cn := range customers {
		cust := model.Customer{
			Name: cn,
		}
		err := db.Create(&cust).Error
		if err != nil {
			return err
		}
	}

	contacts := []model.Contact{
		{
			CustomerID: 1,
			FullName:   "Tester One",
			Email:      "t1@test.com",
			APIKey:     SeedAPIKey,
		},
		{
			CustomerID: 2,
			FullName:   "Tester Two",
			Email:      "t2@test.com",
		},
	}
	for _, c := range contacts {
		err := db.Create(&c).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// createTestDB Remember to defer db.DropTestDB(testDBPath)
func createTestDB() (*gorm.DB, error) {
	_ = os.Setenv("DB_LOG_SILENT", "1")
	_ = db.DropTestDB(testDBPath)
	dbase := db.TestDB(testDBPath)
	if err := db.AutoMigrate(dbase); err != nil {
		return nil, err
	}
	if err := seedDB(dbase); err != nil {
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

func createTestService(cfg *config.AppSettings) (*TestService, error) {
	svc := &TestService{}
	var err error

	svc.dbase, err = createTestDB()
	if err != nil {
		return nil, err
	}

	svc.dbsvc = &db.DBService{}
	svc.dbsvc.SetDb(svc.dbase)

	svc.svr, err = NewServer(cfg, svc.dbsvc)
	if err != nil {
		return nil, err
	}

	svc.ts = httptest.NewServer(svc.svr.mux)

	return svc, nil
}

func TestCustomerRoutes(t *testing.T) {
	Convey("Test customer routes", t, func() {
		logrus.SetLevel(logrus.DebugLevel)

		cfg := &config.AppSettings{
			ListenAddr: "localhost", // just a reference for webauthn RPID
			WebsiteURL: "http://localhost",
		}

		tsvc, err := createTestService(cfg)
		So(err, ShouldBeNil)
		defer tsvc.Close()

		Convey("test admin routes", func() {
			mts, err := webauthnapi.NewMockWebauthnService(tsvc.dbsvc, tsvc.svr.webautnSvc)
			sessionCookie, err := mts.NewLoggedInUser()
			So(err, ShouldBeNil)

			Convey("should rotate api key", func() {
				ocontact, err := tsvc.dbsvc.GetContact(1)
				So(err, ShouldBeNil)
				req, err := http.NewRequest(http.MethodPut, tsvc.ts.URL+AdminAPIPrefix+"/apikey/1", http.NoBody)
				So(err, ShouldBeNil)
				req.AddCookie(sessionCookie)

				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				contact := model.Contact{}
				err = json.NewDecoder(resp.Body).Decode(&contact)
				So(err, ShouldBeNil)
				So(ocontact.APIKey, ShouldNotEqual, contact.APIKey)
			})
			Convey("should delete apikey", func() {
				So(err, ShouldBeNil)
				req, err := http.NewRequest(http.MethodDelete, tsvc.ts.URL+AdminAPIPrefix+"/apikey/1", http.NoBody)
				So(err, ShouldBeNil)
				req.AddCookie(sessionCookie)

				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				contact, err := tsvc.dbsvc.GetContact(1)
				So(err, ShouldBeNil)
				So(contact.APIKey, ShouldBeBlank)
			})
			Convey("should delete customer", func() {
				req, err := http.NewRequest(http.MethodDelete, tsvc.ts.URL+AdminAPIPrefix+"/customer/1", http.NoBody)
				So(err, ShouldBeNil)
				req.AddCookie(sessionCookie)

				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				_, err = tsvc.dbsvc.GetCustomer(1)
				So(err, ShouldNotBeNil)
			})
			Convey("should delete contact", func() {
				req, err := http.NewRequest(http.MethodDelete, tsvc.ts.URL+AdminAPIPrefix+"/contact/1", http.NoBody)
				So(err, ShouldBeNil)
				req.AddCookie(sessionCookie)

				resp, err := http.DefaultClient.Do(req)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
				_, err = tsvc.dbsvc.GetContact(1)
				So(err, ShouldNotBeNil)
			})
		})
	})
}
