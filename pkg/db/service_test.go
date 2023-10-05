package db

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
	"os"
	"testing"
	"webauthndemo/pkg/model"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	testDBPath = "./test_db.db"
)

const (
	SeedAPIKey = "deadbeef"
	SeedCred   = `{"ID":"1xfY65zfiOsvKkYUfmnzLVvbIoo=","PublicKey":"pQEAByYgASFYIPUOouYn1oWI3hnYXkSkZd1l0UqBzokkvr/cxyeHGjAOIlggSGgg0NYsr+WWiW96nMW9dSw35UnQ6Z99iqQVeK6zy4E=","AttestationType":"none","Transport":null,"Flags":{"UserPresent":true,"UserVerified":false,"BackupEligible":true,"BackupState":true},"Authenticator":{"AAGUID":"AAAAAAAAAAAAAAAAAAAAAA==","SignCount":0,"CloneWarning":false,"Attachment":""}}`
	SeedCredID = `1xfY65zfiOsvKkYUfmnzLVvbIoo=`
)

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

	cred := webauthn.Credential{}
	err := json.Unmarshal([]byte(SeedCred), &cred)
	if err != nil {
		return err
	}
	contacts := []model.Contact{
		{
			CustomerID:  1,
			FullName:    "Tester One",
			Email:       "t1@test.com",
			APIKey:      SeedAPIKey,
			Credentials: model.ColumnCredentials{cred},
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
	_ = DropTestDB(testDBPath)
	dbase := TestDB(testDBPath)
	if err := AutoMigrate(dbase); err != nil {
		return nil, err
	}
	if err := seedDB(dbase); err != nil {
		return nil, err
	}
	return dbase, nil
}

func TestContact(t *testing.T) {
	Convey("Test contact", t, func() {
		_, err := createTestDB()
		So(err, ShouldBeNil)
		defer DropTestDB(testDBPath)

		pwd, err := os.Getwd()
		So(err, ShouldBeNil)
		svc, err := NewDBService(fmt.Sprintf("file://%s/%s", pwd, testDBPath))
		So(err, ShouldBeNil)
		Convey("lookup credential", func() {
			contact, err := svc.GetContactByCredentialID(SeedCredID)
			So(err, ShouldBeNil)
			So(contact, ShouldNotBeNil)
			So(contact.ID, ShouldEqual, 1)
			So(len(contact.Credentials), ShouldEqual, 1)
			enc := base64.StdEncoding.EncodeToString(contact.Credentials[0].ID)
			So(enc, ShouldEqual, SeedCredID)
		})
		Convey("rotate apikey", func() {
			oc, err := svc.GetContact(1)
			So(err, ShouldBeNil)
			_, err = svc.RotateContactAPIKey(1)
			So(err, ShouldBeNil)
			c, err := svc.GetContact(1)
			So(err, ShouldBeNil)
			So(c.APIKey, ShouldNotEqual, oc.APIKey)
		})
	})
}
