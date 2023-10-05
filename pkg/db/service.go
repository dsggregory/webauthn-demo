package db

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"webauthndemo/pkg/model"
)

type DBService struct {
	db *gorm.DB
}

func (s *DBService) Db() *gorm.DB {
	return s.db
}

func (s *DBService) SetDb(db *gorm.DB) {
	s.db = db
}

// CreateCustomer creates the customer 'c' and fills the created record in 'c'
func (s *DBService) CreateCustomer(c *model.Customer) error {
	tx := s.db.Begin()
	if err := tx.Create(&c).Error; err != nil {
		tx.Rollback()
		return err
	}

	if c.ID == 0 {
		if err := tx.Where(c.ID).Find(&c).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	if err := tx.Where("id=?", c.ID).Find(c).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func (s *DBService) DeleteCustomer(cid uint) error {
	c := model.Customer{}
	tx := s.db.Begin()
	if err := tx.Create(&c).Error; err != nil {
		tx.Rollback()
		return err
	}

	c.ID = cid
	if c.ID != 0 {
		if err := tx.Where(c.ID).Delete(&c).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func (s *DBService) CustomerByAPIKey(apiKey string) *model.Customer {
	var c model.Customer
	// select customers.* from contacts join customers on customers.id = contacts.customer_id and contacts.api_key = 'deadbeef';
	err := s.db.Raw("select customers.* from contacts join customers on customers.id = contacts.customer_id and contacts.api_key = ?", apiKey).Find(&c).Error
	//	err := s.db.Joins("JOIN customers on customers.id = contacts.customer_id and contacts.api_key = ?", apiKey).Find(&c).Error

	//	err := s.db.Joins("Customer", s.db.Where(&model.Contact{APIKey: apiKey})).Find(&c).Error
	if err != nil || c.ID == 0 {
		return nil
	}

	return &c
}

func (s *DBService) GetCustomer(id uint) (*model.Customer, error) {
	var c model.Customer
	err := s.db.First(&c, id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, err
		}
	}
	return &c, err
}

// CreateContact creates the contact 'c' and fills the created record in 'c'
func (s *DBService) CreateContact(c *model.Contact) error {
	tx := s.db.Begin()
	if err := tx.Create(&c).Error; err != nil {
		tx.Rollback()
		return err
	}

	if c.ID == 0 {
		if err := tx.Where(c.ID).Find(&c).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	if err := tx.Where("id=?", c.ID).Find(c).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// NewUser begins a new webauthn user
func (s *DBService) NewUser(email, displayname string) *model.Contact {
	return &model.Contact{Email: email, FullName: displayname}
}

// PutUserCredentials update webauthn user record with current sets of known credentials for the user. It invalidates
// any current registration_id for the user.
func (s *DBService) PutUserCredentials(contact *model.Contact) error {
	return s.db.Model(&contact).Update("credentials", contact.Credentials).Update("registration_id", "").Error
}

func (s *DBService) DeleteContact(cid uint) error {
	c := model.Contact{}
	tx := s.db.Begin()
	if err := tx.Create(&c).Error; err != nil {
		tx.Rollback()
		return err
	}

	c.ID = cid
	if c.ID != 0 {
		if err := tx.Where(c.ID).Delete(&c).Error; err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}

func (s *DBService) GetContact(id uint) (*model.Contact, error) {
	var c model.Contact
	err := s.db.First(&c, id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, err
		}
	}
	return &c, err
}

func (s *DBService) GetContactByEmail(email string) (*model.Contact, error) {
	user := &model.Contact{Email: email}
	if err := s.db.Where(user).First(user).Error; err != nil {
		return nil, fmt.Errorf("%w; error getting contact '%s': does not exist", err, email)
	}

	return user, nil
}

// GetFirstContact a test to see if we have any contacts registered
func (s *DBService) GetFirstContact() (*model.Contact, error) {
	var c model.Contact
	err := s.db.First(&c).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, err
		}
	}
	return &c, err
}

// GetContactByCredentialID get contact by passkey ID
func (s *DBService) GetContactByCredentialID(creb64 string) (*model.Contact, error) {
	c := model.Contact{}
	q := fmt.Sprintf(`%%"ID":"%s",%%`, creb64)
	err := s.db.Raw("select * from contacts where credentials like ?", q).Find(&c).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *DBService) UpdateContact(c *model.Contact) error {
	if c.ID == 0 {
		return gorm.ErrRecordNotFound
	}

	havc, err := s.GetContact(c.ID)
	if havc == nil {
		if err == nil {
			return gorm.ErrRecordNotFound
		} else {
			return err
		}
	}

	tx := s.db.Begin()
	txwhere := tx.Where("id=?", c.ID)
	if err := txwhere.Save(c).Error; err != nil {
		tx.Rollback()
		return err
	}
	if txwhere.RowsAffected != 1 {
		tx.Rollback()
		return gorm.ErrRecordNotFound
	}
	if err := txwhere.Find(c).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func (s *DBService) GenerateAPIKey(length int) (string, error) {
	if length < 0 {
		length = 32
	}
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *DBService) RotateContactAPIKey(contact_id uint) (*model.Contact, error) {
	contact, err := s.GetContact(contact_id)
	if contact == nil {
		if err == nil {
			return nil, gorm.ErrRecordNotFound
		} else {
			return nil, err
		}
	}

	apikey, err := s.GenerateAPIKey(-1)
	if err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	txwhere := tx.Where("id=?", contact_id)
	contact.APIKey = apikey
	if err := txwhere.Save(contact).Error; err != nil {
		tx.Rollback()
		return nil, err
	}
	if err := txwhere.Find(contact).Error; err != nil {
		tx.Rollback()
		return nil, err
	}

	return contact, tx.Commit().Error
}

func (s *DBService) RevokeContactAPIKey(contact_id uint) error {
	contact, err := s.GetContact(contact_id)
	if contact == nil {
		if err == nil {
			return gorm.ErrRecordNotFound
		} else {
			return err
		}
	}

	contact.APIKey = "" // revoked

	tx := s.db.Begin()
	txwhere := tx.Where("id=?", contact_id)
	if err := txwhere.Save(contact).Error; err != nil {
		tx.Rollback()
		return err
	}
	if err := txwhere.Find(contact).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func NewDBService(dsn string) (*DBService, error) {
	dbg := logrus.GetLevel() == logrus.DebugLevel
	db, err := New(dsn, dbg)
	if err != nil {
		return nil, err
	}
	if err = AutoMigrate(db); err != nil {
		logrus.WithError(err).Warn("cannot auto migrate DB")
	}

	return &DBService{db: db}, nil
}
