package model

import (
	"bytes"
	"encoding/binary"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/gorm"
)

type Customer struct {
	gorm.Model
	Name string
}

// Contact a database model that also satisfies the webauthn.User interface
type Contact struct {
	gorm.Model
	CustomerID uint `gorm:"index"`
	FullName   string
	Email      string `gorm:"unique;not null"`
	// RegistrationID a one-time random ID to use in user registration ceremony. This allows the user to register a passkey credential.
	//
	// The registration ceremony is:
	//   * an admin creates a user
	//   * admin passes the registration URL with one-time ID to user. The URL contains the regid query param that must match user.RegistrationID
	//   * user browses portal, enters his email address, and clicks register
	//   * the browser asks user to create a passkey
	//   * the server is called with the credential to complete registration and give the user access
	RegistrationID string
	APIKey         string
	Credentials    ColumnCredentials `json:"credentials,omitempty" gorm:"index;type:VARCHAR(4096)"`
}

// WebAuthnID returns the user's ID
func (u Contact) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.ID))
	return buf
}

// WebAuthnName returns the user's username
func (u Contact) WebAuthnName() string {
	return u.Email
}

// WebAuthnDisplayName returns the user's display Email
func (u Contact) WebAuthnDisplayName() string {
	return u.FullName
}

// WebAuthnIcon is not (yet) implemented
func (u Contact) WebAuthnIcon() string {
	return ""
}

// GetCredentialByID returns the offset into u.Credentials for the found credential or -1 if not found
func (u *Contact) GetCredentialByID(id []byte) int {
	for i, uc := range u.Credentials {
		if bytes.Equal(uc.ID, id) {
			return i
		}
	}
	return -1
}

// AddCredential associates the credential to the user record. Can also be used to update (not in DB) the credential for the user
func (u *Contact) AddCredential(cred webauthn.Credential) {
	// Check to see if we are replacing the credential data. This use case is largely to update the cred.SignCount.
	if ucoff := u.GetCredentialByID(cred.ID); ucoff >= 0 {
		u.Credentials[ucoff] = cred
	} else {
		// a new credential
		u.Credentials = append(u.Credentials, cred)
	}
}

// WebAuthnCredentials returns Credentials owned by the user
func (u Contact) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all a user's Credentials
func (u Contact) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.Credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

// ContactCompany for use in joins
type ContactCompany struct {
	Contact
	CustomerName string
}
