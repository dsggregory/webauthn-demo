package webauthn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"webauthndemo/pkg/db"
	"webauthndemo/pkg/model"
)

const (
	// SessionAuthentication the authenticated session namespace
	SessionAuthentication = "authentication"
	// SessionDiscoverable the Autofill UI session namespace
	SessionDiscoverable = "discoverable"
	// SessionUserID the session cookie that has the logged-in users creds
	SessionUserID     = "user_id"
	AllowAutoRegister = false
)

// Server the WebAuthn "Relying Party" implementation
type Server struct {
	cfg *WebauthnConfig

	mux *mux.Router

	// RenderTemplateFunc the main server's function to render a named template HTML file
	renderTemplateFunc func(http.ResponseWriter, string, any) error

	webAuthn     *webauthn.WebAuthn
	sessionStore *Store
	userDB       *db.DBService

	websiteURL string

	// allowAutoregister create a contact for the registration request if no other contacts exist. This is a seeding function.
	allowAutoregister bool
}

func (s *Server) SessionStore() *Store {
	return s.sessionStore
}

// WebauthnConfig application config for WebAuthn support
type WebauthnConfig struct {
	// WebsiteURL used for default RPOrigins. MUST be the exact URL used to access your site.
	WebsiteURL string
	// StaticPages path to static web pages relative to where the server is started
	StaticPages string
	// Router existing gorilla mux to add routes
	Router *mux.Router
	// RenderTemplateFunc the main server's function to render a named template HTML file
	RenderTemplateFunc func(http.ResponseWriter, string, any) error
	// UserDB where webauthn gets/stores passkeys for the user
	UserDB *db.DBService
	// RPDisplayName relying party's display name for your site
	RPDisplayName string
	// RPID relying party's ID. Generally the domain name (not hostname) for your site.
	// WebAuthn requires this to be a DNS-registered domain that is used to access the website.
	// When it doesn't match, users will not be able to register or login.
	RPID string
	// RPOrigins relying party's possible origins. Optional other origin URLs allowed for WebAuthn requests.
	RPOrigins     []string
	LogMiddleware mux.MiddlewareFunc
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	_, _ = w.Write(dj)
}

// the browser javascript calls this after the user presses the `Register` button and selects a passkey (iCloud, Yubikey, et.al.).
// The function is to return existing registrations for the user where the browser may decline if a credentials.type=public-key has the same ID as the one being registered.
func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username in request. Ex: foo@bar.com"), http.StatusBadRequest)
		return
	}

	l := logrus.WithField("username", username)
	l.Debug("BeginRegistration")

	// get user
	user, err := s.userDB.GetContactByEmail(username)
	// If no users currently exist, we will allow the first to be auto-registered
	allowWithoutInvite := false
	if err != nil || user == nil {
		fc, err := s.userDB.GetFirstContact()
		if s.allowAutoregister && fc == nil && err != nil { // allow as we have no contacts yet
			l.Info("auto-registering FIRST contact in DB")
			allowWithoutInvite = true
			displayName := strings.Split(username, "@")[0]

			user = s.userDB.NewUser(username, displayName)
			if _, err := s.userDB.CreateContact(user); err != nil {
				jsonResponse(w, fmt.Errorf(err.Error()), http.StatusBadRequest)
				return
			}
			s.allowAutoregister = false // no more after this - just for initial admin user
		} else {
			jsonResponse(w, "user not provisioned", http.StatusNotAcceptable)
			return
		}
	}

	// Cannot register without an invite. The initial invite is by another admin, subsequent invites are made
	// by the user so they may register passkeys from other devices.
	if user.RegistrationID == "" && !allowWithoutInvite {
		jsonResponse(w, fmt.Errorf("no pending invite"), http.StatusForbidden)
		return
	}

	// handle this part of the registration ceremony
	registrationID := r.URL.Query().Get("regid") // can register a credential
	if registrationID != user.RegistrationID {
		err = fmt.Errorf("registration denied due to registrationID mismatch")
		l.WithError(err).WithFields(logrus.Fields{
			"regid":      registrationID,
			"expectedID": user.RegistrationID,
		}).Error("registration failed")
		jsonResponse(w, err.Error(), http.StatusForbidden)
		return
	}

	// generate PublicKeyCredentialCreationOptions, session data
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		// This will include the creds we know for the user. The browser will cancel registration if the passkey ID being registered is in this list.
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}

	options, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		registerOptions,
	)
	if err != nil {
		l.WithError(err).Error("BeginRegistration failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = s.sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		l.WithError(err).Error("SaveWebauthnSession")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

// The browser javascript calls this after browser asks user for creds or browser collects the private creds data from browser's store
func (s *Server) finishRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("Finishregistration")

	// get user
	user, err := s.userDB.GetContactByEmail(username)
	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("user not found")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := s.sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		l.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := s.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		l.WithError(err).Error("FinishRegistration failed")
		extra := err.(*protocol.Error).DevInfo
		jsonResponse(w, err.Error()+"\n"+extra, http.StatusBadRequest)
		return
	}

	user.AddCredential(*credential)
	if err := s.userDB.PutUserCredentials(user); err != nil {
		jsonResponse(w, fmt.Errorf(err.Error()), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, "Registration Success", http.StatusOK)
	return
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("BeginLogin")

	// get user
	user, err := s.userDB.GetContactByEmail(username)

	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("no such user")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := s.webAuthn.BeginLogin(user)
	if err != nil {
		l.WithError(err).Error("BeginLogin failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store session data as marshaled JSON.
	// sessionData.Challenge is a JWT and looks like:
	//  * `2kTSuleq0Xz0SFyqwO-kqfHbKIT2PAaGdDaW5E7e4kw`
	err = s.sessionStore.SaveWebauthnSession(SessionAuthentication, sessionData, r, w)
	if err != nil {
		l.WithError(err).Error("SaveWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username := vars["username"]

	l := logrus.WithField("username", username)
	l.Debug("FinishLogin")

	// get user
	user, err := s.userDB.GetContactByEmail(username)

	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("no such user")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := s.sessionStore.GetWebauthnSession(SessionAuthentication, r)
	if err != nil {
		l.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation we should perform additional
	// checks on the returned 'credential'
	cred, err := s.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		l.WithError(err).Error("FinishLogin failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// At this point, we've confirmed the correct authenticator has been
	// provided and it passed the challenge we gave it. We now need to make
	// sure that the sign counter is higher than what we have stored to help
	// give assurance that this credential wasn't cloned.
	if cred.Authenticator.CloneWarning {
		l.WithError(err).Errorf("credential appears to be cloned")
		jsonResponse(w, "credential cloned", http.StatusForbidden)
		return
	}

	// log the user in. Note: caller (e.g. javascript) needs to redirect to dashboard
	err = s.sessionStore.Set(SessionUserID, user.ID, r, w)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// handle successful login
	resp := struct {
		Msg      string
		Username string
	}{
		Msg:      "login success",
		Username: username,
	}
	jsonResponse(w, &resp, http.StatusOK)
}

func (s *Server) beginDiscoverableLogin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		logrus.WithError(err).Error("BeginDiscoverableLogin failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = s.sessionStore.SaveWebauthnSession(SessionDiscoverable, sessionData, r, w)
	if err != nil {
		logrus.WithError(err).Error("SaveWebauthnSession discoverable failed")
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func (s *Server) verifyDiscoverableLogin(w http.ResponseWriter, r *http.Request) {
	// parse the CredentialAssertionResponse from the body
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		logrus.WithError(err).Error("Parse cred req failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := s.sessionStore.GetWebauthnSession(SessionDiscoverable, r)
	if err != nil {
		logrus.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	var validatedContact *model.Contact

	// this takes the parsed credential response, calls the closure to look up the cred, and validates it against session
	cred, err := s.webAuthn.ValidateDiscoverableLogin(func(rawID, userHandle []byte) (user webauthn.User, err error) {
		credIDb64 := base64.StdEncoding.EncodeToString(rawID)
		//logrus.WithField("rawID-b64", credIDb64).Info("validateDiscoverable cred")
		validatedContact, err = s.userDB.GetContactByCredentialID(credIDb64)
		return *validatedContact, err
	}, sessionData, parsedResponse)
	if err != nil {
		logrus.WithError(err).Error("validateDiscoverable failed")
		jsonResponse(w, err, http.StatusExpectationFailed)
		return
	}
	_ = cred

	// At this point, we've confirmed the correct authenticator has been
	// provided and it passed the challenge we gave it. We now need to make
	// sure that the sign counter is higher than what we have stored to help
	// give assurance that this credential wasn't cloned.
	if cred.Authenticator.CloneWarning {
		logrus.WithError(err).Errorf("credential appears to be cloned")
		jsonResponse(w, "credential cloned", http.StatusForbidden)
		return
	}

	// credentials validated - log the user in. Note: caller (e.g. javascript) needs to redirect to dashboard
	err = s.sessionStore.Set(SessionUserID, validatedContact.ID, r, w)
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if validatedContact != nil {
		logrus.WithField("user", validatedContact.Email).Info("verifyDiscoverableLogin success, signing in")
	}
	jsonResponse(w, "OK", http.StatusOK) // must be a json response
}

func (s *Server) DestroySession(w http.ResponseWriter, r *http.Request) {
	// Not a failure as we would invalidate it anyway. It could have failed because the server was restarted.
	_ = s.sessionStore.DeleteWebauthnSession(SessionAuthentication, r, w)
	_ = s.sessionStore.DeleteWebauthnSession(SessionUserID, r, w)
}

// GetSessionUser looks for the webauthn session and returns the contact and adds to the request context.
// It may delete the session if it finds it to be invalid.
func (s *Server) GetSessionUser(w http.ResponseWriter, r *http.Request) *model.Contact {
	session, _ := s.sessionStore.Get(r, WebauthnSession)
	// Load the user from the database and store it in the request context
	const ctxKey = "user"
	var u *model.Contact
	if id, ok := session.Values[SessionUserID]; ok {
		var err error
		u, err = s.userDB.GetContact(id.(uint))
		if err != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey, nil))
		} else {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey, u))
		}
	} else {
		r = r.WithContext(context.WithValue(r.Context(), ctxKey, nil))
	}

	return u
}

func (s *Server) addRoutes(cfg *WebauthnConfig) error {
	var l func(next http.Handler) http.Handler = s.cfg.LogMiddleware

	if l == nil {
		// noop effectively
		l = func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})
		}
	}
	// webauthn endpoints
	s.mux.Handle("/register/begin/{username}", l(http.HandlerFunc(s.beginRegistration))).Methods("GET")
	s.mux.Handle("/register/finish/{username}", l(http.HandlerFunc(s.finishRegistration))).Methods("POST")
	s.mux.Handle("/login/begin/{username}", l(http.HandlerFunc(s.beginLogin))).Methods("GET")
	s.mux.Handle("/login/finish/{username}", l(http.HandlerFunc(s.finishLogin))).Methods("POST")
	s.mux.Handle("/discoverable/begin", l(http.HandlerFunc(s.beginDiscoverableLogin))).Methods("GET")
	s.mux.Handle("/discoverable/finish", l(http.HandlerFunc(s.verifyDiscoverableLogin))).Methods("POST")

	return nil
}

func newServer(cfg *WebauthnConfig) (*Server, error) {
	s := &Server{
		cfg:                cfg,
		mux:                cfg.Router,
		renderTemplateFunc: cfg.RenderTemplateFunc,
		userDB:             cfg.UserDB,
		websiteURL:         cfg.WebsiteURL,
		allowAutoregister:  true, // only for the first time when no other contacts exist
	}

	rpOrigins := []string{s.websiteURL}
	for _, o := range cfg.RPOrigins {
		rpOrigins = append(rpOrigins, o)
	}
	var err error
	s.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName:        cfg.RPDisplayName, // display name for your site
		RPID:                 cfg.RPID,          // generally the domain name for your site
		RPOrigins:            rpOrigins,         // The origin URLs allowed for WebAuthn requests
		EncodeUserIDAsString: false,             // is/not URLEncodedBase64
	})

	if err != nil {
		return nil, fmt.Errorf("%w; failed to create WebAuthn from config", err)
	}

	s.sessionStore, err = NewStore()
	if err != nil {
		return nil, fmt.Errorf("%w; failed to create session store", err)
	}

	return s, nil
}

// NewServer creates a service to handle WebAuthn credentials. This only supports passkeys.
func NewServer(cfg *WebauthnConfig) (*Server, error) {
	s, err := newServer(cfg)
	if err != nil {
		return nil, err
	}

	if err := s.addRoutes(cfg); err != nil {
		return nil, err
	}

	return s, nil
}
