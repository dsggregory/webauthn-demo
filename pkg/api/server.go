package api

import (
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	jwt2 "github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
	"webauthn/pkg/database"
	"webauthn/pkg/jwt"
	"webauthn/pkg/session"
)

// Server the WebAuthn "Relying Party" implementation
type Server struct {
	href       string
	listenAddr string
	mux        *mux.Router

	webAuthn     *webauthn.WebAuthn
	sessionStore *session.Store
	userDB       *database.UserDB

	// jwtSvc to create a JWT bearer token sent on response to /login
	jwtSvc *jwt.JWT
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	_, _ = w.Write(dj)

	logrus.WithField("httpStatusCode", c).Debug(string(dj))
}

// the browser javascript calls this after the user presses the `Register` button
func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {

	// get username
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	l := logrus.WithField("username", username)
	l.Debug("BeginRegistration")

	// get user
	user, err := s.userDB.GetUser(username)
	// user doesn't exist, create new user
	// WARN: only if you want to allow auto registration of any user
	if err != nil {
		displayName := strings.Split(username, "@")[0]
		user = database.NewUser(username, displayName)
		if err := s.userDB.PutUser(user); err != nil {
			jsonResponse(w, fmt.Errorf(err.Error()), http.StatusBadRequest)
			return
		}
	}

	// generate PublicKeyCredentialCreationOptions, session data
	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
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
	user, err := s.userDB.GetUser(username)
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
	user, err := s.userDB.GetUser(username)

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
	err = s.sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
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
	user, err := s.userDB.GetUser(username)

	// user doesn't exist
	if err != nil {
		l.WithError(err).Error("no such user")
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// load the session data
	sessionData, err := s.sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		l.WithError(err).Error("GetWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation we should perform additional
	// checks on the returned 'credential'
	_, err = s.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		l.WithError(err).Error("FinishLogin failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// create a JWT bearer token and add to the header response
	claims := jwt2.MapClaims{"iss": s.href}
	token := s.jwtSvc.SignClaims(claims, time.Now().Add(5*time.Minute))
	w.Header().Set("Authorization", "Bearer "+token)

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

// GET /logout
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("Logout")

	// TODO how do we know this is for the same user that's passed in?

	if err := s.sessionStore.DeleteWebauthnSession("authentication", r, w); err != nil {
		logrus.WithError(err).Error("DeleteWebauthnSession failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonResponse(w, "Logout Success", http.StatusOK)
}

// test to figure out how client would validate a webauthn-session cookie outside of login flow
func (s *Server) validate(w http.ResponseWriter, r *http.Request) error {
	// load the session data from the `webauthn-session` cookie
	sessionData, err := s.sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		return fmt.Errorf("%w; validate GetWebauthnSession failed", err)
	}

	// TODO fix type inconsistency for UserID
	u := database.User{ID: 0 /*sessionData.UserID*/} // 0 will fail to validate
	_, err = s.webAuthn.ValidateLogin(&u, sessionData, nil)
	return err
}

// GET /state
func (s *Server) showState(w http.ResponseWriter, r *http.Request) {
	if err := s.validate(w, r); err != nil {
		logrus.WithError(err).Error("validate failed")
		jsonResponse(w, err.Error(), http.StatusBadRequest)
	}
	_, _ = w.Write([]byte(`ok`))
}

// Start
func (s *Server) Start() {
	logrus.Info("starting server at ", s.listenAddr)
	logrus.Fatal(http.ListenAndServe(s.listenAddr, s.mux))
}

// NewServer
func NewServer(addr string) (*Server, error) {
	a := strings.Split(addr, ":")
	if len(a) != 2 {
		return nil, fmt.Errorf("requires hostname from listen address to provide as RPOrigin")
	}

	s := &Server{
		listenAddr: addr,
		href:       "http://" + addr,
	}

	var err error
	s.webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName:        "Foobar Corp.",   // display name for your site
		RPID:                 "localhost",      // generally the domain name for your site
		RPOrigins:            []string{s.href}, // The origin URLs allowed for WebAuthn requests
		EncodeUserIDAsString: false,            // is/not URLEncodedBase64
	})

	if err != nil {
		return nil, fmt.Errorf("%w; failed to create WebAuthn from config", err)
	}

	s.userDB, err = database.NewDb("file:./users.db")
	if err != nil {
		return nil, err
	}

	s.sessionStore, err = session.NewStore()
	if err != nil {
		return nil, fmt.Errorf("%w; failed to create session store", err)
	}

	r := mux.NewRouter()
	s.mux = r

	// webauthn endpoints
	r.HandleFunc("/register/begin/{username}", s.beginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", s.finishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", s.beginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", s.finishLogin).Methods("POST")

	r.HandleFunc("/logout", s.logout).Methods("GET")
	r.HandleFunc("/state", s.showState).Methods("GET")

	// to sign JWT bearer token - considering this could be the only authorization flow
	s.jwtSvc, err = jwt.NewJWT("./TestCertificate.crt")
	if err != nil {
		return nil, err
	}
	jwks := s.jwtSvc.NewJWKService()
	r.HandleFunc("/well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks.WriteResponse(w, r)
	}).Methods(http.MethodGet)

	// for static pages e.g. javascript
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./views")))

	return s, nil
}
