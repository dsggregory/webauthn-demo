package api

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"webauthndemo/pkg/model"
)

const (
	AdminAPIPrefix = ""
)

// TODO remove this once we figure out how to send a properly mocked webauthn session cookie in tests
var InTest = false

const XTestAuthHeader = "X-TEST-AUTH"

func (s *Server) testLoginRequired(next http.Handler, w http.ResponseWriter, r *http.Request) {
	logrus.Warn("USING TEST AUTH")
	h := r.Header.Get(XTestAuthHeader)
	if h != "" {
		next.ServeHTTP(w, r)
		return
	}
	http.Redirect(w, r, "/signin", http.StatusTemporaryRedirect)
}

// LoginRequired middleware to check that webauthn session is valid before calling the protected handler
func (s *Server) adminLoginRequired(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if InTest {
			s.testLoginRequired(next, w, r)
			return
		}

		u := s.webautnSvc.GetSessionUser(w, r)

		if u != nil {
			// If we have a valid admin (customer_id=0) user, allow access to the handler. Otherwise,
			// redirect to the main login page.
			if u.CustomerID != 0 { // NOT admin, so fail hard and not even redirect back to signin
				logrus.WithFields(logrus.Fields{
					"email": u.Email,
				}).Error("rejecting non-admin user session")
				s.webautnSvc.DestroySession(w, r)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)

			return
		}
		logrus.WithFields(logrus.Fields{
			"user": u,
		}).Debug("auth redirect")
		http.Redirect(w, r, "/signin", http.StatusTemporaryRedirect)
	})
}

// adminAddAPIKey PUT rotate (or create) contact's api key
func (s *Server) adminAddAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	cid, ok := vars["contact_id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	contact_id, err := strconv.Atoi(cid)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	contact, err := s.db.RotateContactAPIKey(uint(contact_id))
	if err != nil {
		RespondError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	body, _ := json.Marshal(&contact)
	_, _ = w.Write(body)
}

func (s *Server) adminRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	cid, ok := vars["contact_id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	contact_id, err := strconv.Atoi(cid)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err = s.db.RevokeContactAPIKey(uint(contact_id)); err != nil {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func (s *Server) adminAPIKey(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		s.adminAddAPIKey(w, r)
	case http.MethodDelete:
		s.adminRevokeAPIKey(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (s *Server) adminCreateCustomer(w http.ResponseWriter, r *http.Request) {
	c := model.Customer{}
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		RespondError(w, http.StatusBadRequest, err)
		return
	}

	c.ID = 0
	if err := s.db.CreateCustomer(&c); err != nil {
		RespondError(w, http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	body, _ := json.Marshal(&c)
	_, _ = w.Write(body)
}

func (s *Server) adminDeleteCustomer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	cid, ok := vars["customer_id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	customer_id, err := strconv.Atoi(cid)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := s.db.DeleteCustomer(uint(customer_id)); err != nil {
		RespondError(w, http.StatusInternalServerError, err)
	}
}

func (s *Server) contactRegistryLink(contact *model.Contact) string {
	return fmt.Sprintf("%s/signin?regid=%s&username=%s", s.cfg.WebsiteURL, url.QueryEscape(contact.RegistrationID), url.QueryEscape(contact.Email))
}

func (s *Server) adminProvisionContact(w http.ResponseWriter, r *http.Request) {
	var values url.Values
	defaultAccept := CtHtml

	if k := r.Header.Get("Content-Type"); k == CtFormEnc {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		values, _ = url.ParseQuery(string(body))
	} else {
		defaultAccept = CtJson
		values = r.URL.Query()
	}

	regID, err := s.db.GenerateAPIKey(16)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cidstr, ok := values["customer_id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	contactID, err := strconv.Atoi(cidstr[0])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	email, ok := values["username"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fullname := strings.Split(email[0], "@")[0]

	apikey, err := s.db.GenerateAPIKey(-1)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	contact := model.Contact{
		CustomerID:     uint(contactID),
		FullName:       fullname,
		Email:          email[0],
		RegistrationID: regID,
		APIKey:         apikey,
	}
	if _, err := s.db.CreateContact(&contact); err != nil {
		RespondError(w, http.StatusInternalServerError, err)
	}

	accept := NegotiateContentType(r, []string{CtAny, CtJson, CtHtml}, defaultAccept)
	switch accept {
	case CtJson:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&contact)
	case CtHtml, CtAny:
		ru := fmt.Sprintf("/signin?username=%s&regid=%s", contact.Email, contact.RegistrationID)
		_ = s.renderTemplate(w, "userCreated.gohtml", ru)
	}
}

func (s *Server) adminCreateContact(w http.ResponseWriter, r *http.Request) {
	c := model.Contact{}
	err := json.NewDecoder(r.Body).Decode(&c)
	if err != nil {
		RespondError(w, http.StatusBadRequest, err)
		return
	}

	c.ID = 0
	if _, err := s.db.CreateContact(&c); err != nil {
		RespondError(w, http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	body, _ := json.Marshal(&c)
	_, _ = w.Write(body)
}

func (s *Server) adminDeleteContact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	vars := mux.Vars(r)
	cid, ok := vars["contact_id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	contact_id, err := strconv.Atoi(cid)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := s.db.DeleteContact(uint(contact_id)); err != nil {
		RespondError(w, http.StatusInternalServerError, err)
	}
}

// uiAdminInviteContact highly tuned to what contacts.gohtml requests. Response tailored to whether an invite exists or had to be created.
func (s *Server) uiAdminInviteContact(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	cid, ok := vars["contact_id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	contact_id, err := strconv.Atoi(cid)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	contact, err := s.db.GetContact(uint(contact_id))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if contact.RegistrationID == "" {
		// create a new invite
		contact, err = s.db.InviteContactAPIKey(uint(contact_id))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	accept := NegotiateContentType(r, []string{CtAny, CtJson, CtHtml}, CtHtml)
	switch accept {
	case CtJson:
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(contact)
		_, _ = w.Write(body)
	case CtHtml, CtAny:
		ru := struct {
			Contact *model.Contact
			Link    string
		}{
			Contact: contact,
			Link:    s.contactRegistryLink(contact),
		}
		_ = s.renderTemplate(w, "invite.gohtml", &ru)
	}
}

func (s *Server) addAdminRoutes(l mux.MiddlewareFunc) {
	// admin routes require webauthn session cookie
	var authWrap func(next http.Handler) http.HandlerFunc = s.adminLoginRequired

	s.mux.Handle(AdminAPIPrefix+"/apikey/{contact_id}", l(authWrap(http.HandlerFunc(s.adminAPIKey)))).Methods(http.MethodDelete, http.MethodPut)
	s.mux.Handle(AdminAPIPrefix+"/customer", l(authWrap(http.HandlerFunc(s.adminCreateCustomer)))).Methods(http.MethodPost)
	s.mux.Handle(AdminAPIPrefix+"/customer/{customer_id}", l(authWrap(http.HandlerFunc(s.adminDeleteCustomer)))).Methods(http.MethodDelete)
	s.mux.Handle(AdminAPIPrefix+"/contact", l(authWrap(http.HandlerFunc(s.adminCreateContact)))).Methods(http.MethodPost)
	s.mux.Handle(AdminAPIPrefix+"/contact/{contact_id}", l(authWrap(http.HandlerFunc(s.adminDeleteContact)))).Methods(http.MethodDelete)
	s.mux.Handle(AdminAPIPrefix+"/contact/provision", l(authWrap(http.HandlerFunc(s.adminProvisionContact)))).Methods(http.MethodPost)
	s.mux.Handle(AdminAPIPrefix+"/contact/{contact_id}/inviteUI", l(authWrap(http.HandlerFunc(s.uiAdminInviteContact)))).Methods(http.MethodGet)
	s.mux.Handle(AdminAPIPrefix+"/contact/provision", l(authWrap(http.HandlerFunc(s.adminProvisionContact)))).Methods(http.MethodPost)
}
