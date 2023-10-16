package api

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"html/template"
	"net/http"
	"net/url"
	"sync"
	"time"
	"webauthndemo/pkg/config"
	"webauthndemo/pkg/db"
	webauthnapi "webauthndemo/pkg/webauthn"
)

type Server struct {
	cfg *config.AppSettings
	// mux we use gorilla mux so we can handle query path parsing
	mux           *mux.Router
	svr           *http.Server
	templates     *template.Template
	wg            *sync.WaitGroup
	db            *db.DBService
	webautnSvc    *webauthnapi.Server
	logMiddleware mux.MiddlewareFunc
}

func (s *Server) SetSvr(svr *http.Server) {
	s.svr = svr
}

// index renders the dashboard index page, displaying the created credential
// as well as any other credentials previously registered by the authenticated
// user.
func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	_ = s.renderTemplate(w, "dashboard.gohtml", nil)
}

// authenticate renders the sign-in/register page
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) {
	_ = s.renderTemplate(w, "/signin.html", nil)
}

// GET /logout
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("Logout")

	s.webautnSvc.DestroySession(w, r)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func health(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"URL":    r.URL,
		"Method": r.Method,
		"Remote": r.RemoteAddr,
	}).Debug("health request")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) addHealthRoutes() {
	s.mux.Handle("/health", http.HandlerFunc(health))
	s.mux.Handle("/health/", http.HandlerFunc(health)) // I like to configure /health/liveness as liveness probe endpoint
}

// Stop shuts down the web server
func (s *Server) Stop(ctx context.Context) error {
	if s.svr == nil {
		return nil
	}
	err := s.svr.Shutdown(ctx)
	if err == nil {
		s.wg.Wait()
	}
	return err
}

// StartServer starts the proxy web service and writes to `errc` when the service exits. The returned server and waitgroup are to be used by the caller during shutdown.
func (s *Server) StartServer(errc chan<- error) {
	s.svr = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.mux,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	s.wg = &sync.WaitGroup{}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		errc <- s.svr.ListenAndServe()
	}()
}

func (s *Server) newRouter() error {
	var l func(next http.Handler) http.Handler = s.logMiddleware

	s.addHealthRoutes()
	s.addAdminRoutes(l)

	s.mux.HandleFunc("/signin", s.authenticate).Methods("GET") // the login page
	s.mux.HandleFunc("/logout", s.logout).Methods("GET")
	s.mux.HandleFunc("/dashboard", s.adminLoginRequired(http.HandlerFunc(s.index))).Methods("GET")
	s.mux.HandleFunc("/", s.adminLoginRequired(http.HandlerFunc(s.index))).Methods("GET")

	// for static pages e.g. javascript
	s.mux.PathPrefix("/").Handler(http.FileServer(http.Dir(s.cfg.StaticPages)))

	return nil
}

// NewServer creates an instance of the API. See StartServer().
func NewServer(cfg *config.AppSettings, db *db.DBService) (*Server, error) {
	s := &Server{
		cfg:           cfg,
		db:            db,
		mux:           mux.NewRouter(),
		logMiddleware: NewLoggingMiddleware,
	}
	_ = s.LoadTemplates()

	// enable Webauthn login
	wu, err := url.Parse(cfg.WebsiteURL)
	if err != nil {
		return nil, err
	}
	s.webautnSvc, err = webauthnapi.NewServer(&webauthnapi.WebauthnConfig{
		WebsiteURL:         cfg.WebsiteURL,
		Router:             s.mux,
		RenderTemplateFunc: s.renderTemplate,
		UserDB:             db,
		RPDisplayName:      "Webauthn Demo API",
		RPID:               wu.Hostname(),
		RPOrigins:          nil,
	})
	if err != nil {
		return nil, err
	}

	// add routes
	if err := s.newRouter(); err != nil {
		return nil, err
	}

	return s, nil
}
