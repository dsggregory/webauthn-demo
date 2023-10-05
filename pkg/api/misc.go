package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

const (
	AuthTypeNone = iota
	AuthTypeAPIKey
	AuthTypeBearer
)

const APIKeyHeader = "X-API-KEY"

// Authorization a parsed HTTP "Authorization" request header
type Authorization struct {
	// Type AuthTypeNone, et.al.
	Type int
	// Value the authorization data
	Value string
}

// GetRequestAuthorization parse the Authorization header from the HTTP request. Returns nil if not there.
func GetRequestAuthorization(req *http.Request) *Authorization {
	auth := Authorization{}

	h := req.Header.Get(APIKeyHeader)
	if h != "" {
		auth.Type = AuthTypeAPIKey
		auth.Value = h
	} else {
		v := req.Header.Get("Authorization")
		if v != "" {
			i := strings.Index(v, " ")
			if i < 0 || strings.ToLower(v[0:i]) != "bearer" {
				return nil
			}
			auth.Type = AuthTypeBearer
			for ; i < len(v); i++ {
				if v[i] != ' ' {
					break
				}
			}
			auth.Value = v[i:]
		} else {
			for _, cv := range req.Cookies() {
				if cv.Name == "access_token" {
					auth.Type = AuthTypeBearer
					auth.Value = cv.Value
				}
			}
		}
	}

	if auth.Type == AuthTypeNone {
		return nil
	}

	return &auth
}

// ErrResponse the form of an internal apigw error returned to client
type ErrResponse struct {
	Msg string `json:"error"`
}

// RespondError respond to caller on APIGW internal errors
func RespondError(w http.ResponseWriter, status int, err error) {
	e := ErrResponse{Msg: err.Error()}
	jmsg, _ := json.Marshal(&e)

	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(jmsg)
}
