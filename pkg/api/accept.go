package api

import (
	"net/http"
	"strings"
)

const (
	CtJson    = "application/json"
	CtHtml    = "text/html"
	CtAny     = "*/*"
	CtFormEnc = "application/x-www-form-urlencoded"
)

func NegotiateContentType(r *http.Request, offers []string, defaultOffer string) string {
	bestOffer := defaultOffer
	bestQ := -1.0
	bestWild := 3
	specs := ParseAccept(r.Header, "Accept")
	for _, offer := range offers {
		for _, spec := range specs {
			switch {
			case spec.Q == 0.0:
				// ignore
			case spec.Q < bestQ:
				// better match found
			case spec.Value == "*/*":
				if spec.Q > bestQ || bestWild > 2 {
					bestQ = spec.Q
					bestWild = 2
					bestOffer = offer
				}
			case strings.HasSuffix(spec.Value, "/*"):
				if strings.HasPrefix(offer, spec.Value[:len(spec.Value)-1]) &&
					(spec.Q > bestQ || bestWild > 1) {
					bestQ = spec.Q
					bestWild = 1
					bestOffer = offer
				}
			default:
				if spec.Value == offer &&
					(spec.Q > bestQ || bestWild > 0) {
					bestQ = spec.Q
					bestWild = 0
					bestOffer = offer
				}
			}
		}
	}
	return bestOffer
}

type octetType byte

var octetTypes = []octetType{0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

const (
	isToken octetType = 1 << iota
	isSpace
)

func expectTokenSlash(s string) (token, rest string) {
	i := 0
	for ; i < len(s); i++ {
		b := s[i]
		if (octetTypes[b]&isToken == 0) && b != '/' {
			break
		}
	}
	return s[:i], s[i:]
}

func expectQuality(s string) (q float64, rest string) {
	switch {
	case len(s) == 0:
		return -1, ""
	case s[0] == '0':
		q = 0
	case s[0] == '1':
		q = 1
	default:
		return -1, ""
	}
	s = s[1:]
	if !strings.HasPrefix(s, ".") {
		return q, s
	}
	s = s[1:]
	i := 0
	n := 0
	d := 1
	for ; i < len(s); i++ {
		b := s[i]
		if b < '0' || b > '9' {
			break
		}
		n = n*10 + int(b) - '0'
		d *= 10
	}
	return q + float64(n)/float64(d), s[i:]
}

func skipSpace(s string) (rest string) {
	i := 0
	for ; i < len(s); i++ {
		if octetTypes[s[i]]&isSpace == 0 {
			break
		}
	}
	return s[i:]
}

// AcceptSpec describes an Accept* header.
type AcceptSpec struct {
	Value string
	Q     float64
}

func ParseAccept(header http.Header, key string) (specs []AcceptSpec) {
loop:
	for _, s := range header[key] {
		for {
			var spec AcceptSpec
			spec.Value, s = expectTokenSlash(s)
			if spec.Value == "" {
				continue loop
			}
			spec.Q = 1.0
			s = skipSpace(s)
			if strings.HasPrefix(s, ";") {
				s = skipSpace(s[1:])
				if !strings.HasPrefix(s, "q=") {
					continue loop
				}
				spec.Q, s = expectQuality(s[2:])
				if spec.Q < 0.0 {
					continue loop
				}
			}
			specs = append(specs, spec)
			s = skipSpace(s)
			if !strings.HasPrefix(s, ",") {
				continue loop
			}
			s = skipSpace(s[1:])
		}
	}
	return
}
