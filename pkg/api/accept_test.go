package api

import (
	"net/http"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAccept(t *testing.T) {
	Convey("Test accept", t, func() {
		req, err := http.NewRequest(http.MethodGet, "/", http.NoBody)
		So(err, ShouldBeNil)
		offers := []string{CtAny, CtJson, CtHtml}
		Convey("check any", func() {
			req.Header.Set("Accept", CtAny)
			accept := NegotiateContentType(req, offers, CtAny)
			So(accept, ShouldEqual, CtAny)
			accept = NegotiateContentType(req, offers, CtHtml)
			So(accept, ShouldEqual, CtAny)
		})
		Convey("check json", func() {
			req.Header.Set("Accept", CtJson)
			accept := NegotiateContentType(req, offers, CtAny)
			So(accept, ShouldEqual, CtJson)
		})

	})
}
