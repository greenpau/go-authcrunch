// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn

import (
	"context"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type CustomResponseWriter struct {
	body       []byte
	statusCode int
	header     http.Header
}

func NewCustomResponseWriter() *CustomResponseWriter {
	return &CustomResponseWriter{
		header: http.Header{},
	}
}

func (w *CustomResponseWriter) Header() http.Header {
	return w.header
}

func (w *CustomResponseWriter) Write(b []byte) (int, error) {
	w.body = b
	// implement it as per your requirement
	return 0, nil
}

func (w *CustomResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func TestInjectRedirectURL(t *testing.T) {

	t.Run("Strips login hint from redirect URL if present", func(t *testing.T) {
		reqURL := url.URL{
			Scheme:   "https",
			Host:     "foo.bar",
			Path:     "/myPage",
			RawQuery: "redirect_url=https%3A%2F%2Ffoo.bar%2Fredir%3Flogin_hint%3Dmy%40email.com",
		}
		r := http.Request{URL: &reqURL, Method: "GET"}
		f, _ := cookie.NewFactory(nil)
		p := Portal{
			config: &PortalConfig{
				Name: "somePortal",
			},
			logger: zap.L(),
			cookie: f,
		}
		request := requests.NewRequest()

		p.injectRedirectURL(context.Background(), NewCustomResponseWriter(), &r, request)

		cookieParts := strings.Split(request.Response.RedirectURL, ";")
		tests.EvalObjectsWithLog(t, "redirect url", "AUTHP_REDIRECT_URL=https://foo.bar/redir", cookieParts[0], []string{})
	})
}

func TestRefererSanitization(t *testing.T) {
	t.Run("should sanitize referral url if its malformed in a way that is intended to cause a XSS", func(t *testing.T) {
		reqURL := url.URL{
			Scheme:   "https",
			Host:     "foo.bar",
			Path:     "/myPage",
			RawQuery: "redirect_url=https%3A%2F%2Ffoo.bar%2Fredir",
		}
		r := http.Request{URL: &reqURL, Method: "GET"}
		r.Header = make(http.Header)
		maliciousUrl := "https://www.google.com/search?hl=en&q=testing'\"()&%<acx><ScRiPt >alert(9854)</ScRiPt>"
		r.Header.Set("Referer", maliciousUrl)
		f, _ := cookie.NewFactory(nil)
		uiFactory := ui.NewFactory()
		p := Portal{
			config: &PortalConfig{
				Name: "somePortal",
				UI: &ui.Parameters{
					Theme: "",
				},
			},
			logger: zap.L(),
			cookie: f,
			ui:     uiFactory,
		}
		_ = p.configureUserInterface()
		request := requests.NewRequest()
		rw := NewCustomResponseWriter()

		_ = p.handleHTTPError(context.Background(), rw, &r, request, 404)
		rb := string(rw.body)

		tests.EvalObjectsWithLog(t, "sanitized url", true, strings.Contains(rb, "https://www.google.com/search?hl=en%26q=testing%27%22()%26%%3Cacx%3E%3CScRiPt %3Ealert(9854)%3C/ScRiPt%3E"), []string{})
	})
}
