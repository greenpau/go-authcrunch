// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestCrossDeviceOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, url, origin, site string
		duplicate, allow        bool
	}{
		{name: "same origin", url: "https://portal.test/auth/cross-device/start", origin: "https://portal.test", site: "same-origin", allow: true},
		{name: "missing", url: "https://portal.test/auth/cross-device/start"},
		{name: "opaque", url: "https://portal.test/auth/cross-device/start", origin: "null"},
		{name: "cross origin", url: "https://portal.test/auth/cross-device/start", origin: "https://evil.test"},
		{name: "same site sibling", url: "https://portal.test/auth/cross-device/start", origin: "https://portal.test", site: "same-site"},
		{name: "cross site", url: "https://portal.test/auth/cross-device/start", origin: "https://portal.test", site: "cross-site"},
		{name: "duplicate", url: "https://portal.test/auth/cross-device/start", origin: "https://portal.test", duplicate: true},
		{name: "http", url: "http://portal.test/auth/cross-device/start", origin: "http://portal.test"},
		{name: "default port", url: "https://portal.test:443/auth/cross-device/start", origin: "https://portal.test", allow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.url, nil)
			r.RequestURI = r.URL.RequestURI()
			if tc.origin != "" {
				r.Header.Add("Origin", tc.origin)
			}
			if tc.duplicate {
				r.Header.Add("Origin", tc.origin)
			}
			if tc.site != "" {
				r.Header.Set("Sec-Fetch-Site", tc.site)
			}
			if validCrossDeviceOrigin(r) != tc.allow {
				t.Fatal("origin boundary mismatch")
			}
		})
	}
}

func TestCrossDeviceForm(t *testing.T) {
	const contentType = "application/x-www-form-urlencoded"
	for _, tc := range []struct {
		name, body string
		types      []string
		status     int
	}{
		{name: "ordinary", body: "key=body", types: []string{contentType}},
		{name: "charset", body: "key=body", types: []string{contentType + "; charset=UTF-8"}},
		{name: "exact limit", body: "padding=" + strings.Repeat("x", 4096-len("padding=")), types: []string{contentType}},
		{name: "over limit", body: "padding=" + strings.Repeat("x", 4097-len("padding=")), types: []string{contentType}, status: http.StatusRequestEntityTooLarge},
		{name: "malformed encoding", body: "key=%zz", types: []string{contentType}, status: http.StatusBadRequest},
		{name: "duplicate field", body: "key=one&%6bey=two", types: []string{contentType}, status: http.StatusBadRequest},
		{name: "missing type", body: "key=body", status: http.StatusBadRequest},
		{name: "malformed type", types: []string{contentType + "; charset"}, status: http.StatusBadRequest},
		{name: "duplicate type", types: []string{contentType, contentType}, status: http.StatusBadRequest},
		{name: "unsupported type", types: []string{"application/json"}, status: http.StatusUnsupportedMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://portal.test/auth/cross-device/start?key=query", strings.NewReader(tc.body))
			r.ContentLength = -1 // The bound must not depend on a declared length.
			r.Header["Content-Type"] = tc.types
			if status := parseCrossDeviceForm(httptest.NewRecorder(), r); status != tc.status {
				t.Fatalf("HTTP status %d, want %d", status, tc.status)
			}
			if tc.status == 0 && tc.body == "key=body" && r.PostForm.Get("key") != "body" {
				t.Fatal("query data replaced the body value")
			}
		})
	}
}

func TestCrossDeviceAllowedMethods(t *testing.T) {
	p := &Portal{crossDevice: newCrossDeviceStore(time.Now)}
	for _, tc := range []struct{ path, allow string }{
		{"/cross-device", "GET"},
		{"/cross-device/activate", "GET"},
		{"/cross-device/confirm", "GET, POST"},
		{"/cross-device/start", "POST"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "https://portal.test/auth"+tc.path, nil)
			r.RequestURI = r.URL.RequestURI()
			rr := requests.NewRequest()
			rr.Upstream.BasePath = "/auth/"
			w := httptest.NewRecorder()
			if err := p.handleCrossDevice(t.Context(), w, r, rr); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != tc.allow {
				t.Fatalf("HTTP %d, Allow %q; want 405, %q", w.Code, w.Header().Get("Allow"), tc.allow)
			}
		})
	}
}

func TestCrossDeviceDuplicateBrowserCookies(t *testing.T) {
	f, err := cookie.NewFactory(cookie.NewConfig())
	if err != nil {
		t.Fatal(err)
	}
	p := &Portal{cookie: f}
	r := httptest.NewRequest(http.MethodGet, "https://portal.test/auth/cross-device/confirm", nil)
	value := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	r.AddCookie(&http.Cookie{Name: f.CrossDeviceSessionIDCookieName, Value: value})
	if p.crossDeviceBinding(r) != value {
		t.Fatal("valid binding rejected")
	}
	r.AddCookie(&http.Cookie{Name: f.CrossDeviceSessionIDCookieName, Value: value})
	if p.crossDeviceBinding(r) != "" {
		t.Fatal("ambiguous browser binding accepted")
	}
}

func TestCrossDeviceCompletionFamilyReference(t *testing.T) {
	for _, familyID := range []string{"", "committed-local-family"} {
		t.Run("family="+familyID, func(t *testing.T) {
			store, _, entry, _, proof := crossDeviceStoreFixture(t)
			factory, err := cookie.NewFactory(cookie.NewConfig())
			if err != nil {
				t.Fatal(err)
			}
			p := &Portal{crossDevice: store, cookie: factory}
			const binding = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			if err := store.bind(entry.code, binding, entry.origin, entry.basePath); err != nil {
				t.Fatal(err)
			}
			issued, err := user.NewUser(map[string]any{"sub": "alice", "exp": time.Now().Add(time.Hour).Unix(), "sid": "unrelated-public-claim"})
			if err != nil {
				t.Fatal(err)
			}
			var tokens *tokenrefresh.Result
			if familyID != "" {
				tokens = &tokenrefresh.Result{SessionID: familyID}
			}
			r := httptest.NewRequest(http.MethodGet, entry.origin+entry.basePath+"login", nil)
			r.RequestURI = r.URL.RequestURI()
			r.AddCookie(&http.Cookie{Name: factory.CrossDeviceSessionIDCookieName, Value: binding})
			rr := requests.NewRequest()
			rr.Upstream.BasePath = entry.basePath
			p.completeCrossDeviceLogin(httptest.NewRecorder(), r, rr, issued, proof.user, nil, tokens)
			confirmed, err := store.confirmation(binding, entry.origin, entry.basePath)
			if err != nil {
				t.Fatal(err)
			}
			if confirmed.proof.refreshSessionID != familyID {
				t.Fatal("family reference did not come exclusively from local issuance")
			}
		})
	}
}
