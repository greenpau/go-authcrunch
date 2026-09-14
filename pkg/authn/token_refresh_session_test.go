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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func sessionPreconditionRequest(t *testing.T, f *refreshPortalFixture, token *http.Cookie, values []string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/refresh_token", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", refreshTestOrigin)
	r.Header.Set(refreshRequestHeader, "1")
	for _, value := range values {
		r.Header.Add(refreshSessionHeader, value)
	}
	r.AddCookie(token)
	w := httptest.NewRecorder()
	if err := f.portal.ServeHTTP(t.Context(), w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestPortalRefreshSessionPrecondition(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	response := f.login(t, "cookie")
	login := decodeAuth(t, response)
	token := responseCookie(t, response, f.portal.cookie.RefreshTokenCookieName)
	for range 2 {
		info := f.request(t, http.MethodPost, "/auth/api/refresh_session", "{}", true, token)
		var result map[string]string
		if info.Code != http.StatusOK || json.Unmarshal(info.Body.Bytes(), &result) != nil || len(result) != 1 || result["session_id"] != login.SessionID {
			t.Fatal("session lookup failed or disclosed extra state")
		}
		if len(info.Result().Cookies()) != 0 {
			t.Fatal("session lookup changed cookies")
		}
	}
	for _, input := range []struct {
		values []string
		status int
	}{
		{[]string{""}, http.StatusBadRequest}, {[]string{" "}, http.StatusBadRequest},
		{[]string{login.SessionID, login.SessionID}, http.StatusBadRequest},
		{[]string{"other-session"}, http.StatusUnauthorized},
	} {
		response := sessionPreconditionRequest(t, f, token, input.values)
		if response.Code != input.status || len(response.Result().Cookies()) != 0 {
			t.Fatal("invalid precondition was accepted or changed cookies")
		}
	}
	for _, operation := range []string{"refresh_session", "logout"} {
		r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/"+operation, strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", refreshTestOrigin)
		r.Header.Set(refreshRequestHeader, "1")
		r.Header.Set(refreshSessionHeader, login.SessionID)
		r.AddCookie(token)
		w := httptest.NewRecorder()
		if err := f.portal.ServeHTTP(t.Context(), w, r, requests.NewRequest()); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusBadRequest || len(w.Result().Cookies()) != 0 {
			t.Fatal("session precondition was accepted for an unsupported operation")
		}
	}
	next := sessionPreconditionRequest(t, f, token, []string{login.SessionID})
	if decodeAuth(t, next).SessionID != login.SessionID {
		t.Fatal("lookup or invalid precondition consumed the credential")
	}
	if w := f.request(t, http.MethodGet, "/auth/api/refresh_session", "", true, token); w.Code != http.StatusMethodNotAllowed {
		t.Fatal("session lookup accepted GET")
	}
	if w := f.request(t, http.MethodPost, "/auth/api/refresh_session", "{}", false, token); w.Code != http.StatusForbidden {
		t.Fatal("session lookup accepted missing origin")
	}
	if w := f.request(t, http.MethodPost, "/other/api/refresh_session", "{}", true, token); w.Code != http.StatusNotFound {
		t.Fatal("session lookup accepted the wrong mount")
	}
	current := responseCookie(t, next, f.portal.cookie.RefreshTokenCookieName)
	if w := f.request(t, http.MethodPost, "/auth/api/refresh_token", "{}", true, current); w.Code != http.StatusOK {
		t.Fatal("rejected lookup requests consumed or revoked the current family")
	}
}

func TestPortalRefreshSessionRejectsNativeAndDisabled(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	native := decodeAuth(t, f.login(t, "body"))
	body, err := json.Marshal(map[string]string{"refresh_token": native.RefreshToken})
	if err != nil {
		t.Fatal(err)
	}
	if w := f.request(t, http.MethodPost, "/auth/api/refresh_session", string(body), false); w.Code != http.StatusForbidden {
		t.Fatal("browser metadata endpoint accepted native transport")
	}
	r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/api/refresh_token", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(refreshSessionHeader, native.SessionID)
	w := httptest.NewRecorder()
	if err := f.portal.ServeHTTP(t.Context(), w, r, requests.NewRequest()); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusBadRequest {
		t.Fatal("native rotation accepted a browser session precondition")
	}
	if w := f.request(t, http.MethodPost, "/auth/api/refresh_token", string(body), false); w.Code != http.StatusOK {
		t.Fatal("metadata denial consumed native credential")
	}
	disabled := newRefreshPortal(t, false, false)
	if w := disabled.request(t, http.MethodPost, "/auth/api/refresh_session", "{}", true); w.Code != http.StatusNotFound {
		t.Fatal("disabled metadata endpoint available")
	}
}
