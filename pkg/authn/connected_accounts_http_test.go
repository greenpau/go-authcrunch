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
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestTrustedConnectionReturnURL(t *testing.T) {
	const origin = "https://auth.example.test"
	const browser = "connection-test-browser"
	ticket := strings.Repeat("a", 48)
	p := newLoginScreenPortal(t, nil)
	for _, base := range []string{"/", "/auth/", "/team/auth/"} {
		t.Run(base, func(t *testing.T) {
			target := origin + base + "connected-accounts/" + ticket
			pending := accountConnection{
				browser: sha256.Sum256([]byte(browser)), base: base,
				startedAt: time.Now().Unix(), expires: time.Now().Add(time.Minute),
			}
			for _, tc := range []struct {
				name    string
				target  string
				cookies []string
				state   string
				allowed bool
			}{
				{name: "current browser and mount", target: target, cookies: []string{browser}, allowed: true},
				{name: "missing browser", target: target},
				{name: "other browser", target: target, cookies: []string{"another-browser"}},
				{name: "ambiguous browser", target: target, cookies: []string{browser, browser}},
				{name: "not started", target: target, cookies: []string{browser}, state: "not started"},
				{name: "expired", target: target, cookies: []string{browser}, state: "expired"},
				{name: "consumed", target: target, cookies: []string{browser}, state: "missing"},
				{name: "foreign origin", target: "https://other.example.test" + base + "connected-accounts/" + ticket, cookies: []string{browser}},
				{name: "foreign mount", target: origin + "/other/" + base + "connected-accounts/" + ticket, cookies: []string{browser}},
				{name: "relative URL", target: base + "connected-accounts/" + ticket, cookies: []string{browser}},
				{name: "downgrade", target: strings.Replace(target, "https:", "http:", 1), cookies: []string{browser}},
				{name: "userinfo", target: strings.Replace(target, "https://", "https://user@", 1), cookies: []string{browser}},
				{name: "query", target: target + "?redirect_url=https://other.example.test", cookies: []string{browser}},
				{name: "fragment", target: target + "#redirect", cookies: []string{browser}},
				{name: "encoded ticket", target: target[:len(target)-1] + "%61", cookies: []string{browser}},
				{name: "extra path", target: target + "/login", cookies: []string{browser}},
				{name: "malformed URL", target: "%zz", cookies: []string{browser}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					current := pending
					switch tc.state {
					case "not started":
						current.startedAt = 0
					case "expired":
						current.expires = time.Now().Add(-time.Second)
					}
					p.accountConnections.pending = map[string]accountConnection{ticket: current}
					if tc.state == "missing" {
						delete(p.accountConnections.pending, ticket)
					}
					r := httptest.NewRequest(http.MethodGet, origin+base+"login", nil)
					// A normal portal request uses origin-form on the wire.
					r.RequestURI = r.URL.RequestURI()
					for _, value := range tc.cookies {
						r.AddCookie(&http.Cookie{Name: p.cookie.SessionIDCookieName, Value: value})
					}
					got := p.trustedConnectionReturnURL(r, tc.target)
					if tc.allowed && got != target || !tc.allowed && got != "" {
						t.Fatalf("return URL trust mismatch: allowed=%t accepted=%t", tc.allowed, got != "")
					}
				})
			}
		})
	}
}

func TestConnectedAccountLoginBinding(t *testing.T) {
	const origin = "https://auth.example.test"
	const browser = "connection-test-browser"
	ticket := strings.Repeat("a", 48)
	for _, state := range []string{"bound login", "preexisting sandbox", "no login start", "not fresh", "unbound destination", "external login", "wrong store", "wrong browser", "different sandbox", "superseded sandbox", "expired", "consumed", "no issued token"} {
		t.Run(state, func(t *testing.T) {
			p := newLoginScreenPortal(t, nil)
			pending := accountConnection{browser: sha256.Sum256([]byte(browser)), base: "/auth/", store: "local", startedAt: time.Now().Unix(), expires: time.Now().Add(time.Minute)}
			proof := &user.User{LoginFresh: true, LoginReturnURLBound: true, LoginReturnURL: origin + "/auth/connected-accounts/" + ticket,
				Authenticator: user.Authenticator{Method: "local", Name: "local", TempSessionID: "fresh-local-sandbox"}}
			r := httptest.NewRequest(http.MethodPost, origin+"/auth/login?fresh=1", nil)
			r.RequestURI = r.URL.RequestURI()
			binding := browser
			switch state {
			case "preexisting sandbox":
				pending.startedAt = 0
			case "not fresh":
				proof.LoginFresh = false
			case "unbound destination":
				proof.LoginReturnURLBound = false
			case "external login":
				proof.ExternalIdentity.Evidence = requests.AuthenticationEvidence{UserID: "external"}
			case "wrong store":
				proof.Authenticator.Name = "other"
			case "wrong browser":
				binding = "another-browser"
			case "expired":
				pending.expires = time.Now().Add(-time.Second)
			}
			r.AddCookie(&http.Cookie{Name: p.cookie.SessionIDCookieName, Value: binding})
			p.accountConnections.pending = map[string]accountConnection{ticket: pending}
			if state != "no login start" {
				p.bindConnectedAccountLogin(r, proof)
			}
			issued := &user.User{Token: "fresh-local-access-token"}
			switch state {
			case "preexisting sandbox":
				pending.startedAt = time.Now().Unix()
				p.accountConnections.pending[ticket] = pending
			case "different sandbox":
				proof.Authenticator.TempSessionID = "other-sandbox"
			case "superseded sandbox":
				newer := proof.Clone()
				newer.Authenticator.TempSessionID = "newer-sandbox"
				p.bindConnectedAccountLogin(r, newer)
			case "consumed":
				delete(p.accountConnections.pending, ticket)
			case "no issued token":
				issued.Token = ""
			}
			p.completeConnectedAccountLogin(r, proof, issued)
			destination := p.accountConnections.pending[ticket].destination
			if state == "bound login" {
				if destination != sha256.Sum256([]byte(issued.Token)) {
					t.Fatal("completed fresh login did not authorize confirmation")
				}
			} else if destination != ([32]byte{}) {
				t.Fatal("unbound or incomplete login authorized confirmation")
			}
		})
	}
}
