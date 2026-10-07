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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

type hookLoginProvider struct {
	externalLoginTestProvider
	result      *idp.HTTPLoginResult
	failure     error
	name, realm string
	cookieName  string
	calls       int
}

func (p *hookLoginProvider) GetName() string {
	if p.name != "" {
		return p.name
	}
	return "upstream"
}
func (p *hookLoginProvider) GetRealm() string {
	if p.realm != "" {
		return p.realm
	}
	return "upstream"
}
func (p *hookLoginProvider) GetLoginCookieName() string {
	if p.cookieName != "" {
		return p.cookieName
	}
	return "state"
}
func (p *hookLoginProvider) Login(context.Context, *http.Request) (*idp.HTTPLoginResult, error) {
	p.calls++
	return p.result, p.failure
}
func TestProviderLoginRejectsInvalidResults(t *testing.T) {
	identity := &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Roles: []string{"authp/user"}}
	for _, tc := range []struct {
		name    string
		result  *idp.HTTPLoginResult
		failure error
		want    int
	}{
		{name: "nil", want: 502},
		{name: "neither", result: &idp.HTTPLoginResult{}, want: 502},
		{name: "both", result: &idp.HTTPLoginResult{Identity: identity, RedirectURL: "https://issuer.example.test"}, want: 502},
		{name: "identity invalid", result: &idp.HTTPLoginResult{Identity: &idp.LoginIdentity{Subject: "alice"}}, want: 502},
		{name: "http redirect", result: &idp.HTTPLoginResult{RedirectURL: "http://issuer.example.test"}, want: 502},
		{name: "userinfo redirect", result: &idp.HTTPLoginResult{RedirectURL: "https://private@issuer.example.test"}, want: 502},
		{name: "unsafe cookie", result: &idp.HTTPLoginResult{RedirectURL: "https://issuer.example.test", Cookie: &http.Cookie{Name: "state", Value: "x"}}, want: 502},
		{name: "reserved cookie", result: &idp.HTTPLoginResult{RedirectURL: "https://issuer.example.test", Cookie: &http.Cookie{Name: "AUTHP_ACCESS_TOKEN", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/auth/provider/upstream"}}, want: 502},
		{name: "error with identity", result: &idp.HTTPLoginResult{Identity: identity}, failure: errors.New("private verification error"), want: 401},
		{name: "redirect", result: &idp.HTTPLoginResult{RedirectURL: "https://issuer.example.test/login"}, want: 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &hookLoginProvider{result: tc.result, failure: tc.failure}
			p, err := NewPortal(PortalParameters{Config: &PortalConfig{Name: "hook", IdentityProviders: []string{"upstream"}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{provider}})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			r := httptest.NewRequest("GET", "https://portal.example.test/auth/provider/upstream", nil)
			rr := requests.NewRequest()
			rr.User.Username = "stale"
			rr.Response.Payload = map[string]any{"sub": "stale"}
			rr.Response.RedirectURL = "https://stale.example.test"
			w := httptest.NewRecorder()
			if err := p.ServeHTTP(t.Context(), w, r, rr); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.want || provider.calls != 1 || w.Header().Get("Authorization") != "" || strings.Contains(w.Body.String(), "private verification error") || rr.User.Username != "" {
				t.Fatal("invalid result escaped boundary", w.Code)
			}
			if w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unsafe response headers")
			}
		})
	}
}
func TestProviderLoginRealmAndRouteBoundaries(t *testing.T) {
	for _, realm := range []string{"bad/realm", "..", "", "application"} {
		a := &hookLoginProvider{name: "first", realm: realm}
		b := &hookLoginProvider{name: "second", realm: realm}
		// The empty override maps to the existing test provider's safe default; two
		// matching realms must still be rejected independently of instance names.
		if p, err := NewPortal(PortalParameters{Config: &PortalConfig{Name: "duplicates", IdentityProviders: []string{"first", "second"}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{a, b}}); p != nil || err == nil {
			if p != nil {
				p.Close()
			}
			t.Fatal("duplicate/invalid provider realms accepted")
		}
	}
	f := newRefreshPortal(t, false, false)
	provider := &hookLoginProvider{realm: "local"}
	if p, err := NewPortal(PortalParameters{Config: &PortalConfig{Name: "collision", IdentityStores: []string{"localdb"}, IdentityProviders: []string{"upstream"}}, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{f.store}, IdentityProviders: []idp.IdentityProvider{provider}}); p != nil || err == nil {
		if p != nil {
			p.Close()
		}
		t.Fatal("store/provider realm collision accepted")
	}
	for _, path := range []string{"/auth/oauth2/team/provider/callback", "/auth/saml/provider/callback", "/auth/cross-device/provider/app", "/auth/api/provider/app", "/auth/assets/provider/app"} {
		if providerLoginRouteIndex(path) >= 0 {
			t.Fatal("provider captured earlier namespace", path)
		}
	}
	for _, path := range []string{"/auth/provider/cross-device", "/auth/provider/logout", "/auth/provider/portal"} {
		if providerLoginRouteIndex(path) != 5 || crossDeviceRouteIndex(path) >= 0 {
			t.Fatal("realm became another route", path)
		}
	}
}

func TestProviderLoginCookieConstructionCollision(t *testing.T) {
	for _, name := range []string{"AUTHP_ACCESS_TOKEN", "authp_access_token", "AuthP_Access_Token"} {
		provider := &hookLoginProvider{cookieName: name}
		p, err := NewPortal(PortalParameters{Config: &PortalConfig{Name: "cookie-collision", IdentityProviders: []string{"upstream"}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{provider}})
		if p != nil || err == nil {
			if p != nil {
				p.Close()
			}
			t.Fatal("provider binding name collided with portal credential")
		}
	}
}
