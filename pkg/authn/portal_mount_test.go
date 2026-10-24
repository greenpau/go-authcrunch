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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

func TestPortalMountRequestBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, mount, path, raw string
		allowed                bool
	}{
		{"bare", "/auth", "/auth", "", true}, {"trailing", "/auth", "/auth/", "", true}, {"child", "/auth", "/auth/login", "", true},
		{"neighbor", "/auth", "/authentic/login", "", false}, {"outside", "/auth", "/other/login", "", false}, {"case", "/auth", "/AUTH/login", "", false},
		{"encoded mount", "/auth", "/auth/login", "/%61uth/login", false}, {"encoded boundary", "/auth", "/auth/login", "/auth%2flogin", false},
		{"encoded child", "/auth", "/auth/assets/a/b", "/auth/assets/a%2fb", true}, {"encoded data", "/auth", "/auth/assets/a b", "/auth/assets/a%20b", true},
		{"invalid raw", "/auth", "/auth/login", "/%zz", false},
		{"ignored raw", "/auth", "/auth/a b", "/auth/a b", false}, {"inconsistent raw", "/auth", "/auth/login", "/other/login", false},
		{"unicode child", "/auth", "/auth/assets/équipe", "/auth/assets/%C3%A9quipe", true}, {"root", "/", "/any/child", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if portalMountContains(tc.mount, &url.URL{Path: tc.path, RawPath: tc.raw}) != tc.allowed {
				t.Fatal("decoded and escaped boundary disagree with contract")
			}
		})
	}
}

type mountObservingOP struct {
	oidc.OpenIDProvider
	observe func(*http.Request)
}

func (p *mountObservingOP) HandleHTTP(w http.ResponseWriter, r *http.Request) bool {
	p.observe(r)
	w.WriteHeader(http.StatusNoContent)
	return true
}

func TestPortalMountBeforeEarlyDispatchAndRequestPreservation(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	p := f.portal
	calls := 0
	p.oidc = &mountObservingOP{observe: func(*http.Request) { calls++ }}
	// Restore before runtime cleanup; the observation stub owns no provider.
	t.Cleanup(func() { p.oidc = nil })
	for _, tc := range []struct {
		mount, target string
		status        int
	}{
		{"/auth", "/other/.well-known/jwks.json", 404}, {"/auth", "/other/.well-known/openid-configuration", 404},
		{"/auth", "/authentic/oidc/jwks", 404}, {"/auth", "/%61uth/oidc/jwks", 404}, {"/auth", "/auth%2Foidc/jwks", 404},
		{"/login-service", "/login-service/oidc/jwks", 500}, {"", "/auth/login", 500},
		{"/équipe", "/équipe/oidc/jwks", 500}, {"/neutral;parameter", "/neutral;parameter/oidc/jwks", 500},
	} {
		r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+tc.target, nil)
		w := httptest.NewRecorder()
		rr := requests.NewRequest()
		rr.Upstream.BasePath = "/untrusted/"
		if err := p.ServeHTTPAt(t.Context(), w, r, rr, tc.mount); err != nil {
			t.Fatal(err)
		}
		if w.Code != tc.status || calls != 0 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Cache-Control") != "no-store" || rr.Response.Authenticated {
			t.Fatal("boundary refusal reached protocol or issued cookies")
		}
	}
	type callerKey struct{}
	r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/tenant/auth/provider/cross-device?state=preserved", strings.NewReader("unchanged-body"))
	r.RequestURI = r.URL.RequestURI()
	r.Header.Set("X-Test", "preserved")
	r = r.WithContext(context.WithValue(r.Context(), callerKey{}, "caller"))
	originalURL, originalURI, originalBody := *r.URL, r.RequestURI, r.Body
	p.oidc = &mountObservingOP{observe: func(got *http.Request) {
		calls++
		if got == r || got.Context().Value(callerKey{}) != "caller" || got.Header.Get("X-Test") != "preserved" || *got.URL != originalURL || got.RequestURI != originalURI || got.Body != originalBody {
			t.Fatal("explicit mount changed request metadata")
		}
		data, err := io.ReadAll(got.Body)
		if err != nil || string(data) != "unchanged-body" {
			t.Fatal("explicit mount changed request body")
		}
		rr := requests.NewRequest()
		extractBasePath(t.Context(), got, rr)
		rr.Upstream.BasePath = "/stale/"
		extractBasePath(t.Context(), got, rr)
		if rr.Upstream.BasePath != "/tenant/auth/" || rr.Upstream.BaseURL != refreshTestOrigin {
			t.Fatal("repeated extraction lost trusted mount")
		}
	}}
	if err := p.ServeHTTPAt(t.Context(), httptest.NewRecorder(), r, requests.NewRequest(), "/tenant/auth"); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || declaredPortalMount(r) != "" || *r.URL != originalURL || r.RequestURI != originalURI || r.Body != originalBody {
		t.Fatal("explicit mount mutated original request")
	}
}

func TestPortalMountFeatureAgreement(t *testing.T) {
	f := newRefreshPortal(t, true, false)
	p := f.portal
	for _, mount := range []string{"/", "/other"} {
		r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+strings.TrimSuffix(mount, "/")+jwksPath, nil)
		w := httptest.NewRecorder()
		_ = p.ServeHTTPAt(t.Context(), w, r, requests.NewRequest(), mount)
		if w.Code != 500 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("refresh mismatch reached discovery")
		}
	}
	p.config.RefreshTokens.Enabled = false
	p.config.OIDCProvider = oidcTestConfig()
	r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/other/oidc/jwks", nil)
	w := httptest.NewRecorder()
	_ = p.ServeHTTPAt(t.Context(), w, r, requests.NewRequest(), "/other")
	if w.Code != 500 {
		t.Fatal("OP mismatch reached dispatch")
	}
	p.config.OIDCProvider.Enabled = false
	factory, err := cookie.NewFactory(&cookie.Config{SandboxIDCookieName: "__Host-FLOW"})
	if err != nil {
		t.Fatal(err)
	}
	p.cookie = factory
	w = httptest.NewRecorder()
	_ = p.ServeHTTPAt(t.Context(), w, httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth"+jwksPath, nil), requests.NewRequest(), "/auth")
	if w.Code != 500 || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("invalid host-cookie mount reached discovery")
	}
}

func TestPortalMountConcurrentIsolation(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	p := f.portal
	var wg sync.WaitGroup
	failures := make(chan string, 16)
	for i := range 16 {
		wg.Go(func() {
			mount := "/company/auth"
			if i%2 == 0 {
				mount = "/tenant/security"
			}
			r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+mount+"/login", nil)
			r.RequestURI = r.URL.RequestURI()
			w := httptest.NewRecorder()
			rr := requests.NewRequest()
			if p.ServeHTTPAt(t.Context(), w, r, rr, mount) != nil || w.Code != 200 || rr.Upstream.BasePath != mount+"/" {
				failures <- "concurrent mount leaked"
			}
		})
	}
	wg.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestPortalMountProviderRealmOwnership(t *testing.T) {
	provider := &hookLoginProvider{realm: "cross-device", result: &idp.HTTPLoginResult{RedirectURL: "https://issuer.example.test/login"}}
	p, err := NewPortal(PortalParameters{Config: &PortalConfig{Name: "mounted-provider", IdentityProviders: []string{"upstream"}}, Logger: zap.NewNop(), IdentityProviders: []idp.IdentityProvider{provider}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, realm := range []string{"cross-device", "login", "logout", "register", "profile", "beacon"} {
		provider.realm = realm
		before := provider.calls
		r := httptest.NewRequest(http.MethodGet, "https://portal.example.test/team/auth/provider/"+realm, nil)
		w := httptest.NewRecorder()
		rr := requests.NewRequest()
		if err := p.ServeHTTPAt(t.Context(), w, r, rr, "/team/auth"); err != nil {
			t.Fatal(err)
		}
		if w.Code != 302 || provider.calls != before+1 || w.Header().Get("Location") != "https://issuer.example.test/login" || rr.Upstream.BasePath != "/team/auth/" {
			t.Fatal("reserved realm data escaped provider owner")
		}
	}
	before := provider.calls
	r := httptest.NewRequest(http.MethodGet, "https://portal.example.test/team/auth/provider/beacon/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	_ = p.ServeHTTPAt(t.Context(), w, r, requests.NewRequest(), "/team/auth")
	if w.Code != 400 || provider.calls != before || w.Header().Get("Content-Type") == "application/jwk-set+json" {
		t.Fatal("unknown provider child escaped into public discovery")
	}
}
