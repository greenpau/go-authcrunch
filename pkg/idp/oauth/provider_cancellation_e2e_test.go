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

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestE2EOAuthJwksAuthenticationCancellation(t *testing.T) {
	initial, _ := newOAuthEdKey(t, "initial", "")
	replacement, private := newOAuthEdKey(t, "replacement", "")
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var fetches atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
				"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/keys",
			})
		case "/keys":
			key := replacement
			switch fetches.Add(1) {
			case 1:
				key = initial
			case 2:
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-release:
					return
				}
				<-release
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"keys": []*JwksKey{key}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer unblock()
	cfg := lifecycleOAuthConfig(server.URL)
	cfg.IdentityTokenCookieEnabled = true
	provider, err := NewIdentityProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if err := provider.Configure(); err != nil {
		t.Fatal(err)
	}

	// Act as an embedding consumer: initiate login through Authenticate, then
	// return independently signed identity evidence through its token callback.
	newRequest := func(ctx context.Context, query url.Values) *requests.Request {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://portal.example/oauth2/test?"+query.Encode(), nil)
		if err != nil {
			t.Fatal("construct OAuth consumer request")
		}
		r := requests.NewRequest()
		r.Upstream = requests.Upstream{BaseURL: "https://portal.example", Method: "oauth2", Realm: "test", Request: req, SessionID: "synthetic-browser-session"}
		return r
	}
	newCallback := func(ctx context.Context) *requests.Request {
		login := newRequest(ctx, nil)
		if err := provider.Authenticate(login); err != nil || login.Response.Code != http.StatusFound {
			t.Fatal("provider did not initiate login")
		}
		redirect, err := url.Parse(login.Response.RedirectURL)
		if err != nil {
			t.Fatal("provider returned an invalid authorization redirect")
		}
		params := redirect.Query()
		if params.Get("state") == "" || params.Get("nonce") == "" {
			t.Fatal("authorization redirect omitted state or nonce")
		}
		claims := oauthEdClaims()
		claims["iss"], claims["aud"], claims["nonce"] = server.URL, cfg.ClientID, params.Get("nonce")
		token := signOAuthEdToken(t, private, map[string]any{"alg": "EdDSA", "kid": replacement.KeyID}, claims)
		return newRequest(ctx, url.Values{"state": {params.Get("state")}, "id_token": {token}, "access_token": {"opaque"}})
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	callback := newCallback(ctx)
	done := make(chan error, 1)
	go func() { done <- provider.Authenticate(callback) }()
	awaitOAuthLifecycle(t, entered, "authentication key refresh")
	cancel(errors.New("consumer stopped authentication"))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled authentication succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authentication ignored request cancellation")
	}
	awaitOAuthLifecycle(t, canceled, "authentication upstream cancellation")
	if callback.Response.Code == http.StatusOK || callback.Response.Payload != nil || callback.Response.IdentityTokenCookie.Enabled {
		t.Fatal("canceled authentication returned identity evidence")
	}
	unblock()

	// The canceled fetch must leave the provider usable for a fresh login.
	retry := newCallback(t.Context())
	if err := provider.Authenticate(retry); err != nil || retry.Response.Code != http.StatusOK {
		t.Fatal("fresh authentication failed after cancellation")
	}
	claims, ok := retry.Response.Payload.(map[string]any)
	if !ok || claims["sub"] != "ed-user" || !retry.Response.IdentityTokenCookie.Enabled {
		t.Fatal("fresh authentication did not return the verified identity")
	}
	if fetches.Load() != 3 {
		t.Fatal("unexpected discovery or authentication key refresh count")
	}
}

func TestE2EOAuthTokenCallbackStateBinding(t *testing.T) {
	key, private := newOAuthEdKey(t, "callback-key", "EdDSA")
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metadata":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
				"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/keys",
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []*JwksKey{key}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := lifecycleOAuthConfig(server.URL)
	provider, err := NewIdentityProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if err := provider.Configure(); err != nil {
		t.Fatal(err)
	}

	const browserSession = "matching-browser-session"
	newRequest := func(sessionID string, query url.Values) *requests.Request {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://portal.example/oauth2/test?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		r := requests.NewRequest()
		r.Upstream = requests.Upstream{
			BaseURL: "https://portal.example", Method: "oauth2", Realm: "test",
			Request: req, SessionID: sessionID,
		}
		return r
	}

	login := newRequest(browserSession, nil)
	if err := provider.Authenticate(login); err != nil || login.Response.Code != http.StatusFound {
		t.Fatalf("initiate login: code=%d error=%v", login.Response.Code, err)
	}
	redirect, err := url.Parse(login.Response.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	state, nonce := redirect.Query().Get("state"), redirect.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatal("authorization redirect omitted state or nonce")
	}
	claims := oauthEdClaims()
	claims["iss"], claims["aud"], claims["nonce"] = server.URL, cfg.ClientID, nonce
	token := signOAuthEdToken(t, private, map[string]any{"alg": "EdDSA", "kid": key.KeyID}, claims)
	validQuery := url.Values{"state": {state}, "id_token": {token}, "access_token": {"opaque"}}

	wrongBrowser := newRequest("different-browser", validQuery)
	if err := provider.Authenticate(wrongBrowser); err == nil || err.Error() != autherrors.ErrIdentityProviderOauthAuthorizationStateNotFound.Error() {
		t.Fatalf("wrong-browser Authenticate() error = %v, want %v", err, autherrors.ErrIdentityProviderOauthAuthorizationStateNotFound)
	}
	valid := newRequest(browserSession, validQuery)
	if err := provider.Authenticate(valid); err != nil || valid.Response.Code != http.StatusOK {
		t.Fatalf("matching token callback: code=%d error=%v", valid.Response.Code, err)
	}
	identity, ok := valid.Response.Payload.(map[string]any)
	if !ok || identity["sub"] != "ed-user" {
		t.Fatal("matching callback did not return signed identity")
	}

	// A disabled-nonce transaction accepts an independently signed identity
	// token with no nonce while retaining the browser and single-use state
	// boundary. Changing the live flag afterward cannot change its policy.
	provider.disableNonce = true
	disabledLogin := newRequest(browserSession, nil)
	if err := provider.Authenticate(disabledLogin); err != nil || disabledLogin.Response.Code != http.StatusFound {
		t.Fatalf("initiate disabled-nonce login: code=%d error=%v", disabledLogin.Response.Code, err)
	}
	disabledRedirect, err := url.Parse(disabledLogin.Response.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	disabledState := disabledRedirect.Query().Get("state")
	if disabledState == "" || disabledRedirect.Query().Has("nonce") {
		t.Fatal("disabled-nonce authorization redirect has invalid state or nonce")
	}
	disabledClaims := oauthEdClaims()
	disabledClaims["iss"], disabledClaims["aud"] = server.URL, cfg.ClientID
	delete(disabledClaims, "nonce")
	disabledToken := signOAuthEdToken(t, private, map[string]any{"alg": "EdDSA", "kid": key.KeyID}, disabledClaims)
	disabledQuery := url.Values{"state": {disabledState}, "id_token": {disabledToken}, "access_token": {"opaque"}}

	wrongDisabledBrowser := newRequest("different-browser", disabledQuery)
	if err := provider.Authenticate(wrongDisabledBrowser); err == nil || err.Error() != autherrors.ErrIdentityProviderOauthAuthorizationStateNotFound.Error() {
		t.Fatalf("disabled-nonce wrong-browser error = %v", err)
	}
	provider.disableNonce = false
	disabledValid := newRequest(browserSession, disabledQuery)
	if err := provider.Authenticate(disabledValid); err != nil || disabledValid.Response.Code != http.StatusOK {
		t.Fatalf("disabled-nonce matching callback: code=%d error=%v", disabledValid.Response.Code, err)
	}
	if identity, ok := disabledValid.Response.Payload.(map[string]any); !ok || identity["sub"] != "ed-user" {
		t.Fatal("disabled-nonce callback did not return signed identity")
	}

	for _, tc := range []struct {
		name      string
		sessionID string
		query     url.Values
	}{
		{name: "missing state", sessionID: browserSession, query: url.Values{"id_token": {disabledToken}, "access_token": {"opaque"}}},
		{name: "wrong state", sessionID: browserSession, query: url.Values{"state": {"unrelated"}, "id_token": {disabledToken}, "access_token": {"opaque"}}},
		{name: "reused state", sessionID: browserSession, query: disabledQuery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			callback := newRequest(tc.sessionID, tc.query)
			err := provider.Authenticate(callback)
			if err == nil || err.Error() != autherrors.ErrIdentityProviderOauthAuthorizationStateNotFound.Error() {
				t.Fatalf("Authenticate() error = %v, want %v", err, autherrors.ErrIdentityProviderOauthAuthorizationStateNotFound)
			}
			if callback.Response.Code == http.StatusOK || callback.Response.Payload != nil {
				t.Fatal("rejected callback returned identity evidence")
			}
		})
	}
}
