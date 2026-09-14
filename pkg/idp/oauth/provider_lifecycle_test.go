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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestOAuthMetadataValidation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"HTTP failure", `{}`, 503},
		{"invalid JSON", `{`, 200},
		{"missing endpoint", `{}`, 200},
		{"numeric endpoint", `{"authorization_endpoint":1,"token_endpoint":"https://idp/token","jwks_uri":"https://idp/jwks"}`, 200},
		{"null issuer", `{"issuer":null,"authorization_endpoint":"https://idp/auth","token_endpoint":"https://idp/token","jwks_uri":"https://idp/jwks"}`, 200},
		{"invalid UserInfo", `{"userinfo_endpoint":{},"authorization_endpoint":"https://idp/auth","token_endpoint":"https://idp/token","jwks_uri":"https://idp/jwks"}`, 200},
		{"oversized", strings.Repeat(" ", maxOAuthJwksBytes+1), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); w.Write([]byte(tc.body)) }))
			defer server.Close()
			b := oauthEdProvider(t)
			b.config.MetadataURL = server.URL
			b.browserConfig = &browserConfig{TLSInsecureSkipVerify: true}
			if err := b.fetchMetadataURL(); err == nil {
				t.Fatal("invalid discovery accepted")
			}
			if b.metadata != nil || b.keysURL != "" {
				t.Fatal("partial metadata published")
			}
		})
	}
}

func TestOAuthProviderClose(t *testing.T) {
	key, private := newOAuthEdKey(t, "static", "")
	b, err := NewIdentityProvider(&Config{Name: "close-test", Realm: "test", Driver: "generic", ClientID: "client", ClientSecret: "synthetic", BaseAuthURL: "https://idp.example", AuthorizationURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token", JwksKeys: map[string]string{key.KeyID: oauthPublicPEMFile(t, private.Public())}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.Close() }()
	}
	wg.Wait()
	select {
	case <-b.stateDone:
	case <-time.After(time.Second):
		t.Fatal("OAuth state worker did not stop")
	}
	b.config.DelayStart = 3600
	if err := b.fetchConfig(); err == nil {
		t.Fatal("closed provider performed delayed discovery")
	}
	(*IdentityProvider)(nil).Close()
}

func TestOAuthDelayedDiscoveryReadiness(t *testing.T) {
	b := oauthEdProvider(t)
	b.configured.Store(true)
	r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://portal.example/oauth2/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Authenticate(&requests.Request{Upstream: requests.Upstream{Request: r}}); err == nil {
		t.Fatal("unready provider accepted login")
	}
	if b.GetLogoutURL() != "" {
		t.Fatal("unready provider exposed endpoint")
	}
}

func TestOAuthJwksRequestCancellation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  bool
		cause error
	}{
		{name: "before headers"},
		{name: "during body", body: true},
		{name: "custom cause", cause: errors.New("caller stopped authentication")},
		{name: "body with custom cause", body: true, cause: errors.New("caller stopped authentication")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.body {
					w.Write([]byte(`{"keys":[`))
					w.(http.Flusher).Flush()
				}
				close(entered)
				select {
				case <-r.Context().Done():
					close(canceled)
				case <-release:
					return
				}
				// Keep handler completion from racing the cancellation result.
				<-release
			}))
			defer server.Close()
			defer close(release)
			b := oauthEdProvider(t)
			b.keysURL = server.URL
			b.browserConfig = &browserConfig{TLSInsecureSkipVerify: true}
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			type result struct {
				keys          []*JwksKey
				authoritative bool
				err           error
			}
			done := make(chan result, 1)
			go func() {
				keys, authoritative, err := b.fetchRemoteKeys(ctx)
				done <- result{keys, authoritative, err}
			}()
			awaitOAuthLifecycle(t, entered, "JWKS request")
			select {
			case got := <-done:
				t.Fatalf("JWKS request completed before cancellation: %v", got.err)
			default:
			}
			cancel(tc.cause)
			select {
			case got := <-done:
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("JWKS request ignored cancellation: %v", got.err)
				}
				if got.authoritative || len(got.keys) != 0 {
					t.Fatal("canceled JWKS request returned replacement keys")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled JWKS request did not finish")
			}
			awaitOAuthLifecycle(t, canceled, "upstream JWKS cancellation")
			if _, err := b.parseOAuthJWT(ctx, "id_token", "unused"); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled validation continued: %v", err)
			}
		})
	}
}

func TestOAuthDiscoveryPublication(t *testing.T) {
	key, private := newOAuthEdKey(t, "pin", "")
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
			return
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"issuer": "https://discovered.example", "authorization_endpoint": server.URL + "/discovered-auth", "token_endpoint": server.URL + "/discovered-token", "jwks_uri": server.URL + "/jwks", "end_session_endpoint": server.URL + "/logout"})
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	cfg := &Config{Name: "publication", Realm: "test", Driver: "generic", ClientID: oauthValidatorTestClientID, ClientSecret: "synthetic", BaseAuthURL: server.URL, MetadataURL: server.URL + "/metadata", AuthorizationURL: server.URL + "/explicit-auth", TokenURL: server.URL + "/explicit-token", Issuer: oauthValidatorTestIssuer, JwksKeys: map[string]string{key.KeyID: oauthPublicPEMFile(t, private.Public())}, TLSInsecureSkipVerify: true, DelayStart: 1}
	b, err := NewIdentityProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.Configure(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("delayed discovery did not start")
	}
	if err := b.Authenticate(&requests.Request{}); err == nil || b.GetLogoutURL() != "" {
		t.Fatal("incomplete discovery was exposed to requests")
	}
	configResult := make(chan map[string]any, 1)
	go func() { configResult <- b.GetConfig() }()
	releaseOnce.Do(func() { close(release) })
	select {
	case got := <-configResult:
		if got["issuer"] != oauthValidatorTestIssuer {
			t.Fatal("discovery replaced the explicit issuer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("configuration publication did not finish")
	}
	if !b.ready.Load() || b.GetLogoutURL() != server.URL+"/logout" {
		t.Fatal("completed discovery was not published")
	}
	if b.authorizationURL != cfg.AuthorizationURL || b.tokenURL != cfg.TokenURL {
		t.Fatal("discovery replaced explicit endpoints")
	}
	token := signOAuthEdToken(t, private, map[string]any{"alg": "Ed25519", "kid": key.KeyID}, oauthEdClaims())
	if _, err := b.validateAccessToken(t.Context(), "unused", map[string]any{"id_token": token}); err == nil {
		t.Fatal("discovery publication bypassed nonce validation")
	}
	if _, err := b.parseOAuthJWT(t.Context(), "id_token", token); err != nil {
		t.Fatal("published provider could not verify its pinned key", err)
	}
}

func TestOAuthStaticKeyProvisioningFailure(t *testing.T) {
	key, private := newOAuthEdKey(t, "pin", "")
	file := oauthPublicPEMFile(t, private.Public())
	b, err := NewIdentityProvider(&Config{Name: "missing-key", Realm: "test", Driver: "generic", ClientID: "client", ClientSecret: "synthetic", BaseAuthURL: "https://idp.example", AuthorizationURL: "https://idp.example/auth", TokenURL: "https://idp.example/token", JwksKeys: map[string]string{key.KeyID: file}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := b.Configure(); err == nil || b.Configured() || b.ready.Load() {
		t.Fatal("missing static file did not fail provisioning closed")
	}
	keys := make(map[string]string)
	for i := 0; i <= maxOAuthJwksKeys; i++ {
		keys[strings.Repeat("x", i+1)] = file
	}
	b.config.JwksKeys = keys
	if err := b.installStaticKeys(); err == nil {
		t.Fatal("oversized static key set accepted")
	}
}
