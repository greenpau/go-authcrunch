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

package httpserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/sso"
)

func TestServeRejectsInvalidConfigurationAndClosesListener(t *testing.T) {
	if Serve(context.Background(), nil, validConfig(), nil, zap.NewNop()) == nil {
		t.Fatal("nil listener accepted")
	}
	for _, name := range []string{"nil context", "nil logger", "nil config", "invalid config", "nil security", "unknown portal", "missing TLS", "invalid runtime", "canceled"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			logger := zap.NewNop()
			config := validConfig()
			security := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal"}}}
			switch name {
			case "nil context":
				ctx = nil
			case "nil logger":
				logger = nil
			case "nil config":
				config = nil
			case "invalid config":
				config.Portals = nil
			case "nil security":
				security = nil
			case "unknown portal":
				security.AuthenticationPortals[0].Name = "other"
			case "missing TLS":
				config.InsecureHTTP = false
				config.TLSCertificateFile = "missing"
				config.TLSKeyFile = "missing"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := Serve(ctx, listener, config, security, logger); err == nil {
				t.Fatal("invalid setup accepted")
			}
			if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatal("listener ownership was not released")
			}
		})
	}
}

func TestSecurityRouteValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*authcrunch.Config)
	}{
		{"nil portal", func(c *authcrunch.Config) { c.AuthenticationPortals = append(c.AuthenticationPortals, nil) }},
		{"duplicate portal", func(c *authcrunch.Config) {
			c.AuthenticationPortals = append(c.AuthenticationPortals, &authn.PortalConfig{Name: "portal"})
		}},
		{"nil store", func(c *authcrunch.Config) { c.IdentityStores = []*ids.IdentityStoreConfig{nil} }},
		{"store realm", func(c *authcrunch.Config) {
			c.IdentityStores = []*ids.IdentityStoreConfig{{Params: map[string]any{"realm": 42}}}
		}},
		{"nil provider", func(c *authcrunch.Config) { c.IdentityProviders = []*idp.IdentityProviderConfig{nil} }},
		{"provider realm", func(c *authcrunch.Config) {
			c.IdentityProviders = []*idp.IdentityProviderConfig{{Params: map[string]any{"realm": 42}}}
		}},
		{"nil SSO", func(c *authcrunch.Config) { c.SingleSignOnProviders = []*sso.SingleSignOnProviderConfig{nil} }},
		{"nil policy", func(c *authcrunch.Config) { c.AuthorizationPolicies = []*authz.PolicyConfig{nil} }},
		{"nil registry", func(c *authcrunch.Config) {
			c.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{nil}}
		}},
		{"refresh mount", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, BasePath: "/other"}
		}},
		{"OIDC mount", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].OIDCProvider = &authn.OIDCProviderConfig{Enabled: true, Issuer: "https://example.test/other"}
		}},
		{"OIDC invalid issuer", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].OIDCProvider = &authn.OIDCProviderConfig{Enabled: true, Issuer: "://bad"}
		}},
		{"refresh over HTTP", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, BasePath: "/auth"}
		}},
		{"OIDC over HTTP", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].OIDCProvider = &authn.OIDCProviderConfig{Enabled: true, Issuer: "https://example.test/auth"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal"}}}
			tc.change(cfg)
			if validateSecurity(validConfig(), cfg) == nil {
				t.Fatal("invalid graph accepted")
			}
		})
	}
}

func TestPortalHandlerRouting(t *testing.T) {
	h := &portalHandler{routes: []PortalRoute{{Name: "portal", Path: "/tenant/auth"}}, logger: zap.NewNop()}
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/tenant/auth", 307}, {"/tenant/auth/", 307}, {"/tenant/auth?x=1", 307}, {"/tenant/other", 404}, {"/tenant/authextra", 404},
		{"/tenant//auth/login", 400}, {"/tenant/auth/../other", 400}, {"/tenant/%61uth/login", 400},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "https://example.test"+tc.path, nil))
		if rec.Code != tc.status {
			t.Fatalf("%s: status %d", tc.path, rec.Code)
		}
	}
	h.stopping = true
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "https://example.test/tenant/auth/login", nil))
	if rec.Code != 503 {
		t.Fatal("stopped handler accepted request")
	}
	for _, status := range []int{103, 200, 500} {
		rec := httptest.NewRecorder()
		writer := &responseWriter{ResponseWriter: rec}
		writer.WriteHeader(status)
		if writer.written != (status >= 200) || writer.Unwrap() != rec {
			t.Fatal("response commitment tracking failed")
		}
	}
	rec = httptest.NewRecorder()
	writer := &responseWriter{ResponseWriter: rec}
	if _, err := writer.Write([]byte("response")); err != nil || !writer.written || rec.Body.String() != "response" {
		t.Fatal("body commitment tracking failed")
	}
}

func TestHTTPServerDrain(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "deadline"}[force], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			h := &portalHandler{logger: zap.NewNop()}
			entered, release := make(chan struct{}), make(chan struct{})
			canceled := make(chan bool, 1)
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h.mu.Lock()
				h.active.Add(1)
				h.mu.Unlock()
				defer h.active.Done()
				close(entered)
				select {
				case <-release:
					canceled <- false
					w.WriteHeader(http.StatusNoContent)
				case <-r.Context().Done():
					canceled <- true
				}
			}), ReadHeaderTimeout: time.Second}
			done := make(chan error, 1)
			timeout := time.Second
			if force {
				timeout = 30 * time.Millisecond
			}
			go func() { done <- serve(ctx, listener, server, h, timeout, zap.NewNop()) }()
			t.Cleanup(func() { cancel(); _ = server.Close() })
			response := make(chan int, 1)
			client := &http.Client{Timeout: 3 * time.Second}
			defer client.CloseIdleConnections()
			go func() {
				res, err := client.Get("http://" + listener.Addr().String())
				if err != nil {
					response <- 0
					return
				}
				defer res.Body.Close()
				io.Copy(io.Discard, res.Body)
				response <- res.StatusCode
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("handler did not start")
			}
			cancel()
			if !force {
				select {
				case <-done:
					t.Fatal("shutdown returned before request drained")
				case <-time.After(30 * time.Millisecond):
				}
				close(release)
			}
			select {
			case err := <-done:
				if force && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("forced shutdown error: %v", err)
				}
				if !force && err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown hung")
			}
			if got := <-canceled; got != force {
				t.Fatal("request context canceled at wrong time")
			}
			if status := <-response; !force && status != 204 {
				t.Fatalf("drained response was lost: %d", status)
			}
		})
	}
}

func TestHTTPServerUnexpectedListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener.Close()
	err = serve(t.Context(), listener, &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}, &portalHandler{}, time.Second, zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatal("unexpected listener failure hidden")
	}
}
