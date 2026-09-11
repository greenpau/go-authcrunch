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

package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
)

func TestConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"empty URL", func(c *Config) { c.BaseURL = "" }},
		{"relative URL", func(c *Config) { c.BaseURL = "/auth" }},
		{"unsupported scheme", func(c *Config) { c.BaseURL = "ftp://portal.test" }},
		{"missing host", func(c *Config) { c.BaseURL = "https:///auth" }},
		{"userinfo", func(c *Config) { c.BaseURL = "https://user:private@portal.test" }},
		{"query", func(c *Config) { c.BaseURL = "https://portal.test?token=private" }},
		{"empty query", func(c *Config) { c.BaseURL = "https://portal.test?" }},
		{"fragment", func(c *Config) { c.BaseURL = "https://portal.test#private" }},
		{"invalid URL", func(c *Config) { c.BaseURL = "https://%private" }},
		{"empty username", func(c *Config) { c.Username = " " }},
		{"empty realm", func(c *Config) { c.Realm = "" }},
		{"short TOTP", func(c *Config) { c.TOTPCodeLength = 3 }},
		{"long TOTP", func(c *Config) { c.TOTPCodeLength = 9 }},
		{"negative period", func(c *Config) { c.TOTPCodeLifetime = -1 }},
		{"invalid header name", func(c *Config) { c.AccessTokenName = "private\r\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{BaseURL: "https://portal.test", Username: "user", Realm: "local"}
			tc.change(&cfg)
			_, err := NewClient(&cfg, Options{})
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatalf("expected safe validation error, got %v", err)
			}
		})
	}
	if _, err := NewClient(nil, Options{}); err == nil {
		t.Fatal("nil config accepted")
	}
	var nilConfig *Config
	if err := nilConfig.Validate(); err == nil {
		t.Fatal("nil validation accepted")
	}
	cfg := Config{BaseURL: "https://portal.test/auth/", Username: " user ", Realm: " local "}
	client, err := NewClient(&cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TOTPCodeLength != 0 || cfg.BaseURL != "https://portal.test/auth/" {
		t.Fatal("constructor mutated config")
	}
	got := client.config
	if got.BaseURL != "https://portal.test/auth" || got.Username != "user" || got.Realm != "local" || got.TOTPCodeLength != 6 || got.TOTPCodeLifetime != 30 || got.AccessTokenName != DefaultAccessTokenName {
		t.Fatal("defaults or normalization missing")
	}
	if _, err := NewClient(&cfg, Options{UserAgent: "bad\nagent"}); err == nil {
		t.Fatal("invalid user agent accepted")
	}
}

func TestAPIKeyConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
	}{
		{"username", func(c *Config) { c.Username = "user" }},
		{"password", func(c *Config) { c.Password = "test-password" }},
		{"TOTP", func(c *Config) { c.TOTPSecret = "test-secret" }},
		{"missing realm", func(c *Config) { c.Realm = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{BaseURL: "https://portal.test", Realm: "local", APIKey: strings.Repeat("a", 64)}
			tc.change(&cfg)
			if _, err := NewClient(&cfg, Options{}); err == nil || strings.Contains(err.Error(), cfg.APIKey) {
				t.Fatal("expected safe API key configuration error")
			}
		})
	}
}

func TestAPIKeyDoesNotFallBackToChallenges(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		request, err := apiauth.ParseAuthRequest(r.Context(), w, r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if request.APIKey != strings.Repeat("a", 64) || request.Username != "" || r.Header.Get("Authorization") != "" || r.URL.RawQuery != "" {
			t.Error("API key login used unexpected credentials or transport")
		}
		_, _ = w.Write([]byte(`{"sandbox_id":"id","sandbox_secret":"secret","next_challenge":"password"}`))
	}))
	defer server.Close()
	client, err := NewClient(&Config{BaseURL: server.URL, Realm: "local", APIKey: strings.Repeat("a", 64)}, Options{Prompt: func(context.Context, PromptKind) (string, error) {
		t.Error("API key login prompted for another authentication method")
		return "", ErrInputRequired
	}})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if credentials != nil || err == nil || calls.Load() != 1 {
		t.Fatal("API key login accepted a challenge or sent the key again")
	}
}

func TestAuthenticateChallenges(t *testing.T) {
	const secret = "12345678901234567890"
	for _, tc := range []struct {
		name       string
		password   string
		secret     string
		challenges []string
		prompts    []PromptKind
	}{
		{name: "configured password", password: "test-password", challenges: []string{"password"}},
		{name: "prompted password", challenges: []string{"password"}, prompts: []PromptKind{PromptPassword}},
		{name: "configured password and TOTP", password: "test-password", secret: secret, challenges: []string{"password", "totp"}},
		{name: "prompted TOTP", password: "test-password", challenges: []string{"password", "totp"}, prompts: []PromptKind{PromptTOTP}},
		{name: "MFA selection and code", password: "test-password", challenges: []string{"password", "mfa"}, prompts: []PromptKind{PromptMFA, PromptTOTP}},
		{name: "MFA selection and configured secret", password: "test-password", secret: secret, challenges: []string{"password", "mfa"}, prompts: []PromptKind{PromptMFA}},
		{name: "noninteractive MFA", password: "test-password", secret: secret, challenges: []string{"password", "mfa"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				i := int(calls.Add(1)) - 1
				if r.URL.Path != "/auth/login" || r.Method != http.MethodPost {
					t.Error("unexpected endpoint or method")
					w.WriteHeader(404)
					return
				}
				if r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/json" || r.UserAgent() != "test-authenticator/1" {
					t.Error("missing authentication headers")
				}
				if r.Header.Get("Authorization") != "" {
					t.Error("login sent an access token")
				}
				request, err := apiauth.ParseAuthRequest(r.Context(), w, r)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if request.Username != "test-user" || request.Realm != "local" {
					t.Error("identity changed during exchange")
				}
				if i == 0 {
					if request.HasChallengeResponse() {
						t.Error("initial request contained a challenge response")
					}
					http.SetCookie(w, &http.Cookie{Name: "login_session", Value: "test-session", Path: "/auth", Secure: true})
				} else {
					cookie, err := r.Cookie("login_session")
					if err != nil || cookie.Value != "test-session" {
						t.Error("login cookie not retained")
					}
					if i > len(tc.challenges) {
						t.Error("unexpected extra login request")
						w.WriteHeader(400)
						return
					}
					if request.SandboxID != fmt.Sprint(i-1) || request.SandboxSecret != fmt.Sprintf("sandbox-%d", i-1) || request.ChallengeKind != tc.challenges[i-1] {
						t.Error("incorrect sandbox continuation")
					}
					if request.ChallengeKind == "password" {
						if request.ChallengeResponse != "test-password" {
							t.Error("incorrect password answer")
						}
					} else if tc.secret != "" {
						token := identity.MfaToken{Secret: secret, Algorithm: "sha1", Digits: 6, Period: 30}
						if err := token.ValidateCodeWithTime(request.ChallengeResponse, time.Now()); err != nil {
							t.Error("generated code does not match portal verification")
						}
					} else if request.ChallengeResponse != "123456" {
						t.Error("incorrect prompted TOTP answer")
					}
				}
				response := apiauth.AuthResponse{}
				if i == len(tc.challenges) {
					response.Authenticated = true
					response.AccessToken = "test-access-token"
					response.AccessTokenName = "PORTAL_TOKEN"
					response.RefreshToken = "test-refresh-token"
					response.RefreshTokenName = "portal_refresh"
					response.AccessExpiresAt = 100
					response.SessionID = "session-id"
				} else {
					response.SandboxID = fmt.Sprint(i)
					response.SandboxSecret = fmt.Sprintf("sandbox-%d", i)
					response.NextChallenge = tc.challenges[i]
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			var prompts []PromptKind
			opts := Options{HTTPClient: server.Client(), UserAgent: "test-authenticator/1"}
			if len(tc.prompts) > 0 {
				opts.Prompt = func(ctx context.Context, kind PromptKind) (string, error) {
					prompts = append(prompts, kind)
					switch kind {
					case PromptPassword:
						return "test-password", nil
					case PromptMFA:
						return "totp", nil
					default:
						return "123456", nil
					}
				}
			}
			client, err := NewClient(&Config{BaseURL: server.URL + "/auth/", Username: "test-user", Realm: "local", Password: tc.password, TOTPSecret: tc.secret}, opts)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != int32(len(tc.challenges)+1) {
				t.Fatal("wrong login request count")
			}
			if !reflect.DeepEqual(prompts, tc.prompts) {
				t.Fatalf("prompts: got %v, want %v", prompts, tc.prompts)
			}
			header, err := credentials.Authorization()
			if err != nil || header != "portal_token=test-access-token" {
				t.Fatal("incorrect authorization header")
			}
			if credentials.RefreshToken != "test-refresh-token" || credentials.RefreshTokenName != "portal_refresh" || credentials.AccessExpiresAt != 100 || credentials.SessionID != "session-id" {
				t.Fatal("credential metadata was lost")
			}
			if _, err := time.Parse(time.RFC3339Nano, credentials.CreatedAt); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthenticateInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"access denied", `{"message":"private"}`, 401, "status_code: 401"},
		{"redirect", `private`, 307, "status_code: 307"},
		{"bad JSON", `private`, 200, "invalid authentication response JSON"},
		{"wrong type", `{"authenticated":"private"}`, 200, "invalid authentication response JSON"},
		{"trailing data", `{"authenticated":true,"access_token":"private"} {}`, 200, "invalid authentication response JSON"},
		{"null", `null`, 200, "incomplete authentication challenge"},
		{"empty token", `{"authenticated":true}`, 200, "access token is empty"},
		{"invalid token name", `{"authenticated":true,"access_token":"private","access_token_name":"bad\r\n"}`, 200, "invalid access token name"},
		{"invalid token", `{"authenticated":true,"access_token":"private\r\n"}`, 200, "invalid access token transport value"},
		{"no secret", `{"sandbox_id":"private","next_challenge":"password"}`, 200, "incomplete authentication challenge"},
		{"no sandbox", `{"sandbox_secret":"private","next_challenge":"password"}`, 200, "incomplete authentication challenge"},
		{"no challenge", `{"sandbox_id":"id","sandbox_secret":"private"}`, 200, "incomplete authentication challenge"},
		{"unknown challenge", `{"sandbox_id":"id","sandbox_secret":"private","next_challenge":"private"}`, 200, "unsupported authentication challenge"},
		{"WebAuthn", `{"sandbox_id":"id","sandbox_secret":"private","next_challenge":"mfa:u2f:private"}`, 200, "unsupported authentication challenge"},
		{"oversized", strings.Repeat("x", maxResponseSize+1), 200, "size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := NewClient(&Config{BaseURL: server.URL, Username: "user", Realm: "local"}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(context.Background())
			if credentials != nil || err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "private") {
				t.Fatalf("unexpected authentication result: %v", err)
			}
			if tc.status != 200 {
				var statusError *HTTPError
				if !errors.As(err, &statusError) || statusError.StatusCode != tc.status {
					t.Fatal("HTTP error cannot be inspected")
				}
			}
		})
	}
}

func TestAuthenticateStateIsolation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req apiauth.AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.ChallengeResponse != "" || req.SandboxID != "" {
			t.Error("fresh login reused a sandbox")
		}
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"authenticated":true,"access_token":"first","access_token_name":"FIRST","refresh_token":"old-refresh"}`))
		} else {
			_, _ = w.Write([]byte(`{"authenticated":true,"access_token":"second"}`))
		}
	}))
	defer server.Close()
	client, err := NewClient(&Config{BaseURL: server.URL, Username: "user", Realm: "local", AccessTokenName: "fallback"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Authenticate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Authenticate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.AccessToken != "second" || second.RefreshToken != "" || second.AccessTokenName != "fallback" || first.RefreshToken != "old-refresh" {
		t.Fatal("credentials leaked between logins")
	}
}

func TestAuthenticateDoesNotReuseOmittedSandboxFields(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"sandbox_id":"id","sandbox_secret":"secret","next_challenge":"password"}`))
		} else {
			_, _ = w.Write([]byte(`{"sandbox_id":"id","next_challenge":"totp"}`))
		}
	}))
	defer server.Close()
	client, err := NewClient(&Config{BaseURL: server.URL, Username: "user", Realm: "local", Password: "test"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authenticate(context.Background()); err == nil || err.Error() != "incomplete authentication challenge" {
		t.Fatalf("got %v", err)
	}
	if calls.Load() != 2 {
		t.Fatal("invalid continuation was submitted")
	}
}

func TestAuthenticateRequestLimit(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"sandbox_id":"id","sandbox_secret":"secret","next_challenge":"password"}`))
	}))
	defer server.Close()
	prompts := 0
	client, err := NewClient(&Config{BaseURL: server.URL, Username: "user", Realm: "local"}, Options{Prompt: func(context.Context, PromptKind) (string, error) { prompts++; return "test", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authenticate(context.Background()); err == nil || err.Error() != "reached maximum authentication requests" {
		t.Fatalf("got %v", err)
	}
	if calls.Load() != 10 || prompts != 9 {
		t.Fatal("request or prompt limit exceeded")
	}
}

func TestAuthenticateRedirectAndCancellation(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	var redirectChecks atomic.Int32
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { redirectChecks.Add(1); return nil }}
	client, err := NewClient(&Config{BaseURL: redirect.URL, Username: "user", Realm: "local"}, Options{HTTPClient: hc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authenticate(context.Background()); err == nil {
		t.Fatal("redirect accepted")
	}
	if targetCalls.Load() != 0 || redirectChecks.Load() != 0 || hc.Jar != nil {
		t.Fatal("followed redirect or mutated provided client")
	}
	_ = hc.CheckRedirect(nil, nil)
	if redirectChecks.Load() != 1 {
		t.Fatal("provided redirect policy overwritten")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Authenticate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}

	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Consume the body so the server can observe a disconnected client.
		var request apiauth.AuthRequest
		_ = json.NewDecoder(r.Body).Decode(&request)
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err = NewClient(&Config{BaseURL: server.URL, Username: "user", Realm: "local"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := client.Authenticate(ctx); done <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not reach HTTP request")
	}
}

func TestChallengeInput(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name, kind string
		prompt     PromptFunc
		ctx        context.Context
		want       error
		wantText   string
	}{
		{name: "missing password", kind: "password", want: ErrInputRequired},
		{name: "missing TOTP", kind: "totp", want: ErrInputRequired},
		{name: "missing MFA choice", kind: "mfa", want: ErrInputRequired},
		{name: "unsupported U2F", kind: "u2f", want: ErrUnsupportedChallenge},
		{name: "empty answer", kind: "password", prompt: func(context.Context, PromptKind) (string, error) { return " ", nil }, wantText: "empty authentication input"},
		{name: "prompt error", kind: "password", prompt: func(context.Context, PromptKind) (string, error) { return "", context.DeadlineExceeded }, want: context.DeadlineExceeded},
		{name: "canceled", kind: "password", ctx: canceled, want: context.Canceled},
		{name: "invalid MFA choice", kind: "mfa", prompt: func(context.Context, PromptKind) (string, error) { return "private", nil }, wantText: "unsupported MFA selection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			c := &Client{prompt: tc.prompt}
			_, err := c.answer(ctx, tc.kind)
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
			if tc.wantText != "" && (err == nil || err.Error() != tc.wantText) {
				t.Fatalf("got %v", err)
			}
		})
	}
	c := &Client{prompt: func(context.Context, PromptKind) (string, error) { return "webauthn", nil }}
	if answer, err := c.answer(context.Background(), "mfa"); err != nil || answer != "webauthn" {
		t.Fatal("MFA selection negotiation failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.prompt = func(context.Context, PromptKind) (string, error) { cancel(); return "test", nil }
	if _, err := c.answer(ctx, "password"); !errors.Is(err, context.Canceled) {
		t.Fatal("prompt cancellation was ignored")
	}
}

func TestTOTP(t *testing.T) {
	for _, tc := range []struct {
		at   int64
		code string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
		{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		if got := generateTOTP("12345678901234567890", 8, 30, time.Unix(tc.at, 0)); got != tc.code {
			t.Errorf("unexpected code at %d", tc.at)
		}
	}
}
