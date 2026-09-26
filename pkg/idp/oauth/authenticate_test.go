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

package oauth

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"go.uber.org/zap"
)

func TestFetchAccessTokenRejectsUnsafeResponses(t *testing.T) {
	const responseLimit = 1 << 20
	testcases := []struct {
		name, body, wantErr, forbid string
	}{
		{
			name: "bounded valid response",
			body: `{"access_token":"opaque"}` + strings.Repeat(" ", responseLimit-len(`{"access_token":"opaque"}`)),
		},
		{
			name:    "oversized valid response",
			body:    `{"access_token":"opaque","padding":"` + strings.Repeat("x", responseLimit) + `"}`,
			wantErr: "OAuth token response exceeds",
		},
		{
			name:    "non-string error",
			body:    `{"error":7,"error_description":{"secret":"must-not-panic"}}`,
			wantErr: "failed obtaining OAuth 2.0 access token",
			forbid:  "must-not-panic",
		},
		{
			name:    "valid detailed error",
			body:    `{"error":"invalid_grant","error_description":"expired code"}`,
			wantErr: "error: invalid_grant, description: \"expired code\"",
		},
	}

	for _, tc := range testcases {
		for _, endpoint := range []struct {
			name, method string
			facebook     bool
		}{
			{name: "generic", method: http.MethodPost},
			{name: "facebook", method: http.MethodGet, facebook: true},
		} {
			t.Run(tc.name+"/"+endpoint.name, func(t *testing.T) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != endpoint.method {
						t.Errorf("token request method = %s, want %s", r.Method, endpoint.method)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, tc.body)
				}))
				defer server.Close()

				provider := &IdentityProvider{
					config: &Config{
						ClientID:              "client",
						ClientSecret:          "secret",
						TLSInsecureSkipVerify: true,
					},
					tokenURL:      server.URL,
					browserConfig: &browserConfig{TLSInsecureSkipVerify: true},
					logger:        zap.NewNop(),
				}
				var data map[string]any
				var err error
				if endpoint.facebook {
					data, err = provider.fetchFacebookAccessToken("https://client.example/callback", "state", "code")
				} else {
					data, err = provider.fetchAccessToken("https://client.example/callback", "state", "code", "verifier")
				}
				if tc.wantErr == "" {
					if err != nil || data["access_token"] != "opaque" {
						t.Fatalf("token exchange = %#v, %v", data, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("token exchange error = %v, want substring %q", err, tc.wantErr)
				}
				if tc.forbid != "" && strings.Contains(err.Error(), tc.forbid) {
					t.Fatalf("token exchange error exposed malformed provider data: %v", err)
				}
			})
		}
	}
}

func must[T any](val T, err error) T {
	if err != nil {
		panic(err)
	}
	return val
}

func TestAuthenticate(t *testing.T) {
	// For "state"
	uuid.SetRand(rand.New(rand.NewSource(1)))
	defer uuid.SetRand(nil)

	testcases := []struct {
		name      string
		config    *Config
		logger    *zap.Logger
		shouldErr bool
		errPhase  string
		err       error
		request   requests.Request
		want      requests.Response
	}{
		{
			name: "discord provider with overridden urls",
			config: &Config{
				Name:             "discord",
				Realm:            "discord",
				Driver:           "discord",
				ClientID:         "foo",
				ClientSecret:     "bar",
				AuthorizationURL: "https://discordapp.com/other/authorize?prompt=none",
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://discordapp.com/other/authorize?client_id=foo&prompt=none&" +
					"redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=52fdfc07-2182-454f-963f-5f0f9a621d72",
			},
		},
		{
			name: "discord provider ignores request prompt none",
			config: &Config{
				Name:             "discord",
				Realm:            "discord",
				Driver:           "discord",
				ClientID:         "foo",
				ClientSecret:     "bar",
				AuthorizationURL: "https://discordapp.com/other/authorize",
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz&prompt=none", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://discordapp.com/other/authorize?client_id=foo&" +
					"redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=9566c74d-1003-4c4d-bbbb-0407d1e2c649",
			},
		},
		{
			name: "google provider forwards request prompt none",
			config: &Config{
				Name:                    "google",
				Realm:                   "google",
				Driver:                  "google",
				ClientID:                "foo.apps.googleusercontent.com",
				ClientSecret:            "bar",
				Scopes:                  []string{"identify"},
				AuthorizationURL:        "https://accounts.google.com/o/oauth2/v2/auth",
				KeyVerificationDisabled: true,
				NonceDisabled:           true,
				PKCEDisabled:            true,
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz&prompt=none", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://accounts.google.com/o/oauth2/v2/auth?client_id=foo.apps.googleusercontent.com&" +
					"prompt=none&redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=81855ad8-681d-4d86-91e9-1e00167939cb",
			},
		},
		{
			name: "google provider forwards request prompt consent",
			config: &Config{
				Name:                    "google",
				Realm:                   "google",
				Driver:                  "google",
				ClientID:                "foo.apps.googleusercontent.com",
				ClientSecret:            "bar",
				Scopes:                  []string{"identify"},
				AuthorizationURL:        "https://accounts.google.com/o/oauth2/v2/auth",
				KeyVerificationDisabled: true,
				NonceDisabled:           true,
				PKCEDisabled:            true,
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz&prompt=consent", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://accounts.google.com/o/oauth2/v2/auth?client_id=foo.apps.googleusercontent.com&" +
					"prompt=consent&redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=6694d2c4-22ac-4208-a007-2939487f6999",
			},
		},
		{
			name: "google provider forwards request prompt select_account",
			config: &Config{
				Name:                    "google",
				Realm:                   "google",
				Driver:                  "google",
				ClientID:                "foo.apps.googleusercontent.com",
				ClientSecret:            "bar",
				Scopes:                  []string{"identify"},
				AuthorizationURL:        "https://accounts.google.com/o/oauth2/v2/auth",
				KeyVerificationDisabled: true,
				NonceDisabled:           true,
				PKCEDisabled:            true,
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz&prompt=select_account", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://accounts.google.com/o/oauth2/v2/auth?client_id=foo.apps.googleusercontent.com&" +
					"prompt=select_account&redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=eb9d18a4-4784-445d-87f3-c67cf22746e9",
			},
		},
		{
			name: "google provider drops invalid request prompt",
			config: &Config{
				Name:                    "google",
				Realm:                   "google",
				Driver:                  "google",
				ClientID:                "foo.apps.googleusercontent.com",
				ClientSecret:            "bar",
				Scopes:                  []string{"identify"},
				AuthorizationURL:        "https://accounts.google.com/o/oauth2/v2/auth",
				KeyVerificationDisabled: true,
				NonceDisabled:           true,
				PKCEDisabled:            true,
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz&prompt=bogus", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://accounts.google.com/o/oauth2/v2/auth?client_id=foo.apps.googleusercontent.com&" +
					"redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=95af5a25-3679-41ba-a2ff-6cd471c483f1",
			},
		},
		{
			name: "google provider forwards request prompt consent and select account",
			config: &Config{
				Name:                    "google",
				Realm:                   "google",
				Driver:                  "google",
				ClientID:                "foo.apps.googleusercontent.com",
				ClientSecret:            "bar",
				Scopes:                  []string{"identify"},
				AuthorizationURL:        "https://accounts.google.com/o/oauth2/v2/auth",
				KeyVerificationDisabled: true,
				NonceDisabled:           true,
				PKCEDisabled:            true,
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz&prompt=consent+select_account", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://accounts.google.com/o/oauth2/v2/auth?client_id=foo.apps.googleusercontent.com&" +
					"prompt=consent+select_account&redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=5fb90bad-b37c-4821-b6d9-5526a41a9504",
			},
		},
		{
			name: "google provider forwards request prompt select account and consent",
			config: &Config{
				Name:                    "google",
				Realm:                   "google",
				Driver:                  "google",
				ClientID:                "foo.apps.googleusercontent.com",
				ClientSecret:            "bar",
				Scopes:                  []string{"identify"},
				AuthorizationURL:        "https://accounts.google.com/o/oauth2/v2/auth",
				KeyVerificationDisabled: true,
				NonceDisabled:           true,
				PKCEDisabled:            true,
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					BaseURL:  "https://hostname",
					BasePath: "/route",
					Request:  must(http.NewRequest(http.MethodGet, "/foo?bar=baz&prompt=select_account+consent", nil)),
				},
			},
			want: requests.Response{
				Code: 302,
				RedirectURL: "https://accounts.google.com/o/oauth2/v2/auth?client_id=foo.apps.googleusercontent.com&" +
					"prompt=select_account+consent&redirect_uri=https%3A%2F%2Fhostname%2Froute%2Fauthorization-code-callback&" +
					"response_type=code&scope=identify&state=680b4e7c-8b76-4a1b-9d49-d4955c848621",
			},
		},
		{
			name: "discord provider with overridden and invalid urls",
			config: &Config{
				Name:             "discord",
				Realm:            "discord",
				Driver:           "discord",
				ClientID:         "foo",
				ClientSecret:     "bar",
				AuthorizationURL: "https://discordapp.com/other/authorize?prompt=none" + string(byte(1)),
			},
			logger: logutil.NewLogger(),
			request: requests.Request{
				Upstream: requests.Upstream{
					Request: must(http.NewRequest(http.MethodGet, "/foo?bar=baz", nil)),
				},
			},
			shouldErr: true,
			errPhase:  "authenticate",
			err:       errors.ErrIdentityProviderConfig.WithArgs("could not parse authorization url"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}
			msgs = append(msgs, fmt.Sprintf("config:\n%v", tc.config))

			prv, err := NewIdentityProvider(tc.config, tc.logger)
			if tests.EvalErrPhaseWithLog(t, err, "initialize", tc.errPhase, tc.shouldErr, tc.err, msgs) {
				return
			}

			err = prv.Configure()
			if tests.EvalErrPhaseWithLog(t, err, "configure", tc.errPhase, tc.shouldErr, tc.err, msgs) {
				return
			}

			tc.request.Upstream.SessionID = "synthetic-browser-session"
			err = prv.Authenticate(&tc.request)
			if tests.EvalErrPhaseWithLog(t, err, "authenticate", tc.errPhase, tc.shouldErr, tc.err, msgs) {
				return
			}

			tests.EvalObjectsWithLog(t, "authenticate", tc.want, tc.request.Response, msgs)
		})
	}
}
