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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func assertLoginSigningFailureLog(t *testing.T, p *Portal, logs *observer.ObservedLogs, legacy bool) {
	t.Helper()
	entries := logs.FilterMessage("user token signing failed").All()
	if len(entries) != 1 || entries[0].Level != zap.WarnLevel {
		t.Fatal("signing refusal lost its single WARN event")
	}
	fields := entries[0].ContextMap()
	for _, key := range []string{"session_id", "request_id", "error"} {
		value, ok := fields[key].(string)
		if !ok || value == "" {
			t.Fatalf("signing refusal lost %s", key)
		}
	}
	payload, exists := fields["user"]
	if exists != legacy {
		t.Fatal("signing refusal changed its user diagnostic boundary")
	}
	if legacy {
		claims, ok := payload.(map[string]any)
		if !ok || claims["sub"] != tests.TestUser1 {
			t.Fatal("legacy signing diagnostic lost the authenticated username")
		}
	}
	p.logger.Info("unrelated signing diagnostic control")
	if logs.FilterMessage("unrelated signing diagnostic control").All()[0].ContextMap()["user"] != nil {
		t.Fatal("event-specific claims leaked into the shared logger")
	}
	assertAuthenticationEventSecrets(t, logs, tests.TestPwd1)
}

func TestLegacyAccessSigningFailureDiagnostics(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	core, logs := observer.New(zap.InfoLevel)
	p.logger = zap.New(core)
	p.keystore = &kms.CryptoKeyStore{} // Fail signing after real password verification.
	r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth/basic/login/local", nil)
	rr := requests.NewRequest()
	rr.ID, rr.Upstream.SessionID = "signing-log-request", "signing-log-session"
	if err := p.authenticateBasicAuthRequest(t.Context(), httptest.NewRecorder(), r, rr, "local", tests.TestUser1, tests.TestPwd1); err != nil {
		t.Fatal("password control failed")
	}
	u, err := p.authorizeLoginUser(t.Context(), r, rr)
	if err == nil || u != nil || rr.Response.Code != http.StatusInternalServerError {
		t.Fatal("failed signer returned an authorized user")
	}
	assertLoginSigningFailureLog(t, p, logs, true)
}

func TestE2EBasicLoginSigningDiagnostics(t *testing.T) {
	for _, kind := range []string{"legacy", "selected"} {
		for _, fail := range []bool{false, true} {
			name := kind + map[bool]string{false: "/success", true: "/failure"}[fail]
			t.Run(name, func(t *testing.T) {
				var p *Portal
				if kind == "legacy" {
					p = newRefreshPortal(t, false, false).portal
					if fail {
						p.keystore = &kms.CryptoKeyStore{}
					}
				} else {
					f, _, probe := selectedPortal(t, false)
					p = f.portal
					if fail {
						probe.mode = "error"
					}
				}
				core, logs := observer.New(zap.InfoLevel)
				p.logger = zap.New(core)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := p.ServeHTTPAt(r.Context(), w, r, requests.NewRequest(), "/auth"); err != nil {
						t.Error("TLS portal failed to write signing response")
					}
				}))
				defer server.Close()
				client := server.Client()
				client.Timeout = 10 * time.Second
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/auth/basic/login/local", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.SetBasicAuth(tests.TestUser1, tests.TestPwd1)
				response, err := client.Do(req)
				if err != nil {
					t.Fatal("TLS Basic login request failed")
				}
				defer response.Body.Close()
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal("read Basic login response")
				}
				if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
					t.Fatal("missing verified TLS")
				}
				want := http.StatusSeeOther
				if fail {
					want = http.StatusInternalServerError
				}
				if response.StatusCode != want {
					t.Fatalf("Basic login HTTP %d, want %d", response.StatusCode, want)
				}
				if response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("Basic login response was cacheable")
				}
				if fail {
					if response.Header.Get("Authorization") != "" || response.Header.Get("Location") != "" {
						t.Fatal("failed signing emitted authority or navigation")
					}
					for _, cookie := range response.Cookies() {
						if cookie.Name == p.cookie.AccessTokenCookieName && cookie.Value != "" && cookie.MaxAge >= 0 {
							t.Fatal("failed signing issued access cookie")
						}
					}
					assertLoginSigningFailureLog(t, p, logs, kind == "legacy")
				} else {
					if !strings.HasPrefix(response.Header.Get("Authorization"), "Bearer ") {
						t.Fatal("successful Basic login omitted signed access")
					}
					if logs.FilterMessage("user token signing failed").Len() != 0 {
						t.Fatal("successful login emitted signing failure")
					}
				}
				assertAuthenticationEventSecrets(t, logs, tests.TestPwd1, req.Header.Get("Authorization"))
			})
		}
	}
}
