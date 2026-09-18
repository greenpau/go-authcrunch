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

package authz_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func newRedirectGateServer(t *testing.T, cfg *authz.PolicyConfig) *httptest.Server {
	t.Helper()
	cfg.Name = "redirect-boundary"
	cfg.ValidateBearerHeader = true
	cfg.RawCryptoKeyStoreConfig = []string{"crypto key verify " + testutils.GetSharedKey()}
	gate, err := authz.NewGatekeeper(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = gate.Authenticate(w, r, requests.NewAuthorizationRequest())
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func redirectTestToken(t *testing.T, roles ...string) string {
	t.Helper()
	usr := testutils.NewTestUser()
	usr.SetRolesClaim(roles)
	keys, err := testutils.NewTestCryptoKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SignToken("access_token", "HS512", usr); err != nil {
		t.Fatal(err)
	}
	return usr.Token
}

func TestE2EAuthorizationRedirectBoundaries(t *testing.T) {
	t.Run("forbidden URI placeholder remains on the serving origin", func(t *testing.T) {
		server := newRedirectGateServer(t, &authz.PolicyConfig{
			ForbiddenURL: "{uri}",
			AccessListRules: []*acl.RuleConfiguration{{
				Conditions: []string{"match roles administrator"},
				Action:     "allow stop",
			}},
		})
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client.Timeout = 5 * time.Second
		token := redirectTestToken(t, "viewer")
		testcases := []struct {
			target       string
			wantLocation string
		}{
			{target: "//evil.example/private", wantLocation: "/.//evil.example/private"},
			{target: "/%5C%5Cevil.example/private", wantLocation: "/%5C%5Cevil.example/private"},
			{target: "/%2F%2Fevil.example/private", wantLocation: "/%2F%2Fevil.example/private"},
		}
		for _, tc := range testcases {
			t.Run(tc.target, func(t *testing.T) {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+tc.target, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusSeeOther {
					t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSeeOther)
				}
				if got := resp.Header.Get("Location"); got != tc.wantLocation {
					t.Fatalf("Location = %q, want %q", got, tc.wantLocation)
				}
			})
		}
	})

	t.Run("request authority remains inside configured login return parameter", func(t *testing.T) {
		server := newRedirectGateServer(t, &authz.PolicyConfig{
			AuthURLPath:                "https://auth.example/login",
			AuthRedirectQueryParameter: "return_url",
			AccessListRules: []*acl.RuleConfiguration{{
				Conditions: []string{"match roles viewer"},
				Action:     "allow stop",
			}},
		})
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client.Timeout = 5 * time.Second
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"//evil.example/private", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Forwarded-Host", "evil.example")
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
		}
		location, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if location.Scheme != "https" || location.Host != "auth.example" || location.Path != "/login" {
			t.Fatalf("redirect destination = %q, want https://auth.example/login", location.String())
		}
		if got := location.Query().Get("return_url"); got != "https://evil.example//evil.example/private" {
			t.Fatalf("return_url = %q, want forwarded request URL", got)
		}
	})

	t.Run("ambiguous forbidden templates fail without redirect", func(t *testing.T) {
		testcases := []string{
			"/{uri}",
			"https:/{uri}",
			`\{uri}`,
			" /{uri}",
			"//{uri}",
			"///{uri}",
		}
		for _, forbiddenURL := range testcases {
			t.Run(forbiddenURL, func(t *testing.T) {
				server := newRedirectGateServer(t, &authz.PolicyConfig{
					ForbiddenURL: forbiddenURL,
					AccessListRules: []*acl.RuleConfiguration{{
						Conditions: []string{"match roles administrator"},
						Action:     "allow stop",
					}},
				})
				client := server.Client()
				client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
				client.Timeout = 5 * time.Second
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/evil.example/callback", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+redirectTestToken(t, "viewer"))
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
				}
				if got := resp.Header.Get("Location"); got != "" {
					t.Fatalf("Location = %q, want empty", got)
				}
			})
		}
	})
}

func authzChromeExecutable(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("AUTHCRUNCH_TEST_BROWSER"); configured != "" {
		return configured
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	if runtime.GOOS == "darwin" {
		path := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Fatal("Chrome/Chromium is required for browser E2E; set AUTHCRUNCH_TEST_BROWSER to its executable")
	return ""
}

func TestE2EAuthorizationRedirectBrowserOrigin(t *testing.T) {
	gate, err := authz.NewGatekeeper(&authz.PolicyConfig{
		Name:            "browser-redirect-boundary",
		ForbiddenURL:    "/{uri}",
		AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles administrator"}, Action: "allow stop"}},
		RawCryptoKeyStoreConfig: []string{
			"crypto key verify " + testutils.GetSharedKey(),
		},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	token := redirectTestToken(t, "viewer")

	var mu sync.Mutex
	var visits []string
	var finalStatus int
	var finalLocation string
	completed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/start":
			w.Header().Set("Location", "/.//evil.example/landed-double-slash")
			w.WriteHeader(http.StatusSeeOther)
		case strings.Contains(r.RequestURI, "landed-double-slash"):
			mu.Lock()
			visits = append(visits, r.Host+" "+r.RequestURI)
			mu.Unlock()
			w.Header().Set("Location", "/%5C%5Cevil.example/landed-backslash")
			w.WriteHeader(http.StatusSeeOther)
		case strings.Contains(r.RequestURI, "landed-backslash"):
			mu.Lock()
			visits = append(visits, r.Host+" "+r.RequestURI)
			mu.Unlock()
			w.Header().Set("Location", "/%2F%2Fevil.example/landed-encoded-slash")
			w.WriteHeader(http.StatusSeeOther)
		case strings.Contains(r.RequestURI, "landed-encoded-slash"):
			mu.Lock()
			visits = append(visits, r.Host+" "+r.RequestURI)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "access_token", Value: token, Path: "/", Secure: true, HttpOnly: true})
			w.Header().Set("Location", "/evil.example/callback")
			w.WriteHeader(http.StatusSeeOther)
		default:
			recorder := httptest.NewRecorder()
			_ = gate.Authenticate(recorder, r, requests.NewAuthorizationRequest())
			mu.Lock()
			finalStatus = recorder.Code
			finalLocation = recorder.Header().Get("Location")
			mu.Unlock()
			for name, values := range recorder.Header() {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			select {
			case completed <- struct{}{}:
			default:
			}
		}
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, authzChromeExecutable(t),
		"--headless=new",
		"--ignore-certificate-errors",
		"--allow-insecure-localhost",
		"--disable-background-networking",
		"--disable-gpu",
		"--no-first-run",
		"--user-data-dir="+t.TempDir(),
		server.URL+"/start",
	)
	cmd.WaitDelay = 2 * time.Second
	var diagnostic bytes.Buffer
	cmd.Stdout = &diagnostic
	cmd.Stderr = &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Chrome: %v", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case <-completed:
	case err := <-waited:
		t.Fatalf("Chrome exited before completing redirect journey: %v\n%s", err, diagnostic.String())
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-waited:
			t.Fatalf("Chrome redirect journey timed out: %v\n%s", ctx.Err(), diagnostic.String())
		case <-time.After(3 * time.Second):
			t.Fatalf("Chrome redirect journey timed out and the process did not exit: %v", ctx.Err())
		}
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("Chrome did not exit after redirect journey")
	}
	mu.Lock()
	gotVisits := append([]string(nil), visits...)
	gotFinalStatus, gotFinalLocation := finalStatus, finalLocation
	mu.Unlock()
	if len(gotVisits) != 3 {
		t.Fatalf("local redirect visits = %v, want three", gotVisits)
	}
	wantHost := strings.TrimPrefix(server.URL, "https://")
	for _, visit := range gotVisits {
		if !strings.HasPrefix(visit, wantHost+" ") {
			t.Fatalf("browser changed redirect authority: visit=%q, serving authority=%q", visit, wantHost)
		}
	}
	for i, marker := range []string{"//evil.example/landed-double-slash", "%5C%5Cevil.example/landed-backslash", "%2F%2Fevil.example/landed-encoded-slash"} {
		if !strings.Contains(gotVisits[i], marker) {
			t.Fatalf("visit %d = %q, want marker %q", i, gotVisits[i], marker)
		}
	}
	if gotFinalStatus != http.StatusForbidden || gotFinalLocation != "" {
		t.Fatalf("gatekeeper browser response status=%d Location=%q, want 403 without redirect", gotFinalStatus, gotFinalLocation)
	}
	t.Logf("Chrome kept each redirect on %s: %s", wantHost, strings.Join(gotVisits, "; "))
}
