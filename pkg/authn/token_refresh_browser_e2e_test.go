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

package authn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func refreshBrowserExecutable(t *testing.T) string {
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

// Start with a bounded readiness wait and reap the process before reading its
// diagnostics. Chrome can exit before creating DevToolsActivePort; waiting only
// for the file hides the actual startup failure behind a timeout.
func startRefreshBrowser(ctx context.Context, chrome *exec.Cmd, profile string) (string, func(), error) {
	var diagnostic bytes.Buffer
	chrome.Stdout = &diagnostic
	chrome.Stderr = &diagnostic
	chrome.WaitDelay = time.Second
	if err := chrome.Start(); err != nil {
		return "", nil, fmt.Errorf("start browser %q: %w", chrome.Path, err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = chrome.Wait()
		close(done)
	}()
	stop := func() {
		select {
		case <-done:
		default:
			_ = chrome.Process.Kill()
			<-done
		}
	}
	failure := func(err error) (string, func(), error) {
		stop()
		return "", nil, fmt.Errorf("browser %q startup failed: %w\n%s", chrome.Path, err, diagnostic.String())
	}
	// Keep this inside the overall E2E deadline, allowing loaded CI runners
	// more time than the former 15-second startup window.
	startup, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			if startup.Err() != nil {
				return failure(fmt.Errorf("waiting for debugging endpoint: %w", startup.Err()))
			}
			if waitErr != nil {
				return failure(fmt.Errorf("exited before exposing a debugging endpoint: %w", waitErr))
			}
			return failure(fmt.Errorf("exited before exposing a debugging endpoint"))
		case <-startup.Done():
			return failure(fmt.Errorf("waiting for debugging endpoint: %w", startup.Err()))
		case <-ticker.C:
			data, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
			if err != nil {
				continue
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) == 2 && lines[0] != "" && strings.HasPrefix(lines[1], "/devtools/browser/") {
				return "ws://127.0.0.1:" + lines[0] + lines[1], stop, nil
			}
		}
	}
}

// The fixture pauses already rendered old HTML and truncates one already
// committed refresh response. Login, cookies, signatures, storage, Web Locks,
// bootstrap, account replacement and logout remain real production behavior.
func TestE2ERefreshBrowserBootstrap(t *testing.T) {
	browser := refreshBrowserExecutable(t)
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("Node.js is required for browser E2E")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := db.AddUser(&requests.Request{User: requests.User{Username: name, Email: name + "@example.test", Password: tests.TestPwd1, Roles: []string{"authp/user"}}}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{Name: "browser-local", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	portal, err := authn.NewPortal(authn.PortalParameters{Config: &authn.PortalConfig{
		Name: "browser-session", IdentityStores: []string{"browser-local"},
		RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://" + server.Listener.Addr().String(), BasePath: "/auth", AccessLifetimeSeconds: 300, IdleTimeoutSeconds: 600, AbsoluteTimeoutSeconds: 1800},
	}, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store}})
	if err != nil {
		t.Fatal(err)
	}
	var rotations atomic.Int32
	var staleRendered, cutNext atomic.Bool
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); server.Close(); portal.Close() })
	serve := func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Error("browser portal handler failed")
		}
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_test/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"rotations": rotations.Load(), "stale_rendered": staleRendered.Load()})
			return
		case "/_test/cut":
			cutNext.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		case "/_test/release":
			releaseOnce.Do(func() { close(release) })
			w.WriteHeader(http.StatusNoContent)
			return
		}
		stale := r.URL.Path == "/auth/portal" && r.URL.Query().Get("deferred") == "1"
		cut := false
		if r.URL.Path == "/auth/api/refresh_token" {
			rotations.Add(1)
			cut = cutNext.Swap(false)
		}
		if !stale && !cut {
			serve(w, r)
			return
		}
		recorder := httptest.NewRecorder()
		serve(recorder, r)
		if stale {
			staleRendered.Store(true)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		for key, values := range recorder.Header() {
			w.Header()[key] = append([]string(nil), values...)
		}
		if cut {
			if recorder.Code != http.StatusOK {
				t.Error("controlled response loss did not follow a committed refresh")
			}
			// Chrome applies the real Set-Cookie headers, then sees an incomplete
			// body. The coordinator must retain its pending marker in both tabs.
			w.Header().Set("Content-Length", "10000")
			w.WriteHeader(recorder.Code)
			_, _ = w.Write([]byte("{"))
			return
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
	server.StartTLS()
	profile := t.TempDir()
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	chrome := exec.CommandContext(ctx, browser,
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:]),
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking",
		"--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad",
		"--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	driver := exec.CommandContext(ctx, "node", "ui/testdata/token_refresh_browser_e2e.cjs", endpoint, server.URL)
	driver.Stdin = strings.NewReader(tests.TestPwd1)
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("browser E2E failed: %v\n%s", err, output)
	}
	var result struct {
		Passed    bool `json:"passed"`
		Rotations int  `json:"rotations"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed || result.Rotations != 2 {
		t.Fatal("browser driver did not confirm the complete session journey")
	}
}
