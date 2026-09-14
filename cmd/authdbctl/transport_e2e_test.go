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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	clientparser "github.com/greenpau/go-authcrunch/pkg/authclient/parser"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// The unchanged executable talks to a loopback HTTP relay, whose outbound TLS
// connection trusts only the test portal. This keeps private CA installation out
// of OS trust stores (including macOS), while testing real portal TLS handlers.
// pkg/authclient's E2E suite separately verifies direct native TLS and cookie-jar
// isolation. This fixture does not claim direct CLI custom-CA configuration.
func cliNativeRelay(t *testing.T, f *cliE2EPortal) *httptest.Server {
	t.Helper()
	target, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{
		Transport: f.server.Client().Transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(target)
			request.Out.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			t.Error("native fixture relay failed")
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	relay := httptest.NewServer(proxy)
	t.Cleanup(relay.Close)
	return relay
}

func TestE2EAuthdbctlNativeTransport(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "authdbctl")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-race", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build authdbctl: %v\n%s", err, output)
	}
	for _, method := range []string{"password", "totp"} {
		t.Run(method, func(t *testing.T) {
			f := newCLIE2EPortal(t, method, false, &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, BodyTransportEnabled: true})
			relay := cliNativeRelay(t, f)
			home := t.TempDir()
			source := f.config()
			args := [][]string{{"base", "url", relay.URL + "/auth"}, {"username", source.Username}, {"realm", source.Realm}, {"password", source.Password}, {"refresh", "transport", "body"}}
			if method == "totp" {
				args = append(args, []string{"totp", "secret", source.TOTPSecret})
			}
			var directives []string
			for _, values := range args {
				directives = append(directives, cfgutil.EncodeArgs(values))
			}
			parsed, err := clientparser.NewAuthenticationClientConfigFromDirectives(directives)
			if err != nil {
				t.Fatal(err)
			}
			cfg := Config{Config: *parsed}
			writeE2EConfig(t, home, cfg)
			path := filepath.Join(home, ".config", "authdbctl", "token.jwt")
			var previous *authclient.Credentials
			for range 2 {
				out, diagnostic, err := runCLIProcess(t, binary, home, "", nil, "connect")
				if err != nil {
					t.Fatalf("native connect failed: %v", err)
				}
				store, err := authclient.NewFileTokenStore(path)
				if err != nil {
					t.Fatal(err)
				}
				credentials, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				if credentials.RefreshToken == "" || credentials.SessionID == "" || credentials.RefreshTokenName != "AUTHP_REFRESH_TOKEN" {
					t.Fatal("executable did not save native credentials")
				}
				for _, secret := range []string{cfg.Password, cliE2ESecret, credentials.AccessToken, credentials.RefreshToken} {
					if strings.Contains(out+diagnostic, secret) {
						t.Fatal("executable leaked a credential")
					}
				}
				if previous != nil && (previous.RefreshToken == credentials.RefreshToken || previous.SessionID == credentials.SessionID) {
					t.Fatal("fresh connect reused previous native credentials")
				}
				previous = credentials
			}
			count := 4
			if method == "totp" {
				count = 6
			}
			f.assertOnlyLogin(t, count)
			f.assertCredential(t, path)
		})
	}
	t.Run("body unavailable preserves cache", func(t *testing.T) {
		f := newCLIE2EPortal(t, "password", false, &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}})
		relay := cliNativeRelay(t, f)
		home := t.TempDir()
		cfg := f.config()
		cfg.BaseURL = relay.URL + "/auth"
		cfg.RefreshTransport = authclient.RefreshTransportBody
		writeE2EConfig(t, home, cfg)
		path := filepath.Join(home, ".config", "authdbctl", "token.jwt")
		store, err := authclient.NewFileTokenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(&authclient.Credentials{AccessToken: "previous-access", RefreshToken: "previous-refresh"}); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := runCLIProcess(t, binary, home, "", nil, "connect"); err == nil {
			t.Fatal("unavailable transport exited successfully")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(before) != string(after) {
			t.Fatal("failed native login changed cached credentials")
		}
		f.assertOnlyLogin(t, 1)
	})
}
