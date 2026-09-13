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

package cookie_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"golang.org/x/net/publicsuffix"
)

func TestE2ECookieDomainPolicy(t *testing.T) {
	for _, state := range []string{"enabled", "disabled"} {
		t.Run(state, func(t *testing.T) {
			config, err := cookieparser.NewCookieConfigFromDirectives([]string{
				cfgutil.EncodeArgs([]string{"cookie", "prefix", "TENANT"}),
				cfgutil.EncodeArgs([]string{"cookie", "domain", "example.test", "path", "/auth"}),
				cfgutil.EncodeArgs([]string{"cookie", "domain", "example.test", "lifetime", "600"}),
				cfgutil.EncodeArgs([]string{"cookie", "domain", "example.test", "same", "site", "lax"}),
				cfgutil.EncodeArgs([]string{"cookie", "domain", "example.test", "strip", "domain", state}),
			})
			if err != nil {
				t.Fatal(err)
			}
			factory, err := cookie.NewFactory(config)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/auth/issue":
					w.Header().Add("Set-Cookie", factory.GetAccessTokenCookie(r.Host, "synthetic"))
				case "/auth/delete":
					w.Header().Add("Set-Cookie", factory.GetDeleteAccessTokenCookie(r.Host))
				default:
					if c, err := r.Cookie("TENANT_ACCESS_TOKEN"); err == nil && c.Value == "synthetic" {
						w.WriteHeader(http.StatusOK)
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
				}
			}))
			t.Cleanup(server.Close)
			client := server.Client()
			transport := client.Transport.(*http.Transport).Clone()
			// Route synthetic hostnames to this listener while retaining certificate
			// verification against its IP SAN and the server client's trusted CA.
			transport.TLSClientConfig.ServerName = server.Listener.Addr().(*net.TCPAddr).IP.String()
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}
			t.Cleanup(transport.CloseIdleConnections)
			client.Transport, client.Timeout = transport, 5*time.Second
			client.Jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
			if err != nil {
				t.Fatal(err)
			}
			request := func(host, path string, want int) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+host+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
				response.Body.Close()
				if response.StatusCode != want {
					t.Fatalf("cookie scope at %s%s: HTTP %d, want %d", host, path, response.StatusCode, want)
				}
				return response
			}
			issued := request("login.example.test", "/auth/issue", http.StatusOK).Cookies()
			if len(issued) != 1 || issued[0].Name != "TENANT_ACCESS_TOKEN" || !issued[0].Secure || !issued[0].HttpOnly || issued[0].SameSite != http.SameSiteLaxMode || issued[0].Path != "/auth" || issued[0].MaxAge != 600 {
				t.Fatal("issued cookie lost configured names or attributes")
			}
			if (issued[0].Domain == "") != (state == "enabled") {
				t.Fatal("domain stripping did not match configuration")
			}
			request("login.example.test", "/auth/read", http.StatusOK)
			request("login.example.test", "/outside", http.StatusUnauthorized)
			siblingStatus := http.StatusOK
			if state == "enabled" {
				siblingStatus = http.StatusUnauthorized
			}
			request("app.example.test", "/auth/read", siblingStatus)
			deleted := request("login.example.test", "/auth/delete", http.StatusOK).Cookies()
			if len(deleted) != 1 || deleted[0].Name != issued[0].Name || deleted[0].Domain != issued[0].Domain || deleted[0].Path != issued[0].Path {
				t.Fatal("deletion changed cookie scope")
			}
			request("login.example.test", "/auth/read", http.StatusUnauthorized)
			request("app.example.test", "/auth/read", http.StatusUnauthorized)
		})
	}
}
