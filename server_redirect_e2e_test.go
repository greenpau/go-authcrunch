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

package authcrunch_test

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// HTTP/3 must reach the gatekeeper through quic-go's real request parser. Merely
// setting ProtoMajor on a net/http request would miss the original regression.
func serveRedirectHTTP3(t *testing.T, server *httptest.Server) {
	t.Helper()
	conn, err := net.ListenPacket("udp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{Handler: server.Config.Handler, TLSConfig: server.TLS.Clone()}
	done := make(chan error, 1)
	go func() { done <- h3.Serve(conn) }()
	t.Cleanup(func() {
		if err := h3.Close(); err != nil {
			t.Errorf("close HTTP/3 server: %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Errorf("close HTTP/3 socket: %v", err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("HTTP/3 server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	})
}

type redirectLoginFixture struct {
	client              *http.Client
	application, portal string
	protocol            int
}

func newRedirectLoginFixture(t *testing.T, protocol int) *redirectLoginFixture {
	t.Helper()
	appServer := httptest.NewUnstartedServer(nil)
	portalServer := httptest.NewUnstartedServer(nil)
	t.Cleanup(appServer.Close)
	t.Cleanup(portalServer.Close)
	f := &redirectLoginFixture{
		application: "https://" + appServer.Listener.Addr().String(),
		portal:      "https://" + portalServer.Listener.Addr().String(),
		protocol:    protocol,
	}
	trusted, err := redirects.NewRedirectURIMatchConfig("exact", appServer.Listener.Addr().String(), "prefix", "/")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{
		Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"},
	}}); err != nil {
		t.Fatal("provision redirect test identity")
	}
	keys := []string{"crypto key redirect sign-verify from file testdata/rskeys/test_2_pri.pem"}
	runtime, err := authcrunch.NewServer(&authcrunch.Config{
		IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": dbPath}}},
		AuthenticationPortals: []*authn.PortalConfig{{
			Name: "portal", IdentityStores: []string{"local"}, RawCryptoKeyStoreConfig: keys,
			TrustedLoginRedirectURIConfigs: []*redirects.RedirectURIMatchConfig{trusted},
		}},
		AuthorizationPolicies: []*authz.PolicyConfig{{
			Name: "policy", AuthURLPath: f.portal + "/auth/login", RawCryptoKeyStoreConfig: keys,
			AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
		}},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		appServer.Close()
		portalServer.Close()
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	})
	portal, err := runtime.GetPortalByName("portal")
	if err != nil {
		t.Fatal(err)
	}
	gate, err := runtime.GetGatekeeperByName("policy")
	if err != nil {
		t.Fatal(err)
	}
	portalServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Errorf("redirect portal request: %v", err)
		}
	})
	appServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != protocol || (protocol == 3 && (!r.URL.IsAbs() || !strings.HasPrefix(r.RequestURI, "/"))) {
			t.Errorf("unexpected server request representation: protocol=%s URL=%q RequestURI=%q", r.Proto, r.URL.String(), r.RequestURI)
			http.Error(w, "unexpected protocol", http.StatusBadRequest)
			return
		}
		ar := requests.NewAuthorizationRequest()
		// An unauthenticated request already has a redirect response. Only
		// the explicit Authorized outcome may execute the application.
		if err := gate.Authenticate(w, r, ar); err != nil || !ar.Response.Authorized {
			return
		}
		_, _ = io.WriteString(w, "protected resource: "+r.RequestURI)
	})
	appServer.EnableHTTP2 = protocol == 2
	portalServer.EnableHTTP2 = protocol == 2
	appServer.StartTLS()
	portalServer.StartTLS()
	f.client = appServer.Client()
	if protocol == 3 {
		serveRedirectHTTP3(t, appServer)
		serveRedirectHTTP3(t, portalServer)
		tlsConfig := f.client.Transport.(*http.Transport).TLSClientConfig.Clone()
		transport := &http3.Transport{TLSClientConfig: tlsConfig}
		f.client.Transport = transport
		t.Cleanup(func() {
			if err := transport.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(f.client.CloseIdleConnections)
	f.client.Timeout = 10 * time.Second
	f.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return f
}

func (f *redirectLoginFixture) request(t *testing.T, method, target string, form url.Values, wantStatus int) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatalf("redirect journey request: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal("read redirect journey response")
	}
	if resp.StatusCode != wantStatus || resp.ProtoMajor != f.protocol {
		t.Fatalf("response = %s %d, want HTTP/%d %d", resp.Proto, resp.StatusCode, f.protocol, wantStatus)
	}
	return resp, string(data)
}

func TestE2EServerAuthorizationLoginRedirectProtocols(t *testing.T) {
	for _, protocol := range []struct {
		name  string
		major int
	}{{"HTTP1", 1}, {"HTTP2", 2}, {"HTTP3", 3}} {
		t.Run(protocol.name, func(t *testing.T) {
			f := newRedirectLoginFixture(t, protocol.major)
			for _, target := range []string{"/", "/files/a%2fb?x=one%26two&x=three+four", "//other.example/private"} {
				t.Run(target, func(t *testing.T) {
					var err error
					f.client.Jar, err = cookiejar.New(nil)
					if err != nil {
						t.Fatal(err)
					}
					wantReturn := f.application + target
					redirect, _ := f.request(t, http.MethodGet, wantReturn, nil, http.StatusFound)
					loginURL, err := url.Parse(redirect.Header.Get("Location"))
					if err != nil {
						t.Fatal(err)
					}
					if loginURL.Scheme+"://"+loginURL.Host+loginURL.Path != f.portal+"/auth/login" {
						t.Fatalf("unexpected portal destination %q", loginURL.String())
					}
					if got := loginURL.Query().Get("redirect_url"); got != wantReturn {
						t.Fatalf("redirect_url = %q, want %q", got, wantReturn)
					}
					f.request(t, http.MethodGet, loginURL.String(), nil, http.StatusOK)
					start, _ := f.request(t, http.MethodPost, f.portal+"/auth/login", url.Values{"username": {"alice"}, "realm": {"local"}}, http.StatusSeeOther)
					sandbox, err := start.Location()
					if err != nil {
						t.Fatal(err)
					}
					f.request(t, http.MethodPost, sandbox.String(), url.Values{"secret": {tests.TestPwd1}}, http.StatusSeeOther)
					completed, _ := f.request(t, http.MethodGet, sandbox.String(), nil, http.StatusSeeOther)
					if got := completed.Header.Get("Location"); got != wantReturn {
						t.Fatalf("post-login destination = %q, want %q", got, wantReturn)
					}
					_, body := f.request(t, http.MethodGet, completed.Header.Get("Location"), nil, http.StatusOK)
					if body != "protected resource: "+target {
						t.Fatalf("returned resource = %q, want original protected resource", body)
					}
				})
			}
		})
	}
}
