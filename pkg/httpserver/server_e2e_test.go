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

package httpserver_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	"github.com/greenpau/go-authcrunch/pkg/httpserver"
	serverparser "github.com/greenpau/go-authcrunch/pkg/httpserver/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EHTTPServerSessions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "admin", Email: "admin@example.test", Password: tests.TestPwd1, Roles: []string{"authp/admin", "authp/user"}}}); err != nil {
		t.Fatal("provision identity:", err)
	}
	certFixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certFixture.TLS.Certificates[0]
	client := certFixture.Client()
	client.Timeout = 5 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	certFixture.Close()
	defer client.CloseIdleConnections()
	privateKey, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for filename, block := range map[string]*pem.Block{certFile: {Type: "CERTIFICATE", Bytes: cert.Certificate[0]}, keyFile: {Type: "PRIVATE KEY", Bytes: privateKey}} {
		if err := os.WriteFile(filename, pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	origin := "https://" + listener.Addr().String()
	issuer := origin + "/tenant/auth"
	transport, err := serverparser.NewHTTPServerConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"listen", listener.Addr().String()}),
		cfgutil.EncodeArgs([]string{"tls", "certificate", certFile}), cfgutil.EncodeArgs([]string{"tls", "key", keyFile}),
		"portal portal /tenant/auth", "timeout read header 500ms", "timeout shutdown 2s",
	})
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{"realms local", cfgutil.EncodeArgs([]string{"public", "origin", origin}), "base path /tenant/auth", "body transport enabled"})
	if err != nil {
		t.Fatal(err)
	}
	oidcKey := filepath.Join(dir, "oidc.pem")
	if err := oidc.GenerateSigningKeyFile(oidcKey); err != nil {
		t.Fatal(err)
	}
	application, err := oidcparser.NewOIDCClientConfigFromDirectives("test", []string{"client_id test-app", "token_endpoint_auth_method none", "redirect_uri https://app.example.test/callback", "require_pkce on"})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oidcparser.NewOIDCProviderConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"issuer", issuer}), "realms local", cfgutil.EncodeArgs([]string{"signing", "key", "files", oidcKey}), "applications test"}, map[string]*oidc.ClientConfig{"test": application})
	if err != nil {
		t.Fatal(err)
	}
	security := &authcrunch.Config{
		IdentityStores:        []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": dbPath}}},
		AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", IdentityStores: []string{"local"}, RefreshTokens: refresh, OIDCProvider: provider}},
	}
	// Consumers can persist parser results before starting the production host.
	saved, err := json.Marshal(security)
	if err != nil {
		t.Fatal(err)
	}
	security = &authcrunch.Config{}
	if err := json.Unmarshal(saved, security); err != nil {
		t.Fatal(err)
	}
	saved, err = json.Marshal(transport)
	if err != nil {
		t.Fatal(err)
	}
	transport = &httpserver.Config{}
	if err := json.Unmarshal(saved, transport); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan error, 1)
	go func() { finished <- httpserver.Serve(ctx, listener, transport, security, zap.NewNop()) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("runtime did not shut down")
		}
	})
	// The TCP listener is already open; TLS requests wait until the host is ready.
	response, err := client.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var discovery map[string]any
	err = json.NewDecoder(response.Body).Decode(&discovery)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || discovery["issuer"] != issuer || discovery["token_endpoint"] != issuer+"/oidc/token" {
		t.Fatal("OIDC discovery was not mounted correctly")
	}
	response, err = client.Get(issuer + "/oidc/jwks")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("OIDC signing-key endpoint unavailable")
	}
	auth, err := authclient.NewClient(&authclient.Config{BaseURL: issuer, Realm: "local", Username: "admin", Password: tests.TestPwd1, RefreshTransport: authclient.RefreshTransportBody}, authclient.Options{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := auth.Authenticate(t.Context())
	if err != nil {
		t.Fatal("native login failed:", err)
	}
	if credentials.RefreshToken == "" || credentials.SessionID == "" {
		t.Fatal("native credentials missing")
	}
	post := func(operation, token string) (int, *apiauth.AuthResponse) {
		t.Helper()
		body, err := json.Marshal(map[string]string{"refresh_token": token})
		if err != nil {
			t.Fatal("encode refresh request")
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer+"/api/"+operation, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		result, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer result.Body.Close()
		var response apiauth.AuthResponse
		if operation == "refresh_token" && result.StatusCode == 200 {
			if err := json.NewDecoder(result.Body).Decode(&response); err != nil {
				t.Fatal("invalid refresh response")
			}
		} else {
			io.Copy(io.Discard, result.Body)
		}
		return result.StatusCode, &response
	}
	status, rotated := post("refresh_token", credentials.RefreshToken)
	if status != 200 || rotated.RefreshToken == "" || rotated.RefreshToken == credentials.RefreshToken || rotated.SessionID != credentials.SessionID {
		t.Fatal("refresh rotation failed through standalone listener")
	}
	status, _ = post("logout", rotated.RefreshToken)
	if status != 200 && status != 204 {
		t.Fatalf("native logout status %d", status)
	}
	status, _ = post("refresh_token", rotated.RefreshToken)
	if status == 200 {
		t.Fatal("logout did not invalidate native session")
	}
	// ReadHeaderTimeout applies to real TLS connections, including incomplete requests.
	connection, err := tls.Dial("tcp", listener.Addr().String(), client.Transport.(*http.Transport).TLSClientConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, "GET /tenant/auth/login HTTP/1.1\r\nHost: "+listener.Addr().String()+"\r\n"); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	_, err = connection.Read(one[:])
	if err == nil {
		t.Fatal("incomplete request received unexpected response")
	}
	if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		t.Fatal("configured header deadline was not enforced")
	}
}
