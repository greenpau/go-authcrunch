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

package rsapss_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	signing "github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
	"github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss/parser"
)

// This fixture is a Go host for the public refresh engine, not a new portal
// plugin loader. It also runs from a separate module, with no internal imports.
type databaseIdentity struct{ db *identity.Database }

func (d databaseIdentity) WithIdentity(ctx context.Context, p tokenrefresh.Principal, apply func(map[string]any) error) error {
	if p.Backend != "local" || p.Realm != "local" || len(p.Methods) != 1 || p.Methods[0] != "pwd" {
		return tokenrefresh.ErrDenied
	}
	proof := requests.AuthenticationEvidence{UserID: p.UserID, BackendVersion: p.BackendVersion, CredentialVersion: p.CredentialVersion, Method: "pwd"}
	err := d.db.WithRefreshIdentity(ctx, proof, func(current identity.RefreshIdentity) error {
		if current.Username != p.Subject || len(current.Challenges) != 1 || current.Challenges[0] != "password" || current.AuthChallengePolicy {
			return tokenrefresh.ErrDenied
		}
		return apply(map[string]any{"sub": current.Username, "email": current.Email, "name": current.Name, "roles": current.Roles, "aud": []string{"api"}, "custom": map[string]any{"number": json.Number("9007199254740993"), "null": nil, "active": true}})
	})
	if errors.Is(err, identity.ErrRefreshIdentityDenied) {
		return tokenrefresh.ErrDenied
	}
	return err
}

type rejectedCommit struct{ tokenrefresh.Store }

func (s rejectedCommit) Create(context.Context, tokenrefresh.Session, int64) error {
	return tokenrefresh.ErrUnavailable
}
func (s rejectedCommit) Rotate(context.Context, tokenrefresh.Session, [32]byte, int64, int64) error {
	return tokenrefresh.ErrUnavailable
}

type observedSigner struct {
	next             tokenrefresh.Signer
	calls            atomic.Int32
	started, stopped chan struct{}
}

func (s *observedSigner) Sign(ctx context.Context, claims map[string]any) (string, error) {
	s.calls.Add(1)
	if s.started != nil {
		close(s.started)
		<-ctx.Done()
		close(s.stopped)
		return "", ctx.Err()
	}
	return s.next.Sign(ctx, claims)
}

type credentials struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

func TestE2EPS256LoginRefreshAndAuthorization(t *testing.T) {
	const password = "SyntheticPS256Password123!"
	_, path1, pub1 := testKey(t, 2048)
	key2, path2, pub2 := testKey(t, 2048)
	// Rotate from PKCS#8 to PKCS#1 through the same public consumer workflow.
	writeTestFile(t, path2, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key2)}))
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	issuer := origin + "/auth"
	db, err := identity.NewDatabase(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: password, Roles: []string{"viewer"}}}); err != nil {
		t.Fatal("provision fixture account")
	}
	store, err := tokenrefresh.NewMemoryStore(32, 32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	signers := make(map[string]*signing.Signer)
	for _, spec := range []struct{ name, path, issuer string }{{"v1", path1, issuer}, {"v2", path2, issuer}, {"wrong-binding", path1, issuer + "/other"}} {
		cfg, err := parser.NewRSAPSSSigningConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"key", "file", spec.path}), "key id " + spec.name, cfgutil.EncodeArgs([]string{"issuer", spec.issuer}), "audience api", "max lifetime 5m"})
		if err != nil {
			t.Fatal(err)
		}
		// A serialized config remains sufficient to construct the runtime.
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var restored signing.Config
		if err := json.Unmarshal(data, &restored); err != nil {
			t.Fatal(err)
		}
		signer, err := signing.New(&restored)
		if err != nil {
			t.Fatal(err)
		}
		signers[spec.name] = signer
	}
	watched := &observedSigner{next: signers["v1"]}
	cancelSigner := &observedSigner{next: signers["v1"], started: make(chan struct{}), stopped: make(chan struct{})}
	managers := make(map[string]*tokenrefresh.Manager)
	for _, mode := range []string{"v1", "v2", "wrong-binding", "commit-failure", "cancel"} {
		var backend tokenrefresh.Signer = signers[mode]
		var sessions tokenrefresh.Store = store
		if mode == "commit-failure" {
			backend = watched
			sessions = rejectedCommit{Store: store}
		}
		if mode == "cancel" {
			backend = cancelSigner
		}
		manager, err := tokenrefresh.NewManager(sessions, databaseIdentity{db}, backend, tokenrefresh.Policy{AccessLifetime: 2 * time.Minute, IdleTimeout: 5 * time.Minute, AbsoluteTimeout: 10 * time.Minute}, tokenrefresh.Binding{Portal: "fixture", Origin: origin, BasePath: "/auth"})
		if err != nil {
			t.Fatal(err)
		}
		managers[mode] = manager
	}
	gates := make(map[string]*authz.Gatekeeper)
	for _, mode := range []string{"overlap", "v2-only"} {
		paths := []string{pub2}
		if mode == "overlap" {
			paths = append(paths, pub1)
		}
		var directives []string
		for i, path := range paths {
			directives = append(directives, cfgutil.EncodeArgs([]string{"crypto", "key", fmt.Sprintf("public-%d", i), "verify", "from", "file", path}))
		}
		gate, err := authz.NewGatekeeper(&authz.PolicyConfig{Name: mode, AuthRedirectDisabled: true, ValidateBearerHeader: true, ValidateMethodPath: true, RawCryptoKeyStoreConfig: directives, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer", "match method GET", "exact match path /private"}, Action: "allow stop"}}}, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(gate.Close)
		gates[mode] = gate
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := r.Header.Get("X-Fixture-Mode")
		if mode == "" {
			mode = "v1"
		}
		if r.URL.Path == "/jwks" {
			keys, err := signers[mode].PublicJWKS()
			if err != nil {
				http.Error(w, "keys unavailable", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(keys)
			return
		}
		if r.URL.Path == "/private" {
			gate := gates["overlap"]
			if mode == "v2-only" {
				gate = gates[mode]
			}
			ar := requests.NewAuthorizationRequest()
			err := gate.Authenticate(w, r, ar)
			if err != nil {
				http.Error(w, "invalid token", 401)
				return
			}
			if !ar.Response.Authorized {
				http.Error(w, "denied", 403)
				return
			}
			w.WriteHeader(204)
			return
		}
		manager := managers[mode]
		if manager == nil {
			http.Error(w, "unknown fixture mode", 400)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}
		var result *tokenrefresh.Result
		var err error
		switch r.URL.Path {
		case "/auth/login":
			username, pwd, ok := r.BasicAuth()
			if !ok {
				http.Error(w, "credentials required", 401)
				return
			}
			request := &requests.Request{User: requests.User{Username: username, Password: pwd}}
			if db.AuthenticateUser(request) != nil {
				http.Error(w, "denied", 401)
				return
			}
			proof := request.Authentication
			// Fresh password evidence is consumed exactly once by this request.
			principal := tokenrefresh.Principal{Backend: "local", Realm: "local", UserID: proof.UserID, Subject: username, BackendVersion: proof.BackendVersion, CredentialVersion: proof.CredentialVersion, AuthTime: proof.AuthenticatedAt, Methods: []string{proof.Method}, Challenges: []string{"password"}, Audience: []string{"api"}}
			result, err = manager.Issue(r.Context(), principal, tokenrefresh.BodyTransport)
		case "/auth/refresh":
			var input credentials
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			if err := decoder.Decode(&input); err != nil {
				if _, large := errors.AsType[*http.MaxBytesError](err); large {
					http.Error(w, "too large", 413)
				} else {
					http.Error(w, "invalid", 400)
				}
				return
			}
			result, err = manager.Refresh(r.Context(), input.Refresh, tokenrefresh.BodyTransport)
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			status := 503
			if errors.Is(err, tokenrefresh.ErrDenied) || errors.Is(err, tokenrefresh.ErrInvalid) {
				status = 401
			}
			http.Error(w, "issuance failed", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(credentials{Access: result.AccessToken, Refresh: result.RefreshToken})
	})
	server.StartTLS()
	client := server.Client()
	client.Timeout = 5 * time.Second
	send := func(ctx context.Context, route, mode, pwd, token string, want int) []byte {
		t.Helper()
		method := http.MethodPost
		var body io.Reader
		if route == "/jwks" || route == "/private" {
			method = http.MethodGet
		} else {
			data, _ := json.Marshal(credentials{Refresh: token})
			body = strings.NewReader(string(data))
		}
		req, err := http.NewRequestWithContext(ctx, method, origin+route, body)
		if err != nil {
			t.Error(err)
			return nil
		}
		req.Header.Set("X-Fixture-Mode", mode)
		switch route {
		case "/auth/login":
			req.SetBasicAuth("alice", pwd)
		case "/private":
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			if want == 0 && errors.Is(err, context.Canceled) {
				return nil
			}
			t.Error("consumer request failed:", err)
			return nil
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
		if err != nil {
			t.Error(err)
		}
		if resp.StatusCode != want {
			t.Errorf("%s %s: status %d, want %d", route, mode, resp.StatusCode, want)
		}
		if want != 200 && (strings.Contains(string(data), "access_token") || strings.Contains(string(data), "refresh_token")) {
			t.Error("failure exposed staged credentials")
		}
		return data
	}
	decode := func(data []byte) credentials {
		t.Helper()
		var result credentials
		if json.Unmarshal(data, &result) != nil || result.Access == "" || result.Refresh == "" {
			t.Fatal("successful response missing credentials")
		}
		return result
	}
	login := func(mode string) credentials {
		return decode(send(t.Context(), "/auth/login", mode, password, "", 200))
	}
	send(t.Context(), "/auth/login", "v1", "wrong-password", "", 401)
	first := login("v1")
	jwks1 := send(t.Context(), "/jwks", "v1", "", "", 200)
	claims, err := verifyPS256(first.Access, jwks1, issuer, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if claims["custom"].(map[string]any)["number"] != json.Number("9007199254740993") || claims["amr"].([]any)[0] != "pwd" || claims["roles"].([]any)[0] != "viewer" {
		t.Fatal("canonical claims were not preserved")
	}
	send(t.Context(), "/private", "overlap", "", first.Access, 204)
	send(t.Context(), "/private", "overlap", "", first.Access, 204) // cache journey
	send(t.Context(), "/private", "v2-only", "", first.Access, 401)
	// The same old refresh credential remains usable after a signing rejection
	// and after a failed commit that occurs after successful signing.
	send(t.Context(), "/auth/refresh", "wrong-binding", "", first.Refresh, 503)
	send(t.Context(), "/auth/refresh", "commit-failure", "", first.Refresh, 503)
	if watched.calls.Load() != 1 {
		t.Fatal("commit failure did not follow signing")
	}
	// Cancellation propagates from a real in-flight HTTP request into the signer.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan struct{})
	go func() { defer close(finished); send(ctx, "/auth/refresh", "cancel", "", first.Refresh, 0) }()
	select {
	case <-cancelSigner.started:
	case <-time.After(3 * time.Second):
		t.Fatal("signing never started")
	}
	cancel()
	select {
	case <-cancelSigner.stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP cancellation not propagated")
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled client did not exit")
	}
	rotated := decode(send(t.Context(), "/auth/refresh", "v2", "", first.Refresh, 200))
	if rotated.Refresh == first.Refresh {
		t.Fatal("refresh credential was not rotated")
	}
	jwks2 := send(t.Context(), "/jwks", "v2", "", "", 200)
	nextClaims, err := verifyPS256(rotated.Access, jwks2, issuer, "v2")
	if err != nil {
		t.Fatal(err)
	}
	if nextClaims["sid"] != claims["sid"] || nextClaims["auth_time"] != claims["auth_time"] || nextClaims["jti"] == claims["jti"] {
		t.Fatal("rotation changed family or reused token ID")
	}
	if _, err := verifyPS256(first.Access, jwks2, issuer, "v1"); err == nil {
		t.Fatal("retired key still verifies")
	}
	send(t.Context(), "/private", "v2-only", "", rotated.Access, 204)
	send(t.Context(), "/private", "overlap", "", rotated.Access, 204)
	// Tamper with claims while retaining the signature; both consumer verifiers deny.
	parts := strings.Split(rotated.Access, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","roles":["viewer"]}`))
	forged := strings.Join(parts, ".")
	if _, err := verifyPS256(forged, jwks2, issuer, "v2"); err == nil {
		t.Fatal("tampered token verified")
	}
	send(t.Context(), "/private", "overlap", "", forged, 401)
	send(t.Context(), "/auth/refresh", "v2", "", first.Refresh, 401) // replay revokes family
	send(t.Context(), "/auth/refresh", "v2", "", rotated.Refresh, 401)
	send(t.Context(), "/auth/login", "commit-failure", password, "", 503)
	if watched.calls.Load() != 2 {
		t.Fatal("failed initial commit did not follow signing")
	}
	active := login("v2")
	// Rejected reloads leave the live signer usable. A symlink must target a
	// valid private key so malformed key contents cannot hide a loader regression.
	link := filepath.Join(t.TempDir(), "reload.pem")
	if err := os.Symlink(path1, link); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path2, []byte("invalid replacement"))
	for _, path := range []string{link, path2} {
		if candidate, err := signing.New(&signing.Config{KeyFile: path, KeyID: "v3", Issuer: issuer, Audience: "api"}); err == nil || candidate != nil {
			t.Fatal("invalid reload published")
		}
		active = decode(send(t.Context(), "/auth/refresh", "v2", "", active.Refresh, 200))
		if _, err := verifyPS256(active.Access, jwks2, issuer, "v2"); err != nil {
			t.Fatal("active signer changed after rejected reload")
		}
		send(t.Context(), "/private", "v2-only", "", active.Access, 204)
	}
	// The fixture's real identity transaction invalidates previously issued proof.
	account := &requests.Request{User: requests.User{Username: "alice", Password: password}}
	if db.AuthenticateUser(account) != nil {
		t.Fatal("authenticate revocation fixture")
	}
	if db.RevokeUserSessions(t.Context(), account.Authentication.UserID) != nil {
		t.Fatal("revoke identity")
	}
	send(t.Context(), "/auth/refresh", "v2", "", active.Refresh, 401)
}
