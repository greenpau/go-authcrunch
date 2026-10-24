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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

type managedPortalIdentity struct {
	*local.IdentityStore
	calls atomic.Int64
}

func (s *managedPortalIdentity) Request(op operator.Type, r *requests.Request) error {
	s.calls.Add(1)
	return s.IdentityStore.Request(op, r)
}

type managedPortalView struct {
	*tokenrefresh.MemoryStore
	generation tokenrefresh.Generation
}

func (v *managedPortalView) Generation() tokenrefresh.Generation { return v.generation }

type managedPortalStore struct {
	descriptor          *tokenrefresh.ExternalStoreConfig
	memory              *tokenrefresh.MemoryStore
	activations, closes int
	activationError     error
	generation          tokenrefresh.Generation
}

func (s *managedPortalStore) Metadata() (tokenrefresh.StoreMetadata, error) {
	c := s.descriptor
	return tokenrefresh.StoreMetadata{Kind: c.Kind, ConfigDigest: c.ConfigDigest, MaxSessions: c.MaxSessions, MaxRotations: c.MaxRotations}, nil
}
func (s *managedPortalStore) CheckReady(context.Context) error { return nil }
func (s *managedPortalStore) ActivateGeneration(_ context.Context, g tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	s.activations++
	s.generation = g
	if s.activationError != nil {
		return nil, s.activationError
	}
	return &managedPortalView{MemoryStore: s.memory, generation: g}, nil
}
func (s *managedPortalStore) Close() error { s.closes++; s.memory.Close(); return nil }

func newManagedPortalFixture(t *testing.T, withOP bool) (*refreshPortalFixture, *managedPortalStore, *managedPortalIdentity) {
	t.Helper()
	f := newRefreshPortal(t, true, false)
	original := f.portal
	data, err := json.Marshal(original.config)
	if err != nil {
		t.Fatal(err)
	}
	var config PortalConfig
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("portal fixture snapshot failed")
	}
	original.Close()
	config.RefreshTokens.Store = "durable"
	if withOP {
		config.OIDCProvider = oidcTestConfig()
	}
	descriptor, err := tokenrefresh.NewExternalStoreConfig("durable", "probe", config.RefreshTokens.MaxSessions, config.RefreshTokens.MaxRotations, struct{ ID string }{"probe"})
	if err != nil {
		t.Fatal(err)
	}
	memory, err := tokenrefresh.NewMemoryStore(descriptor.MaxSessions, descriptor.MaxRotations)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(memory.Close)
	runtime := &managedPortalStore{descriptor: descriptor, memory: memory}
	backend := &managedPortalIdentity{IdentityStore: f.store}
	f.portal, err = NewPortal(PortalParameters{Config: &config, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{backend}, RefreshStore: &tokenrefresh.ExternalStoreBinding{Config: descriptor, Store: runtime}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.portal.Close)
	return f, runtime, backend
}

func TestManagedRefreshPortalPendingPublication(t *testing.T) {
	f, runtime, backend := newManagedPortalFixture(t, true)
	p := f.portal
	if p.refresh != nil || p.refreshStore != nil || p.GetOIDCProvider() != nil || p.oidc == nil || runtime.activations != 0 {
		t.Fatal("pending portal published a manager, fallback or OP")
	}
	initialCalls := backend.calls.Load()
	basic := &authproxy.Request{Realm: "local", Secret: base64.StdEncoding.EncodeToString([]byte(tests.TestUser1 + ":" + tests.TestPwd1))}
	if p.BasicAuth(basic) == nil || basic.Response.Payload != "" {
		t.Fatal("pending portal accepted direct password")
	}
	if p.APIKeyAuth(&authproxy.Request{Realm: "local", Secret: "unverified-key"}) == nil {
		t.Fatal("pending portal accepted direct API key")
	}
	if backend.calls.Load() != initialCalls {
		t.Fatal("pending direct request reached identity backend")
	}
	if _, _, err := p.issueSandboxTokens(t.Context(), nil, nil, nil); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("pending sandbox helper fell back to access-only issuance")
	}
	if err := p.signAccessUser(t.Context(), &user.User{}); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("pending signer attempted issuance")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "access=staged; Secure; HttpOnly")
		w.Header().Set("Authorization", "Bearer staged")
		if r.URL.Query().Get("explicit") == "1" {
			_ = p.ServeHTTPAt(r.Context(), w, r, requests.NewRequest(), "/auth")
		} else {
			_ = p.ServeHTTP(r.Context(), w, r, requests.NewRequest())
		}
	}))
	defer server.Close()
	for _, path := range []string{"/auth/login", "/auth/login?explicit=1", "/auth/.well-known/jwks.json", "/auth/oidc/jwks", "/auth/api/refresh_token"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal("pending TLS request failed")
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if readErr != nil || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.StatusCode != 503 || response.Header.Get("Cache-Control") != "no-store" || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("Authorization") != "" {
			t.Fatal("pending TLS response published authority or missed admission guard")
		}
	}
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err := p.ConfigurePersistentState(storage, "durable-caller-epoch-1"); err != nil {
		t.Fatal(err)
	}
	if p.refresh == nil || p.refreshStore != nil || p.GetOIDCProvider() == nil || runtime.activations != 1 {
		t.Fatal("persistent activation did not publish exactly one borrowed manager")
	}
	login := decodeAuth(t, f.login(t, "body"))
	if !login.Authenticated || login.AccessToken == "" || login.RefreshToken == "" {
		t.Fatal("activated positive login failed")
	}
	p.Close()
	if runtime.closes != 0 {
		t.Fatal("portal closed borrowed store")
	}
}

func TestManagedRefreshPortalFailedSetupLatches(t *testing.T) {
	f, runtime, _ := newManagedPortalFixture(t, false)
	runtime.activationError = tokenrefresh.ErrCommitUncertain
	dir := filepath.Join(t.TempDir(), "state")
	storage, err := state.Open(&state.Config{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	if err := f.portal.ConfigurePersistentState(storage, "epoch"); !errors.Is(err, tokenrefresh.ErrCommitUncertain) {
		t.Fatal("activation uncertainty classification lost")
	}
	runtime.activationError = nil
	if f.portal.ConfigurePersistentState(storage, "epoch") == nil || runtime.activations != 1 || !f.portal.managedRefreshUnavailable() {
		t.Fatal("failed selected portal retried activation")
	}
	if f.portal.refresh != nil || f.portal.refreshStore != nil {
		t.Fatal("failed selected portal created fallback")
	}
	record := sha256.Sum256([]byte("portal-refresh/" + f.portal.config.Name))
	if _, err := os.Stat(filepath.Join(dir, hex.EncodeToString(record[:])+".state")); !os.IsNotExist(err) {
		t.Fatal("borrowed families created a memory snapshot")
	}
	w := httptest.NewRecorder()
	_ = f.portal.refreshError(t.Context(), w, errors.Join(tokenrefresh.ErrCommitUncertain, tokenrefresh.ErrDenied))
	if w.Code != 503 {
		t.Fatal("joined denial hid uncertain commit")
	}
	f.portal.Close()
	if runtime.closes != 0 {
		t.Fatal("failed portal closed borrowed storage")
	}
}

func TestManagedRefreshGenerationInitialization(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	storage, err := state.Open(&state.Config{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = storage.Close() }()
	generations := make(chan tokenrefresh.Generation, 16)
	failures := make(chan error, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			g, err := managedRefreshGeneration(storage, "caller-epoch-a")
			if err != nil {
				failures <- err
				return
			}
			generations <- g
		})
	}
	wg.Wait()
	close(generations)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	var first tokenrefresh.Generation
	for generation := range generations {
		if first == (tokenrefresh.Generation{}) {
			first = generation
		}
		if generation != first {
			t.Fatal("concurrent portals initialized different generation identities")
		}
	}
	if len(first.Namespace) != 64 || len(first.ID) != 64 {
		t.Fatal("invalid generation identity")
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	same, err := managedRefreshGeneration(storage, "caller-epoch-a")
	if err != nil || same != first {
		t.Fatal("compatible restart changed generation")
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	next, err := managedRefreshGeneration(storage, "caller-epoch-b")
	if err != nil || next.Namespace != first.Namespace || next.ID == first.ID {
		t.Fatal("changed caller epoch failed to retire generation")
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	record, err := storage.OpenRecord("managed-refresh/namespace", "authcrunch-managed-refresh-namespace")
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Save([]byte(strings.Repeat("x", 31))); err != nil {
		t.Fatal(err)
	}
	if _, err := managedRefreshGeneration(storage, "caller-epoch-b"); err == nil {
		t.Fatal("corrupt namespace identity accepted")
	}
}

// This seam tests HTTP classification after real issuer preparation. The real
// SQLite form E2E separately establishes attempted driver-COMMIT uncertainty.
type uncertainCreateStore struct {
	*tokenrefresh.MemoryStore
	failure error
	calls   int
}

func (s *uncertainCreateStore) Create(context.Context, tokenrefresh.Session, int64) error {
	s.calls++
	return s.failure
}
func (s *uncertainCreateStore) CreateReplacing(context.Context, tokenrefresh.Session, int64, [][32]byte) error {
	s.calls++
	return s.failure
}

func TestManagedRefreshHTTPUncertaintyPrecedence(t *testing.T) {
	failure := errors.Join(tokenrefresh.ErrCommitUncertain, tokenrefresh.ErrDenied, context.Canceled)
	t.Run("provider", func(t *testing.T) {
		p := providerRefreshFixture(t)
		store := &uncertainCreateStore{MemoryStore: p.refreshStore, failure: failure}
		if err := p.configureRefreshManager(store, tokenrefresh.Generation{}); err != nil {
			t.Fatal(err)
		}
		r, rr := providerCallback(t)
		w := httptest.NewRecorder()
		if err := p.authorizeProviderRefresh(t.Context(), w, r, rr); !errors.Is(err, tokenrefresh.ErrCommitUncertain) || rr.Response.Code != http.StatusServiceUnavailable || store.calls != 1 {
			t.Fatal("provider denied status hid attempted commit uncertainty")
		}
		if w.Header().Get("Authorization") != "" || len(w.Result().Cookies()) != 0 {
			t.Fatal("uncertain provider published credentials")
		}
	})
	t.Run("cross_device", func(t *testing.T) {
		f := newRefreshPortal(t, true, false)
		p := f.portal
		proof, rr := completedIdentityProof(t, f)
		proof.LoginMethods = []string{"pwd"}
		proof.LoginEvidence.AuthenticatedAt = time.Now().Unix()
		proof.RefreshTransport = tokenrefresh.CookieTransport
		rr.Upstream.BasePath, rr.Upstream.BaseURL = "/auth/", refreshTestOrigin
		r := httptest.NewRequest(http.MethodPost, refreshTestOrigin+"/auth/cross-device/poll", nil)
		r.RequestURI = r.URL.RequestURI()
		r.Header.Set("Origin", refreshTestOrigin)
		issued, tokens, err := p.issueSandboxTokens(t.Context(), r, rr, proof)
		if err != nil || tokens == nil {
			t.Fatal("approving family fixture failed", err)
		}
		if err := p.sessions.Add(issued.Claims.ID, issued); err != nil {
			t.Fatal(err)
		}
		store := &uncertainCreateStore{MemoryStore: p.refreshStore, failure: failure}
		if err := p.configureRefreshManager(store, tokenrefresh.Generation{}); err != nil {
			t.Fatal(err)
		}
		transfer := &crossDeviceProof{user: proof, sessionID: issued.Claims.ID, sessionToken: crossDeviceHash(issued.Token), refreshSessionID: tokens.SessionID, expires: time.Now().Add(time.Minute).Unix()}
		w := httptest.NewRecorder()
		if err := p.redeemCrossDevice(t.Context(), w, r, rr, transfer); err != nil || w.Code != http.StatusServiceUnavailable || store.calls != 1 {
			t.Fatal("cross-device denial hid attempted commit uncertainty", err)
		}
		if len(w.Result().Cookies()) != 0 || w.Header().Get("Authorization") != "" {
			t.Fatal("uncertain transfer published credentials")
		}
	})
	if crossDeviceSessionErrorStatus(failure, http.StatusUnauthorized) != http.StatusServiceUnavailable {
		t.Fatal("session uncertainty lost precedence")
	}
	// Keep the preexisting ordinary denial result distinct from uncertainty.
	if crossDeviceSessionErrorStatus(tokenrefresh.ErrDenied, http.StatusUnauthorized) != http.StatusUnauthorized {
		t.Fatal("ordinary denial classification changed")
	}
}

// This seam checks the terminal browser caller as well as the helper: an
// access-only replacement must not hide an uncertain old-family revocation.
// The separate SQLite E2E creates real driver COMMIT uncertainty.
type uncertainRevokeStore struct {
	*tokenrefresh.MemoryStore
	failure error
	calls   int
}

func (s *uncertainRevokeStore) Revoke(context.Context, [32]byte, tokenrefresh.Binding) error {
	s.calls++
	return s.failure
}

func TestManagedRefreshAccessOnlyReplacementUncertainty(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		name := "ordinary_invalid"
		if uncertain {
			name = "uncertain_invalid"
		}
		t.Run(name, func(t *testing.T) {
			f := newRefreshPortal(t, true, false)
			p := f.portal
			previous := f.login(t, "cookie")
			decodeAuth(t, previous)
			old := responseCookie(t, previous, p.cookie.RefreshTokenCookieName)
			store := &uncertainRevokeStore{MemoryStore: p.refreshStore, failure: tokenrefresh.ErrInvalid}
			if uncertain {
				store.failure = errors.Join(tokenrefresh.ErrCommitUncertain, tokenrefresh.ErrInvalid, context.Canceled)
			}
			// Retain the refresh manager and old credential, but make this new
			// local login access-only, so no replacement family needs cleanup.
			p.config.RefreshTokens.Realms = []string{"other-realm"}
			if err := p.configureRefreshManager(store, tokenrefresh.Generation{}); err != nil {
				t.Fatal(err)
			}
			start := browserSandboxRequest(t, p, http.MethodPost, "/auth/login?redirect_url=", url.Values{"username": {tests.TestUser1}, "realm": {"local"}})
			location, err := start.Result().Location()
			if start.Code != http.StatusSeeOther || err != nil {
				t.Fatal("replacement fixture start failed")
			}
			var proof *http.Cookie
			for _, c := range start.Result().Cookies() {
				if strings.HasPrefix(c.Name, p.cookie.SandboxIDCookieName+"_") {
					proof = c
				}
			}
			if proof == nil {
				t.Fatal("replacement fixture proof missing")
			}
			target := location.RequestURI()
			password := browserSandboxRequest(t, p, http.MethodPost, target, url.Values{"secret": {tests.TestPwd1}}, proof)
			if password.Code != http.StatusSeeOther {
				t.Fatal("replacement password checkpoint failed")
			}
			result := browserSandboxRequest(t, p, http.MethodGet, target, nil, proof, old)
			if store.calls != 1 {
				t.Fatal("replacement did not attempt exactly one old-family revocation")
			}
			if !uncertain {
				if result.Code != http.StatusSeeOther || responseCookie(t, result, p.cookie.AccessTokenCookieName).Value == "" {
					t.Fatal("ordinary invalid old family prevented independent login")
				}
				return
			}
			if result.Code != http.StatusServiceUnavailable || result.Header().Get("Authorization") != "" || result.Header().Get("Location") != "" || !strings.Contains(result.Header().Get("Cache-Control"), "no-store") {
				t.Fatal("uncertain revocation did not withhold terminal login authority")
			}
			deleted := false
			for _, c := range result.Result().Cookies() {
				if c.Name == proof.Name && c.MaxAge < 0 {
					deleted = true
				}
				if (c.Name == p.cookie.AccessTokenCookieName || c.Name == p.cookie.RefreshTokenCookieName || c.Name == p.cookie.OIDCSessionIDCookieName) && c.Value != "" && c.MaxAge >= 0 {
					t.Fatal("uncertain replacement delivered a credential")
				}
			}
			if !deleted {
				t.Fatal("uncertain replacement lost consumed-flow tombstone")
			}
		})
	}
}

// Protocol verification is the provider seam here; real callback handlers,
// attached identity lookup, signing and old-family replacement remain active.
type uncertainCallbackProvider struct {
	externalLoginTestProvider
	attachment *attachment.Attachment
	connected  bool
	kind       string
}

func (p *uncertainCallbackProvider) GetKind() string                            { return p.kind }
func (p *uncertainCallbackProvider) IdentityAttachment() *attachment.Attachment { return p.attachment }
func (p *uncertainCallbackProvider) GetLoginCookieName() string                 { return "" }
func (p *uncertainCallbackProvider) Login(context.Context, *http.Request) (*idp.HTTPLoginResult, error) {
	return &idp.HTTPLoginResult{Identity: &idp.LoginIdentity{Subject: "external-subject", Email: "external@example.test", Roles: []string{"authp/user"}}}, nil
}
func (p *uncertainCallbackProvider) Request(_ operator.Type, rr *requests.Request) error {
	rr.Response.Code = http.StatusOK
	rr.Response.LoginState = strings.Repeat("A", 43)
	rr.Response.Payload = map[string]any{"sub": "external-subject", "email": "external@example.test", "roles": []string{"authp/user"}}
	if !p.connected {
		return nil
	}
	rr.ExternalIdentity = requests.ExternalIdentity{Issuer: "https://issuer.example.test", Subject: "external-subject"}
	return p.attachment.Authenticate(rr.Upstream.Request.Context(), rr, p.GetName(), p.GetKind())
}

func TestManagedRefreshCallbackReplacementUncertainty(t *testing.T) {
	for _, tc := range []struct {
		name, method, kind string
		connected          bool
	}{
		{"oauth", "oauth2", "oauth", false},
		{"saml", "saml", "saml", false},
		{"connected_oauth", "oauth2", "oauth", true},
		{"connected_saml", "saml", "saml", true},
		{"http_provider", "provider", "ticket", true},
		{"basic", "basic", "oauth", false},
	} {
		for _, uncertain := range []bool{false, true} {
			name := tc.name + "/ordinary_invalid"
			if uncertain {
				name = tc.name + "/uncertain_invalid"
			}
			t.Run(name, func(t *testing.T) {
				f := newRefreshPortal(t, true, false)
				p := f.portal
				previous := f.login(t, "cookie")
				decodeAuth(t, previous)
				old := responseCookie(t, previous, p.cookie.RefreshTokenCookieName)
				binding, err := attachment.New(attachment.Config{})
				if err != nil {
					t.Fatal(err)
				}
				provider := &uncertainCallbackProvider{attachment: binding, connected: tc.connected, kind: tc.kind}
				p.identityProviders = []idp.IdentityProvider{provider}
				store := &uncertainRevokeStore{MemoryStore: p.refreshStore, failure: tokenrefresh.ErrInvalid}
				if uncertain {
					store.failure = errors.Join(tokenrefresh.ErrCommitUncertain, tokenrefresh.ErrInvalid, context.Canceled)
				}
				if err := p.configureRefreshManager(store, tokenrefresh.Generation{}); err != nil {
					t.Fatal(err)
				}
				method, path := http.MethodGet, "/auth/"+tc.method+"/upstream"
				if tc.method == "saml" {
					method = http.MethodPost
				}
				if tc.method == "oauth2" {
					path += "/authorization-code-callback"
				}
				if tc.method == "basic" {
					path = "/auth/basic/login/local"
				}
				r := httptest.NewRequest(method, refreshTestOrigin+path, nil)
				r.RequestURI = r.URL.RequestURI()
				r.Header.Set("Origin", refreshTestOrigin)
				r.Header.Set("Accept", "text/html")
				r.AddCookie(old)
				if tc.method == "basic" {
					r.SetBasicAuth(tests.TestUser1, tests.TestPwd1)
				}
				rr := requests.NewRequest()
				rr.Upstream.Request, rr.Upstream.BaseURL, rr.Upstream.BasePath, rr.Upstream.SessionID = r, refreshTestOrigin, "/auth/", "replacement-callback"
				w := httptest.NewRecorder()
				switch tc.method {
				case "provider":
					err = p.handleHTTPProviderLogin(t.Context(), w, r, rr)
				case "basic":
					err = p.handleHTTPBasicLogin(t.Context(), w, r, rr)
				default:
					err = p.handleHTTPExternalLogin(t.Context(), w, r, rr, tc.method)
				}
				if err != nil || store.calls != 1 {
					t.Fatal("callback did not reach exactly one old-family revocation")
				}
				if !uncertain {
					if w.Code != http.StatusSeeOther || responseCookie(t, w, p.cookie.AccessTokenCookieName).Value == "" {
						t.Fatal("ordinary invalid old family blocked callback completion")
					}
					return
				}
				if w.Code != http.StatusServiceUnavailable || rr.Response.Authenticated || w.Header().Get("Authorization") != "" || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("callback failed to classify uncertain replacement as unavailable")
				}
				for _, c := range w.Result().Cookies() {
					if (c.Name == p.cookie.AccessTokenCookieName || c.Name == p.cookie.RefreshTokenCookieName || c.Name == p.cookie.OIDCSessionIDCookieName) && c.Value != "" && c.MaxAge >= 0 {
						t.Fatal("uncertain callback delivered authority")
					}
				}
			})
		}
	}
}
