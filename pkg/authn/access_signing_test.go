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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/accessclaims"
	"github.com/greenpau/go-authcrunch/internal/tests"
	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type selectedSignerProbe struct {
	kms.AccessSigner
	mode   string
	cancel context.CancelFunc
	calls  int
}

func (s *selectedSignerProbe) Sign(ctx context.Context, claims map[string]any) (string, error) {
	s.calls++
	switch s.mode {
	case "mutate":
		claims["roles"] = []string{"administrator"}
	case "added":
		claims["unapproved"] = true
	case "removed":
		delete(claims, "email")
	case "number":
		claims["precise"] = json.Number("9007199254740992")
	case "empty":
		return "", nil
	case "error":
		return "", fmt.Errorf("private signer error canary")
	case "canceled":
		return "", fmt.Errorf("private error: %w", context.Canceled)
	case "deadline":
		return "", fmt.Errorf("private error: %w", context.DeadlineExceeded)
	}
	token, err := s.AccessSigner.Sign(ctx, claims)
	if s.mode == "cancel after sign" {
		s.cancel()
	}
	return token, err
}
func selectedPortal(t *testing.T, renewable bool) (*refreshPortalFixture, *fixture.Fixture, *selectedSignerProbe) {
	t.Helper()
	old := newRefreshPortal(t, false, false)
	old.portal.Close()
	key := fixture.New(t, refreshTestOrigin+"/auth")
	probe := &selectedSignerProbe{AccessSigner: key.Signer}
	cfg := &PortalConfig{Name: "selected", IdentityStores: []string{"localdb"}, CookieConfig: cookie.NewConfig(), AccessSigner: key.Descriptor.Name, AccessTokenProfile: key.Profile.Clone(), RawCryptoKeyStoreConfig: []string{"crypto default token name LOGICAL", "crypto default token lifetime 60", "crypto key current verify from file " + key.PublicFile}, UserTransformerConfigs: []*transformer.Config{{Matchers: []string{"match roles authp/user"}, Actions: []string{"add audience api"}}}}
	cfg.CookieConfig.AccessTokenCookieName = "WIRE_ACCESS"
	if renewable {
		cfg.RefreshTokens = &TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: refreshTestOrigin, BasePath: "/auth", BodyTransportEnabled: true, AccessLifetimeSeconds: 300}
	}
	p, err := NewPortal(PortalParameters{Config: cfg, Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{old.store}, AccessSigner: &kms.AccessSignerBinding{Config: key.Descriptor, Signer: probe}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return &refreshPortalFixture{portal: p, store: old.store}, key, probe
}
func assertSelectedAccess(t *testing.T, p *Portal, u *user.User) {
	t.Helper()
	if u == nil || u.Token == "" || u.TokenName != "LOGICAL" {
		t.Fatal("missing selected token or changed logical label")
	}
	claims, err := p.keystore.VerifyAccessToken(t.Context(), u.Token)
	if err != nil || !accessclaims.Equal(claims, u.AsMap()) {
		t.Fatal("issued token differs from canonical user")
	}
	if u.Claims.NotBefore != u.Claims.IssuedAt || u.Claims.ExpiresAt-u.Claims.IssuedAt > 60 {
		t.Fatal("selected issuer lifetime was not applied")
	}
}
func TestSelectedAccessSigningSixProducers(t *testing.T) {
	f, _, probe := selectedPortal(t, false)
	p := f.portal
	proof, rr := completedIdentityProof(t, f)
	proof.LoginMethods = []string{"pwd"}
	proof.LoginEvidence.AuthenticatedAt = time.Now().Unix()
	var err error
	p.transformer, err = transformer.NewFactory(p.config.UserTransformerConfigs)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+"/auth/sandbox/proof", nil)
	current := identity.RefreshIdentity{Username: proof.LoginUsername, Email: proof.LoginEmail, Roles: []string{"authp/user"}, Challenges: []string{"password"}}
	t.Run("sandbox", func(t *testing.T) {
		u, err := p.issueSandboxAccessToken(t.Context(), r, rr, proof, current)
		if err != nil {
			t.Fatal(err)
		}
		assertSelectedAccess(t, p, u)
		if u.LoginEvidence != proof.LoginEvidence || u.LoginUsername != proof.LoginUsername || u.Authenticator.Name != proof.Authenticator.Name {
			t.Fatal("canonical proof was lost")
		}
	})
	t.Run("ordinary", func(t *testing.T) {
		u, err := p.authorizeLoginUser(t.Context(), r, rr)
		if err != nil {
			t.Fatal(err)
		}
		assertSelectedAccess(t, p, u)
	})
	t.Run("direct", func(t *testing.T) {
		request := &authproxy.Request{Realm: "local", Secret: base64.StdEncoding.EncodeToString([]byte(tests.TestUser1 + ":" + tests.TestPwd1)), Address: "127.0.0.1"}
		if err := p.BasicAuth(request); err != nil {
			t.Fatal(err)
		}
		claims, err := p.keystore.VerifyAccessToken(t.Context(), request.Response.Payload)
		if err != nil || claims["iss"] != refreshTestOrigin+"/auth" || request.Response.Name != "LOGICAL" {
			t.Fatal("direct authentication bypassed selected signer")
		}
	})
	t.Run("connected", func(t *testing.T) {
		claims := map[string]any{"sub": "issuer-subject", "aud": "api", "roles": []string{"authp/user"}, "iat": time.Now().Unix(), "nbf": time.Now().Unix() - 60, "exp": time.Now().Unix() + 20}
		rr.ExternalIdentity.Evidence.AuthenticatedAt = time.Now().Unix()
		rr.ExternalIdentity.Provider = "upstream"
		u, err := p.signConnectedUser(t.Context(), rr, claims, []string{"federated"})
		if err != nil {
			t.Fatal(err)
		}
		assertSelectedAccess(t, p, u)
		if u.ExternalIdentity != rr.ExternalIdentity || u.Claims.ExpiresAt != claims["exp"] {
			t.Fatal("connected proof or tighter expiry lost")
		}
	})
	t.Run("cross-device", func(t *testing.T) {
		p.identityProviders = []idp.IdentityProvider{&mockIdentityProvider{name: "upstream", realm: "upstream", kind: "oauth", driver: "generic"}}
		u, err := user.NewUser(map[string]any{"sub": "upstream", "roles": []string{"authp/user"}})
		if err != nil {
			t.Fatal(err)
		}
		u.Authenticator = user.Authenticator{Name: "upstream", Realm: "upstream", Method: "oauth"}
		rr.Upstream.Realm = "upstream"
		expiry := time.Now().Unix() + 20
		transfer := &crossDeviceProof{user: u, expires: expiry, providerClaims: []byte(`{"sub":"upstream","roles":["authp/user"]}`)}
		issued, err := p.issueCrossDeviceProvider(t.Context(), r, rr, transfer)
		if err != nil {
			t.Fatal(err)
		}
		assertSelectedAccess(t, p, issued)
		if issued.Claims.ExpiresAt != expiry {
			t.Fatal("transfer extended source proof")
		}
	})
	if probe.calls != 5 {
		t.Fatalf("five access-only producers made %d signing calls", probe.calls)
	}
	t.Run("renewal", func(t *testing.T) {
		f, _, probe := selectedPortal(t, true)
		first := decodeAuth(t, f.login(t, "body"))
		if first.AccessTokenName != "WIRE_ACCESS" {
			t.Fatal("native wire name changed")
		}
		body, _ := json.Marshal(map[string]string{"refresh_token": first.RefreshToken})
		next := decodeAuth(t, f.request(t, http.MethodPost, "/auth/api/refresh_token", string(body), false))
		claims, err := f.portal.keystore.VerifyAccessToken(t.Context(), next.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		expiry, _ := accessclaims.Integer(claims["exp"])
		iat, _ := accessclaims.Integer(claims["iat"])
		if next.AccessExpiresAt != expiry || expiry-iat != 60 || next.RefreshToken == first.RefreshToken || probe.calls != 2 {
			t.Fatal("refresh result and signed lifetime diverged")
		}
		f.portal.transformer, err = transformer.NewFactory([]*transformer.Config{{Matchers: []string{"match roles authp/user"}, Actions: []string{"delete aud"}}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ = json.Marshal(map[string]string{"refresh_token": next.RefreshToken})
		if w := f.request(t, http.MethodPost, "/auth/api/refresh_token", string(body), false); w.Code != http.StatusUnauthorized {
			t.Fatal("renewal replenished a removed audience")
		}
		if probe.calls != 2 {
			t.Fatal("audience refusal reached signing")
		}
	})
}
func TestSelectedAccessSigningStagedOutput(t *testing.T) {
	f, key, probe := selectedPortal(t, false)
	p := f.portal
	for _, mode := range []string{"mutate", "added", "removed", "number", "empty", "error", "canceled", "deadline", "cancel after sign"} {
		t.Run(mode, func(t *testing.T) {
			claims := key.Claims()
			claims["email"] = "alice@example.test"
			claims["precise"] = json.Number("9007199254740993")
			u, err := p.newAccessUser(claims)
			if err != nil {
				t.Fatal(err)
			}
			_, before, _ := accessclaims.Encode(u.AsMap())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			probe.mode, probe.cancel = mode, cancel
			err = p.signAccessUser(ctx, u)
			if err == nil || u.Token != "" || u.TokenName != "" || !accessclaims.Equal(before, u.AsMap()) {
				t.Fatal("failed staged signing mutated published identity")
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatal("plugin error leaked")
			}
			if (mode == "canceled" || mode == "cancel after sign") && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation classification lost")
			}
			if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("deadline classification lost")
			}
		})
	}
	probe.mode = ""
	u, err := p.newAccessUser(key.Claims())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.signAccessUser(t.Context(), u); err != nil {
		t.Fatal("same signer failed after isolated refusals", err)
	}
	assertSelectedAccess(t, p, u)
}
func TestSelectedAccessSigningNormalizationAndCookie(t *testing.T) {
	f, key, _ := selectedPortal(t, false)
	p := f.portal
	for name, edit := range map[string]func(map[string]any){"fractional": func(c map[string]any) { c["exp"] = float64(time.Now().Unix()) + 0.5 }, "overflow": func(c map[string]any) { c["iat"] = json.Number("9223372036854775808") }, "addition overflow": func(c map[string]any) { c["iat"] = int64(math.MaxInt64) }, "invalid nbf": func(c map[string]any) { c["nbf"] = "1" }, "future nbf": func(c map[string]any) { c["nbf"] = time.Now().Unix() + 1 }, "expired": func(c map[string]any) { c["exp"] = time.Now().Unix() }, "missing audience": func(c map[string]any) { delete(c, "aud") }, "multiple audience": func(c map[string]any) { c["aud"] = []string{"api", "other"} }} {
		t.Run(name, func(t *testing.T) {
			c := key.Claims()
			edit(c)
			if _, err := p.newAccessUser(c); err == nil {
				t.Fatal("invalid pre-conversion claims accepted")
			}
		})
	}
	claims := key.Claims()
	claims["nbf"] = time.Now().Unix() - 60
	claims["exp"] = time.Now().Unix() + 20
	claims["iss"] = "request-derived"
	claims["precise"] = json.Number("9007199254740993")
	u, err := p.newAccessUser(claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.signAccessUser(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	assertSelectedAccess(t, p, u)
	if u.Claims.ExpiresAt != claims["exp"] || u.AsMap()["precise"] != claims["precise"] {
		t.Fatal("normalization extended expiry or rounded custom number")
	}
	for _, lifetime := range []int{0, 5, 3600} {
		cfg := cookie.NewConfig()
		cfg.Lifetime = lifetime
		cfg.AccessTokenCookieName = "WIRE_ACCESS"
		p.cookie, err = cookie.NewFactory(cfg)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := p.accessTokenCookie("auth.example.test", u)
		if err != nil {
			t.Fatal(err)
		}
		c, err := http.ParseSetCookie(raw)
		if err != nil || c.Name != "WIRE_ACCESS" || c.Value != u.Token {
			t.Fatal("cookie wire identity changed")
		}
		if lifetime == 0 && (c.MaxAge != 0 || !c.Expires.IsZero()) || lifetime == 5 && c.MaxAge != 5 || lifetime == 3600 && (c.MaxAge < 1 || c.MaxAge > 20) {
			t.Fatal("cookie deadline extended or became persistent")
		}
	}
	claims["exp"] = time.Now().Unix() - 1
	u, err = user.NewUser(claims)
	if err != nil {
		t.Fatal(err)
	}
	u.Token = "staged"
	if _, err := p.accessTokenCookie("auth.example.test", u); err == nil {
		t.Fatal("expired staged cookie emitted")
	}
}
func TestSelectedAccessSigningFailureDoesNotSpendRefresh(t *testing.T) {
	f, _, probe := selectedPortal(t, true)
	first := decodeAuth(t, f.login(t, "body"))
	probe.mode = "mutate"
	result, err := f.portal.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.BodyTransport)
	if err == nil || result != nil {
		t.Fatal("unapproved staged refresh committed")
	}
	probe.mode = ""
	next, err := f.portal.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.BodyTransport)
	if err != nil || next == nil {
		t.Fatal("failed signing spent refresh proof", err)
	}
	if _, err := f.portal.refresh.Refresh(t.Context(), first.RefreshToken, tokenrefresh.BodyTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("committed rotation lost replay detection")
	}
	if _, err := f.portal.refresh.Refresh(t.Context(), next.RefreshToken, tokenrefresh.BodyTransport); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("replay did not revoke the committed family")
	}
}

func TestSelectedAccessSigningFailureDiagnostics(t *testing.T) {
	f, _, probe := selectedPortal(t, false)
	p := f.portal
	probe.mode = "mutate"
	core, logs := observer.New(zap.WarnLevel)
	p.logger = zap.New(core)
	p.identityProviders = []idp.IdentityProvider{&mockIdentityProvider{name: "upstream", realm: "upstream", kind: "oauth", driver: "generic"}}
	r, rr := providerCallback(t)
	rr.Response.Payload.(map[string]any)["access_token"] = "provider-private-credential-canary"
	u, err := p.authorizeLoginUser(t.Context(), r, rr)
	if err == nil || u != nil {
		t.Fatal("altered provider grant escaped staging")
	}
	entries := logs.FilterMessage("user token signing failed").All()
	if len(entries) != 1 {
		t.Fatal("missing signing refusal correlation")
	}
	for _, entry := range entries {
		fields := entry.ContextMap()
		if _, ok := fields["user"]; ok {
			t.Fatal("selected failure logged arbitrary provider claims")
		}
		if fields["session_id"] != rr.Upstream.SessionID {
			t.Fatal("failure correlation lost")
		}
		data, _ := json.Marshal(fields)
		if strings.Contains(string(data), "provider-private-credential-canary") {
			t.Fatal("selected failure logged provider credential")
		}
	}
}
