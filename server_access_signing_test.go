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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch"
	fixture "github.com/greenpau/go-authcrunch/internal/tests/accesssigner"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

type rootAccessSignerProbe struct {
	kms.AccessSigner
	calls, closes int
	broken        bool
}

func (s *rootAccessSignerProbe) Metadata() (kms.AccessSignerMetadata, error) {
	s.calls++
	if s.broken {
		panic("private initialization canary")
	}
	return s.AccessSigner.Metadata()
}
func (s *rootAccessSignerProbe) Close() error { s.closes++; return nil }
func TestServerExternalAccessSignerOwnership(t *testing.T) {
	f := fixture.New(t, "https://login.test/auth")
	probe := &rootAccessSignerProbe{AccessSigner: f.Signer}
	config := func() *authcrunch.Config {
		return &authcrunch.Config{ExternalAccessSigners: []*kms.ExternalAccessSignerConfig{f.Descriptor}, AuthorizationPolicies: []*authz.PolicyConfig{{Name: "legacy-policy", AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}}}
	}
	for name, options := range map[string]authcrunch.ServerOptions{"missing": {}, "nil": {AccessSigners: map[string]kms.AccessSigner{"access": nil}}, "extra": {AccessSigners: map[string]kms.AccessSigner{"access": probe, "extra": probe}}, "typed nil": {AccessSigners: map[string]kms.AccessSigner{"access": (*rootAccessSignerProbe)(nil)}}, "panic": {AccessSigners: map[string]kms.AccessSigner{"access": &rootAccessSignerProbe{AccessSigner: f.Signer, broken: true}}}} {
		t.Run(name, func(t *testing.T) {
			cfg := config()
			dir := filepath.Join(t.TempDir(), "state")
			cfg.State = &state.Config{Directory: dir}
			if runtime, err := authcrunch.NewServerWithOptions(cfg, zap.NewNop(), options); err == nil || runtime != nil {
				if runtime != nil {
					_ = runtime.Close()
				}
				t.Fatal("invalid runtime binding published")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("binding rejection opened persistent state")
			}
		})
	}
	options := authcrunch.ServerOptions{AccessSigners: map[string]kms.AccessSigner{"access": probe}}
	runtime, err := authcrunch.NewServerWithOptions(config(), zap.NewNop(), options)
	if err != nil {
		t.Fatal("unused valid declaration rejected", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if probe.closes != 0 {
		t.Fatal("root closed borrowed signer")
	}
	if _, err := probe.Sign(context.Background(), f.Claims()); err != nil {
		t.Fatal("borrowed signer unusable after root close")
	}
	// A downstream construction failure also leaves the caller's signer usable.
	cfg := config()
	cfg.AuthorizationPolicies[0].RawCryptoKeyStoreConfig = []string{"crypto key verify from file " + filepath.Join(t.TempDir(), "missing.pem")}
	if runtime, err := authcrunch.NewServerWithOptions(cfg, zap.NewNop(), options); err == nil || runtime != nil {
		t.Fatal("downstream construction unexpectedly succeeded")
	}
	if probe.closes != 0 {
		t.Fatal("failed root closed borrowed signer")
	}
	if _, err := probe.Sign(context.Background(), f.Claims()); err != nil {
		t.Fatal("failed root broke borrowed signer")
	}
}
func TestServerAccessSignerPureSelectionValidation(t *testing.T) {
	f := fixture.New(t, "https://login.test/auth")
	probe := &rootAccessSignerProbe{AccessSigner: f.Signer}
	base := func() *authcrunch.Config {
		return &authcrunch.Config{ExternalAccessSigners: []*kms.ExternalAccessSignerConfig{f.Descriptor}, AuthenticationPortals: []*authn.PortalConfig{{Name: "selected", AccessSigner: "access", AccessTokenProfile: f.Profile.Clone(), RawCryptoKeyStoreConfig: []string{"crypto key current verify from file /must-not-open/public.pem"}}}}
	}
	for name, edit := range map[string]func(*authcrunch.Config){"missing selection": func(c *authcrunch.Config) { c.AuthenticationPortals[0].AccessSigner = "unknown" }, "missing profile": func(c *authcrunch.Config) { c.AuthenticationPortals[0].AccessTokenProfile = nil }, "profile without signer": func(c *authcrunch.Config) { c.AuthenticationPortals[0].AccessSigner = "" }, "wrong audience": func(c *authcrunch.Config) { c.AuthenticationPortals[0].AccessTokenProfile.Audience = "other" }, "duplicate descriptor": func(c *authcrunch.Config) { c.ExternalAccessSigners = append(c.ExternalAccessSigners, f.Descriptor) }, "nil descriptor": func(c *authcrunch.Config) { c.ExternalAccessSigners = []*kms.ExternalAccessSignerConfig{nil} }, "no explicit key": func(c *authcrunch.Config) { c.AuthenticationPortals[0].RawCryptoKeyStoreConfig = nil }, "ordinary signer": func(c *authcrunch.Config) {
		c.AuthenticationPortals[0].RawCryptoKeyStoreConfig = []string{"crypto key current sign-verify from file /must-not-open/private.pem"}
	}, "negative lifetime": func(c *authcrunch.Config) {
		c.AuthenticationPortals[0].RawCryptoKeyStoreConfig = append(c.AuthenticationPortals[0].RawCryptoKeyStoreConfig, "crypto default token lifetime -1")
	}, "renewable issuer": func(c *authcrunch.Config) {
		c.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://other.test", BasePath: "/auth"}
	}} {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			edit(cfg)
			before := probe.calls
			if runtime, err := authcrunch.NewServerWithOptions(cfg, zap.NewNop(), authcrunch.ServerOptions{AccessSigners: map[string]kms.AccessSigner{"access": probe}}); err == nil || runtime != nil {
				t.Fatal("invalid selection published")
			}
			if probe.calls != before {
				t.Fatal("pure selection failure reached runtime metadata")
			}
		})
	}
}
