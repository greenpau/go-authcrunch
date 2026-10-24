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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

type rootRefreshStoreProbe struct {
	descriptor                                     *tokenrefresh.ExternalStoreConfig
	metadataCalls, readyCalls, activations, closes int
	broken                                         bool
}

func (s *rootRefreshStoreProbe) Metadata() (tokenrefresh.StoreMetadata, error) {
	if s == nil {
		return tokenrefresh.StoreMetadata{}, tokenrefresh.ErrUnavailable
	}
	s.metadataCalls++
	if s.broken {
		panic("private readiness canary")
	}
	c := s.descriptor
	return tokenrefresh.StoreMetadata{Kind: c.Kind, ConfigDigest: c.ConfigDigest, MaxSessions: c.MaxSessions, MaxRotations: c.MaxRotations}, nil
}
func (s *rootRefreshStoreProbe) CheckReady(ctx context.Context) error {
	s.readyCalls++
	return ctx.Err()
}
func (s *rootRefreshStoreProbe) ActivateGeneration(context.Context, tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	s.activations++
	return nil, tokenrefresh.ErrUnavailable
}
func (s *rootRefreshStoreProbe) Close() error { s.closes++; return nil }
func rootRefreshStoreDescriptor(t *testing.T) *tokenrefresh.ExternalStoreConfig {
	t.Helper()
	c, err := tokenrefresh.NewExternalStoreConfig("refresh", "probe", 2, 3, struct{ Capacity int }{2})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestServerExternalRefreshStorePreflight(t *testing.T) {
	descriptor := rootRefreshStoreDescriptor(t)
	config := func() *authcrunch.Config {
		return &authcrunch.Config{ExternalRefreshStores: []*tokenrefresh.ExternalStoreConfig{descriptor}, AuthorizationPolicies: []*authz.PolicyConfig{{Name: "legacy", AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}}}
	}
	probe := &rootRefreshStoreProbe{descriptor: descriptor}
	for name, bindings := range map[string]map[string]tokenrefresh.ManagedStore{
		"missing": nil, "nil": {"refresh": nil}, "typed_nil": {"refresh": (*rootRefreshStoreProbe)(nil)}, "extra": {"refresh": probe, "other": probe}, "panic": {"refresh": &rootRefreshStoreProbe{descriptor: descriptor, broken: true}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config()
			dir := filepath.Join(t.TempDir(), "state")
			cfg.State = &state.Config{Directory: dir}
			runtime, err := authcrunch.NewServerWithOptions(cfg, zap.NewNop(), authcrunch.ServerOptions{RefreshStores: bindings})
			if runtime != nil {
				_ = runtime.Close()
			}
			if err == nil || runtime != nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("invalid managed binding published")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("managed binding rejection opened root state")
			}
		})
	}
	runtime, err := authcrunch.NewServerWithOptions(config(), zap.NewNop(), authcrunch.ServerOptions{RefreshStores: map[string]tokenrefresh.ManagedStore{"refresh": probe}})
	if err != nil {
		t.Fatal("unused valid managed declaration rejected", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if probe.readyCalls == 0 || probe.activations != 0 || probe.closes != 0 {
		t.Fatal("unused binding was activated or ownership changed")
	}
}
func TestServerExternalRefreshStorePureSelection(t *testing.T) {
	descriptor := rootRefreshStoreDescriptor(t)
	probe := &rootRefreshStoreProbe{descriptor: descriptor}
	for _, name := range []string{"missing_state", "missing_declaration", "disabled", "session_limit", "rotation_limit", "duplicate_descriptor", "nil_descriptor"} {
		t.Run(name, func(t *testing.T) {
			cfg := &authcrunch.Config{State: &state.Config{Directory: filepath.Join(t.TempDir(), "state")}, ExternalRefreshStores: []*tokenrefresh.ExternalStoreConfig{descriptor}, AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Store: "refresh", Realms: []string{"local"}, PublicOrigin: "https://login.test", BasePath: "/auth", MaxSessions: 2, MaxRotations: 3}}}}
			switch name {
			case "missing_state":
				cfg.State = nil
			case "missing_declaration":
				cfg.ExternalRefreshStores = nil
			case "disabled":
				cfg.AuthenticationPortals[0].RefreshTokens.Enabled = false
			case "session_limit":
				cfg.AuthenticationPortals[0].RefreshTokens.MaxSessions = 3
			case "rotation_limit":
				cfg.AuthenticationPortals[0].RefreshTokens.MaxRotations = 4
			case "duplicate_descriptor":
				cfg.ExternalRefreshStores = append(cfg.ExternalRefreshStores, descriptor)
			case "nil_descriptor":
				cfg.ExternalRefreshStores[0] = nil
			}
			before := probe.metadataCalls
			runtime, err := authcrunch.NewServerWithOptions(cfg, zap.NewNop(), authcrunch.ServerOptions{RefreshStores: map[string]tokenrefresh.ManagedStore{"refresh": probe}})
			if runtime != nil {
				_ = runtime.Close()
			}
			if err == nil || runtime != nil || probe.metadataCalls != before || probe.activations != 0 {
				t.Fatal("invalid pure managed selection reached runtime construction")
			}
		})
	}
}
