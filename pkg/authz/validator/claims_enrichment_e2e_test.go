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

package validator_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	enrichmentparser "github.com/greenpau/go-authcrunch/pkg/authz/enrichment/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type claimsBackend struct {
	calls atomic.Int64
	deny  atomic.Bool
}

func (b *claimsBackend) Lookup(_ context.Context, r enrichment.Request) (*enrichment.Result, error) {
	b.calls.Add(1)
	attributes := map[string]any{"enrichment.access": []string{"read"}}
	if b.deny.Load() {
		attributes = nil
	}
	return &enrichment.Result{Identity: r.Identity, Audience: r.Audience, Purpose: r.Purpose, Source: "directory", Version: "v1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second), Attributes: attributes}, nil
}

func TestE2EClaimsEnrichmentEveryGuardian(t *testing.T) {
	for flags := range 8 {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			keys, err := kms.NewCryptoKeyStoreConfig(nil)
			if err != nil {
				t.Fatal(err)
			}
			v, err := validator.NewTokenValidator(keys, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(v.Close)
			list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{{Name: "entitlement", Claim: "enrichment.access", Type: "string_list"}})
			if err != nil {
				t.Fatal(err)
			}
			conditions := []string{"match entitlement read"}
			if flags&1 != 0 {
				conditions = append(conditions, "match method GET", "prefix match path /private/")
			}
			if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: conditions, Action: "allow stop"}); err != nil {
				t.Fatal(err)
			}
			opts := options.NewTokenValidatorOptions()
			opts.ValidateMethodPath = flags&1 != 0
			opts.ValidateSourceAddress = flags&2 != 0
			opts.ValidateAccessListPathClaim = flags&4 != 0
			opts.ValidateBearerHeader = true
			opts.AuthorizationHeaderNames = []string{"access_token"}
			if err := v.Configure(t.Context(), list, opts); err != nil {
				t.Fatal(err)
			}
			config, err := enrichmentparser.NewClaimsEnrichmentConfigFromDirectives([]string{"source directory", "version v1", "issuer issuer", "realm realm", "subject claim immutable", "tenant claim tenant", "audience api", "attribute enrichment.access string list"})
			if err != nil {
				t.Fatal(err)
			}
			backend := &claimsBackend{}
			enricher, err := enrichment.New(config, backend)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.SetClaimsEnricher(enricher); err != nil {
				t.Fatal(err)
			}
			u, err := user.NewUser(map[string]any{"iss": "issuer", "origin": "realm", "immutable": "id", "tenant": "north", "aud": "api", "sub": "display", "roles": []string{"viewer"}, "exp": time.Now().Add(time.Minute).Unix(), "addr": "127.0.0.1", "acl": map[string]any{"paths": []any{"/private/**"}}, "enrichment.access": []string{"forged"}})
			if err != nil {
				t.Fatal(err)
			}
			before := u.Clone()
			cached := u.Clone()
			cached.Token = "synthetic-cached-identity"
			if err := v.CacheUser(cached); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var err error
				if r.Header.Get("Authorization") != "" {
					var got *user.User
					got, err = v.Authorize(r.Context(), r, requests.NewAuthorizationRequest())
					if got != nil && (!got.Cached || !reflect.DeepEqual(got.AsMap(), before.AsMap())) {
						t.Error("cached identity changed or was not used")
					}
				} else {
					err = v.AuthorizeUser(r.Context(), r, u)
				}
				if err != nil {
					http.Error(w, "denied", 403)
					return
				}
				w.WriteHeader(204)
			}))
			defer srv.Close()
			client := srv.Client()
			client.Timeout = 5 * time.Second
			for _, cache := range []bool{false, true} {
				for _, tc := range []struct {
					method, path string
					want         int
				}{{"GET", "/private/read", 204}, {"POST", "/private/read", map[bool]int{true: 403, false: 204}[flags&1 != 0]}, {"GET", "/outside", map[bool]int{true: 403, false: 204}[flags&5 != 0]}} {
					req, err := http.NewRequestWithContext(t.Context(), tc.method, srv.URL+tc.path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if cache {
						req.Header.Set("Authorization", "Bearer "+cached.Token)
					}
					for _, deny := range []bool{false, true} {
						backend.deny.Store(deny)
						want := tc.want
						if deny {
							want = 403
						}
						prior := backend.calls.Load()
						resp, err := client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						_, _ = io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
						if resp.StatusCode != want || backend.calls.Load() != prior+1 {
							t.Fatal("hook or guardian was bypassed")
						}
					}
				}
			}
			if !reflect.DeepEqual(u, before) {
				t.Fatal("authenticated identity mutated")
			}
			v.Close()
			if v.SetClaimsEnricher(enricher) == nil {
				t.Fatal("closed validator accepted attachment")
			}
		})
	}
}

type expiringClaimsBackend struct {
	expires time.Time
	slow    atomic.Bool
	calls   atomic.Int64
}

func (b *expiringClaimsBackend) Lookup(ctx context.Context, req enrichment.Request) (*enrichment.Result, error) {
	b.calls.Add(1)
	if b.slow.Load() {
		// Simulate a lookup that would succeed just after the token expires.
		timer := time.NewTimer(time.Until(b.expires.Add(20 * time.Millisecond)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	now := time.Now()
	return &enrichment.Result{
		Identity: req.Identity, Audience: req.Audience, Purpose: req.Purpose,
		Source: "directory", Version: "v1", ObservedAt: now,
		ExpiresAt: now.Add(time.Minute), Attributes: map[string]any{"foo": "bar"},
	}, nil
}

func TestE2EClaimsEnrichmentCredentialExpiry(t *testing.T) {
	const secret = "claims-enrichment-expiry-test-signing-secret"
	for _, mode := range []string{"signed token", "cached token", "authenticated user"} {
		t.Run(mode, func(t *testing.T) {
			keys, err := kms.NewCryptoKeyStoreConfig([]string{"crypto key sign-verify " + secret})
			if err != nil {
				t.Fatal(err)
			}
			v, err := validator.NewTokenValidator(keys, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(v.Close)
			list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{{Name: "custom", Claim: "foo", Type: "string"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: []string{"match custom bar"}, Action: "allow stop"}); err != nil {
				t.Fatal(err)
			}
			opts := options.NewTokenValidatorOptions()
			opts.ValidateBearerHeader = true
			opts.AuthorizationHeaderNames = []string{"access_token"}
			if err := v.Configure(t.Context(), list, opts); err != nil {
				t.Fatal(err)
			}
			binding, err := enrichmentparser.NewClaimsEnrichmentConfigFromDirectives([]string{
				"source directory", "version v1", "issuer issuer", "realm realm",
				"subject claim immutable", "tenant claim tenant", "audience api",
				"attribute foo string", "timeout 10s",
			})
			if err != nil {
				t.Fatal(err)
			}
			backend := &expiringClaimsBackend{expires: time.Unix(time.Now().Add(2*time.Second).Unix(), 0)}
			enricher, err := enrichment.New(binding, backend)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.SetClaimsEnricher(enricher); err != nil {
				t.Fatal(err)
			}
			claims := jwt.MapClaims{
				"iss": "issuer", "origin": "realm", "sub": "display", "immutable": "account-id",
				"tenant": "north", "aud": "api", "exp": backend.expires.Unix(), "roles": []string{"viewer"},
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
			if err != nil {
				t.Fatal(err)
			}
			usr, err := user.NewUser(map[string]any(claims))
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var err error
				if mode == "authenticated user" {
					err = v.AuthorizeUser(r.Context(), r, usr)
				} else {
					var got *user.User
					got, err = v.Authorize(r.Context(), r, requests.NewAuthorizationRequest())
					if err == nil && mode == "cached token" && !backend.slow.Load() {
						err = v.CacheUser(got)
					}
					if mode == "cached token" && backend.slow.Load() && got != nil && !got.Cached {
						t.Error("expiry regression did not use the cached token")
					}
				}
				if err != nil {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()
			client := srv.Client()
			client.Timeout = 5 * time.Second
			for _, want := range []int{http.StatusNoContent, http.StatusForbidden} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/private", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != want {
					t.Errorf("%s: got HTTP %d, want %d", mode, resp.StatusCode, want)
				}
				backend.slow.Store(true)
			}
			if backend.calls.Load() != 2 {
				t.Fatal("credential did not remain valid until both lookups began")
			}
		})
	}
}
