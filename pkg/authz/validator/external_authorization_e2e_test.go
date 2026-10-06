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
	"encoding/json"
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
	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	bindingparser "github.com/greenpau/go-authcrunch/pkg/authz/external/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson"
	httpparser "github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson/parser"
)

func TestE2EExternalAuthorizationEveryGuardian(t *testing.T) {
	const secret = "external-authorization-guardian-synthetic-signing-key"
	for flags := range 8 {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			var calls atomic.Int64
			var deny atomic.Bool
			service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var input external.Request
				if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&input) != nil {
					t.Error("invalid service input")
					return
				}
				if !reflect.DeepEqual(input.Attributes, map[string]any{"enrichment.access": []any{"signed"}}) {
					t.Error("external authorizer received enriched or unselected claims")
				}
				decision := "allow"
				if deny.Load() {
					decision = "deny"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(external.Result{Decision: decision, Policy: input.Policy, Version: input.Version})
			}))
			defer service.Close()
			httpConfig, err := httpparser.NewHTTPJSONAuthorizerConfigFromDirectives([]string{"endpoint " + service.URL})
			if err != nil {
				t.Fatal(err)
			}
			backend, err := httpjson.New(httpConfig, service.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			binding, err := bindingparser.NewExternalAuthorizationConfigFromDirectives([]string{"policy reports", "version v1", "issuer issuer", "realm realm", "attribute enrichment.access"})
			if err != nil {
				t.Fatal(err)
			}
			authorizer, err := external.New(binding, backend)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := kms.NewCryptoKeyStoreConfig([]string{"crypto key verify " + secret})
			if err != nil {
				t.Fatal(err)
			}
			v, err := validator.NewTokenValidator(keys, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{{Name: "entitlement", Claim: "enrichment.access", Type: "string_list"}})
			if err != nil {
				t.Fatal(err)
			}
			conditions := []string{"match roles viewer", "match entitlement read"}
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
			if err := v.Configure(t.Context(), list, opts); err != nil {
				t.Fatal(err)
			}
			if err := v.SetExternalAuthorizer(authorizer); err != nil {
				t.Fatal(err)
			}
			enrichmentConfig, err := enrichmentparser.NewClaimsEnrichmentConfigFromDirectives([]string{"source directory", "version v1", "issuer issuer", "realm realm", "subject claim immutable", "tenant claim tenant", "audience api", "attribute enrichment.access string list"})
			if err != nil {
				t.Fatal(err)
			}
			claimsSource := &claimsBackend{}
			enricher, err := enrichment.New(enrichmentConfig, claimsSource)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.SetClaimsEnricher(enricher); err != nil {
				t.Fatal(err)
			}
			claims := map[string]any{"iss": "issuer", "origin": "realm", "sub": "alice", "immutable": "account-id", "tenant": "north", "aud": "api", "enrichment.access": []string{"signed"}, "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{"viewer"}, "addr": "127.0.0.1", "acl": map[string]any{"paths": []any{"/private/**"}}}
			usr, err := user.NewUser(claims)
			if err != nil {
				t.Fatal(err)
			}
			before := usr.Clone()
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString([]byte(secret))
			if err != nil {
				t.Fatal(err)
			}
			app := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var err error
				if r.Header.Get("X-Fixture-Mode") == "authenticated" {
					err = v.AuthorizeUser(r.Context(), r, usr)
				} else {
					var got *user.User
					got, err = v.Authorize(r.Context(), r, requests.NewAuthorizationRequest())
					if err == nil {
						if r.Header.Get("X-Fixture-Mode") == "cached" && !got.Cached {
							t.Error("cache was not exercised")
						}
						if err := v.CacheUser(got); err != nil {
							t.Error(err)
						}
					}
				}
				if err != nil {
					http.Error(w, "denied", 403)
					return
				}
				w.WriteHeader(204)
			}))
			defer app.Close()
			client := app.Client()
			client.Timeout = 5 * time.Second
			for _, mode := range []string{"signed", "cached", "authenticated"} {
				for _, denied := range []bool{false, true} {
					deny.Store(denied)
					prior := calls.Load()
					req, _ := http.NewRequestWithContext(t.Context(), "GET", app.URL+"/private/read", nil)
					req.Header.Set("Authorization", "Bearer "+token)
					req.Header.Set("X-Fixture-Mode", mode)
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					want := 204
					if denied {
						want = 403
					}
					if resp.StatusCode != want || calls.Load() != prior+1 {
						t.Fatal("external decision bypassed by guardian or cache")
					}
				}
				// An absent enrichment value fails the local ACL before any
				// remote allow can be consulted, including with cached identities.
				deny.Store(false)
				claimsSource.deny.Store(true)
				prior := calls.Load()
				req, err := http.NewRequestWithContext(t.Context(), "GET", app.URL+"/private/read", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("X-Fixture-Mode", mode)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusForbidden || calls.Load() != prior {
					t.Fatal("local enrichment rejection reached remote authorizer")
				}
				claimsSource.deny.Store(false)
			}
			if !reflect.DeepEqual(usr.AsMap(), before.AsMap()) {
				t.Fatal("authenticated user mutated")
			}
			if v.SetExternalAuthorizer(nil) == nil {
				t.Fatal("nil authorizer accepted")
			}
			v.Close()
			if v.SetExternalAuthorizer(authorizer) == nil {
				t.Fatal("closed validator accepted authorizer")
			}
		})
	}
}
