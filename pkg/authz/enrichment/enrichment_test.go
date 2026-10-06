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

package enrichment_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type lookupFunc func(context.Context, enrichment.Request) (*enrichment.Result, error)

func (f lookupFunc) Lookup(ctx context.Context, r enrichment.Request) (*enrichment.Result, error) {
	return f(ctx, r)
}
func config() *enrichment.Config {
	return &enrichment.Config{Source: "directory", Version: "v1", Issuer: "issuer", Realm: "realm", SubjectClaim: "id", TenantClaim: "tenant", Audience: "api", Attributes: []enrichment.AttributeConfig{{Name: "enrichment.entitlements", Type: "string_list"}}}
}
func identity(t *testing.T) *user.User {
	t.Helper()
	u, err := user.NewUser(map[string]any{"iss": "issuer", "origin": "realm", "id": "immutable", "tenant": "north", "sub": "display", "aud": "api", "roles": []string{"viewer"}, "amr": []string{"pwd"}, "enrichment.entitlements": []string{"forged"}, "enrichment.extra": "unrequested"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func result(req enrichment.Request) *enrichment.Result {
	return &enrichment.Result{Identity: req.Identity, Audience: req.Audience, Purpose: req.Purpose, Source: "directory", Version: "v1", ObservedAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(30 * time.Second), Attributes: map[string]any{"enrichment.entitlements": []string{"read"}}}
}

func TestEnrichmentTrustBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*enrichment.Result)
		fail   bool
	}{
		{"valid", func(*enrichment.Result) {}, false},
		{"absent removes", func(r *enrichment.Result) { r.Attributes = nil }, false},
		{"empty list", func(r *enrichment.Result) { r.Attributes["enrichment.entitlements"] = []string{} }, false},
		{"literal templates", func(r *enrichment.Result) {
			r.Attributes["enrichment.entitlements"] = []string{"{roles}", "${${admin}}"}
		}, false},
		{"issuer", func(r *enrichment.Result) { r.Identity.Issuer = "other" }, true},
		{"realm", func(r *enrichment.Result) { r.Identity.Realm = "other" }, true},
		{"subject", func(r *enrichment.Result) { r.Identity.Subject = "other" }, true},
		{"tenant", func(r *enrichment.Result) { r.Identity.Tenant = "other" }, true},
		{"audience", func(r *enrichment.Result) { r.Audience = "other" }, true},
		{"purpose", func(r *enrichment.Result) { r.Purpose = "login" }, true},
		{"source", func(r *enrichment.Result) { r.Source = "other" }, true},
		{"version", func(r *enrichment.Result) { r.Version = "v0" }, true},
		{"expired", func(r *enrichment.Result) { r.ExpiresAt = time.Now().Add(-time.Second) }, true},
		{"old", func(r *enrichment.Result) { r.ObservedAt = time.Now().Add(-time.Hour) }, true},
		{"future", func(r *enrichment.Result) { r.ObservedAt = time.Now().Add(time.Hour) }, true},
		{"zero", func(r *enrichment.Result) { r.ObservedAt = time.Time{} }, true},
		{"long validity", func(r *enrichment.Result) { r.ExpiresAt = time.Now().Add(time.Hour) }, true},
		{"reserved", func(r *enrichment.Result) { r.Attributes = map[string]any{"roles": []string{"admin"}} }, true},
		{"provider claims", func(r *enrichment.Result) { r.Attributes = map[string]any{"github_id": "forged"} }, true},
		{"null", func(r *enrichment.Result) { r.Attributes["enrichment.entitlements"] = nil }, true},
		{"typed null", func(r *enrichment.Result) { r.Attributes["enrichment.entitlements"] = []string(nil) }, true},
		{"scalar", func(r *enrichment.Result) { r.Attributes["enrichment.entitlements"] = "read" }, true},
		{"mixed", func(r *enrichment.Result) { r.Attributes["enrichment.entitlements"] = []any{"read", 2} }, true},
		{"nested", func(r *enrichment.Result) { r.Attributes["enrichment.entitlements"] = map[string]any{"read": true} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := identity(t)
			before := u.Clone()
			var response *enrichment.Result
			e, err := enrichment.New(config(), lookupFunc(func(_ context.Context, req enrichment.Request) (*enrichment.Result, error) {
				if req.Identity.Subject != "immutable" || req.Identity.Tenant != "north" || req.Purpose != "authorization" || !reflect.DeepEqual(req.Attributes, []string{"enrichment.entitlements"}) {
					t.Error("lookup was not bound to the selected identity and attributes")
				}
				response = result(req)
				tc.modify(response)
				return response, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.Enrich(t.Context(), u)
			if (err != nil) != tc.fail || (tc.fail && got != nil) {
				t.Fatalf("success=%t, expected failure=%t", err == nil, tc.fail)
			}
			if !reflect.DeepEqual(u, before) {
				t.Fatal("caller identity was mutated")
			}
			if tc.fail {
				return
			}
			if !reflect.DeepEqual(got.Claims.Roles, u.Claims.Roles) || !reflect.DeepEqual(got.Claims.AuthenticationMethods, u.Claims.AuthenticationMethods) {
				t.Fatal("protected claims changed")
			}
			if _, ok := got.AsMap()["enrichment.extra"]; ok {
				t.Fatal("unrequested namespace value survived")
			}
			if response.Attributes == nil {
				if _, ok := got.AsMap()["enrichment.entitlements"]; ok {
					t.Fatal("absent value retained a privilege")
				}
				return
			}
			if !reflect.DeepEqual(got.AsMap()["enrichment.entitlements"], response.Attributes["enrichment.entitlements"]) {
				t.Fatal("result did not reach detached claims")
			}
			response.Attributes["enrichment.entitlements"] = []string{"changed"}
			if reflect.DeepEqual(got.AsMap()["enrichment.entitlements"], response.Attributes["enrichment.entitlements"]) {
				t.Fatal("backend response aliases decision data")
			}
		})
	}
}

func TestEnrichmentFailureAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lookup lookupFunc
		want   error
	}{
		{"outage", func(context.Context, enrichment.Request) (*enrichment.Result, error) {
			return nil, errors.New("sensitive-backend-canary")
		}, nil},
		{"nil response", func(context.Context, enrichment.Request) (*enrichment.Result, error) { return nil, nil }, nil},
		{"timeout", func(ctx context.Context, _ enrichment.Request) (*enrichment.Result, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config()
			c.Timeout = "2ms"
			e, err := enrichment.New(c, tc.lookup)
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.Enrich(t.Context(), identity(t))
			if got != nil || err == nil || strings.Contains(err.Error(), "canary") || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatal("unsafe failure result")
			}
		})
	}
	calls := 0
	e, err := enrichment.New(config(), lookupFunc(func(_ context.Context, r enrichment.Request) (*enrichment.Result, error) {
		calls++
		return result(r), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.Enrich(ctx, identity(t)); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("canceled operation called backend")
	}
	for _, key := range []string{"iss", "origin", "id", "tenant", "aud"} {
		u := identity(t)
		m := u.AsMap()
		delete(m, key)
		u, err = user.NewUser(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Enrich(t.Context(), u); err == nil {
			t.Fatal("incomplete identity accepted")
		}
	}
	if calls != 0 {
		t.Fatal("unbound identity reached backend")
	}
}

func TestEnrichmentSnapshotsAndConcurrency(t *testing.T) {
	c := config()
	e, err := enrichment.New(c, lookupFunc(func(_ context.Context, r enrichment.Request) (*enrichment.Result, error) { return result(r), nil }))
	if err != nil {
		t.Fatal(err)
	}
	c.Attributes[0].Name = "roles"
	c.Source = "changed"
	u := identity(t)
	before := u.Clone()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			got, err := e.Enrich(t.Context(), u)
			if err != nil || got == nil {
				t.Error("concurrent enrichment failed")
				return
			}
			got.AsMap()["enrichment.entitlements"].([]string)[0] = "changed"
		})
	}
	wg.Wait()
	if !reflect.DeepEqual(before, u) {
		t.Fatal("concurrent caller mutation")
	}
}

func TestConfigAndAttributeValidation(t *testing.T) {
	for _, change := range []func(*enrichment.Config){
		func(c *enrichment.Config) { c.Source = "" }, func(c *enrichment.Config) { c.SubjectClaim = "enrichment.id" }, func(c *enrichment.Config) { c.TenantClaim = c.SubjectClaim }, func(c *enrichment.Config) { c.Timeout = "-1s" }, func(c *enrichment.Config) { c.Timeout = "31s" }, func(c *enrichment.Config) { c.MaxAge = "25h" }, func(c *enrichment.Config) { c.MaxAge = "invalid" }, func(c *enrichment.Config) { c.Attributes = nil }, func(c *enrichment.Config) { c.Attributes[0].Name = "roles" }, func(c *enrichment.Config) { c.Attributes[0].Type = "number" }, func(c *enrichment.Config) { c.Attributes = append(c.Attributes, c.Attributes[0]) },
	} {
		c := config()
		change(c)
		if c.Validate() == nil {
			t.Fatal("invalid config accepted")
		}
	}
	if (*enrichment.Config)(nil).Validate() == nil {
		t.Fatal("nil config accepted")
	}
	c := config()
	if err := c.Validate(); err != nil || c.Timeout != "1s" || c.MaxAge != "1m" {
		t.Fatal("defaults missing")
	}
	if e, err := enrichment.New(nil, nil); e != nil || err == nil {
		t.Fatal("nil dependencies accepted")
	}
	for _, tc := range []struct {
		value any
		kind  string
		valid bool
	}{
		{"", "string", true}, {"hello, world", "string", true}, {[]any{"hello", ""}, "string_list", true}, {nil, "string", false}, {strings.Repeat("x", 4097), "string", false}, {"\xff", "string", false}, {"\n", "string", false}, {[]string{}, "string_list", true}, {make([]string, 129), "string_list", false}, {[]any(nil), "string_list", false}, {[]any{nil}, "string_list", false}, {"x", "number", false},
	} {
		_, err := enrichment.CopyAttribute(tc.value, tc.kind)
		if (err == nil) != tc.valid {
			t.Fatal("attribute validation mismatch")
		}
	}
}

func TestPlainCustomClaims(t *testing.T) {
	c := config()
	c.Attributes = []enrichment.AttributeConfig{{Name: "foo", Type: "string"}, {Name: "permissions", Type: "string_list"}}
	calls := 0
	e, err := enrichment.New(c, lookupFunc(func(_ context.Context, req enrichment.Request) (*enrichment.Result, error) {
		calls++
		r := result(req)
		r.Attributes = map[string]any{"foo": "bar", "permissions": []string{"read", "write"}}
		return r, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	original := identity(t)
	for range 2 {
		enriched, err := e.Enrich(t.Context(), original)
		if err != nil || enriched.AsMap()["foo"] != "bar" || !reflect.DeepEqual(enriched.AsMap()["permissions"], []string{"read", "write"}) {
			t.Fatal("plain custom claims did not reach the authorization identity")
		}
		if _, exists := original.AsMap()["foo"]; exists {
			t.Fatal("custom claims leaked into the caller or cached identity")
		}
	}
	// Any plain claim collision fails, including provider fields unknown to core.
	// This prevents an absent backend response falling back to signed privileges.
	original.AsMap()["foo"] = "bar"
	if enriched, err := e.Enrich(t.Context(), original); enriched != nil || err == nil || calls != 2 {
		t.Fatal("authenticated claim collision did not fail before lookup")
	}
}

func TestProtectedAttributeDeclarations(t *testing.T) {
	for _, name := range []string{"roles", "role", "groups", "group", "subject", "id", "mail", "scope", "realm", "app_metadata", "realm_access", "paths", "frontend_links", "challenges", "auth_methods", "auth_time", "acr", "azp", "sid", "nonce", "at_hash", "c_hash", "s_hash", "cnf", "github_id", "github_orgs", "authcrunch_session"} {
		t.Run(name, func(t *testing.T) {
			if err := (enrichment.AttributeConfig{Name: name, Type: "string"}).Validate(); err == nil {
				t.Fatal("protected claim accepted")
			}
		})
	}
	// All present and future canonical user claims must remain protected.
	claimsType := reflect.TypeFor[user.Claims]()
	for field := range claimsType.Fields() {
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		if err := (enrichment.AttributeConfig{Name: name, Type: "string"}).Validate(); err == nil {
			t.Errorf("canonical claim %s is not protected", name)
		}
	}
	for _, binding := range []string{"immutable_id", "tenant"} {
		c := config()
		c.SubjectClaim = "immutable_id"
		c.Attributes = []enrichment.AttributeConfig{{Name: binding, Type: "string"}}
		if c.Validate() == nil {
			t.Fatal("enrichment can supply its own identity binding")
		}
	}
	for _, name := range []string{"foo", "permissions", "enrichment.roles", "featureFlags", "department-code", "https://example.test/claims/foo", "custom.key", "custom key"} {
		if err := (enrichment.AttributeConfig{Name: name, Type: "string"}).Validate(); err != nil {
			t.Fatal("valid literal custom claim rejected", err)
		}
	}
}

func TestEnrichmentCredentialLifetime(t *testing.T) {
	for _, tc := range []struct {
		name        string
		lifetime    time.Duration
		delay       time.Duration
		wantFailure bool
	}{
		{"valid", time.Minute, time.Second, false},
		{"expires during lookup", 2 * time.Second, 3 * time.Second, true},
		{"already expired", -time.Second, 0, true},
		{"expires now", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := config()
				c.Timeout = "10s"
				usr := identity(t)
				usr.SetExpiresAtClaim(time.Now().Add(tc.lifetime).Unix())
				calls := 0
				e, err := enrichment.New(c, lookupFunc(func(_ context.Context, req enrichment.Request) (*enrichment.Result, error) {
					calls++
					// Deliberately return success even after the credential expires.
					time.Sleep(tc.delay)
					return result(req), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				got, err := e.Enrich(t.Context(), usr)
				if (err != nil) != tc.wantFailure || (tc.wantFailure && got != nil) {
					t.Fatal("lookup extended the authenticated credential's lifetime")
				}
				if tc.lifetime <= 0 && calls != 0 {
					t.Fatal("expired credential reached the backend")
				}
			})
		})
	}
}

func TestEnrichmentDeadlineSelection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		expiry time.Duration
		parent time.Duration
		want   time.Duration
	}{
		{"credential", 2 * time.Second, 30 * time.Second, 2 * time.Second},
		{"caller", 20 * time.Second, time.Second, time.Second},
		{"configured", 20 * time.Second, 30 * time.Second, 10 * time.Second},
		{"external lifetime", 0, 30 * time.Second, 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := config()
				c.Timeout = "10s"
				usr := identity(t)
				start := time.Now()
				if tc.expiry > 0 {
					usr.SetExpiresAtClaim(start.Add(tc.expiry).Unix())
				}
				ctx, cancel := context.WithTimeout(t.Context(), tc.parent)
				defer cancel()
				e, err := enrichment.New(c, lookupFunc(func(ctx context.Context, req enrichment.Request) (*enrichment.Result, error) {
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(start.Add(tc.want)) {
						t.Error("lookup did not receive the earliest validity bound")
					}
					<-ctx.Done()
					return nil, ctx.Err()
				}))
				if err != nil {
					t.Fatal(err)
				}
				if got, err := e.Enrich(ctx, usr); got != nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != tc.want {
					t.Fatal("lookup outlived its controlling deadline")
				}
			})
		})
	}
}
