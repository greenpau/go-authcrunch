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

package external_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

type decisionFunc func(context.Context, external.Request) (*external.Result, error)

func (f decisionFunc) Decide(ctx context.Context, r external.Request) (*external.Result, error) {
	return f(ctx, r)
}
func config() *external.Config {
	return &external.Config{Policy: "reports", Version: "v1", Issuer: "issuer", Realm: "realm", TenantClaim: "tenant", Attributes: []string{"custom"}}
}
func identity(t *testing.T) *user.User {
	t.Helper()
	u, err := user.NewUser(map[string]any{"iss": "issuer", "origin": "realm", "sub": "alice", "tenant": "north", "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"viewer"}, "custom": map[string]any{"number": json.Number("9007199254740993"), "active": true}, "secret": "never send"})
	if err != nil {
		t.Fatal(err)
	}
	return u
}
func allow(r external.Request) *external.Result {
	return &external.Result{Policy: r.Policy, Version: r.Version, Decision: "allow"}
}

func TestAuthorizationBindingsAndSnapshots(t *testing.T) {
	usr := identity(t)
	before := usr.Clone()
	cfg := config()
	var resources []string
	backend := decisionFunc(func(_ context.Context, r external.Request) (*external.Result, error) {
		resources = append(resources, r.Resource)
		if r.Identity != (external.Identity{Issuer: "issuer", Realm: "realm", Subject: "alice", Tenant: "north"}) || r.Action != "GET" || len(r.Attributes) != 1 {
			t.Error("incorrect identity or excessive disclosure")
		}
		custom := r.Attributes["custom"].(map[string]any)
		if custom["number"] != json.Number("9007199254740993") {
			t.Error("attribute precision or isolation lost")
		}
		custom["number"] = "changed"
		return allow(r), nil
	})
	a, err := external.New(cfg, backend)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Issuer = "changed"
	cfg.Attributes[0] = "secret"
	req := httptest.NewRequest("GET", "https://app.test/private/../reports?secret=never-send", nil)
	req.Header.Set("X-Subject", "mallory")
	if err := a.Authorize(t.Context(), req, usr); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resources, []string{"/private/../reports", "/reports"}) {
		t.Fatalf("wrong path interpretations: %v", resources)
	}
	if !reflect.DeepEqual(usr.AsMap(), before.AsMap()) || req.URL.RawQuery != "secret=never-send" {
		t.Fatal("caller state changed")
	}
}

func TestAuthorizationRejections(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(*user.User)
		response func(external.Request) *external.Result
		err      error
		path     string
	}{
		{name: "deny", response: func(r external.Request) *external.Result { x := allow(r); x.Decision = "deny"; return x }},
		{name: "missing", response: func(external.Request) *external.Result { return nil }},
		{name: "unknown", response: func(r external.Request) *external.Result { x := allow(r); x.Decision = ""; return x }},
		{name: "wrong policy", response: func(r external.Request) *external.Result { x := allow(r); x.Policy = "other"; return x }},
		{name: "wrong version", response: func(r external.Request) *external.Result { x := allow(r); x.Version = "v2"; return x }},
		{name: "outage", err: errors.New("private-response-canary")},
		{name: "issuer", edit: func(u *user.User) { u.Claims.Issuer = "other" }},
		{name: "realm", edit: func(u *user.User) { u.Claims.Origin = "other" }},
		{name: "subject", edit: func(u *user.User) { u.AsMap()["sub"] = map[string]any{} }},
		{name: "tenant", edit: func(u *user.User) { delete(u.AsMap(), "tenant") }},
		{name: "attribute", edit: func(u *user.User) { u.AsMap()["custom"] = math.NaN() }},
		{name: "expired", edit: func(u *user.User) { u.Claims.ExpiresAt = time.Now().Unix() - 1 }},
		{name: "encoded separator", path: "https://app.test/a%2Fb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			usr := identity(t)
			if tc.edit != nil {
				tc.edit(usr)
			}
			called := false
			a, err := external.New(config(), decisionFunc(func(_ context.Context, r external.Request) (*external.Result, error) {
				called = true
				if tc.response != nil {
					return tc.response(r), tc.err
				}
				return allow(r), tc.err
			}))
			if err != nil {
				t.Fatal(err)
			}
			path := tc.path
			if path == "" {
				path = "https://app.test/reports"
			}
			err = a.Authorize(t.Context(), httptest.NewRequest("GET", path, nil), usr)
			if err == nil || strings.Contains(err.Error(), "canary") {
				t.Fatal("invalid authorization accepted or disclosed")
			}
			if (tc.edit != nil || tc.path != "") && called {
				t.Fatal("invalid input reached backend")
			}
		})
	}
}

func TestAuthorizationEveryPathSharesDeadline(t *testing.T) {
	for _, mode := range []string{"deny final path", "shared deadline"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				var paths []string
				a, err := external.New(config(), decisionFunc(func(ctx context.Context, r external.Request) (*external.Result, error) {
					paths = append(paths, r.Resource)
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(start.Add(time.Second)) {
						t.Error("path interpretation reset the total deadline")
					}
					result := allow(r)
					if len(paths) == 1 {
						time.Sleep(400 * time.Millisecond)
					} else if mode == "shared deadline" {
						<-ctx.Done()
					} else {
						result.Decision = "deny"
					}
					return result, nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				err = a.Authorize(t.Context(), httptest.NewRequest("GET", "https://app.test/private/../reports", nil), identity(t))
				want := external.ErrDenied
				if mode == "shared deadline" {
					want = context.DeadlineExceeded
					if time.Since(start) != time.Second {
						t.Error("path interpretations exceeded total time budget")
					}
				}
				if !errors.Is(err, want) || !reflect.DeepEqual(paths, []string{"/private/../reports", "/reports"}) {
					t.Fatal("first path allowed the complete request despite a later rejection")
				}
			})
		})
	}
}

func TestAuthorizationDeadlines(t *testing.T) {
	for _, mode := range []string{"policy", "caller", "credential", "ignores context"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := config()
				cfg.Timeout = "10s"
				usr := identity(t)
				ctx := t.Context()
				want := 10 * time.Second
				if mode == "credential" {
					usr.Claims.ExpiresAt = time.Now().Add(2 * time.Second).Unix()
					want = 2 * time.Second
				}
				if mode == "caller" {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					want = 3 * time.Second
				}
				a, err := external.New(cfg, decisionFunc(func(ctx context.Context, r external.Request) (*external.Result, error) {
					if mode == "ignores context" {
						time.Sleep(11 * time.Second)
					} else {
						<-ctx.Done()
					}
					return allow(r), nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now()
				err = a.Authorize(ctx, httptest.NewRequest("GET", "https://app.test/reports", nil), usr)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("late allow accepted")
				}
				if mode != "ignores context" && time.Since(start) != want {
					t.Fatal("incorrect effective deadline")
				}
			})
		})
	}
	a, err := external.New(config(), decisionFunc(func(context.Context, external.Request) (*external.Result, error) {
		t.Error("canceled request called backend")
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(a.Authorize(ctx, httptest.NewRequest("GET", "https://app.test/reports", nil), identity(t)), context.Canceled) {
		t.Fatal("cancellation lost")
	}
	var noContext context.Context
	if a.Authorize(noContext, nil, nil) == nil || (*external.Authorizer)(nil).Authorize(t.Context(), nil, nil) == nil {
		t.Fatal("nil input accepted")
	}
}

func TestConfigAndConcurrentUse(t *testing.T) {
	if (*external.Config)(nil).Validate() == nil {
		t.Fatal("nil config accepted")
	}
	for _, edit := range []func(*external.Config){func(c *external.Config) { c.Policy = "" }, func(c *external.Config) { c.Version = "" }, func(c *external.Config) { c.Realm = "" }, func(c *external.Config) { c.Issuer = "\xff" }, func(c *external.Config) { c.SubjectClaim = "bad\n" }, func(c *external.Config) { c.TenantClaim = "sub" }, func(c *external.Config) { c.Timeout = "0s" }, func(c *external.Config) { c.Timeout = "31s" }, func(c *external.Config) { c.Attributes = []string{"a", "a"} }, func(c *external.Config) { c.Attributes = make([]string, 17) }} {
		c := config()
		edit(c)
		if c.Validate() == nil {
			t.Fatal("bad config accepted")
		}
	}
	if a, err := external.New(nil, nil); a != nil || err == nil {
		t.Fatal("nil constructor accepted")
	}
	cfg := config()
	if err := cfg.Validate(); err != nil || cfg.Timeout != "1s" || cfg.SubjectClaim != "sub" {
		t.Fatal("bad defaults")
	}
	a, err := external.New(cfg, decisionFunc(func(_ context.Context, r external.Request) (*external.Result, error) {
		r.Attributes["custom"].(map[string]any)["active"] = false
		return allow(r), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	usr := identity(t)
	req := httptest.NewRequest("GET", "https://app.test/reports", nil)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := a.Authorize(t.Context(), req, usr); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if usr.AsMap()["custom"].(map[string]any)["active"] != true {
		t.Fatal("backend mutated caller")
	}
}

func TestRequestSnapshotBounds(t *testing.T) {
	good := external.Request{Policy: "reports", Version: "v1", Identity: external.Identity{Issuer: "issuer", Realm: "realm", Subject: "alice"}, Action: "GET", Resource: "/report ", Attributes: map[string]any{"custom": map[string]any{"null": nil}}}
	snapshot, err := good.Snapshot()
	if err != nil || snapshot.Resource != "/report " {
		t.Fatal("valid path data rejected or changed")
	}
	snapshot.Attributes["custom"].(map[string]any)["null"] = true
	if good.Attributes["custom"].(map[string]any)["null"] != nil {
		t.Fatal("snapshot aliases caller")
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, change := range []func(*external.Request){
		func(r *external.Request) { r.Action = "GET POST" }, func(r *external.Request) { r.Action = "GET\r" },
		func(r *external.Request) { r.Resource = "relative" }, func(r *external.Request) { r.Resource = "/\xff" }, func(r *external.Request) { r.Resource = "/\n" }, func(r *external.Request) { r.Resource = "/" + strings.Repeat("a", 4096) },
		func(r *external.Request) { r.Identity.Subject = "" }, func(r *external.Request) { r.Identity.Tenant = "\x00" },
		func(r *external.Request) { r.Attributes = map[string]any{"cycle": cycle} }, func(r *external.Request) { r.Attributes = map[string]any{"unsupported": time.Now()} },
		func(r *external.Request) { r.Attributes = map[string]any{"\xff": true} },
		func(r *external.Request) {
			r.Attributes = map[string]any{}
			for i := range 17 {
				r.Attributes[strings.Repeat("a", i+1)] = true
			}
		},
		func(r *external.Request) {
			r.Attributes = map[string]any{}
			for i := range 16 {
				r.Attributes[strings.Repeat("a", i+1)] = strings.Repeat("a", 4096)
			}
		},
	} {
		req := good
		change(&req)
		if _, err := req.Snapshot(); err == nil {
			t.Fatal("invalid or oversized request accepted")
		}
	}
}
