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

package static_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static"
)

func lookupRequest() enrichment.Request {
	return enrichment.Request{
		Identity: enrichment.Identity{Issuer: "issuer", Realm: "staff", Subject: "account-id", Tenant: "north"},
		Audience: "api", Purpose: "authorization", Attributes: []string{"foo"},
	}
}

func TestStaticClaims(t *testing.T) {
	config := &static.Config{Claims: map[string]any{"foo": "bar", "message": "hello, world", "empty": "", "literal": "${roles}"}}
	backend, err := static.New(config)
	if err != nil {
		t.Fatal(err)
	}
	config.Claims["foo"] = "changed"
	delete(config.Claims, "message")
	before := time.Now()
	result, err := backend.Lookup(t.Context(), lookupRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Attributes, map[string]any{"foo": "bar"}) {
		t.Fatal("lookup did not return the selected static claim")
	}
	if result.Identity != lookupRequest().Identity || result.Audience != "api" || result.Purpose != "authorization" || result.Source != static.Source || result.Version != static.Version || result.ObservedAt.Before(before) || result.ExpiresAt.Sub(result.ObservedAt) != time.Minute {
		t.Fatal("response metadata was not bound to the request")
	}
	result.Attributes["foo"] = "mutated"
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			request := lookupRequest()
			// The same configured data applies to every consumer-accepted identity.
			request.Identity.Subject = "another-account"
			request.Attributes = []string{"foo", "message", "empty", "literal"}
			got, err := backend.Lookup(t.Context(), request)
			if err != nil || !reflect.DeepEqual(got.Attributes, map[string]any{"foo": "bar", "message": "hello, world", "empty": "", "literal": "${roles}"}) {
				t.Error("configuration or lookup results share mutable state")
				return
			}
			got.Attributes["foo"] = "concurrent mutation"
		})
	}
	wg.Wait()
}

func TestStaticValidation(t *testing.T) {
	for _, claims := range []map[string]any{
		nil, {}, {"roles": "admin"}, {"github_id": "123"}, {" bad": "value"}, {"": "bar"}, {"foo": make(chan int)}, {"foo": strings.Repeat("x", 4097)}, {"foo": "\xff"},
	} {
		backend, err := static.New(&static.Config{Claims: claims})
		if err == nil || backend != nil || strings.Contains(err.Error(), "canary") {
			t.Fatal("invalid config accepted or disclosed")
		}
	}
	claims := make(map[string]any)
	for i := range 32 {
		claims[fmt.Sprintf("field_%d", i)] = "value"
	}
	if _, err := static.New(&static.Config{Claims: claims}); err != nil {
		t.Fatal("claim limit should be inclusive")
	}
	claims["extra"] = "value"
	if _, err := static.New(&static.Config{Claims: claims}); err == nil {
		t.Fatal("claim limit not enforced")
	}
	if _, err := static.New(nil); err == nil {
		t.Fatal("nil config accepted")
	}
}

func TestStaticInvalidRequests(t *testing.T) {
	backend, err := static.New(&static.Config{Claims: map[string]any{"foo": "bar", "other": "value"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		modify func(*enrichment.Request)
	}{
		{"identity", func(r *enrichment.Request) { r.Identity.Subject = "" }},
		{"audience", func(r *enrichment.Request) { r.Audience = "" }},
		{"purpose", func(r *enrichment.Request) { r.Purpose = "login" }},
		{"empty selection", func(r *enrichment.Request) { r.Attributes = nil }},
		{"undeclared", func(r *enrichment.Request) { r.Attributes = []string{"missing"} }},
		{"duplicate", func(r *enrichment.Request) { r.Attributes = []string{"foo", "foo"} }},
		{"oversized selection", func(r *enrichment.Request) { r.Attributes = []string{"foo", "other", "third"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := lookupRequest()
			tc.modify(&req)
			if result, err := backend.Lookup(t.Context(), req); result != nil || err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := backend.Lookup(ctx, lookupRequest()); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if result, err := backend.Lookup(ctx, lookupRequest()); result != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline ignored")
	}

	for _, unconstructed := range []*static.Backend{nil, {}} {
		if _, err := unconstructed.Lookup(t.Context(), lookupRequest()); err == nil {
			t.Fatal("unconstructed backend accepted")
		}
	}
}

func TestStaticJSONSnapshots(t *testing.T) {
	object := map[string]any{
		"flag": true, "count": 7, "ratio": 0.5, "nothing": nil,
		"items":   []any{"string", false, map[string]any{"nested": []string{"read"}}},
		"message": " whitespace\n", "custom.key": "literal",
	}
	backend, err := static.New(&static.Config{Claims: map[string]any{"foo": object}})
	if err != nil {
		t.Fatal(err)
	}
	object["flag"] = false
	object["items"].([]any)[2].(map[string]any)["nested"].([]string)[0] = "changed"
	for range 2 {
		result, err := backend.Lookup(t.Context(), lookupRequest())
		if err != nil {
			t.Fatal(err)
		}
		got := result.Attributes["foo"].(map[string]any)
		if got["flag"] != true || got["count"] != 7 || got["ratio"] != 0.5 || got["nothing"] != nil || got["items"].([]any)[2].(map[string]any)["nested"].([]string)[0] != "read" {
			t.Fatal("nested claim data was altered or shared")
		}
		got["items"].([]any)[2].(map[string]any)["nested"].([]string)[0] = "returned mutation"
	}
	// Test nil as part of invalid context inputs, without substituting a live
	// context and losing coverage of the public API's nil guard.
	var missingContext context.Context
	if _, err := backend.Lookup(missingContext, lookupRequest()); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestClaimsAttachmentRejectsMissingRuntime(t *testing.T) {
	for name, attach := range map[string]func(*enrichment.Enricher) error{
		"nil gatekeeper":           (*authz.Gatekeeper)(nil).SetClaimsEnricher,
		"unconstructed gatekeeper": new(authz.Gatekeeper).SetClaimsEnricher,
		"nil validator":            (*validator.TokenValidator)(nil).SetClaimsEnricher,
	} {
		t.Run(name, func(t *testing.T) {
			for _, enricher := range []*enrichment.Enricher{nil, new(enrichment.Enricher)} {
				if err := attach(enricher); err == nil {
					t.Fatal("missing runtime accepted attachment")
				}
			}
		})
	}
}
