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

package enrichment

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/user"
)

// Identity identifies an immutable account within its complete trust domain.
type Identity struct {
	Issuer  string `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Realm   string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Subject string `json:"subject,omitempty" xml:"subject,omitempty" yaml:"subject,omitempty"`
	Tenant  string `json:"tenant,omitempty" xml:"tenant,omitempty" yaml:"tenant,omitempty"`
}

// Validate rejects incomplete identities without disclosing their values.
func (i Identity) Validate() error {
	for _, value := range []string{i.Issuer, i.Realm, i.Subject, i.Tenant} {
		if !validText(value, 1024) {
			return fmt.Errorf("claims enrichment identity is invalid")
		}
	}
	return nil
}

// Request contains only verified identity bindings and server-selected intent.
type Request struct {
	Identity   Identity `json:"identity" xml:"identity" yaml:"identity"`
	Audience   string   `json:"audience,omitempty" xml:"audience,omitempty" yaml:"audience,omitempty"`
	Purpose    string   `json:"purpose,omitempty" xml:"purpose,omitempty" yaml:"purpose,omitempty"`
	Attributes []string `json:"attributes,omitempty" xml:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Result is a complete snapshot of the requested attributes. Absent attributes
// remove earlier values; null is allowed only for explicitly JSON-typed claims.
type Result struct {
	Identity   Identity       `json:"identity" xml:"identity" yaml:"identity"`
	Audience   string         `json:"audience,omitempty" xml:"audience,omitempty" yaml:"audience,omitempty"`
	Purpose    string         `json:"purpose,omitempty" xml:"purpose,omitempty" yaml:"purpose,omitempty"`
	Source     string         `json:"source,omitempty" xml:"source,omitempty" yaml:"source,omitempty"`
	Version    string         `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
	ObservedAt time.Time      `json:"observed_at" xml:"observed_at" yaml:"observed_at"`
	ExpiresAt  time.Time      `json:"expires_at" xml:"expires_at" yaml:"expires_at"`
	Attributes map[string]any `json:"attributes,omitempty" xml:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Backend retrieves attributes and must honor cancellation, return independent
// snapshots, and support concurrent lookups. The injecting host owns its lifetime.
type Backend interface {
	Lookup(context.Context, Request) (*Result, error)
}

// Enricher validates backend responses and builds detached ACL-only identities.
// It owns no goroutines, caches, or backend resources and is safe for concurrent use.
type Enricher struct {
	config  Config
	backend Backend
	timeout time.Duration
	maxAge  time.Duration
}

// New constructs an enricher from an independent validated config snapshot.
func New(config *Config, backend Backend) (*Enricher, error) {
	if config == nil || backend == nil {
		return nil, fmt.Errorf("claims enrichment config and backend are required")
	}
	c := *config
	c.Attributes = slices.Clone(config.Attributes)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	timeout, _ := time.ParseDuration(c.Timeout)
	maxAge, _ := time.ParseDuration(c.MaxAge)
	return &Enricher{config: c, backend: backend, timeout: timeout, maxAge: maxAge}, nil
}

// Enrich uses an already authenticated user. Only the returned user's claim map
// has enrichment data; token, roles, authentication evidence and caller state
// remain unchanged. Use the result for this authorization decision only.
// Backends are synchronous and must honor the supplied deadline; an uncooperative
// in-process implementation cannot be forcibly canceled by this library.
// A nonzero authenticated expiration also bounds the lookup. Identities whose
// lifetime is managed externally may omit exp; the caller still owns that check.
func (e *Enricher) Enrich(ctx context.Context, usr *user.User) (*user.User, error) {
	if e == nil || usr == nil || usr.Claims == nil || ctx == nil {
		return nil, fmt.Errorf("claims enrichment requires an authenticated identity and context")
	}
	deadline := time.Now().Add(e.timeout)
	if exp := usr.Claims.ExpiresAt; exp != 0 {
		if expires := time.Unix(exp, 0); expires.Before(deadline) {
			deadline = expires
		}
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// WithDeadline preserves an earlier deadline on the caller's context.
	deadline, _ = ctx.Deadline()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	claims := usr.AsMap()
	subject, _ := claims[e.config.SubjectClaim].(string)
	tenant, _ := claims[e.config.TenantClaim].(string)
	id := Identity{Issuer: usr.Claims.Issuer, Realm: usr.Claims.Origin, Subject: subject, Tenant: tenant}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if id.Issuer != e.config.Issuer || id.Realm != e.config.Realm || !slices.Contains(usr.Claims.Audience, e.config.Audience) {
		return nil, fmt.Errorf("claims enrichment identity binding mismatch")
	}
	names := make([]string, 0, len(e.config.Attributes))
	for _, a := range e.config.Attributes {
		// Plain custom claims are additive. Refuse collisions with any claim from
		// authentication, including provider-specific claims unknown to this package.
		if _, exists := claims[a.Name]; exists && !strings.HasPrefix(a.Name, Namespace) {
			return nil, fmt.Errorf("claims enrichment attribute collides with authenticated claims")
		}
		names = append(names, a.Name)
	}
	req := Request{Identity: id, Audience: e.config.Audience, Purpose: "authorization", Attributes: names}
	result, err := e.backend.Lookup(ctx, req)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, fmt.Errorf("claims enrichment lookup failed")
	}
	if result == nil || result.Identity != id || result.Audience != e.config.Audience || result.Purpose != "authorization" || result.Source != e.config.Source || result.Version != e.config.Version {
		return nil, fmt.Errorf("claims enrichment response binding mismatch")
	}
	now := time.Now()
	if result.ObservedAt.IsZero() || result.ObservedAt.After(now) || now.Sub(result.ObservedAt) > e.maxAge || !result.ExpiresAt.After(now) || !result.ExpiresAt.After(result.ObservedAt) || result.ExpiresAt.Sub(result.ObservedAt) > e.maxAge {
		return nil, fmt.Errorf("claims enrichment response is stale or has invalid validity")
	}
	if len(result.Attributes) > len(e.config.Attributes) {
		return nil, fmt.Errorf("claims enrichment returned undeclared attributes")
	}
	types := make(map[string]string, len(e.config.Attributes))
	for _, a := range e.config.Attributes {
		types[a.Name] = a.Type
	}
	values := make(map[string]any, len(result.Attributes))
	for name, value := range result.Attributes {
		kind, ok := types[name]
		if !ok {
			return nil, fmt.Errorf("claims enrichment returned undeclared attributes")
		}
		copied, err := CopyAttribute(value, kind)
		if err != nil {
			return nil, err
		}
		values[name] = copied
	}
	out := usr.Clone()
	// The selected source exclusively owns this namespace. Signed, cached and
	// unrequested values must never survive a missing/removal response.
	for key := range out.AsMap() {
		if strings.HasPrefix(key, Namespace) {
			delete(out.AsMap(), key)
		}
	}
	maps.Copy(out.AsMap(), values)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Timer delivery may lag CPU-bound copying. Do not let that scheduling delay
	// extend the caller's deadline or the authenticated credential's validity.
	if !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	return out, nil
}

// CopyAttribute validates and snapshots a string, string list, or JSON value. Values are
// literal data, never templates. Lists contain at most 128 elements and strings
// at most 4096 UTF-8 bytes. JSON values additionally support null, booleans, numbers,
// arrays and objects, bounded to 16 container levels, 4096 nodes and 64 KiB of
// encoded JSON per attribute. JSON strings preserve whitespace and escapes.
func CopyAttribute(value any, kind string) (any, error) {
	if kind == "json" {
		return copyJSON(value)
	}
	invalid := func() (any, error) { return nil, fmt.Errorf("claims enrichment attribute has invalid type or size") }
	valid := func(s string) bool { return s == "" || (len(s) <= 4096 && validText(s, 4096)) }
	if kind == "string" {
		v, ok := value.(string)
		if !ok || !valid(v) {
			return invalid()
		}
		return v, nil
	}
	if kind != "string_list" {
		return invalid()
	}
	var values []string
	switch v := value.(type) {
	case []string:
		if v == nil || len(v) > 128 {
			return invalid()
		}
		values = slices.Clone(v)
	case []any:
		if v == nil || len(v) > 128 {
			return invalid()
		}
		values = make([]string, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return invalid()
			}
			values[i] = s
		}
	default:
		return invalid()
	}
	for _, s := range values {
		if !valid(s) {
			return invalid()
		}
	}
	return values, nil
}
