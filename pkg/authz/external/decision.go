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

package external

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
)

// ErrDenied means the identity/request binding or a backend decision denied access.
var ErrDenied = errors.New("external authorization denied")

// ErrUnavailable means no valid decision could be obtained. It never grants access.
var ErrUnavailable = errors.New("external authorization unavailable")

// Identity binds an authenticated subject to its issuer, realm and optional tenant.
type Identity struct {
	Issuer  string `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Realm   string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Subject string `json:"subject,omitempty" xml:"subject,omitempty" yaml:"subject,omitempty"`
	Tenant  string `json:"tenant,omitempty" xml:"tenant,omitempty" yaml:"tenant,omitempty"`
}

// Request describes one interpretation of a protected request. Resource is a
// path, without host, query, fragment, headers or body. Action is the HTTP method.
// Each path interpretation requires its own allow under the same total deadline.
type Request struct {
	Policy     string         `json:"policy,omitempty" xml:"policy,omitempty" yaml:"policy,omitempty"`
	Version    string         `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
	Identity   Identity       `json:"identity" xml:"identity" yaml:"identity"`
	Action     string         `json:"action,omitempty" xml:"action,omitempty" yaml:"action,omitempty"`
	Resource   string         `json:"resource,omitempty" xml:"resource,omitempty" yaml:"resource,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty" xml:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Snapshot validates and copies a bounded JSON request. Callers must not mutate
// input during this operation. Custom marshalers and non-JSON Go types fail.
func (r Request) Snapshot() (Request, error) {
	invalid := func() (Request, error) { return Request{}, ErrUnavailable }
	for _, s := range []string{r.Policy, r.Version, r.Identity.Issuer, r.Identity.Realm, r.Identity.Subject} {
		if !validText(s, 1024) {
			return invalid()
		}
	}
	if r.Identity.Tenant != "" && !validText(r.Identity.Tenant, 1024) {
		return invalid()
	}
	if !validText(r.Action, 64) || strings.ContainsFunc(r.Action, func(c rune) bool {
		return !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c))
	}) || len(r.Resource) > 4096 || !utf8.ValidString(r.Resource) || strings.ContainsFunc(r.Resource, unicode.IsControl) || !strings.HasPrefix(r.Resource, "/") || len(r.Attributes) > 16 {
		return invalid()
	}
	attrs := make(map[string]any, len(r.Attributes))
	for name, value := range r.Attributes {
		if !validText(name, 1024) {
			return invalid()
		}
		copied, err := enrichment.CopyAttribute(value, "json")
		if err != nil {
			return invalid()
		}
		attrs[name] = copied
	}
	r.Attributes = attrs
	data, err := json.Marshal(r)
	if err != nil || len(data) > 64<<10 {
		return invalid()
	}
	return r, nil
}

// Result is an explicit allow or deny bound to the selected policy version.
// Additional obligations, mutations and cached decisions are not supported.
type Result struct {
	Decision string `json:"decision,omitempty" xml:"decision,omitempty" yaml:"decision,omitempty"`
	Policy   string `json:"policy,omitempty" xml:"policy,omitempty" yaml:"policy,omitempty"`
	Version  string `json:"version,omitempty" xml:"version,omitempty" yaml:"version,omitempty"`
}

// Validate checks the exact request binding and rejects absent/unknown decisions.
func (r *Result) Validate(request Request) error {
	if r == nil || r.Policy != request.Policy || r.Version != request.Version || (r.Decision != "allow" && r.Decision != "deny") {
		return ErrUnavailable
	}
	return nil
}

// Backend evaluates authenticated requests concurrently and honors context
// deadlines. It owns transport details; the embedding host owns its lifetime.
type Backend interface {
	Decide(context.Context, Request) (*Result, error)
}
