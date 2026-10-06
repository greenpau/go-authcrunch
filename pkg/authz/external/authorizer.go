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
	"net/http"
	"slices"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/internal/uri"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// Authorizer enforces required decisions without caching or mutating identities.
// Configuration is immutable; the host owns backend shutdown and replacement.
type Authorizer struct {
	config  Config
	backend Backend
	timeout time.Duration
}

// New snapshots validated configuration. The backend must honor cancellation;
// an uncooperative in-process backend cannot be forcibly interrupted.
func New(config *Config, backend Backend) (*Authorizer, error) {
	if config == nil || backend == nil {
		return nil, ErrUnavailable
	}
	c := *config
	c.Attributes = slices.Clone(c.Attributes)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	timeout, _ := time.ParseDuration(c.Timeout)
	return &Authorizer{config: c, backend: backend, timeout: timeout}, nil
}

// Authorize requires an already authenticated identity whose local constraints
// and ACLs passed. It does not authenticate caller-supplied claims. Selected
// attributes come from the original authenticated identity, before enrichment.
// A nonzero credential expiration bounds all calls; callers own expiration for
// identities managed outside JWTs that have no exp. Queries are not policy input.
func (a *Authorizer) Authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if a == nil || a.backend == nil || ctx == nil || usr == nil || usr.Claims == nil {
		return ErrUnavailable
	}
	paths, valid := uri.RequestPaths(r)
	if !valid {
		return ErrDenied
	}
	deadline := time.Now().Add(a.timeout)
	if exp := usr.Claims.ExpiresAt; exp != 0 && time.Unix(exp, 0).Before(deadline) {
		deadline = time.Unix(exp, 0)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	deadline, _ = ctx.Deadline()
	if err := ctx.Err(); err != nil {
		return err
	}
	claims := usr.AsMap()
	subject, _ := claims[a.config.SubjectClaim].(string)
	id := Identity{Issuer: usr.Claims.Issuer, Realm: usr.Claims.Origin, Subject: subject}
	if a.config.TenantClaim != "" {
		tenant, ok := claims[a.config.TenantClaim].(string)
		if !ok || !validText(tenant, 1024) {
			return ErrDenied
		}
		id.Tenant = tenant
	}
	if id.Issuer != a.config.Issuer || id.Realm != a.config.Realm {
		return ErrDenied
	}
	base := Request{Policy: a.config.Policy, Version: a.config.Version, Identity: id, Action: r.Method, Attributes: make(map[string]any)}
	for _, name := range a.config.Attributes {
		if value, present := claims[name]; present {
			base.Attributes[name] = value
		}
	}
	for _, path := range paths {
		base.Resource = path
		req, err := base.Snapshot()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := a.backend.Decide(ctx, req)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		if err != nil || result.Validate(req) != nil {
			return ErrUnavailable
		}
		if result.Decision == "deny" {
			return ErrDenied
		}
	}
	return nil
}
