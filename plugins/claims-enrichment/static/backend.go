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

package static

import (
	"context"
	"fmt"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
)

// Backend supplies immutable configured claims and supports concurrent lookups.
// It owns no resources or workers and requires no cleanup. Construct a new
// backend to change configuration; the host owns attachment and request draining.
type Backend struct {
	claims map[string]any
}

var _ enrichment.Backend = (*Backend)(nil)

// New validates and copies configuration without retaining caller-owned maps.
func New(config *Config) (*Backend, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	claims := make(map[string]any, len(config.Claims))
	for name, value := range config.Claims {
		copied, err := enrichment.CopyAttribute(value, "json")
		if err != nil {
			return nil, err
		}
		claims[name] = copied
	}
	return &Backend{claims: claims}, nil
}

// Lookup returns independent snapshots of the requested configured claims.
// The consumer authenticates and pins identity and audience before calling this
// method. Static claims are observed on each lookup and valid for one minute;
// configure the consumer's MaxAge to at least one minute.
func (b *Backend) Lookup(ctx context.Context, req enrichment.Request) (*enrichment.Result, error) {
	if b == nil || len(b.claims) == 0 || ctx == nil {
		return nil, fmt.Errorf("static claims backend and context are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := req.Identity.Validate(); err != nil {
		return nil, err
	}
	if req.Audience == "" || req.Purpose != "authorization" {
		return nil, fmt.Errorf("static claims request binding is invalid")
	}
	if len(req.Attributes) == 0 || len(req.Attributes) > len(b.claims) {
		return nil, fmt.Errorf("static claims requested attributes are invalid")
	}
	values := make(map[string]any, len(req.Attributes))
	for _, name := range req.Attributes {
		value, exists := b.claims[name]
		if _, duplicate := values[name]; !exists || duplicate {
			return nil, fmt.Errorf("static claims requested attributes are invalid")
		}
		copied, err := enrichment.CopyAttribute(value, "json")
		if err != nil {
			return nil, err
		}
		values[name] = copied
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	return &enrichment.Result{
		Identity: req.Identity, Audience: req.Audience, Purpose: req.Purpose,
		Source: Source, Version: Version, ObservedAt: now, ExpiresAt: now.Add(time.Minute),
		Attributes: values,
	}, nil
}
