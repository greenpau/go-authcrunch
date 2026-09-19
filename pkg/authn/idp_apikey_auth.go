// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package authn

import (
	"context"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// APIKeyAuth performs API key authentication.
func (p *Portal) APIKeyAuth(r *authproxy.Request) error {
	return p.apiKeyAuth(context.Background(), r, "authp")
}

// apiKeyAuth preserves the caller's policy context. HTTP login supplies its
// current issuer URL and cancellation; the public proxy API has no HTTP request.
func (p *Portal) apiKeyAuth(ctx context.Context, r *authproxy.Request, issuer string) error {
	if r.Realm == "" {
		return errors.ErrAPIKeyAuthFailedRealmNotSet
	}

	rr := requests.NewRequest()
	rr.Logger = p.logger
	rr.Response.Authenticated = false
	rr.Key.Payload = r.Secret
	rr.Upstream.Realm = r.Realm

	backend := p.getIdentityStoreByRealm(r.Realm)
	if backend == nil {
		p.logger.Warn(
			"realm backend not found",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "apikey"),
			zap.String("realm", r.Realm),
		)
		return errors.ErrAPIKeyAuthFailed
	}

	if err := backend.Request(operator.LookupAPIKey, rr); err != nil {
		p.logger.Warn(
			"api key lookup failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "apikey"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrAPIKeyAuthFailed
	}

	proof := rr.Authentication
	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		p.logger.Warn(
			"user lookup following api key lookup failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "apikey"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrAPIKeyAuthFailed
	}

	// Retain credential verification evidence; IdentifyUser only binds a lookup.
	rr.Authentication = proof

	usr, err := p.issueDirectAuthenticationToken(ctx, rr, issuer, r.Address, nil)
	if err != nil {
		p.logger.Warn("direct authentication token issuance failed", zap.String("realm", r.Realm), zap.Error(err))
		return errors.ErrAPIKeyAuthFailed
	}

	r.Response.Payload = usr.Token
	r.Response.Name = usr.TokenName
	return nil
}
