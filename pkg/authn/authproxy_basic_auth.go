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
	"encoding/base64"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// BasicAuth performs password authentication subject to the effective policy.
func (p *Portal) BasicAuth(r *authproxy.Request) error {
	if p.closed.Load() {
		return errors.ErrBasicAuthFailed
	}
	if r.Realm == "" {
		return errors.ErrBasicAuthFailedRealmNotSet
	}

	rr := requests.NewRequest()
	rr.Logger = p.logger
	rr.Response.Authenticated = false
	rr.Upstream.Realm = r.Realm

	arr, err := base64.StdEncoding.DecodeString(r.Secret)
	if err != nil {
		p.logger.Warn(
			"failed to decode credentials",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailedDecodeSecret
	}

	creds := strings.SplitN(string(arr), ":", 2)
	if len(creds) != 2 || strings.TrimSpace(creds[0]) == "" || creds[1] == "" {
		p.logger.Warn(
			"failed to parse credentials",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.String("error", "username or password is missing"),
		)
		return errors.ErrBasicAuthFailedDecodeSecret
	}
	rr.User.Username = creds[0]
	rr.User.Password = creds[1]

	backend := p.getIdentityStoreByRealm(r.Realm)
	if backend == nil {
		p.logger.Warn(
			"realm backend not found",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
		)
		return errors.ErrBasicAuthFailedBackendNotFound
	}

	/*
		if err := backend.Request(operator.LookupBasic, rr); err != nil {
			p.logger.Warn(
				"api key lookup failed",
				zap.String("source_address", r.Address),
				zap.String("custom_auth", "basicauth"),
				zap.String("realm", r.Realm),
				zap.Error(err),
			)
			return errors.ErrBasicAuthFailed
		}
	*/

	if err := backend.Request(operator.IdentifyUser, rr); err != nil {
		p.logger.Warn(
			"user lookup failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailed
	}

	if err := p.authenticatePassword(r.Address, func() error {
		return backend.Request(operator.Authenticate, rr)
	}); err != nil {
		p.logger.Warn(
			"user authentication failed",
			zap.String("source_address", r.Address),
			zap.String("custom_auth", "basicauth"),
			zap.String("realm", r.Realm),
			zap.Error(err),
		)
		return errors.ErrBasicAuthFailed
	}

	usr, err := p.issueDirectAuthenticationToken(context.Background(), rr, "authp", r.Address, []string{"password"})
	if err != nil {
		p.logger.Warn("direct authentication token issuance failed", zap.String("realm", r.Realm), zap.Error(err))
		return errors.ErrBasicAuthFailed
	}

	r.Response.Payload = usr.Token
	r.Response.Name = usr.TokenName
	return nil
}
