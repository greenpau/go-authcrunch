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

package authz

import (
	"context"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/kms"

	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Gatekeeper is an auth.
type Gatekeeper struct {
	id             string
	config         *PolicyConfig
	tokenValidator *validator.TokenValidator
	opts           *options.TokenValidatorOptions
	accessList     *acl.AccessList
	authenticators []authproxy.Authenticator
	// Enable authorization bypass for specific URIs.
	bypassEnabled bool
	// The names of the headers injected by an instance.
	injectedHeaders     map[string]bool
	logger              *zap.Logger
	sessionIDCookieName string
}

// NewGatekeeper returns an instance of Gatekeeper.
func NewGatekeeper(cfg *PolicyConfig, logger *zap.Logger) (*Gatekeeper, error) {
	if logger == nil {
		return nil, errors.ErrNewGatekeeperLoggerNil
	}
	if cfg == nil {
		return nil, errors.ErrNewGatekeeperConfigNil
	}
	if err := cfg.Validate(); err != nil {
		return nil, errors.ErrNewGatekeeper.WithArgs(err)
	}
	p := &Gatekeeper{
		id:     uuid.New().String(),
		config: cfg,
		logger: logger,
	}
	if err := p.configure(); err != nil {
		return nil, err
	}
	return p, nil
}

// GetLogger returns logger associated with the gatekeeper.
func (g *Gatekeeper) GetLogger() *zap.Logger {
	return g.logger
}

func (g *Gatekeeper) configure() error {
	ctx := context.Background()

	// Set bypass URLs, if necessary.
	if len(g.config.BypassConfigs) > 0 {
		g.bypassEnabled = true
	}

	// Configure header injection.
	for _, entry := range g.config.HeaderInjectionConfigs {
		if g.injectedHeaders == nil {
			g.injectedHeaders = make(map[string]bool)
		}
		g.injectedHeaders[entry.Header] = true
	}

	// Load token configuration into key managers, extract token verification
	// keys and add them to token validator.

	ks, err := kms.NewCryptoKeyStore(g.config.CryptoKeyStoreConfig, g.logger)
	if err != nil {
		return errors.ErrCryptoKeyStoreConfig.WithArgs(g.config.Name, err)
	}

	if err := ks.HasVerifyKeys(); err != nil {
		return errors.ErrInvalidConfiguration.WithArgs(g.config.Name, err)
	}

	// Initialize token validator and associated options.
	tokenValidator, err := validator.NewTokenValidator(ks.GetConfig(), g.logger)
	if err != nil {
		return errors.ErrInvalidConfiguration.WithArgs(g.config.Name, err)
	}
	g.tokenValidator = tokenValidator

	g.opts = options.NewTokenValidatorOptions()
	if g.config.ValidateMethodPath {
		g.opts.ValidateMethodPath = true
	}
	if g.config.ValidateBearerHeader {
		g.opts.ValidateBearerHeader = true
	}
	if g.config.ValidateAccessListPathClaim {
		g.opts.ValidateAccessListPathClaim = true
	}
	if g.config.ValidateSourceAddress {
		g.opts.ValidateSourceAddress = true
	}

	g.opts.AuthorizationHeaderNames = []string{
		"access_token",
		"jwt_access_token",
	}
	g.opts.AuthorizationQueryParamNames = []string{
		"access_token",
		"jwt_access_token",
	}

	if len(g.config.AccessTokenCookieNames) > 0 {
		g.opts.AuthorizationCookieNames = g.config.AccessTokenCookieNames
		for _, accessTokenCookieName := range g.config.AccessTokenCookieNames {
			g.opts.AuthorizationHeaderNames = append(g.opts.AuthorizationHeaderNames, strings.ToLower(accessTokenCookieName))
			g.opts.AuthorizationQueryParamNames = append(g.opts.AuthorizationQueryParamNames, strings.ToLower(accessTokenCookieName))
		}
	} else {
		g.opts.AuthorizationCookieNames = []string{
			"access_token",
			"jwt_access_token",
		}
	}

	// Load access list.
	if len(g.config.AccessListRules) == 0 {
		return errors.ErrInvalidConfiguration.WithArgs(g.config.Name, "access list rule config not found")
	}
	accessList := acl.NewAccessList()
	accessList.SetLogger(g.logger)
	if err := accessList.AddRules(ctx, g.config.AccessListRules); err != nil {
		return errors.ErrInvalidConfiguration.WithArgs(g.config.Name, err)
	}

	// Configure token validator with keys and access list.
	if err := g.tokenValidator.Configure(ctx, accessList, g.opts); err != nil {
		return errors.ErrInvalidConfiguration.WithArgs(g.config.Name, err)
	}

	// Set allow token sources and their priority.
	if len(g.config.AllowedTokenSources) > 0 {
		if err := g.tokenValidator.SetSourcePriority(g.config.AllowedTokenSources); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(g.config.Name, err)
		}
	}

	// Configure API key auth header name
	g.tokenValidator.SetAPIKeyHeaderName(g.config.APIKeyHeaderName)

	// Configure authentication realm header name
	g.tokenValidator.SetAuthRealmHeaderName(g.config.AuthRealmHeaderName)

	if g.config.SessionIDCookieName != "" {
		g.sessionIDCookieName = g.config.SessionIDCookieName
	} else {
		g.sessionIDCookieName = cookie.DefaultSessionIDCookieName
	}

	g.logger.Debug(
		"Configured gatekeeper",
		zap.String("gatekeeper_name", g.config.Name),
		zap.String("gatekeeper_id", g.id),
		zap.String("auth_url_path", g.config.AuthURLPath),
		zap.String("token_sources", strings.Join(g.tokenValidator.GetSourcePriority(), " ")),
		zap.Any("token_validator_options", g.opts),
		zap.Any("access_list_rules", g.config.AccessListRules),
		zap.String("api_key_auth_header_name", g.config.APIKeyHeaderName),
		zap.String("auth_realm_header_name", g.config.AuthRealmHeaderName),
		zap.String("forbidden_path", g.config.ForbiddenURL),
		zap.String("session_id_cookie_name", g.sessionIDCookieName),
		zap.Any("auth_cookies", g.tokenValidator.GetAuthCookies()),
		zap.Any("crypto_key_store_keys", ks.GetKeysInfo()),
	)
	return nil
}

// AddAuthenticators adds authproxy.Authenticator instances to Gatekeeper.
func (g *Gatekeeper) AddAuthenticators(authenticators []authproxy.Authenticator) error {
	g.authenticators = authenticators
	if g.config.AuthProxyConfig != nil {
		if err := g.tokenValidator.RegisterAuthProxy(g.config.AuthProxyConfig, g.authenticators); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(g.config.Name, err)
		}
	}
	return nil
}
