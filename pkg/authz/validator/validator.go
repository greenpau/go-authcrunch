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

package validator

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz/cache"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

type guardian interface {
	authorize(context.Context, *http.Request, *user.User) error
}

type guardianBase struct {
	accessList *acl.AccessList
}

type guardianWithSrcAddr struct {
	accessList *acl.AccessList
}

type guardianWithPathClaim struct {
	accessList *acl.AccessList
}

type guardianWithMethodPath struct {
	accessList *acl.AccessList
}

type guardianWithSrcAddrPathClaim struct {
	accessList *acl.AccessList
}

type guardianWithMethodPathSrcAddr struct {
	accessList *acl.AccessList
}

type guardianWithMethodPathPathClaim struct {
	accessList *acl.AccessList
}

type guardianWithMethodPathSrcAddrPathClaim struct {
	accessList *acl.AccessList
}

// TokenValidator validates tokens in http requests.
type TokenValidator struct {
	keystore            *kms.CryptoKeyStore
	authHeaders         map[string]interface{}
	authCookies         map[string]interface{}
	authQueryParams     map[string]interface{}
	cache               *cache.TokenCache
	accessList          *acl.AccessList
	guardian            guardian
	tokenSources        []string
	opts                *options.TokenValidatorOptions
	authProxyConfig     *authproxy.Config
	apiKeyHeaderName    string
	authRealmHeaderName string
	logger              *zap.Logger
}

// NewTokenValidator returns an instance of TokenValidator
func NewTokenValidator(keystoreConfig *kms.CryptoKeyStoreConfig, logger *zap.Logger) (*TokenValidator, error) {

	ks, err := kms.NewCryptoKeyStore(keystoreConfig, logger)
	if err != nil {
		return nil, err
	}

	v := &TokenValidator{
		keystore:        ks,
		authHeaders:     make(map[string]interface{}),
		authCookies:     make(map[string]interface{}),
		authQueryParams: make(map[string]interface{}),
		logger:          logger,
	}

	v.cache = cache.NewTokenCache(0)
	v.tokenSources = defaultTokenSources
	return v, nil
}

// GetAuthCookies returns auth cookies registered with TokenValidator.
func (v *TokenValidator) GetAuthCookies() map[string]interface{} {
	return v.authCookies
}

// GetAuthProxyConfig returns auth proxy config.
func (v *TokenValidator) GetAuthProxyConfig() *authproxy.Config {
	return v.authProxyConfig
}

// SetSourcePriority sets the order in which various token sources are being
// evaluated for the presence of keys. The default order is cookie, header,
// and query parameters.
func (v *TokenValidator) SetSourcePriority(arr []string) error {
	if len(arr) == 0 || len(arr) > 3 {
		return errors.ErrInvalidSourcePriority
	}
	m := make(map[string]bool)
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s != tokenSourceHeader && s != tokenSourceCookie && s != tokenSourceQuery {
			return errors.ErrInvalidSourceName.WithArgs(s)
		}
		if _, exists := m[s]; exists {
			return errors.ErrDuplicateSourceName.WithArgs(s)
		}
		m[s] = true
	}
	v.tokenSources = arr
	return nil
}

// GetSourcePriority returns the allowed token sources in their priority order.
func (v *TokenValidator) GetSourcePriority() []string {
	return v.tokenSources
}

func (g *guardianBase) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	// Note: the cache was removed because authorize uses the same
	// authorization endpoint. Previously, the endpoint was
	// attached to a route.
	// if usr.Cached {
	//	return nil
	// }
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	return nil
}

func (g *guardianWithSrcAddr) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := addrutil.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}
	return nil
}

func (g *guardianWithPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

func (g *guardianWithSrcAddrPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	if userAllowed := g.accessList.Allow(ctx, usr.GetData()); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := addrutil.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}
	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

func (g *guardianWithMethodPath) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	return nil
}

func (g *guardianWithMethodPathSrcAddr) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := addrutil.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}
	return nil
}

func (g *guardianWithMethodPathPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

func (g *guardianWithMethodPathSrcAddrPathClaim) authorize(ctx context.Context, r *http.Request, usr *user.User) error {
	kv := make(map[string]interface{})
	for k, v := range usr.GetData() {
		kv[k] = v
	}
	kv["method"] = r.Method
	kv["path"] = r.URL.Path
	if userAllowed := g.accessList.Allow(ctx, kv); !userAllowed {
		return errors.ErrAccessNotAllowed
	}
	if usr.Claims.Address == "" {
		return errors.ErrSourceAddressNotFound
	}
	reqAddr := addrutil.GetSourceAddress(r)
	if usr.Claims.Address != reqAddr {
		return errors.ErrSourceAddressMismatch.WithArgs(usr.Claims.Address, reqAddr)
	}

	if usr.Claims.AccessList == nil {
		return errors.ErrAccessNotAllowedByPathACL
	}
	for path := range usr.Claims.AccessList.Paths {
		if acl.MatchPathBasedACL(path, r.URL.Path) {
			return nil
		}
	}
	return errors.ErrAccessNotAllowedByPathACL
}

// SetAPIKeyHeaderName sets API key auth header name.
func (v *TokenValidator) SetAPIKeyHeaderName(s string) {
	v.apiKeyHeaderName = s
}

// SetAuthRealmHeaderName sets authentication realm header name.
func (v *TokenValidator) SetAuthRealmHeaderName(s string) {
	v.authRealmHeaderName = s
}

// Configure adds access list and keys for the verification of tokens.
func (v *TokenValidator) Configure(ctx context.Context, accessList *acl.AccessList, opts *options.TokenValidatorOptions) error {
	keys := []*kms.CryptoKey{}
	for _, k := range v.keystore.GetKeys() {
		if !k.Verify.Token.Capable {
			continue
		}
		if k.Verify.Token.Name == "" {
			continue
		}
		if k.Verify.Token.MaxLifetime == 0 {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return errors.ErrValidatorCryptoKeyStoreNoVerifyKeys
	}

	if err := v.addAccessList(ctx, accessList); err != nil {
		return err
	}
	if opts == nil {
		return errors.ErrTokenValidatorOptionsNotFound
	}

	v.opts = opts

	v.clearAuthSources()

	for _, cookieName := range opts.AuthorizationCookieNames {
		v.authCookies[cookieName] = true
		for _, k := range keys {
			k.Verify.Token.CookieNames[cookieName] = true
		}
	}
	for _, headerName := range opts.AuthorizationHeaderNames {
		v.authHeaders[headerName] = true
		for _, k := range keys {
			k.Verify.Token.HeaderNames[headerName] = true
			if v.opts.ValidateBearerHeader {
				k.Verify.Token.HeaderNames[tokenSourceBearerHeader] = true
			}
		}
	}
	for _, queryParamName := range opts.AuthorizationQueryParamNames {
		v.authQueryParams[queryParamName] = true
		for _, k := range keys {
			k.Verify.Token.QueryParamNames[queryParamName] = true
		}
	}

	switch {
	case opts.ValidateMethodPath && opts.ValidateSourceAddress && opts.ValidateAccessListPathClaim:
		g := &guardianWithMethodPathSrcAddrPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateMethodPath && opts.ValidateAccessListPathClaim:
		g := &guardianWithMethodPathPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateMethodPath && opts.ValidateSourceAddress:
		g := &guardianWithMethodPathSrcAddr{accessList: accessList}
		v.guardian = g
	case opts.ValidateSourceAddress && opts.ValidateAccessListPathClaim:
		g := &guardianWithSrcAddrPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateAccessListPathClaim:
		g := &guardianWithPathClaim{accessList: accessList}
		v.guardian = g
	case opts.ValidateMethodPath:
		g := &guardianWithMethodPath{accessList: accessList}
		v.guardian = g
	case opts.ValidateSourceAddress:
		g := &guardianWithSrcAddr{accessList: accessList}
		v.guardian = g
	default:
		g := &guardianBase{accessList: accessList}
		v.guardian = g
	}
	return nil
}

func (v *TokenValidator) addAccessList(_ context.Context, accessList *acl.AccessList) error {
	if accessList == nil {
		return errors.ErrNoAccessList
	}
	if len(accessList.GetRules()) == 0 {
		return errors.ErrAccessListNoRules
	}

	v.accessList = accessList
	return nil
}

// CacheUser adds a user to token validator cache.
func (v *TokenValidator) CacheUser(usr *user.User) error {
	return v.cache.Add(usr)
}

// RegisterAuthProxy registers authproxy.Authenticator  with TokenValidator.
func (v *TokenValidator) RegisterAuthProxy(cfg *authproxy.Config, authenticators []authproxy.Authenticator) error {
	if cfg == nil {
		return errors.ErrValidatorAuthProxyConfigNil
	}

	v.authProxyConfig = cfg

	for _, authenticator := range authenticators {
		if !cfg.HasPortal(authenticator.GetName()) {
			continue
		}
		if err := v.authProxyConfig.AddAuthenticator(authenticator.GetName(), authenticator); err != nil {
			return err
		}
		v.logger.Debug("associated portal with auth proxy config",
			zap.String("portal_name", authenticator.GetName()),
			zap.Any("auth_proxy_config", v.GetAuthProxyConfig()),
		)
	}
	return nil
}

// RegisterRemoteAuthProxies registers remote authproxy.Authenticator instances with TokenValidator.
func (v *TokenValidator) RegisterRemoteAuthProxies(cfg *authproxy.Config) ([]authproxy.Authenticator, error) {
	authenticators := []authproxy.Authenticator{}

	if cfg == nil {
		return authenticators, nil
	}

	v.authProxyConfig = cfg

	for realmName, realmCfg := range cfg.Realms {
		if realmCfg.HasAuthenticator() {
			continue
		}
		if realmCfg.PortalName != "" {
			continue
		}

		// for _, keystore.Get
		var cryptoKey *kms.CryptoKey
		for _, key := range v.keystore.GetKeys() {
			ki := key.GetKeyInfo()
			if ki.Usage == "system" {
				cryptoKey = key
				break
			}
		}

		if cryptoKey == nil {
			return nil, fmt.Errorf("failed to find system crypto key for remote authenticator for %q realm", realmName)
		}

		remoteAuthenticator, err := authproxy.NewRemoteAuthenticator(realmName, cryptoKey, realmCfg, v.logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create remote authenticator for %q realm: %v", realmName, err)
		}
		realmCfg.AddAuthenticator(remoteAuthenticator)
		authenticators = append(authenticators, remoteAuthenticator)
	}

	return authenticators, nil
}
