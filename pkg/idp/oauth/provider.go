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

package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

const (
	providerKind = "oauth"
)

// IdentityProvider represents OAuth-based identity provider.
type IdentityProvider struct {
	setupMu  sync.RWMutex
	ready    atomic.Bool
	config   *Config
	metadata map[string]interface{}
	// Published key sets are immutable; readers never observe partial refreshes.
	keyMu            sync.RWMutex
	keys             oauthJwksSet
	staticKeys       oauthJwksSet
	keyFetchVersion  uint64
	keyFetchMu       sync.Mutex
	keyFetchError    error
	authorizationURL string
	tokenURL         string
	keysURL          string
	logoutURL        string
	// The UserInfo API endpoint URL. Please
	// see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	// for details.
	userInfoURL string
	// The regex filters for user groups extracted via the UserInfo API. If
	// a group matches the filter, the group will be include into user
	// roles issued by the portal.
	userGroupFilters []*regexp.Regexp
	// The regex filters for user orgs extracted from an identity provider.
	userOrgFilters []*regexp.Regexp
	// The name of the server hosting OAuth 2.0 IDP. For example, with public
	// Gitlab the server would be gitlab.com. However, if it is a hosted
	// instance, the name could be gitlab.mydomain.com. It is derived from
	// base url config entry.
	serverName             string
	lastKeyFetch           time.Time
	keyFetchAttempts       int
	disableKeyVerification bool
	disablePassGrantType   bool
	disableResponseType    bool
	disableNonce           bool
	disableScope           bool
	disablePKCE            bool
	enableAcceptHeader     bool
	enableBodyDecoder      bool
	requiredTokenFields    map[string]interface{}
	scopeMap               map[string]interface{}
	userInfoFields         map[string]interface{}
	userInfoRolesFieldName string
	// state stores cached state IDs
	state         *stateManager
	logger        *zap.Logger
	browserConfig *browserConfig
	configured    bool
	stop          chan struct{}
	stateDone     chan struct{}
	stopOnce      sync.Once
	// Disabled the check for the presence of email field in a token.
	disableEmailClaimCheck bool
}

// NewIdentityProvider returns an instance of IdentityProvider.
func NewIdentityProvider(cfg *Config, logger *zap.Logger) (*IdentityProvider, error) {
	if logger == nil {
		return nil, errors.ErrIdentityProviderConfigureLoggerNotFound
	}

	b := &IdentityProvider{
		config:    cfg,
		state:     newStateManager(),
		stop:      make(chan struct{}),
		stateDone: make(chan struct{}),
		logger:    logger,
	}

	if err := b.config.Validate(); err != nil {
		return nil, err
	}

	if jsonCfgData, err := json.Marshal(cfg); err == nil {
		var cfgDataMap map[string]any
		if err := json.Unmarshal(jsonCfgData, &cfgDataMap); err == nil {
			for key := range cfgDataMap {
				if strings.Contains(strings.ToLower(key), "secret") {
					delete(cfgDataMap, key)
				}
			}
			logger.Debug("validated identity provider config", zap.Any("idp_config", cfgDataMap))
		}
	}

	go func() { defer close(b.stateDone); manageStateManager(b.state, b.stop) }()

	return b, nil
}

// Close releases the OAuth state worker. Call after draining provider requests.
// It is safe to call Close repeatedly or concurrently.
func (b *IdentityProvider) Close() {
	if b == nil {
		return
	}
	b.stopOnce.Do(func() {
		if b.stop != nil {
			close(b.stop)
		}
	})
	if b.stateDone != nil {
		<-b.stateDone
	}
}

// GetRealm return authentication realm.
func (b *IdentityProvider) GetRealm() string {
	return b.config.Realm
}

// GetName return the name associated with this identity provider.
func (b *IdentityProvider) GetName() string {
	return b.config.Name
}

// GetKind returns the authentication method associated with this identity provider.
func (b *IdentityProvider) GetKind() string {
	return providerKind
}

// Configured returns true if the identity provider was configured.
func (b *IdentityProvider) Configured() bool {
	return b.configured
}

// GetConfig returns IdentityProvider configuration.
func (b *IdentityProvider) GetConfig() map[string]interface{} {
	b.setupMu.RLock()
	defer b.setupMu.RUnlock()
	var m map[string]interface{}
	j, _ := json.Marshal(b.config)
	json.Unmarshal(j, &m)
	return m
}

// ScopeExists returns true if any of the provided scopes exist.
func (b *IdentityProvider) ScopeExists(scopes ...string) bool {
	for _, scope := range scopes {
		if _, exists := b.scopeMap[scope]; exists {
			return true
		}
	}
	return false
}

// Request performs the requested identity provider operation.
func (b *IdentityProvider) Request(op operator.Type, r *requests.Request) error {
	switch op {
	case operator.Authenticate:
		return b.Authenticate(r)
	}
	return errors.ErrOperatorNotSupported.WithArgs(op)
}

// Configure configures IdentityProvider.
func (b *IdentityProvider) Configure() error {
	if b.config.EmailClaimCheckDisabled {
		b.disableEmailClaimCheck = true
	}
	if b.config.KeyVerificationDisabled {
		b.disableKeyVerification = true
	}
	if b.config.PassGrantTypeDisabled {
		b.disablePassGrantType = true
	}
	if b.config.ResponseTypeDisabled {
		b.disableResponseType = true
	}
	if b.config.NonceDisabled {
		b.disableNonce = true
	}
	if b.config.ScopeDisabled {
		b.disableScope = true
	}
	if b.config.PKCEDisabled {
		b.disablePKCE = true
	}

	if b.config.AcceptHeaderEnabled {
		b.enableAcceptHeader = true
	}

	if b.config.AuthorizationURL != "" {
		b.authorizationURL = b.config.AuthorizationURL
	}
	if b.config.TokenURL != "" {
		b.tokenURL = b.config.TokenURL
	}

	if b.config.TLSInsecureSkipVerify {
		b.browserConfig = &browserConfig{
			TLSInsecureSkipVerify: true,
		}
	}

	b.scopeMap = make(map[string]interface{})
	for _, scope := range b.config.Scopes {
		b.scopeMap[scope] = true
	}

	switch b.config.Driver {
	case "generic":
	case "okta":
	case "google":
	case "gitlab":
	case "azure":
	case "github":
		b.disableKeyVerification = true
		b.disablePassGrantType = true
		b.disableResponseType = true
		b.disableNonce = true
		b.disablePKCE = true
		b.enableAcceptHeader = true
	case "facebook":
		b.disableKeyVerification = true
		b.disablePassGrantType = true
		b.disableResponseType = true
		b.disableNonce = true
		b.disablePKCE = true
		b.enableAcceptHeader = true
	case "discord":
		b.disableKeyVerification = true
		b.disableNonce = true
		b.disablePKCE = true
		b.enableAcceptHeader = true
	case "linkedin":
		b.disableNonce = true
		b.disablePKCE = true
	case "nextcloud":
		b.disableKeyVerification = true
	}

	b.serverName = b.config.ServerName

	b.requiredTokenFields = make(map[string]interface{})
	for _, fieldName := range b.config.RequiredTokenFields {
		b.requiredTokenFields[fieldName] = true
	}

	b.userInfoFields = make(map[string]interface{})
	for _, fieldName := range b.config.UserInfoFields {
		b.userInfoFields[fieldName] = true
	}

	if b.config.UserInfoRolesFieldName != "" {
		b.userInfoRolesFieldName = b.config.UserInfoRolesFieldName
	} else {
		b.userInfoRolesFieldName = "roles"
	}

	// Configure user group filters, if any.
	for _, pattern := range b.config.UserGroupFilters {
		b.userGroupFilters = append(b.userGroupFilters, regexp.MustCompile(pattern))
	}

	// Configure user org filters, if any.
	for _, pattern := range b.config.UserOrgFilters {
		b.userOrgFilters = append(b.userOrgFilters, regexp.MustCompile(pattern))
	}

	if err := b.installStaticKeys(); err != nil {
		return err
	}

	if b.config.DelayStart > 0 {
		go b.fetchConfig()
	} else {
		if err := b.fetchConfig(); err != nil {
			return err
		}
	}

	b.logger.Info(
		"successfully configured OAuth 2.0 identity provider",
		zap.String("provider", b.config.Driver),
		zap.String("client_id", b.config.ClientID),
		zap.String("server_id", b.config.ServerID),
		zap.String("domain_name", b.config.DomainName),
		zap.Int("static_key_count", len(b.staticKeys.all)),
		zap.Strings("required_token_fields", b.config.RequiredTokenFields),
		zap.Int("delayed_by", b.config.DelayStart),
		zap.Int("retry_attempts", b.config.RetryAttempts),
		zap.Int("retry_interval", b.config.RetryInterval),
		zap.Strings("scopes", b.config.Scopes),
		zap.Any("login_icon", b.config.LoginIcon),
		zap.String("identity_token_cookie_name", b.config.IdentityTokenCookieName),
		zap.Bool("identity_token_cookie_enabled", b.config.IdentityTokenCookieEnabled),
	)

	b.configured = true
	return nil
}

func (b *IdentityProvider) fetchConfig() (err error) {
	b.setupMu.Lock()
	defer func() {
		if err == nil {
			b.ready.Store(true)
		}
		b.setupMu.Unlock()
	}()
	if b.config.DelayStart > 0 {
		b.logger.Debug(
			"Delaying identity provider configuration",
			zap.String("identity_provider_name", b.config.Name),
			zap.Int("delayed_by", b.config.DelayStart),
		)
		timer := time.NewTimer(time.Duration(b.config.DelayStart) * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-b.stop:
			return fmt.Errorf("OAuth provider closed before discovery")
		}
	}

	if b.authorizationURL == "" || (len(b.config.JwksKeys) > 0 && b.config.MetadataURL != "") {
		if b.config.RetryAttempts > 0 {
			for i := 0; i < b.config.RetryAttempts; i++ {
				err := b.fetchMetadataURL()
				if err == nil {
					break
				}
				if i >= (b.config.RetryAttempts - 1) {
					return errors.ErrIdentityProviderOauthMetadataFetchFailed.WithArgs(err)
				}
				b.logger.Debug(
					"fetchMetadataURL failed",
					zap.String("identity_provider_name", b.config.Name),
					zap.Int("attempt_id", i),
					zap.Error(errors.ErrIdentityProviderOauthMetadataFetchFailed.WithArgs(err)),
				)
				time.Sleep(time.Duration(b.config.RetryInterval) * time.Second)
			}
		} else {
			if err := b.fetchMetadataURL(); err != nil {
				b.logger.Debug(
					"fetchMetadataURL failed",
					zap.String("identity_provider_name", b.config.Name),
					zap.Error(errors.ErrIdentityProviderOauthMetadataFetchFailed.WithArgs(err)),
				)
				return errors.ErrIdentityProviderOauthMetadataFetchFailed.WithArgs(err)
			}
		}
		b.logger.Debug(
			"fetchMetadataURL succeeded",
			zap.String("identity_provider_name", b.config.Name),
			zap.Any("metadata", b.metadata),
			zap.Any("userinfo_endpoint", b.userInfoURL),
		)
	}

	if !b.disableKeyVerification && (b.keysURL != "" || len(b.staticKeys.all) == 0) {
		if b.config.RetryAttempts > 0 {
			for i := 0; i < b.config.RetryAttempts; i++ {
				err := b.fetchKeysURL()
				if err == nil {
					break
				}
				if i >= (b.config.RetryAttempts - 1) {
					return errors.ErrIdentityProviderOauthKeyFetchFailed.WithArgs(err)
				}
				b.logger.Debug(
					"fetchKeysURL failed",
					zap.String("identity_provider_name", b.config.Name),
					zap.Int("attempt_id", i),
					zap.Error(errors.ErrIdentityProviderOauthKeyFetchFailed.WithArgs(err)),
				)
				time.Sleep(time.Duration(b.config.RetryInterval) * time.Second)
			}
		} else {
			if err := b.fetchKeysURL(); err != nil {
				return errors.ErrIdentityProviderOauthKeyFetchFailed.WithArgs(err)
			}
		}
	}
	return nil
}

func (b *IdentityProvider) fetchMetadataURL() error {
	cli, err := b.newBrowser()
	if err != nil {
		return err
	}
	defer cli.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, b.config.MetadataURL, nil)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OAuth metadata endpoint returned HTTP %d", resp.StatusCode)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuthJwksBytes+1))
	if err != nil {
		return err
	}
	if len(respBody) > maxOAuthJwksBytes {
		return fmt.Errorf("OAuth metadata response exceeds %d bytes", maxOAuthJwksBytes)
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(respBody, &metadata); err != nil {
		return err
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		value, exists := metadata[k]
		if !exists {
			return errors.ErrIdentityProviderOauthMetadataFieldNotFound.WithArgs(k, b.config.Driver)
		}
		if text, ok := value.(string); !ok || text == "" {
			return fmt.Errorf("OAuth metadata %s must be a nonempty string", k)
		}
	}
	for _, k := range []string{"issuer", "userinfo_endpoint", "end_session_endpoint"} {
		if value, exists := metadata[k]; exists {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("OAuth metadata %s must be a string", k)
			}
		}
	}
	// Publish only validated metadata, preserving explicitly configured endpoints.
	b.metadata = metadata
	if b.config.AuthorizationURL == "" {
		b.authorizationURL = metadata["authorization_endpoint"].(string)
	}
	if b.config.TokenURL == "" {
		b.tokenURL = metadata["token_endpoint"].(string)
	}
	b.keysURL = metadata["jwks_uri"].(string)
	b.userInfoURL, _ = metadata["userinfo_endpoint"].(string)
	b.logoutURL, _ = metadata["end_session_endpoint"].(string)
	if issuer, exists := metadata["issuer"].(string); exists && issuer != "" && b.config.Issuer == "" {
		b.config.Issuer = issuer
	}
	if b.config.Driver == "cognito" {
		b.logoutURL = strings.ReplaceAll(b.authorizationURL, "oauth2/authorize", "logout")
	}
	return nil
}

// GetLoginIcon returns the instance of the icon associated with the provider.
func (b *IdentityProvider) GetLoginIcon() *icons.LoginIcon {
	return b.config.LoginIcon
}

// GetLogoutURL returns the logout URL associated with the provider.
func (b *IdentityProvider) GetLogoutURL() string {
	if b.configured && !b.ready.Load() {
		return ""
	}
	b.setupMu.RLock()
	defer b.setupMu.RUnlock()
	if b.config.LogoutURL != "" {
		return b.config.LogoutURL
	}
	switch b.config.Driver {
	case "cognito":
		return b.logoutURL + "?client_id=" + b.config.ClientID
	case "google":
		return "https://accounts.google.com/logout"
	}
	return b.logoutURL
}

// GetDriver returns the name of the driver associated with the provider.
func (b *IdentityProvider) GetDriver() string {
	return b.config.Driver
}

// GetIdentityTokenCookieName returns the name of the identity token cookie associated with the provider.
func (b *IdentityProvider) GetIdentityTokenCookieName() string {
	if b.config.IdentityTokenCookieEnabled {
		return b.config.IdentityTokenCookieName
	}
	return ""
}
