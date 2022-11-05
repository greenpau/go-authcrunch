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
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	providerKind = "oauth"
)

// IdentityProvider represents OAuth-based identity provider.
type IdentityProvider struct {
	config           *Config `json:"config,omitempty" xml:"config,omitempty" yaml:"config,omitempty"`
	metadata         map[string]interface{}
	keys             map[string]*JwksKey
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
	enableAcceptHeader     bool
	enableBodyDecoder      bool
	requiredTokenFields    map[string]interface{}
	scopeMap               map[string]interface{}
	userInfoFields         map[string]interface{}
	// state stores cached state IDs
	state         *stateManager
	logger        *zap.Logger
	browserConfig *browserConfig
	configured    bool
	// Disabled the check for the presence of email field in a token.
	disableEmailClaimCheck bool
}

// NewIdentityProvider returns an instance of IdentityProvider.
func NewIdentityProvider(cfg *Config, logger *zap.Logger) (*IdentityProvider, error) {
	if logger == nil {
		return nil, errors.ErrIdentityProviderConfigureLoggerNotFound
	}

	b := &IdentityProvider{
		config: cfg,
		state:  newStateManager(),
		keys:   make(map[string]*JwksKey),
		logger: logger,
	}

	if err := b.config.Validate(); err != nil {
		return nil, err
	}

	go manageStateManager(b.state)

	return b, nil
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
		b.enableAcceptHeader = true
	case "facebook":
		b.disableKeyVerification = true
		b.disablePassGrantType = true
		b.disableResponseType = true
		b.disableNonce = true
		b.enableAcceptHeader = true
	case "discord":
		b.disableKeyVerification = true
		b.disableNonce = true
		b.enableAcceptHeader = true
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

	// Configure user group filters, if any.
	for _, pattern := range b.config.UserGroupFilters {
		b.userGroupFilters = append(b.userGroupFilters, regexp.MustCompile(pattern))
	}

	// Configure user org filters, if any.
	for _, pattern := range b.config.UserOrgFilters {
		b.userOrgFilters = append(b.userOrgFilters, regexp.MustCompile(pattern))
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
		zap.Any("metadata", b.metadata),
		zap.Any("jwks_keys", b.keys),
		zap.Strings("required_token_fields", b.config.RequiredTokenFields),
		zap.Int("delayed_by", b.config.DelayStart),
		zap.Int("retry_attempts", b.config.RetryAttempts),
		zap.Int("retry_interval", b.config.RetryInterval),
		zap.Strings("scopes", b.config.Scopes),
		zap.Any("login_icon", b.config.LoginIcon),
	)

	b.configured = true
	return nil
}

func (b *IdentityProvider) fetchConfig() error {
	if b.config.DelayStart > 0 {
		b.logger.Debug(
			"Delaying identity provider configuration",
			zap.String("identity_provider_name", b.config.Name),
			zap.Int("delayed_by", b.config.DelayStart),
		)
		time.Sleep(time.Duration(b.config.DelayStart) * time.Second)
	}

	if b.authorizationURL == "" {
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

	if !b.disableKeyVerification {
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
	req, err := http.NewRequest("GET", b.config.MetadataURL, nil)
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(respBody, &b.metadata); err != nil {
		return err
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if _, exists := b.metadata[k]; !exists {
			return errors.ErrIdentityProviderOauthMetadataFieldNotFound.WithArgs(k, b.config.Driver)
		}
	}
	b.authorizationURL = b.metadata["authorization_endpoint"].(string)
	b.tokenURL = b.metadata["token_endpoint"].(string)
	b.keysURL = b.metadata["jwks_uri"].(string)
	if _, exists := b.metadata["userinfo_endpoint"]; exists {
		b.userInfoURL = b.metadata["userinfo_endpoint"].(string)
	}
	if _, exists := b.metadata["end_session_endpoint"]; exists {
		b.logoutURL = b.metadata["end_session_endpoint"].(string)
	}

	switch b.config.Driver {
	case "cognito":
		b.logoutURL = strings.ReplaceAll(b.authorizationURL, "oauth2/authorize", "logout")
	}
	return nil
}

func (b *IdentityProvider) countFetchKeysAttempt() {
	b.lastKeyFetch = time.Now().UTC()
	b.keyFetchAttempts++
	return
}

func (b *IdentityProvider) fetchKeysURL() error {
	if b.keyFetchAttempts > 3 {
		timeDiff := time.Now().UTC().Sub(b.lastKeyFetch).Minutes()
		if timeDiff < 5 {
			return errors.ErrIdentityProviderOauthJwksKeysTooManyAttempts
		}
		b.lastKeyFetch = time.Now().UTC()
		b.keyFetchAttempts = 0
	}
	b.countFetchKeysAttempt()

	//  Create new http client instance.
	cli, err := b.newBrowser()
	if err != nil {
		return err
	}
	req, err := http.NewRequest("GET", b.keysURL, nil)
	if err != nil {
		return err
	}

	// Fetch data from the URL.
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	data := make(map[string]interface{})

	if err := json.Unmarshal(respBody, &data); err != nil {
		return err
	}

	if _, exists := data["keys"]; !exists {
		return errors.ErrIdentityProviderOauthJwksResponseKeysNotFound
	}

	jwksJSON, err := json.Marshal(data["keys"])
	if err != nil {
		return errors.ErrIdentityProviderOauthJwksKeysParseFailed.WithArgs(err)
	}

	keys := []*JwksKey{}
	if err := json.Unmarshal(jwksJSON, &keys); err != nil {
		return err
	}

	if len(keys) < 1 {
		return errors.ErrIdentityProviderOauthJwksKeysNotFound
	}

	for _, k := range keys {
		if err := k.Validate(); err != nil {
			return errors.ErrIdentityProviderOauthJwksInvalidKey.WithArgs(err)
		}
		b.keys[k.KeyID] = k
	}

	return nil
}

// GetLoginIcon returns the instance of the icon associated with the provider.
func (b *IdentityProvider) GetLoginIcon() *icons.LoginIcon {
	return b.config.LoginIcon
}

// GetLogoutURL returns the logout URL associated with the provider.
func (b *IdentityProvider) GetLogoutURL() string {
	switch b.config.Driver {
	case "cognito":
		return b.logoutURL + "?client_id=" + b.config.ClientID
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
