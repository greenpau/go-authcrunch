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

package ldap

import (
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"net/url"
	"regexp"
	"strings"
)

const (
	storeKind = "ldap"
)

var (
	emailRegexPattern    = regexp.MustCompile("^[a-zA-Z0-9.+\\._~-]{1,61}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	usernameRegexPattern = regexp.MustCompile("^[a-zA-Z0-9.+\\._~-]{1,61}$")
)

// Config holds the configuration for the IdentityStore.
type Config struct {
	Name               string         `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Realm              string         `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Servers            []AuthServer   `json:"servers,omitempty" xml:"servers,omitempty" yaml:"servers,omitempty"`
	BindUsername       string         `json:"bind_username,omitempty" xml:"bind_username,omitempty" yaml:"bind_username,omitempty"`
	BindPassword       string         `json:"bind_password,omitempty" xml:"bind_password,omitempty" yaml:"bind_password,omitempty"`
	Attributes         UserAttributes `json:"attributes,omitempty" xml:"attributes,omitempty" yaml:"attributes,omitempty"`
	SearchBaseDN       string         `json:"search_base_dn,omitempty" xml:"search_base_dn,omitempty" yaml:"search_base_dn,omitempty"`
	SearchUserFilter   string         `json:"search_user_filter,omitempty" xml:"search_user_filter,omitempty" yaml:"search_user_filter,omitempty"`
	SearchGroupFilter  string         `json:"search_group_filter,omitempty" xml:"search_group_filter,omitempty" yaml:"search_group_filter,omitempty"`
	Groups             []UserGroup    `json:"groups,omitempty" xml:"groups,omitempty" yaml:"groups,omitempty"`
	TrustedAuthorities []string       `json:"trusted_authorities,omitempty" xml:"trusted_authorities,omitempty" yaml:"trusted_authorities,omitempty"`

	// LoginIcon is the UI login icon attributes.
	LoginIcon *icons.LoginIcon `json:"login_icon,omitempty" xml:"login_icon,omitempty" yaml:"login_icon,omitempty"`

	// RegistrationEnabled controls whether visitors can registers.
	RegistrationEnabled bool `json:"registration_enabled,omitempty" xml:"registration_enabled,omitempty" yaml:"registration_enabled,omitempty"`
	// UsernameRecoveryEnabled controls whether a user could recover username by providing an email address.
	UsernameRecoveryEnabled bool `json:"username_recovery_enabled,omitempty" xml:"username_recovery_enabled,omitempty" yaml:"username_recovery_enabled,omitempty"`
	// PasswordRecoveryEnabled controls whether a user could recover password by providing an email address.
	PasswordRecoveryEnabled bool `json:"password_recovery_enabled,omitempty" xml:"password_recovery_enabled,omitempty" yaml:"password_recovery_enabled,omitempty"`
	// ContactSupportEnabled controls whether contact support link is available.
	ContactSupportEnabled bool `json:"contact_support_enabled,omitempty" xml:"contact_support_enabled,omitempty" yaml:"contact_support_enabled,omitempty"`

	// SupportLink is the link to the support portal.
	SupportLink string `json:"support_link,omitempty" xml:"support_link,omitempty" yaml:"support_link,omitempty"`
	// SupportEmail is the email address to reach support.
	SupportEmail string `json:"support_email,omitempty" xml:"support_email,omitempty" yaml:"support_email,omitempty"`

	// The roles assigned to a user when no matching LDAP groups found.
	FallbackRoles []string `json:"fallback_roles,omitempty" xml:"fallback_roles,omitempty" yaml:"fallback_roles,omitempty"`
}

// UserGroup represent the binding between BaseDN and a serarch filter.
// Upon successful authentation for the combination, a user gets
// assigned the roles associated with the binding.
type UserGroup struct {
	GroupDN string   `json:"dn,omitempty" xml:"dn,omitempty" yaml:"dn,omitempty"`
	Roles   []string `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
}

// AuthServer represents an instance of LDAP server.
type AuthServer struct {
	Address          string   `json:"address,omitempty" xml:"address,omitempty" yaml:"address,omitempty"`
	URL              *url.URL `json:"-"`
	Port             string   `json:"-"`
	Encrypted        bool     `json:"-"`
	IgnoreCertErrors bool     `json:"ignore_cert_errors,omitempty" xml:"ignore_cert_errors,omitempty" yaml:"ignore_cert_errors,omitempty"`
	PosixGroups      bool     `json:"posix_groups,omitempty" xml:"posix_groups,omitempty" yaml:"posix_groups,omitempty"`
	Timeout          int      `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// UserAttributes represent the mapping of LDAP attributes
// to JWT fields.
type UserAttributes struct {
	Name     string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Surname  string `json:"surname,omitempty" xml:"surname,omitempty" yaml:"surname,omitempty"`
	Username string `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	MemberOf string `json:"member_of,omitempty" xml:"member_of,omitempty" yaml:"member_of,omitempty"`
	Email    string `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
}

// IdentityStore represents authentication provider with LDAP identity store.
type IdentityStore struct {
	config        *Config        `json:"-"`
	authenticator *Authenticator `json:"-"`
	logger        *zap.Logger
	configured    bool
}

// NewIdentityStore return an instance of LDAP-based identity store.
func NewIdentityStore(cfg *Config, logger *zap.Logger) (*IdentityStore, error) {
	if logger == nil {
		return nil, errors.ErrIdentityStoreConfigureLoggerNotFound
	}

	b := &IdentityStore{
		config:        cfg,
		authenticator: NewAuthenticator(),
		logger:        logger,
	}

	if err := b.config.Validate(); err != nil {
		return nil, err
	}

	return b, nil
}

// GetRealm return authentication realm.
func (b *IdentityStore) GetRealm() string {
	return b.config.Realm
}

// GetName return the name associated with this identity store.
func (b *IdentityStore) GetName() string {
	return b.config.Name
}

// GetKind returns the authentication method associated with this identity store.
func (b *IdentityStore) GetKind() string {
	return storeKind
}

// Configured returns true if the identity store was configured.
func (b *IdentityStore) Configured() bool {
	return b.configured
}

// Request performs the requested identity store operation.
func (b *IdentityStore) Request(op operator.Type, r *requests.Request) error {
	switch op {
	case operator.Authenticate:
		return b.Authenticate(r)
	case operator.IdentifyUser:
		return b.IdentifyUser(r)
	case operator.ChangePassword:
		return errors.ErrOperatorNotAvailable.WithArgs(op)
	}
	return errors.ErrOperatorNotSupported.WithArgs(op)
}

// Authenticate performs authentication.
func (b *IdentityStore) Authenticate(r *requests.Request) error {
	if strings.Contains(r.User.Username, "@") {
		if !emailRegexPattern.MatchString(r.User.Username) {
			return errors.ErrIdentityStoreLdapAuthenticateInvalidUserEmail
		}
	} else {
		if !usernameRegexPattern.MatchString(r.User.Username) {
			return errors.ErrIdentityStoreLdapAuthenticateInvalidUsername
		}
	}
	if len(r.User.Password) < 3 {
		return errors.ErrIdentityStoreLdapAuthenticateInvalidPassword
	}
	return b.authenticator.AuthenticateUser(r)
}

// IdentifyUser  performs user identification.
func (b *IdentityStore) IdentifyUser(r *requests.Request) error {
	if strings.Contains(r.User.Username, "@") {
		if !emailRegexPattern.MatchString(r.User.Username) {
			return errors.ErrIdentityStoreLdapAuthenticateInvalidUserEmail
		}
	} else {
		if !usernameRegexPattern.MatchString(r.User.Username) {
			return errors.ErrIdentityStoreLdapAuthenticateInvalidUsername
		}
	}
	return b.authenticator.IdentifyUser(r)
}

// Configure configures IdentityStore.
func (b *IdentityStore) Configure() error {
	b.authenticator.logger = b.logger

	if err := b.authenticator.ConfigureRealm(b.config); err != nil {
		b.logger.Error("failed configuring realm (domain) for LDAP authentication",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.authenticator.ConfigureSearch(b.config); err != nil {
		b.logger.Error("failed configuring base DN, search filter, attributes for LDAP queries",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.authenticator.ConfigureServers(b.config); err != nil {
		b.logger.Error("failed to configure LDAP server addresses",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.authenticator.ConfigureBindCredentials(b.config); err != nil {
		b.logger.Error("failed configuring user credentials for LDAP binding",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.authenticator.ConfigureUserGroups(b.config); err != nil {
		b.logger.Error("failed configuring user groups for LDAP search",
			zap.String("error", err.Error()))
		return err
	}
	if err := b.authenticator.ConfigureTrustedAuthorities(b.config); err != nil {
		b.logger.Error("failed configuring trusted authorities",
			zap.String("error", err.Error()))
		return err
	}

	// Configure UI login icon.
	if b.config.LoginIcon == nil {
		b.config.LoginIcon = icons.NewLoginIcon(storeKind)
	} else {
		b.config.LoginIcon.Configure(storeKind)
	}

	// Add support and credentials recovery to the UI login icon.
	b.config.LoginIcon.RegistrationEnabled = b.config.RegistrationEnabled
	b.config.LoginIcon.UsernameRecoveryEnabled = b.config.UsernameRecoveryEnabled
	b.config.LoginIcon.PasswordRecoveryEnabled = b.config.PasswordRecoveryEnabled
	b.config.LoginIcon.ContactSupportEnabled = b.config.ContactSupportEnabled
	b.config.LoginIcon.SupportLink = b.config.SupportLink
	b.config.LoginIcon.SupportEmail = b.config.SupportEmail

	b.logger.Info(
		"successfully configured identity store",
		zap.String("name", b.config.Name),
		zap.String("kind", storeKind),
		zap.Any("login_icon", b.config.LoginIcon),
	)

	b.configured = true

	return nil
}

// GetConfig returns IdentityStore configuration.
func (b *IdentityStore) GetConfig() map[string]interface{} {
	var m map[string]interface{}
	j, _ := json.Marshal(b.config)
	json.Unmarshal(j, &m)
	if _, exists := m["bind_password"]; exists {
		m["bind_password"] = "**masked**"
	}
	return m
}

// Validate validates identity store configuration.
func (cfg *Config) Validate() error {
	if cfg.Name == "" {
		return errors.ErrIdentityStoreConfigureNameEmpty
	}
	if cfg.Realm == "" {
		return errors.ErrIdentityStoreConfigureRealmEmpty
	}
	return nil
}

// GetLoginIcon returns the instance of the icon associated with the provider.
func (b *IdentityStore) GetLoginIcon() *icons.LoginIcon {
	return b.config.LoginIcon
}
