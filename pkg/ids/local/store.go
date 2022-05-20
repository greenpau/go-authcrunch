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

package local

import (
	"encoding/json"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

const (
	storeKind = "local"
)

// Config holds the configuration for the identity store.
type Config struct {
	Name  string  `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Realm string  `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Path  string  `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Users []*User `json:"users,omitempty" xml:"users,omitempty" yaml:"users,omitempty"`

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
}

// IdentityStore represents authentication provider with local identity store.
type IdentityStore struct {
	config        *Config        `json:"-"`
	authenticator *Authenticator `json:"-"`
	logger        *zap.Logger
	configured    bool
}

// NewIdentityStore return an instance of AuthDB-based identity store.
func NewIdentityStore(cfg *Config, logger *zap.Logger) (*IdentityStore, error) {
	if logger == nil {
		return nil, errors.ErrIdentityStoreConfigureLoggerNotFound
	}

	b := &IdentityStore{
		config: cfg,
		logger: logger,
	}

	// Configure UI login icon.
	if b.config.LoginIcon == nil {
		b.config.LoginIcon = icons.NewLoginIcon(storeKind)
	} else {
		b.config.LoginIcon.Configure(storeKind)
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
		return b.authenticator.IdentifyUser(r)
	case operator.ChangePassword:
		return b.authenticator.ChangePassword(r)
	case operator.AddKeySSH:
		return b.authenticator.AddPublicKey(r)
	case operator.AddKeyGPG:
		return b.authenticator.AddPublicKey(r)
	case operator.DeletePublicKey:
		return b.authenticator.DeletePublicKey(r)
	case operator.AddMfaToken:
		// b.logger.Debug("detected supported identity store operation", zap.Any("op", op), zap.Any("params", r))
		return b.authenticator.AddMfaToken(r)
	case operator.DeleteMfaToken:
		return b.authenticator.DeleteMfaToken(r)
	case operator.AddAPIKey:
		return b.authenticator.AddAPIKey(r)
	case operator.DeleteAPIKey:
		return b.authenticator.DeleteAPIKey(r)
	case operator.GetPublicKeys:
		return b.authenticator.GetPublicKeys(r)
	case operator.GetAPIKeys:
		return b.authenticator.GetAPIKeys(r)
	case operator.GetMfaTokens:
		return b.authenticator.GetMfaTokens(r)
	case operator.AddUser:
		return b.authenticator.AddUser(r)
	case operator.GetUsers:
		return b.authenticator.GetUsers(r)
	case operator.GetUser:
		return b.authenticator.GetUser(r)
	case operator.DeleteUser:
		return b.authenticator.DeleteUser(r)
	case operator.LookupAPIKey:
		return b.authenticator.LookupAPIKey(r)
	}

	b.logger.Error(
		"detected unsupported identity store operation",
		zap.Any("op", op),
		zap.Any("params", r),
	)
	return errors.ErrOperatorNotSupported.WithArgs(op)
}

// Configure configures IdentityStore.
func (b *IdentityStore) Configure() error {
	if b.authenticator == nil {
		b.authenticator = NewAuthenticator()
	}
	b.authenticator.logger = b.logger

	if err := b.authenticator.Configure(b.config.Path, b.config.Users); err != nil {
		return err
	}

	b.logger.Info(
		"successfully configured identity store",
		zap.String("name", b.config.Name),
		zap.String("kind", storeKind),
		zap.String("db_path", b.config.Path),
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
	return m
}

// Authenticate performs authentication.
func (b *IdentityStore) Authenticate(r *requests.Request) error {
	if err := b.authenticator.AuthenticateUser(r); err != nil {
		return errors.ErrIdentityStoreLocalAuthFailed.WithArgs(err)
	}
	return nil
}

// Validate validates identity store configuration.
func (cfg *Config) Validate() error {
	if cfg.Name == "" {
		return errors.ErrIdentityStoreConfigureNameEmpty
	}
	if cfg.Realm == "" {
		return errors.ErrIdentityStoreConfigureRealmEmpty
	}
	if cfg.Path == "" {
		return errors.ErrIdentityStoreLocalConfigurePathEmpty
	}
	return nil
}

// GetLoginIcon returns the instance of the icon associated with the provider.
func (b *IdentityStore) GetLoginIcon() *icons.LoginIcon {
	// Add support and credentials recovery to the UI login icon.
	b.config.LoginIcon.RegistrationEnabled = b.config.RegistrationEnabled
	b.config.LoginIcon.UsernameRecoveryEnabled = b.config.UsernameRecoveryEnabled
	b.config.LoginIcon.PasswordRecoveryEnabled = b.config.PasswordRecoveryEnabled
	b.config.LoginIcon.ContactSupportEnabled = b.config.ContactSupportEnabled
	b.config.LoginIcon.SupportLink = b.config.SupportLink
	b.config.LoginIcon.SupportEmail = b.config.SupportEmail
	return b.config.LoginIcon
}
