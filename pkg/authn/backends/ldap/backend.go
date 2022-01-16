// Copyright 2020 Paul Greenberg greenpau@outlook.com
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
	"fmt"
	"github.com/greenpau/aaasf/pkg/authn/enums/operator"
	"github.com/greenpau/aaasf/pkg/errors"
	"github.com/greenpau/aaasf/pkg/requests"
	"go.uber.org/zap"
	"net/url"
	"regexp"
	"strings"
)

var (
	emailRegexPattern    = regexp.MustCompile("^[a-zA-Z0-9.+\\._~-]{1,61}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	usernameRegexPattern = regexp.MustCompile("^[a-zA-Z0-9.+\\._~-]{1,61}$")
)

// Config holds the configuration for the backend.
type Config struct {
	Name               string         `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Method             string         `json:"method,omitempty" xml:"method,omitempty" yaml:"method,omitempty"`
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
}

// UserGroup represent the binding between BaseDN and a serarch filter.
// Upon successful authentation for the combination, a user gets
// assigned the roles associated with the binding.
type UserGroup struct {
	GroupDN string   `json:"group_dn,omitempty" xml:"group_dn,omitempty" yaml:"group_dn,omitempty"`
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

// Backend represents authentication provider with LDAP backend.
type Backend struct {
	Config        *Config        `json:"-"`
	Authenticator *Authenticator `json:"-"`
	logger        *zap.Logger
}

// NewDatabaseBackend return an instance of authentication provider
// with LDAP backend.
func NewDatabaseBackend(cfg *Config, logger *zap.Logger) *Backend {
	b := &Backend{
		Config:        cfg,
		Authenticator: NewAuthenticator(),
		logger:        logger,
	}
	return b
}

// GetRealm return authentication realm.
func (b *Backend) GetRealm() string {
	return b.Config.Realm
}

// GetName return the name associated with this backend.
func (b *Backend) GetName() string {
	return b.Config.Name
}

// GetMethod returns the authentication method associated with this backend.
func (b *Backend) GetMethod() string {
	return b.Config.Method
}

// Request performs the requested backend operation.
func (b *Backend) Request(op operator.Type, r *requests.Request) error {
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
func (b *Backend) Authenticate(r *requests.Request) error {
	if strings.Contains(r.User.Username, "@") {
		if !emailRegexPattern.MatchString(r.User.Username) {
			return errors.ErrBackendLdapAuthenticateInvalidUserEmail
		}
	} else {
		if !usernameRegexPattern.MatchString(r.User.Username) {
			return errors.ErrBackendLdapAuthenticateInvalidUsername
		}
	}
	if len(r.User.Password) < 3 {
		return errors.ErrBackendLdapAuthenticateInvalidPassword
	}
	return b.Authenticator.AuthenticateUser(r)
}

// IdentifyUser  performs user identification.
func (b *Backend) IdentifyUser(r *requests.Request) error {
	if strings.Contains(r.User.Username, "@") {
		if !emailRegexPattern.MatchString(r.User.Username) {
			return errors.ErrBackendLdapAuthenticateInvalidUserEmail
		}
	} else {
		if !usernameRegexPattern.MatchString(r.User.Username) {
			return errors.ErrBackendLdapAuthenticateInvalidUsername
		}
	}
	return b.Authenticator.IdentifyUser(r)
}

// Configure configures Backend.
func (b *Backend) Configure() error {
	if b.Config.Name == "" {
		return errors.ErrBackendConfigureNameEmpty
	}
	if b.Config.Method == "" {
		return errors.ErrBackendConfigureMethodEmpty
	}
	if b.Config.Realm == "" {
		return errors.ErrBackendConfigureRealmEmpty
	}

	if b.Authenticator == nil {
		b.Authenticator = NewAuthenticator()
	}

	b.Authenticator.logger = b.logger

	if err := b.Authenticator.ConfigureRealm(b.Config); err != nil {
		b.logger.Error("failed configuring realm (domain) for LDAP authentication",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureSearch(b.Config); err != nil {
		b.logger.Error("failed configuring base DN, search filter, attributes for LDAP queries",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureServers(b.Config); err != nil {
		b.logger.Error("failed to configure LDAP server addresses",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureBindCredentials(b.Config); err != nil {
		b.logger.Error("failed configuring user credentials for LDAP binding",
			zap.String("error", err.Error()))
		return err
	}

	if err := b.Authenticator.ConfigureUserGroups(b.Config); err != nil {
		b.logger.Error("failed configuring user groups for LDAP search",
			zap.String("error", err.Error()))
		return err
	}
	if err := b.Authenticator.ConfigureTrustedAuthorities(b.Config); err != nil {
		b.logger.Error("failed configuring trusted authorities",
			zap.String("error", err.Error()))
		return err
	}

	return nil
}

// Validate checks whether Backend is functional.
func (b *Backend) Validate() error {
	b.logger.Debug("validating LDAP backend")

	if b.Authenticator == nil {
		return fmt.Errorf("LDAP authenticator is nil")
	}

	b.logger.Debug("successfully validated LDAP backend")
	return nil
}

// GetConfig returns Backend configuration.
func (b *Backend) GetConfig() string {
	var sb strings.Builder
	sb.WriteString("name " + b.Config.Name + "\n")
	sb.WriteString("method " + b.Config.Method + "\n")
	sb.WriteString("realm " + b.Config.Realm + "\n")
	return sb.String()
}
