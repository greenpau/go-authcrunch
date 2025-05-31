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
	"regexp"
	"slices"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

const (
	defaultGuestRoleName = "authp/guest"
	defaultUserRoleName  = "authp/user"
	defaultAdminRoleName = "authp/admin"
)

// PortalConfig represents Portal configuration.
type PortalConfig struct {
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	// UI holds the configuration for the user interface.
	UI *ui.Parameters `json:"ui,omitempty" xml:"ui,omitempty" yaml:"ui,omitempty"`
	// UserTransformerConfig holds the configuration for the user transformer.
	UserTransformerConfigs []*transformer.Config `json:"user_transformer_configs,omitempty" xml:"user_transformer_configs,omitempty" yaml:"user_transformer_configs,omitempty"`
	// CookieConfig holds the configuration for the cookies issues by Authenticator.
	CookieConfig *cookie.Config `json:"cookie_config,omitempty" xml:"cookie_config,omitempty" yaml:"cookie_config,omitempty"`
	// The names of identity stores.
	IdentityStores []string `json:"identity_stores,omitempty" xml:"identity_stores,omitempty" yaml:"identity_stores,omitempty"`
	// The names of identity providers.
	IdentityProviders []string `json:"identity_providers,omitempty" xml:"identity_providers,omitempty" yaml:"identity_providers,omitempty"`
	// The names of SSO providers.
	SingleSignOnProviders []string `json:"sso_providers,omitempty" xml:"sso_providers,omitempty" yaml:"sso_providers,omitempty"`
	// The names of user registries.
	UserRegistries []string `json:"user_registries,omitempty" xml:"user_registries,omitempty" yaml:"user_registries,omitempty"`
	// AccessListConfigs hold the configurations for the ACL of the token validator.
	AccessListConfigs []*acl.RuleConfiguration `json:"access_list_configs,omitempty" xml:"access_list_configs,omitempty" yaml:"access_list_configs,omitempty"`
	// TokenValidatorOptions holds the configuration for the token validator.
	TokenValidatorOptions *options.TokenValidatorOptions `json:"token_validator_options,omitempty" xml:"token_validator_options,omitempty" yaml:"token_validator_options,omitempty"`
	// CryptoKeyConfigs hold the configurations for the keys used to issue and validate user tokens.
	CryptoKeyConfigs []*kms.CryptoKeyConfig `json:"crypto_key_configs,omitempty" xml:"crypto_key_configs,omitempty" yaml:"crypto_key_configs,omitempty"`
	// CryptoKeyStoreConfig hold the default configuration for the keys, e.g. token name and lifetime.
	CryptoKeyStoreConfig map[string]interface{} `json:"crypto_key_store_config,omitempty" xml:"crypto_key_store_config,omitempty" yaml:"crypto_key_store_config,omitempty"`
	// TokenGrantorOptions holds the configuration for the tokens issues by Authenticator.
	TokenGrantorOptions *options.TokenGrantorOptions `json:"token_grantor_options,omitempty" xml:"token_grantor_options,omitempty" yaml:"token_grantor_options,omitempty"`
	// TrustedLogoutRedirectURIConfigs holds the configuration of trusted logout redirect URIs.
	TrustedLogoutRedirectURIConfigs []*redirects.RedirectURIMatchConfig `json:"trusted_logout_redirect_uri_configs,omitempty" xml:"trusted_logout_redirect_uri_configs,omitempty" yaml:"trusted_logout_redirect_uri_configs,omitempty"`

	// PortalAdminRoles holds the list of role names granted to do administrative tasks in the portal.
	PortalAdminRoles map[string]interface{} `json:"portal_admin_roles,omitempty" xml:"portal_admin_roles,omitempty" yaml:"portal_admin_roles,omitempty"`
	// PortalUserRoles holds the list of role names granted to do perform profile tasks in the portal.
	PortalUserRoles map[string]interface{} `json:"portal_user_roles,omitempty" xml:"portal_user_roles,omitempty" yaml:"portal_user_roles,omitempty"`
	// PortalGuestRoles holds the list of role names without admin or user privileges in the portal.
	PortalGuestRoles map[string]interface{} `json:"portal_guest_roles,omitempty" xml:"portal_guest_roles,omitempty" yaml:"portal_guest_roles,omitempty"`

	// PortalAdminRolePatterns holds the list of regular expressions for the role names granted to do administrative tasks in the portal.
	PortalAdminRolePatterns []string `json:"portal_admin_role_patterns,omitempty" xml:"portal_admin_role_patterns,omitempty" yaml:"portal_admin_role_patterns,omitempty"`
	adminRolePatterns       []*regexp.Regexp
	// PortalUserRolePatterns holds the list of regular expressions for the role names granted to do perform profile tasks in the portal.
	PortalUserRolePatterns []string `json:"portal_user_role_patterns,omitempty" xml:"portal_user_role_patterns,omitempty" yaml:"portal_user_role_patterns,omitempty"`
	userRolePatterns       []*regexp.Regexp
	// PortalGuestRolePatterns holds the list of regular expressions for the role names without admin or user privileges in the portal.
	PortalGuestRolePatterns []string `json:"portal_guest_role_patterns,omitempty" xml:"portal_guest_role_patterns,omitempty" yaml:"portal_guest_role_patterns,omitempty"`
	guestRolePatterns       []*regexp.Regexp
	reservedPortalRoles     map[string]interface{}
	guestPortalRoles        []string
	// API holds the configuration for API endpoints.
	API *APIConfig `json:"api,omitempty" xml:"api,omitempty" yaml:"api,omitempty"`

	// Holds raw crypto configuration.
	cryptoRawConfigs []string

	// Indicated that the config was successfully validated.
	validated bool
}

// AddRawCryptoConfigs adds raw crypto configs.
func (cfg *PortalConfig) AddRawCryptoConfigs(s string) {
	cfg.cryptoRawConfigs = append(cfg.cryptoRawConfigs, s)
}

// parseRawCryptoConfigs parses raw crypto configs into CryptoKeyConfigs
// and CryptoKeyStoreConfig.
func (cfg *PortalConfig) parseRawCryptoConfigs() error {
	var cryptoKeyConfig, cryptoKeyStoreConfig []string
	var cryptoKeyConfigFound, cryptoKeyStoreConfigFound bool
	for _, encodedArgs := range cfg.cryptoRawConfigs {
		args, err := cfgutil.DecodeArgs(encodedArgs)
		if err != nil {
			return errors.ErrConfigDirectiveFail.WithArgs("crypto", encodedArgs, err)
		}
		if len(args) < 3 {
			return errors.ErrConfigDirectiveShort.WithArgs("crypto", args)
		}
		cryptoKeyConfig = append(cryptoKeyConfig, encodedArgs)
		switch args[0] {
		case "key":
			cryptoKeyConfigFound = true
		case "default":
			cryptoKeyStoreConfig = append(cryptoKeyStoreConfig, encodedArgs)
			cryptoKeyStoreConfigFound = true
		default:
			return errors.ErrConfigDirectiveValueUnsupported.WithArgs("crypto", args)
		}
	}

	if cryptoKeyConfigFound {
		configs, err := kms.ParseCryptoKeyConfigs(strings.Join(cryptoKeyConfig, "\n"))
		if err != nil {
			return errors.ErrConfigDirectiveFail.WithArgs("crypto.key", cryptoKeyConfig, err)
		}
		cfg.CryptoKeyConfigs = configs
	}

	if cryptoKeyStoreConfigFound {
		configs, err := kms.ParseCryptoKeyStoreConfig(strings.Join(cryptoKeyStoreConfig, "\n"))
		if err != nil {
			return errors.ErrConfigDirectiveFail.WithArgs("crypto.keystore", cryptoKeyStoreConfig, err)
		}
		cfg.CryptoKeyStoreConfig = configs
	}
	return nil
}

// GetReservedPortalRoles returns the names of reserved portal roles.
func (cfg *PortalConfig) GetReservedPortalRoles() map[string]interface{} {
	if cfg.reservedPortalRoles == nil {
		cfg.parsePortalRoles()
	}
	return cfg.reservedPortalRoles
}

// GetGuestPortalRoles returns the names of guest portal roles.
func (cfg *PortalConfig) GetGuestPortalRoles() []string {
	return cfg.guestPortalRoles
}

// parsePortalRoles validates the configuration of portal roles.
func (cfg *PortalConfig) parsePortalRoles() error {
	if cfg.reservedPortalRoles == nil {
		cfg.reservedPortalRoles = make(map[string]interface{})
	}

	if cfg.PortalAdminRoles == nil {
		cfg.PortalAdminRoles = make(map[string]interface{})
	}
	if len(cfg.PortalAdminRoles) < 1 {
		cfg.PortalAdminRoles[defaultAdminRoleName] = true
		cfg.reservedPortalRoles[defaultAdminRoleName] = true
	}

	if cfg.PortalUserRoles == nil {
		cfg.PortalUserRoles = make(map[string]interface{})
	}
	if len(cfg.PortalUserRoles) < 1 {
		cfg.PortalUserRoles[defaultUserRoleName] = true
		cfg.reservedPortalRoles[defaultUserRoleName] = true
	}

	if cfg.PortalGuestRoles == nil {
		cfg.PortalGuestRoles = make(map[string]interface{})
		cfg.reservedPortalRoles[defaultGuestRoleName] = true
	}
	if len(cfg.PortalGuestRoles) < 1 {
		cfg.PortalGuestRoles[defaultGuestRoleName] = true
	}

	if slices.Contains(cfg.guestPortalRoles, defaultGuestRoleName) {
		cfg.guestPortalRoles = append(cfg.guestPortalRoles, defaultGuestRoleName)
	}

	for _, ptrn := range cfg.PortalAdminRolePatterns {
		if ptrn == "" {
			return errors.ErrInvalidConfiguration.WithArgs("portal", "admin role pattern is empty")
		}
		r, err := regexp.Compile(ptrn)
		if err != nil {
			return errors.ErrInvalidConfiguration.WithArgs("portal admin role pattern", err)
		}
		cfg.adminRolePatterns = append(cfg.adminRolePatterns, r)
	}

	for _, ptrn := range cfg.PortalUserRolePatterns {
		if ptrn == "" {
			return errors.ErrInvalidConfiguration.WithArgs("portal", "user role pattern is empty")
		}
		r, err := regexp.Compile(ptrn)
		if err != nil {
			return errors.ErrInvalidConfiguration.WithArgs("portal user role pattern", err)
		}
		cfg.userRolePatterns = append(cfg.userRolePatterns, r)
	}

	for _, ptrn := range cfg.PortalGuestRolePatterns {
		if ptrn == "" {
			return errors.ErrInvalidConfiguration.WithArgs("portal", "guest role pattern is empty")
		}
		r, err := regexp.Compile(ptrn)
		if err != nil {
			return errors.ErrInvalidConfiguration.WithArgs("portal guest role pattern", err)
		}
		cfg.guestRolePatterns = append(cfg.guestRolePatterns, r)
	}

	return nil
}

// Validate validates PortalConfig.
func (cfg *PortalConfig) Validate() error {
	if cfg.validated {
		return nil
	}
	if cfg.Name == "" {
		return errors.ErrPortalConfigNameNotFound
	}

	// if len(cfg.IdentityStores) == 0 && len(cfg.IdentityProviders) == 0 {
	//	  return errors.ErrPortalConfigBackendsNotFound
	// }

	if err := cfg.parsePortalRoles(); err != nil {
		return err
	}

	if err := cfg.parseRawCryptoConfigs(); err != nil {
		return err
	}

	for _, redirURIConfig := range cfg.TrustedLogoutRedirectURIConfigs {
		if err := redirURIConfig.Validate(); err != nil {
			return err
		}
	}

	// Inialize user interface settings
	if cfg.UI == nil {
		cfg.UI = &ui.Parameters{}
	}

	if cfg.UI.Templates == nil {
		cfg.UI.Templates = make(map[string]string)
	}

	cfg.validated = true
	return nil
}
