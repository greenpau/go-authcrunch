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
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
	"strings"
)

// PolicyConfig is Gatekeeper configuration.
type PolicyConfig struct {
	Name                       string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	AuthURLPath                string `json:"auth_url_path,omitempty" xml:"auth_url_path,omitempty" yaml:"auth_url_path,omitempty"`
	AuthRedirectDisabled       bool   `json:"disable_auth_redirect,omitempty" xml:"disable_auth_redirect,omitempty" yaml:"disable_auth_redirect,omitempty"`
	AuthRedirectQueryDisabled  bool   `json:"disable_auth_redirect_query,omitempty" xml:"disable_auth_redirect_query,omitempty" yaml:"disable_auth_redirect_query,omitempty"`
	AuthRedirectQueryParameter string `json:"auth_redirect_query_param,omitempty" xml:"auth_redirect_query_param,omitempty" yaml:"auth_redirect_query_param,omitempty"`
	// The status code for the HTTP redirect for non-authorized users.
	AuthRedirectStatusCode int `json:"auth_redirect_status_code,omitempty" xml:"auth_redirect_status_code,omitempty" yaml:"auth_redirect_status_code,omitempty"`
	// Enable the redirect with Javascript, as opposed to HTTP redirect.
	RedirectWithJavascript bool `json:"redirect_with_javascript,omitempty" xml:"redirect_with_javascript,omitempty" yaml:"redirect_with_javascript,omitempty"`
	// The list of URI prefixes which bypass authorization.
	BypassConfigs []*bypass.Config `json:"bypass_configs,omitempty" xml:"bypass_configs,omitempty" yaml:"bypass_configs,omitempty"`
	// The list of mappings between header names and field names.
	HeaderInjectionConfigs []*injector.Config       `json:"header_injection_configs,omitempty" xml:"header_injection_configs,omitempty" yaml:"header_injection_configs,omitempty"`
	AccessListRules        []*acl.RuleConfiguration `json:"access_list_rules,omitempty" xml:"access_list_rules,omitempty" yaml:"access_list_rules,omitempty"`
	CryptoKeyConfigs       []*kms.CryptoKeyConfig   `json:"crypto_key_configs,omitempty" xml:"crypto_key_configs,omitempty" yaml:"crypto_key_configs,omitempty"`
	// CryptoKeyStoreConfig hold the default configuration for the keys, e.g. token name and lifetime.
	CryptoKeyStoreConfig map[string]interface{} `json:"crypto_key_store_config,omitempty" xml:"crypto_key_store_config,omitempty" yaml:"crypto_key_store_config,omitempty"`
	AuthProxyConfig      *authproxy.Config      `json:"auth_proxy_config,omitempty" xml:"auth_proxy_config,omitempty" yaml:"auth_proxy_config,omitempty"`
	AllowedTokenSources  []string               `json:"allowed_token_sources,omitempty" xml:"allowed_token_sources,omitempty" yaml:"allowed_token_sources,omitempty"`
	StripTokenEnabled    bool                   `json:"strip_token_enabled,omitempty" xml:"strip_token_enabled,omitempty" yaml:"strip_token_enabled,omitempty"`
	ForbiddenURL         string                 `json:"forbidden_url,omitempty" xml:"forbidden_url,omitempty" yaml:"forbidden_url,omitempty"`
	UserIdentityField    string                 `json:"user_identity_field,omitempty" xml:"user_identity_field,omitempty" yaml:"user_identity_field,omitempty"`
	// Validate HTTP Authorization header.
	ValidateBearerHeader bool `json:"validate_bearer_header,omitempty" xml:"validate_bearer_header,omitempty" yaml:"validate_bearer_header,omitempty"`
	// Validate HTTP method and path.
	ValidateMethodPath bool `json:"validate_method_path,omitempty" xml:"validate_method_path,omitempty" yaml:"validate_method_path,omitempty"`
	// Validate HTTP path derived from JWT token.
	ValidateAccessListPathClaim bool `json:"validate_access_list_path_claim,omitempty" xml:"validate_access_list_path_claim,omitempty" yaml:"validate_access_list_path_claim,omitempty"`
	// Validate source address matches between HTTP request and JWT token.
	ValidateSourceAddress bool `json:"validate_source_address,omitempty" xml:"validate_source_address,omitempty" yaml:"validate_source_address,omitempty"`
	// Pass claims from JWT token via HTTP X- headers.
	PassClaimsWithHeaders bool `json:"pass_claims_with_headers,omitempty" xml:"pass_claims_with_headers,omitempty" yaml:"pass_claims_with_headers,omitempty"`
	// Validate the login hint which can be passed to the auth provider
	LoginHintValidators []string `json:"login_hint_validators,omitempty" xml:"login_hint_validators,omitempty" yaml:"login_hint_validators,omitempty"`
	// Allow to append scopes that come from the query parameter 'additionalScopes'
	AdditionalScopes bool `json:"additional_scopes,omitempty" xml:"additional_scopes,omitempty" yaml:"additional_scopes,omitempty"`
	// Holds raw crypto configuration.
	cryptoRawConfigs []string
	// Holds raw identity provider configuration.
	authProxyRawConfig []string

	// Indicated that the config was successfully validated.
	validated bool
}

// AddRawCryptoConfigs adds raw crypto configs.
func (cfg *PolicyConfig) AddRawCryptoConfigs(s string) {
	cfg.cryptoRawConfigs = append(cfg.cryptoRawConfigs, s)
}

// AddRawIdpConfig add raw identity provider configs.
func (cfg *PolicyConfig) AddRawIdpConfig(s string) {
	cfg.authProxyRawConfig = append(cfg.authProxyRawConfig, s)
}

// parseRawCryptoConfigs parses raw crypto configs into CryptoKeyConfigs
// and CryptoKeyStoreConfig.
func (cfg *PolicyConfig) parseRawCryptoConfigs() error {
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

// parseRawAuthProxyConfig parses raw auth proxy configs
// into AuthProxyConfig.
func (cfg *PolicyConfig) parseRawAuthProxyConfig() error {
	if len(cfg.authProxyRawConfig) > 0 {
		config, err := authproxy.ParseConfig(cfg.authProxyRawConfig)
		if err != nil {
			return errors.ErrConfigDirectiveFail.WithArgs("authproxy", cfg.authProxyRawConfig, err)
		}
		cfg.AuthProxyConfig = config
	}
	return nil
}

// Validate validates PolicyConfig.
func (cfg *PolicyConfig) Validate() error {
	if cfg.validated {
		return nil
	}
	if cfg.Name == "" {
		return errors.ErrPolicyConfigNameNotFound
	}
	if err := cfg.parseRawCryptoConfigs(); err != nil {
		return err
	}
	if err := cfg.parseRawAuthProxyConfig(); err != nil {
		return err
	}

	// Set authentication redirect URL.
	if cfg.AuthURLPath == "" {
		cfg.AuthURLPath = "/auth"
	}

	// Set authentication redirect URI parameter.
	if cfg.AuthRedirectQueryParameter == "" {
		cfg.AuthRedirectQueryParameter = "redirect_url"
	}

	// Set authentication redirect status code value.
	if cfg.AuthRedirectStatusCode == 0 {
		cfg.AuthRedirectStatusCode = 302
	}

	// Validate bypass URLs, if necessary.
	for _, entry := range cfg.BypassConfigs {
		if err := entry.Validate(); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(cfg.Name, err)
		}
	}

	// Validate header injection configs.
	for _, entry := range cfg.HeaderInjectionConfigs {
		if err := entry.Validate(); err != nil {
			return errors.ErrInvalidConfiguration.WithArgs(cfg.Name, err)
		}
		// cfg.PassClaimsWithHeaders = true
	}

	if len(cfg.AccessListRules) == 0 {
		return errors.ErrInvalidConfiguration.WithArgs(cfg.Name, "access list rule config not found")
	}

	accessList := acl.NewAccessList()
	accessList.SetLogger(logutil.NewLogger())
	if err := accessList.AddRules(context.Background(), cfg.AccessListRules); err != nil {
		return errors.ErrInvalidConfiguration.WithArgs(cfg.Name, err)
	}

	cfg.validated = true
	return nil
}
