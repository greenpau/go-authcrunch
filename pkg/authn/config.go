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
	// "time"

	"github.com/greenpau/aaasf/pkg/acl"
	"github.com/greenpau/aaasf/pkg/authn/backends"
	// "github.com/greenpau/aaasf/pkg/authn/cache"
	"github.com/greenpau/aaasf/pkg/authn/cookie"
	"github.com/greenpau/aaasf/pkg/authn/registration"
	"github.com/greenpau/aaasf/pkg/authn/transformer"
	"github.com/greenpau/aaasf/pkg/authn/ui"
	"github.com/greenpau/aaasf/pkg/authz/options"
	// "github.com/greenpau/aaasf/pkg/authz/validator"
	"github.com/greenpau/aaasf/pkg/errors"
	"github.com/greenpau/aaasf/pkg/kms"
	cfgutil "github.com/greenpau/aaasf/pkg/util/cfg"
	// "go.uber.org/zap"
	"strings"
)

// PortalConfig TODO
type PortalConfig struct {
	Name string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	// UI holds the configuration for the user interface.
	UI *ui.Parameters `json:"ui,omitempty" xml:"ui,omitempty" yaml:"ui,omitempty"`
	// UserRegistrationConfig holds the configuration for the user registration.
	UserRegistrationConfig *registration.Config `json:"user_registration_config,omitempty" xml:"user_registration_config,omitempty" yaml:"user_registration_config,omitempty"`
	// UserTransformerConfig holds the configuration for the user transformer.
	UserTransformerConfigs []*transformer.Config `json:"user_transformer_configs,omitempty" xml:"user_transformer_configs,omitempty" yaml:"user_transformer_configs,omitempty"`
	// CookieConfig holds the configuration for the cookies issues by Authenticator.
	CookieConfig *cookie.Config `json:"cookie_config,omitempty" xml:"cookie_config,omitempty" yaml:"cookie_config,omitempty"`
	// BackendConfigs hold the configurations for authentication backends.
	BackendConfigs []backends.Config `json:"backend_configs,omitempty" xml:"backend_configs,omitempty" yaml:"backend_configs,omitempty"`
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

	// Holds raw crypto configuration
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

// Validate validates PortalConfig.
func (cfg *PortalConfig) Validate() error {
	if cfg.validated {
		return nil
	}
	if cfg.Name == "" {
		return errors.ErrPortalConfigNameNotFound
	}
	if len(cfg.BackendConfigs) == 0 {
		return errors.ErrPortalConfigBackendsNotFound
	}

	if err := cfg.parseRawCryptoConfigs(); err != nil {
		return err
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
