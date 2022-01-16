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
	"github.com/greenpau/aaasf/pkg/kms"
	// "go.uber.org/zap"
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
}
