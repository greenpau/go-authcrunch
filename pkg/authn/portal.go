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
	"context"
	"github.com/greenpau/aaasf/pkg/acl"
	"github.com/greenpau/aaasf/pkg/authn/backends"
	"github.com/greenpau/aaasf/pkg/authn/cache"
	"github.com/greenpau/aaasf/pkg/authn/cookie"
	"github.com/greenpau/aaasf/pkg/authn/transformer"
	"github.com/greenpau/aaasf/pkg/authn/ui"
	"github.com/greenpau/aaasf/pkg/authz/options"
	"github.com/greenpau/aaasf/pkg/authz/validator"
	"github.com/greenpau/aaasf/pkg/errors"
	"github.com/greenpau/aaasf/pkg/identity"
	"github.com/greenpau/aaasf/pkg/kms"

	"go.uber.org/zap"
	"path"
	"strings"
	"time"
)

const (
	defaultPortalACLCondition = "match roles authp/admin authp/user authp/guest superuser superadmin"
	defaultPortalACLAction    = "allow stop"
)

// Portal is an authentication portal.
type Portal struct {
	config       *PortalConfig
	registrar    *identity.Database
	validator    *validator.TokenValidator
	keystore     *kms.CryptoKeyStore
	backends     []*backends.Backend
	cookie       *cookie.Factory
	transformer  *transformer.Factory
	ui           *ui.Factory
	startedAt    time.Time
	sessions     *cache.SessionCache
	sandboxes    *cache.SandboxCache
	loginOptions map[string]interface{}
	logger       *zap.Logger
}

// NewPortal returns an instance of Portal.
func NewPortal(cfg *PortalConfig, logger *zap.Logger) (*Portal, error) {
	if logger == nil {
		return nil, errors.ErrNewPortalLoggerNil
	}
	if cfg == nil {
		return nil, errors.ErrNewPortalConfigNil
	}
	if err := cfg.Validate(); err != nil {
		return nil, errors.ErrNewPortal.WithArgs(err)
	}
	p := &Portal{
		config: cfg,
		logger: logger,
	}
	if err := p.configure(); err != nil {
		return nil, err
	}
	return p, nil
}

// Register registers the Portal with PortalRegistry.
func (p *Portal) Register() error {
	return portalRegistry.Register(p.config.Name, p)
}

func (p *Portal) configure() error {
	if err := p.configureEssentials(); err != nil {
		return err
	}
	if err := p.configureCryptoKeyStore(); err != nil {
		return err
	}
	if err := p.configureBackends(); err != nil {
		return err
	}
	if err := p.configureUserRegistration(); err != nil {
		return err
	}
	if err := p.configureUserInterface(); err != nil {
		return err
	}
	if err := p.configureUserTransformer(); err != nil {
		return err
	}
	return nil
}

func (p *Portal) configureEssentials() error {
	p.logger.Debug(
		"Configuring caching",
		zap.String("portal_name", p.config.Name),
	)

	p.sessions = cache.NewSessionCache()
	p.sessions.Run()
	p.sandboxes = cache.NewSandboxCache()
	p.sandboxes.Run()

	p.logger.Debug(
		"Configuring cookie parameters",
		zap.String("portal_name", p.config.Name),
	)

	c, err := cookie.NewFactory(p.config.CookieConfig)
	if err != nil {
		return err
	}
	p.cookie = c
	return nil
}

func (p *Portal) configureCryptoKeyStore() error {
	if len(p.config.AccessListConfigs) == 0 {
		p.config.AccessListConfigs = []*acl.RuleConfiguration{
			{
				// Admin users can access everything.
				Conditions: []string{defaultPortalACLCondition},
				Action:     defaultPortalACLAction,
			},
		}
	}

	p.logger.Debug(
		"Configuring authentication ACL",
		zap.String("portal_name", p.config.Name),
		zap.Any("access_list_configs", p.config.AccessListConfigs),
	)

	if p.config.TokenValidatorOptions == nil {
		p.config.TokenValidatorOptions = options.NewTokenValidatorOptions()
	}
	p.config.TokenValidatorOptions.ValidateBearerHeader = true

	// The below line is disabled because path match is not part of the ACL.
	// p.config.TokenValidatorOptions.ValidateMethodPath = true

	accessList := acl.NewAccessList()
	accessList.SetLogger(p.logger)
	ctx := context.Background()
	if err := accessList.AddRules(ctx, p.config.AccessListConfigs); err != nil {
		return errors.ErrCryptoKeyStoreConfig.WithArgs(p.config.Name, err)
	}

	p.keystore = kms.NewCryptoKeyStore()
	p.keystore.SetLogger(p.logger)

	// Load token configuration into key managers, extract token verification
	// keys and add them to token validator.
	if p.config.CryptoKeyStoreConfig != nil {
		// Add default token name, lifetime, etc.
		if err := p.keystore.AddDefaults(p.config.CryptoKeyStoreConfig); err != nil {
			return errors.ErrCryptoKeyStoreConfig.WithArgs(p.config.Name, err)
		}
	}

	if len(p.config.CryptoKeyConfigs) == 0 {
		if err := p.keystore.AutoGenerate("default", "ES512"); err != nil {
			return errors.ErrCryptoKeyStoreConfig.WithArgs(p.config.Name, err)
		}
	} else {
		if err := p.keystore.AddKeysWithConfigs(p.config.CryptoKeyConfigs); err != nil {
			return errors.ErrCryptoKeyStoreConfig.WithArgs(p.config.Name, err)
		}
	}

	if err := p.keystore.HasVerifyKeys(); err != nil {
		return errors.ErrCryptoKeyStoreConfig.WithArgs(p.config.Name, err)
	}

	p.validator = validator.NewTokenValidator()
	if err := p.validator.Configure(ctx, p.keystore.GetVerifyKeys(), accessList, p.config.TokenValidatorOptions); err != nil {
		return errors.ErrCryptoKeyStoreConfig.WithArgs(p.config.Name, err)
	}

	p.logger.Debug(
		"Configured validator ACL",
		zap.String("instance_name", p.config.Name),
		zap.Any("token_validator_options", p.config.TokenValidatorOptions),
		zap.Any("token_grantor_options", p.config.TokenGrantorOptions),
	)
	return nil
}

func (p *Portal) configureBackends() error {
	p.logger.Debug(
		"Configuring authentication backends",
		zap.String("portal_name", p.config.Name),
		zap.Int("backend_count", len(p.config.BackendConfigs)),
	)

	if len(p.config.BackendConfigs) == 0 {
		return errors.ErrNoBackendsFound.WithArgs(p.config.Name)
	}

	backendNameRef := make(map[string]interface{})
	var loginRealms []map[string]string
	var externalLoginProviders []map[string]string

	p.loginOptions = make(map[string]interface{})
	p.loginOptions["form_required"] = "no"
	p.loginOptions["realm_dropdown_required"] = "no"
	p.loginOptions["identity_required"] = "no"
	p.loginOptions["external_providers_required"] = "no"
	p.loginOptions["registration_required"] = "no"
	p.loginOptions["password_recovery_required"] = "no"

	for _, cfg := range p.config.BackendConfigs {
		backend, err := backends.NewBackend(&cfg, p.logger)
		if err != nil {
			return errors.ErrBackendConfigurationFailed.WithArgs(p.config.Name, err)
		}
		if err := backend.Configure(); err != nil {
			return errors.ErrBackendConfigurationFailed.WithArgs(p.config.Name, err)
		}
		if err := backend.Validate(); err != nil {
			return errors.ErrBackendValidationFailed.WithArgs(p.config.Name, err)
		}
		backendName := backend.GetName()

		if _, exists := backendNameRef[backendName]; exists {
			return errors.ErrDuplicateBackendName.WithArgs(backendName, p.config.Name)
		}
		backendNameRef[backendName] = true
		backendRealm := backend.GetRealm()
		backendMethod := backend.GetMethod()
		if backendMethod == "local" || backendMethod == "ldap" {
			loginRealm := make(map[string]string)
			loginRealm["realm"] = backendRealm
			loginRealm["default"] = "no"
			if backendMethod == "ldap" {
				loginRealm["label"] = strings.ToUpper(backendRealm)
			} else {
				loginRealm["label"] = strings.ToTitle(backendRealm)
				loginRealm["default"] = "yes"
			}
			loginRealms = append(loginRealms, loginRealm)
		}
		if backendMethod != "local" && backendMethod != "ldap" {
			externalLoginProvider := make(map[string]string)
			externalLoginProvider["endpoint"] = path.Join(backendMethod, backendRealm)
			externalLoginProvider["icon"] = backendMethod
			externalLoginProvider["realm"] = backendRealm
			switch backendRealm {
			case "google":
				externalLoginProvider["icon"] = "google"
				externalLoginProvider["text"] = "Google"
				externalLoginProvider["color"] = "red darken-1"
			case "facebook":
				externalLoginProvider["icon"] = "facebook"
				externalLoginProvider["text"] = "Facebook"
				externalLoginProvider["color"] = "blue darken-4"
			case "twitter":
				externalLoginProvider["icon"] = "twitter"
				externalLoginProvider["text"] = "Twitter"
				externalLoginProvider["color"] = "blue darken-1"
			case "linkedin":
				externalLoginProvider["icon"] = "linkedin"
				externalLoginProvider["text"] = "LinkedIn"
				externalLoginProvider["color"] = "blue darken-1"
			case "github":
				externalLoginProvider["icon"] = "github"
				externalLoginProvider["text"] = "Github"
				externalLoginProvider["color"] = "grey darken-3"
			case "windows":
				externalLoginProvider["icon"] = "windows"
				externalLoginProvider["text"] = "Microsoft"
				externalLoginProvider["color"] = "orange darken-1"
			case "azure":
				externalLoginProvider["icon"] = "windows"
				externalLoginProvider["text"] = "Azure"
				externalLoginProvider["color"] = "blue"
			case "aws", "amazon":
				externalLoginProvider["icon"] = "aws"
				externalLoginProvider["text"] = "AWS"
				externalLoginProvider["color"] = "blue-grey darken-2"
			default:
				externalLoginProvider["icon"] = "codepen"
				externalLoginProvider["text"] = backendRealm
				externalLoginProvider["color"] = "grey darken-3"
			}
			externalLoginProviders = append(externalLoginProviders, externalLoginProvider)
		}
		p.backends = append(p.backends, backend)
		p.logger.Debug(
			"Provisioned authentication backend",
			zap.String("portal_name", p.config.Name),
			zap.String("backend_name", backendName),
			zap.String("backend_type", backendMethod),
			zap.String("backend_realm", backendRealm),
		)
	}

	if len(loginRealms) > 0 {
		p.loginOptions["form_required"] = "yes"
		p.loginOptions["identity_required"] = "yes"
		p.loginOptions["realms"] = loginRealms
	}
	if len(loginRealms) > 1 {
		p.loginOptions["realm_dropdown_required"] = "yes"
	}
	if len(externalLoginProviders) > 0 {
		p.loginOptions["external_providers_required"] = "yes"
		p.loginOptions["external_providers"] = externalLoginProviders
	}

	p.logger.Debug(
		"Provisioned login options",
		zap.String("portal_name", p.config.Name),
		zap.Any("options", p.loginOptions),
	)
	return nil
}

func (p *Portal) configureUserRegistration() error {
	if p.config.UserRegistrationConfig == nil {
		return nil
	}
	if p.config.UserRegistrationConfig.Dropbox == "" {
		return nil
	}

	p.logger.Debug(
		"Configuring user registration",
		zap.String("portal_name", p.config.Name),
		zap.Int("backend_count", len(p.config.BackendConfigs)),
	)

	p.loginOptions["registration_required"] = "yes"

	if p.config.UserRegistrationConfig.Title == "" {
		p.config.UserRegistrationConfig.Title = "Sign Up"
	}

	db, err := identity.NewDatabase(p.config.UserRegistrationConfig.Dropbox)
	if err != nil {
		return errors.ErrUserRegistrationConfig.WithArgs(p.config.Name, err)
	}
	p.registrar = db

	p.logger.Debug(
		"Configured user registration",
		zap.String("portal_name", p.config.Name),
		zap.String("dropbox", p.config.UserRegistrationConfig.Dropbox),
	)
	return nil
}

func (p *Portal) configureUserInterface() error {
	p.logger.Debug(
		"Configuring user interface",
		zap.String("portal_name", p.config.Name),
	)

	p.ui = ui.NewFactory()
	if p.config.UI.Title == "" {
		p.ui.Title = "Sign In"
	} else {
		p.ui.Title = p.config.UI.Title
	}

	if p.config.UI.CustomCSSPath != "" {
		p.ui.CustomCSSPath = p.config.UI.CustomCSSPath
		if err := ui.StaticAssets.AddAsset("assets/css/custop.css", "text/css", p.config.UI.CustomCSSPath); err != nil {
			return errors.ErrStaticAssetAddFailed.WithArgs("assets/css/custop.css", "text/css", p.config.UI.CustomCSSPath, p.config.Name, err)
		}
	}

	if p.config.UI.CustomJsPath != "" {
		p.ui.CustomJsPath = p.config.UI.CustomJsPath
		if err := ui.StaticAssets.AddAsset("assets/js/custop.js", "application/javascript", p.config.UI.CustomJsPath); err != nil {
			return errors.ErrStaticAssetAddFailed.WithArgs("assets/js/custop.js", "application/javascript", p.config.UI.CustomJsPath, p.config.Name, err)
		}
	}

	if p.config.UI.LogoURL != "" {
		p.ui.LogoURL = p.config.UI.LogoURL
		p.ui.LogoDescription = p.config.UI.LogoDescription
	} else {
		p.ui.LogoURL = path.Join(p.ui.LogoURL)
	}

	if len(p.config.UI.PrivateLinks) > 0 {
		p.ui.PrivateLinks = p.config.UI.PrivateLinks
	}

	if len(p.config.UI.Realms) > 0 {
		p.ui.Realms = p.config.UI.Realms
	}

	if p.config.UI.Theme == "" {
		p.config.UI.Theme = "basic"
	}
	if _, exists := ui.Themes[p.config.UI.Theme]; !exists {
		return errors.ErrUserInterfaceThemeNotFound.WithArgs(p.config.Name, p.config.UI.Theme)
	}

	if p.config.UI.PasswordRecoveryEnabled {
		p.loginOptions["password_recovery_required"] = "yes"
	}

	p.logger.Debug(
		"Configured user interface",
		zap.String("portal_name", p.config.Name),
		zap.String("title", p.ui.Title),
		zap.String("logo_url", p.ui.LogoURL),
		zap.String("logo_description", p.ui.LogoDescription),
		zap.Any("action_endpoint", p.ui.ActionEndpoint),
		zap.Any("private_links", p.ui.PrivateLinks),
		zap.Any("realms", p.ui.Realms),
		zap.String("theme", p.config.UI.Theme),
	)

	// User Interface Templates
	for k := range ui.PageTemplates {
		tmplNameParts := strings.SplitN(k, "/", 2)
		tmplTheme := tmplNameParts[0]
		tmplName := tmplNameParts[1]
		if tmplTheme != p.config.UI.Theme {
			continue
		}
		if _, exists := p.config.UI.Templates[tmplName]; !exists {
			p.logger.Debug(
				"Configuring default authentication user interface templates",
				zap.String("portal_name", p.config.Name),
				zap.String("template_theme", tmplTheme),
				zap.String("template_name", tmplName),
			)
			if err := p.ui.AddBuiltinTemplate(k); err != nil {
				return errors.ErrUserInterfaceBuiltinTemplateAddFailed.WithArgs(p.config.Name, tmplName, tmplTheme, err)
			}
			p.ui.Templates[tmplName] = p.ui.Templates[k]
		}
	}

	for tmplName, tmplPath := range p.config.UI.Templates {
		p.logger.Debug(
			"Configuring non-default authentication user interface templates",
			zap.String("portal_name", p.config.Name),
			zap.String("template_name", tmplName),
			zap.String("template_path", tmplPath),
		)
		if err := p.ui.AddTemplate(tmplName, tmplPath); err != nil {
			return errors.ErrUserInterfaceCustomTemplateAddFailed.WithArgs(p.config.Name, tmplName, tmplPath, err)
		}
	}

	p.logger.Debug(
		"Configured user interface",
		zap.String("portal_name", p.config.Name),
		zap.String("title", p.ui.Title),
		zap.String("logo_url", p.ui.LogoURL),
		zap.String("logo_description", p.ui.LogoDescription),
		zap.Any("action_endpoint", p.ui.ActionEndpoint),
		zap.Any("private_links", p.ui.PrivateLinks),
		zap.Any("realms", p.ui.Realms),
		zap.String("theme", p.config.UI.Theme),
	)

	return nil
}

func (p *Portal) configureUserTransformer() error {
	if len(p.config.UserTransformerConfigs) == 0 {
		return nil
	}

	p.logger.Debug(
		"Configuring user transforms",
		zap.String("portal_name", p.config.Name),
	)

	tr, err := transformer.NewFactory(p.config.UserTransformerConfigs)
	if err != nil {
		return err
	}
	p.transformer = tr

	p.logger.Debug(
		"Configured user transforms",
		zap.String("portal_name", p.config.Name),
		zap.Any("transforms", p.config.UserTransformerConfigs),
	)
	return nil
}
