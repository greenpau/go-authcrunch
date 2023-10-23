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
	"os"
	"sort"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/cache"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/sso"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"

	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	defaultPortalACLCondition = "match roles authp/admin authp/user authp/guest superuser superadmin"
	defaultPortalACLAction    = "allow stop"
)

// Portal is an authentication portal.
type Portal struct {
	id                string
	config            *PortalConfig
	userRegistry      registry.UserRegistry
	validator         *validator.TokenValidator
	keystore          *kms.CryptoKeyStore
	identityStores    []ids.IdentityStore
	identityProviders []idp.IdentityProvider
	ssoProviders      []sso.SingleSignOnProvider
	cookie            *cookie.Factory
	transformer       *transformer.Factory
	ui                *ui.Factory
	startedAt         time.Time
	sessions          *cache.SessionCache
	sandboxes         *cache.SandboxCache
	loginOptions      map[string]interface{}
	logger            *zap.Logger
}

// PortalParameters are input parameters for NewPortal.
type PortalParameters struct {
	Config                *PortalConfig              `json:"config,omitempty" xml:"config,omitempty" yaml:"config,omitempty"`
	Logger                *zap.Logger                `json:"logger,omitempty" xml:"logger,omitempty" yaml:"logger,omitempty"`
	IdentityStores        []ids.IdentityStore        `json:"identity_stores,omitempty" xml:"identity_stores,omitempty" yaml:"identity_stores,omitempty"`
	IdentityProviders     []idp.IdentityProvider     `json:"identity_providers,omitempty" xml:"identity_providers,omitempty" yaml:"identity_providers,omitempty"`
	SingleSignOnProviders []sso.SingleSignOnProvider `json:"sso_providers,omitempty" xml:"sso_providers,omitempty" yaml:"sso_providers,omitempty"`
}

// NewPortal returns an instance of Portal.
func NewPortal(params PortalParameters) (*Portal, error) {
	if params.Logger == nil {
		return nil, errors.ErrNewPortalLoggerNil
	}
	if params.Config == nil {
		return nil, errors.ErrNewPortalConfigNil
	}

	if err := params.Config.Validate(); err != nil {
		return nil, errors.ErrNewPortal.WithArgs(err)
	}
	p := &Portal{
		id:     uuid.New().String(),
		config: params.Config,
		logger: params.Logger,
	}

	for _, storeName := range params.Config.IdentityStores {
		var storeFound bool
		for _, store := range params.IdentityStores {
			if store.GetName() == storeName {
				if !store.Configured() {
					return nil, errors.ErrNewPortal.WithArgs(
						fmt.Errorf("identity store %q not configured", storeName),
					)
				}
				p.identityStores = append(p.identityStores, store)
				storeFound = true
				break
			}
		}
		if !storeFound {
			return nil, errors.ErrNewPortal.WithArgs(
				fmt.Errorf("identity store %q not found", storeName),
			)
		}
	}

	for _, providerName := range params.Config.IdentityProviders {
		var providerFound bool
		for _, provider := range params.IdentityProviders {
			if provider.GetName() == providerName {
				if !provider.Configured() {
					return nil, errors.ErrNewPortal.WithArgs(
						fmt.Errorf("identity provider %q not configured", providerName),
					)
				}
				p.identityProviders = append(p.identityProviders, provider)
				providerFound = true
				break
			}
		}
		if !providerFound {
			return nil, errors.ErrNewPortal.WithArgs(
				fmt.Errorf("identity provider %q not found", providerName),
			)
		}
	}

	for _, providerName := range params.Config.SingleSignOnProviders {
		var providerFound bool
		for _, provider := range params.SingleSignOnProviders {
			if provider.GetName() == providerName {
				if !provider.Configured() {
					return nil, errors.ErrNewPortal.WithArgs(
						fmt.Errorf("sso provider %q not configured", providerName),
					)
				}
				p.ssoProviders = append(p.ssoProviders, provider)
				providerFound = true
				break
			}
		}
		if !providerFound {
			return nil, errors.ErrNewPortal.WithArgs(
				fmt.Errorf("sso provider %q not found", providerName),
			)
		}
	}

	if len(p.identityStores) < 1 && len(p.identityProviders) < 1 {
		return nil, errors.ErrNewPortal.WithArgs(errors.ErrPortalConfigBackendsNotFound)
	}

	if err := p.configure(); err != nil {
		return nil, err
	}
	return p, nil
}

// GetName returns the configuration name of the Portal.
func (p *Portal) GetName() string {
	return p.config.Name
}

func (p *Portal) configure() error {
	if err := p.configureEssentials(); err != nil {
		return err
	}
	if err := p.configureCryptoKeyStore(); err != nil {
		return err
	}
	if err := p.configureLoginOptions(); err != nil {
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
		zap.String("portal_id", p.id),
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
		zap.String("portal_id", p.id),
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
		zap.String("portal_name", p.config.Name),
		zap.String("portal_id", p.id),
		zap.Any("token_validator_options", p.config.TokenValidatorOptions),
		zap.Any("token_grantor_options", p.config.TokenGrantorOptions),
	)
	return nil
}

func (p *Portal) configureLoginOptions() error {
	p.loginOptions = make(map[string]interface{})
	p.loginOptions["form_required"] = "no"
	p.loginOptions["realm_dropdown_required"] = "no"
	p.loginOptions["authenticators_required"] = "no"
	p.loginOptions["identity_required"] = "no"

	if err := p.configureIdentityStoreLogin(); err != nil {
		return err
	}

	if err := p.configureIdentityProviderLogin(); err != nil {
		return err
	}

	if err := p.configureLoginIcons(); err != nil {
		return err
	}

	p.logger.Debug(
		"Provisioned login options",
		zap.String("portal_name", p.config.Name),
		zap.String("portal_id", p.id),
		zap.Any("options", p.loginOptions),
		zap.Int("identity_store_count", len(p.config.IdentityStores)),
		zap.Int("identity_provider_count", len(p.config.IdentityProviders)),
	)

	return nil
}

func (p *Portal) configureLoginIcons() error {
	var entries []*icons.LoginIcon

	for _, store := range p.identityStores {
		icon := store.GetLoginIcon()
		entries = append(entries, icon)
	}

	for _, provider := range p.identityProviders {
		icon := provider.GetLoginIcon()
		entries = append(entries, icon)
	}

	sort.Slice(entries[:], func(i, j int) bool {
		return entries[i].Priority > entries[j].Priority
	})

	var iconConfigs []map[string]string

	for i, icon := range entries {
		iconConfig := icon.GetConfig()
		iconConfigs = append(iconConfigs, iconConfig)
		if i == 0 {
			p.loginOptions["default_realm"] = iconConfig["realm"]
		}
	}

	p.loginOptions["authenticators"] = iconConfigs

	if len(iconConfigs) == 1 {
		p.loginOptions["hide_contact_support_link"] = "yes"
		p.loginOptions["hide_forgot_username_link"] = "yes"
		p.loginOptions["hide_register_link"] = "yes"
		p.loginOptions["hide_links"] = "yes"
		for _, iconConfig := range iconConfigs {
			if v, exists := iconConfig["contact_support_enabled"]; exists && v == "yes" {
				p.loginOptions["hide_contact_support_link"] = "no"
				p.loginOptions["hide_links"] = "no"
			}
			if v, exists := iconConfig["registration_enabled"]; exists && v == "yes" {
				p.loginOptions["hide_register_link"] = "no"
				p.loginOptions["hide_links"] = "no"
			}
			if v, exists := iconConfig["username_recovery_enabled"]; exists && v == "yes" {
				p.loginOptions["hide_forgot_username_link"] = "no"
				p.loginOptions["hide_links"] = "no"
			}
		}
	}

	return nil
}

func (p *Portal) configureIdentityStoreLogin() error {
	if len(p.config.IdentityStores) < 1 {
		return nil
	}

	p.logger.Debug(
		"Configuring identity store login options",
		zap.String("portal_name", p.config.Name),
		zap.String("portal_id", p.id),
		zap.Int("identity_store_count", len(p.config.IdentityStores)),
	)

	var stores []map[string]string

	for _, store := range p.identityStores {
		cfg := make(map[string]string)
		cfg["realm"] = store.GetRealm()
		cfg["default"] = "no"
		switch store.GetKind() {
		case "local":
			cfg["label"] = strings.ToTitle(store.GetRealm())
			cfg["default"] = "yes"
		case "ldap":
			cfg["label"] = strings.ToUpper(store.GetRealm())
		default:
			cfg["label"] = strings.ToTitle(store.GetRealm())
		}
		stores = append(stores, cfg)
	}

	if len(stores) > 0 {
		p.loginOptions["form_required"] = "yes"
		p.loginOptions["identity_required"] = "yes"
		p.loginOptions["realms"] = stores
	}

	if len(stores) > 1 {
		p.loginOptions["realm_dropdown_required"] = "yes"
		p.loginOptions["authenticators_required"] = "yes"
	}

	for _, store := range p.identityStores {
		icon := store.GetLoginIcon()
		icon.SetRealm(store.GetRealm())
		switch store.GetKind() {
		case "local":
			icon.RegistrationEnabled = false
			icon.UsernameRecoveryEnabled = false
		case "ldap":
			icon.RegistrationEnabled = false
			icon.UsernameRecoveryEnabled = false
		}
	}

	return nil
}

func (p *Portal) configureIdentityProviderLogin() error {
	if len(p.config.IdentityProviders) < 1 {
		return nil
	}

	p.logger.Debug(
		"Configuring identity provider login options",
		zap.String("portal_name", p.config.Name),
		zap.String("portal_id", p.id),
		zap.Int("identity_provider_count", len(p.config.IdentityProviders)),
	)

	for _, provider := range p.identityProviders {
		icon := provider.GetLoginIcon()
		icon.SetRealm(provider.GetRealm())
		switch provider.GetKind() {
		case "oauth":
			icon.SetEndpoint(path.Join(provider.GetKind()+"2", provider.GetRealm()))
		default:
			icon.SetEndpoint(path.Join(provider.GetKind(), provider.GetRealm()))
		}
	}

	p.loginOptions["authenticators_required"] = "yes"

	return nil
}

func (p *Portal) configureUserInterface() error {
	p.logger.Debug(
		"Configuring user interface",
		zap.String("portal_name", p.config.Name),
		zap.String("portal_id", p.id),
	)

	p.ui = ui.NewFactory()
	if p.config.UI.Title == "" {
		p.ui.Title = "Sign In"
	} else {
		p.ui.Title = p.config.UI.Title
	}

	if p.config.UI.CustomCSSPath != "" {
		p.ui.CustomCSSPath = p.config.UI.CustomCSSPath
		if err := ui.StaticAssets.AddAsset("assets/css/custom.css", "text/css", p.config.UI.CustomCSSPath); err != nil {
			return errors.ErrStaticAssetAddFailed.WithArgs("assets/css/custom.css", "text/css", p.config.UI.CustomCSSPath, p.config.Name, err)
		}
	}

	if p.config.UI.CustomJsPath != "" {
		p.ui.CustomJsPath = p.config.UI.CustomJsPath
		if err := ui.StaticAssets.AddAsset("assets/js/custom.js", "application/javascript", p.config.UI.CustomJsPath); err != nil {
			return errors.ErrStaticAssetAddFailed.WithArgs("assets/js/custom.js", "application/javascript", p.config.UI.CustomJsPath, p.config.Name, err)
		}
	}

	if p.config.UI.CustomHTMLHeaderPath != "" {
		b, err := os.ReadFile(p.config.UI.CustomHTMLHeaderPath)
		if err != nil {
			return errors.ErrCustomHTMLHeaderNotReadable.WithArgs(p.config.UI.CustomHTMLHeaderPath, p.config.Name, err)
		}
		for k, v := range ui.PageTemplates {
			headIndex := strings.Index(v, "<meta name=\"description\"")
			if headIndex < 1 {
				continue
			}
			v = v[:headIndex] + string(b) + v[headIndex:]
			ui.PageTemplates[k] = v
		}
	}

	for _, staticAsset := range p.config.UI.StaticAssets {
		if err := ui.StaticAssets.AddAsset(staticAsset.Path, staticAsset.ContentType, staticAsset.FsPath); err != nil {
			return errors.ErrStaticAssetAddFailed.WithArgs(staticAsset.Path, staticAsset.ContentType, staticAsset.FsPath, p.config.Name, err)
		}
	}

	if p.config.UI.LogoURL != "" {
		p.ui.LogoURL = p.config.UI.LogoURL
		p.ui.LogoDescription = p.config.UI.LogoDescription
	} else {
		p.ui.LogoURL = path.Join(p.ui.LogoURL)
	}

	if p.config.UI.MetaTitle != "" {
		p.ui.MetaTitle = p.config.UI.MetaTitle
	} else {
		p.ui.MetaTitle = "Authentication Portal"
	}

	if p.config.UI.MetaAuthor != "" {
		p.ui.MetaAuthor = p.config.UI.MetaAuthor
	} else {
		p.ui.MetaAuthor = "Paul Greenberg github.com/greenpau"
	}

	if p.config.UI.MetaDescription != "" {
		p.ui.MetaDescription = p.config.UI.MetaDescription
	} else {
		p.ui.MetaDescription = "Performs user authentication."
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
			zap.String("portal_id", p.id),
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
		zap.String("portal_id", p.id),
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
		zap.String("portal_id", p.id),
	)

	tr, err := transformer.NewFactory(p.config.UserTransformerConfigs)
	if err != nil {
		return err
	}
	p.transformer = tr

	p.logger.Debug(
		"Configured user transforms",
		zap.String("portal_name", p.config.Name),
		zap.String("portal_id", p.id),
		zap.Any("transforms", p.config.UserTransformerConfigs),
	)
	return nil
}

// AddUserRegistry adds registry.UserRegistry instance to Portal.
func (p *Portal) AddUserRegistry(userRegistry registry.UserRegistry) error {
	p.config.UserRegistries = cfgutil.DedupStrArr(p.config.UserRegistries)

	if len(p.config.UserRegistries) < 1 {
		return fmt.Errorf("auth portal has no user registries configured")
	}
	if len(p.config.UserRegistries) > 1 {
		return fmt.Errorf("auth portal does not support multiple user registries: %v", p.config.UserRegistries)
	}

	p.userRegistry = userRegistry

	p.logger.Debug(
		"Configured user registration",
		zap.String("portal_name", p.config.Name),
		zap.String("portal_id", p.id),
		zap.Any("user_registry", p.userRegistry.GetConfig()),
	)

	return nil
}

// GetIdentityStoreNames returns a list of existing identity stores.
func (p *Portal) GetIdentityStoreNames() map[string]string {
	var m map[string]string
	for _, store := range p.identityStores {
		if m == nil {
			m = make(map[string]string)
		}
		m[store.GetName()] = store.GetRealm()
	}
	return m
}
