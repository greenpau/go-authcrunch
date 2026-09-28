// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package httpserver

import (
	"fmt"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

type initializationError struct{ cause error }

func (e *initializationError) Error() string {
	return "initialize AuthCrunch runtime: check security configuration and required resources (details withheld because they may contain credentials)"
}

func (e *initializationError) Unwrap() error { return e.cause }

// The legacy KMS decoder indexes the directive's first two tokens before its
// semantic checks. Reject incomplete records before invoking that decoder.
func validateCryptoStatements(statements []string) error {
	for i, statement := range statements {
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) < 2 {
			return fmt.Errorf("invalid crypto configuration statement %d", i+1)
		}
	}
	return nil
}

// Serialized collections represent concrete objects, but JSON also permits
// null entries. Several existing component validators dereference those entries.
// Check the typed JSON model without reflection, leaving optional fields nil
// and opaque provider parameters to their owning validators. The test suite
// discovers every serialized collection to keep this traversal complete as the
// model evolves. Do not include map keys or configuration values in errors.
func validateConfigurationObjects(config *authcrunch.Config) error {
	if config == nil {
		return nil
	}
	for _, err := range []error{
		validateObjectList(config.AuthenticationPortals, "security.authentication_portals"),
		validateObjectList(config.AuthorizationPolicies, "security.authorization_policies"),
		validateObjectList(config.IdentityStores, "security.identity_stores"),
		validateObjectList(config.IdentityProviders, "security.identity_providers"),
		validateObjectList(config.SingleSignOnProviders, "security.sso_providers"),
		validateObjectList(config.OAuthApplications, "security.oauth_applications"),
	} {
		if err != nil {
			return err
		}
	}
	if config.Credentials != nil {
		if err := validateObjectList(config.Credentials.Generic, "security.credentials.generic"); err != nil {
			return err
		}
	}
	if config.Messaging != nil {
		if err := validateObjectList(config.Messaging.EmailProviders, "security.messaging.email_providers"); err != nil {
			return err
		}
		if err := validateObjectList(config.Messaging.FileProviders, "security.messaging.file_providers"); err != nil {
			return err
		}
	}
	if config.UserRegistration != nil {
		if err := validateObjectList(config.UserRegistration.LocalProviders, "security.user_registration.local_providers"); err != nil {
			return err
		}
	}
	for _, portal := range config.AuthenticationPortals {
		if err := validatePortalObjects(portal); err != nil {
			return err
		}
	}
	for _, policy := range config.AuthorizationPolicies {
		if err := validatePolicyObjects(policy); err != nil {
			return err
		}
	}
	return nil
}

func validateObjectList[T any](entries []*T, location string) error {
	for i, entry := range entries {
		if entry == nil {
			return fmt.Errorf("%s[%d] must not be null", location, i)
		}
	}
	return nil
}

func validateObjectMap[T any](entries map[string]*T, location string) error {
	for _, entry := range entries {
		if entry == nil {
			return fmt.Errorf("%s contains a null object", location)
		}
	}
	return nil
}

func validatePortalObjects(portal *authn.PortalConfig) error {
	const location = "security.authentication_portals."
	for _, err := range []error{
		validateObjectList(portal.UserTransformerConfigs, location+"user_transformer_configs"),
		validateObjectList(portal.AccessListConfigs, location+"access_list_configs"),
		validateObjectList(portal.TrustedLoginRedirectURIConfigs, location+"trusted_login_redirect_uri_configs"),
		validateObjectList(portal.TrustedLogoutRedirectURIConfigs, location+"trusted_logout_redirect_uri_configs"),
	} {
		if err != nil {
			return err
		}
	}
	if portal.UI != nil {
		for _, err := range []error{
			validateObjectList(portal.UI.PrivateLinks, location+"ui.private_links"),
			validateObjectList(portal.UI.Realms, location+"ui.realms"),
			validateObjectList(portal.UI.StaticAssets, location+"ui.static_assets"),
		} {
			if err != nil {
				return err
			}
		}
	}
	if portal.CookieConfig != nil {
		if err := validateObjectMap(portal.CookieConfig.Domains, location+"cookie_config.domains"); err != nil {
			return err
		}
	}
	if portal.OIDCProvider != nil {
		if err := validateObjectList(portal.OIDCProvider.Clients, location+"oidc_provider.clients"); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyObjects(policy *authz.PolicyConfig) error {
	const location = "security.authorization_policies."
	for _, err := range []error{
		validateObjectList(policy.BypassConfigs, location+"bypass_configs"),
		validateObjectList(policy.HeaderInjectionConfigs, location+"header_injection_configs"),
		validateObjectList(policy.AccessListRules, location+"access_list_rules"),
		validateObjectList(policy.AccessListFields, location+"access_list_fields"),
	} {
		if err != nil {
			return err
		}
	}
	if policy.AuthProxyConfig != nil {
		return validateObjectMap(policy.AuthProxyConfig.Realms, location+"auth_proxy_config.realms")
	}
	return nil
}
