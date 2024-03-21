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

package tag

import (
	"bufio"
	"fmt"
	"strings"
	"unicode"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	authncache "github.com/greenpau/go-authcrunch/pkg/authn/cache"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/cache"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/qr"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/idp/saml"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/ids/ldap"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/sso"
	"github.com/greenpau/go-authcrunch/pkg/tagging"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"github.com/greenpau/go-authcrunch/pkg/util/cfg"

	"os"
	"path/filepath"
	"testing"
)

func TestTagCompliance(t *testing.T) {
	testcases := []struct {
		name      string
		entry     interface{}
		opts      *Options
		shouldErr bool
		err       error
	}{
		{
			name:  "test sso.KeyInfo struct",
			entry: &sso.KeyInfo{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.SingleSignOnService struct",
			entry: &sso.SingleSignOnService{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.EntityDescriptor struct",
			entry: &sso.EntityDescriptor{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.X509Data struct",
			entry: &sso.X509Data{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.IDPEntityDescriptor struct",
			entry: &sso.IDPEntityDescriptor{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.Service struct",
			entry: &sso.Service{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.IDPSSODescriptor struct",
			entry: &sso.IDPSSODescriptor{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.KeyDescriptor struct",
			entry: &sso.KeyDescriptor{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test sso.Provider struct",
			entry: &sso.Provider{},
			opts:  &Options{},
		},
		{
			name:  "test sso.SingleSignOnProviderConfig struct",
			entry: &sso.SingleSignOnProviderConfig{},
			opts:  &Options{},
		},
		{
			name:  "test sso.Request struct",
			entry: &sso.Request{},
			opts:  &Options{},
		},
		{
			name:  "test ui.NavigationItem struct",
			entry: &ui.NavigationItem{},
			opts:  &Options{},
		},
		{
			name:  "test requests.IdentityTokenCookie struct",
			entry: &requests.IdentityTokenCookie{},
			opts:  &Options{},
		},
		{
			name:  "test icons.LoginIcon struct",
			entry: &icons.LoginIcon{},
			opts:  &Options{},
		},
		{
			name:  "test registry.LocaUserRegistry struct",
			entry: &registry.LocaUserRegistry{},
			opts:  &Options{},
		},
		{
			name:  "test messaging.FileProvider struct",
			entry: &messaging.FileProvider{},
			opts:  &Options{},
		},
		{
			name:  "test messaging.FileProviderSendInput struct",
			entry: &messaging.FileProviderSendInput{},
			opts:  &Options{},
		},
		{
			name:  "test messaging.EmailProviderSendInput struct",
			entry: &messaging.EmailProviderSendInput{},
			opts:  &Options{},
		},
		{
			name:  "test authn.PortalParameters struct",
			entry: &authn.PortalParameters{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"sso_providers": true,
				},
			},
		},
		{
			name:  "test idp.IdentityProviderConfig struct",
			entry: &idp.IdentityProviderConfig{},
			opts:  &Options{},
		},
		{
			name:  "test ids.IdentityStoreConfig struct",
			entry: &ids.IdentityStoreConfig{},
			opts:  &Options{},
		},
		{
			name:  "test util.Browser struct",
			entry: &util.Browser{},
			opts:  &Options{},
		},
		{
			name:  "test authn.APIConfig struct",
			entry: &authn.APIConfig{},
			opts:  &Options{},
		},
		{
			name:  "test cookie.DomainConfig struct",
			entry: &cookie.DomainConfig{},
			opts:  &Options{},
		},
		{
			name:  "test registry.RegistrationCache struct",
			entry: &registry.RegistrationCache{},
			opts:  &Options{},
		},
		{
			name:  "test registry.RegistrationCacheEntry struct",
			entry: &registry.RegistrationCacheEntry{},
			opts:  &Options{},
		},
		{
			name:  "test messaging.EmailProvider struct",
			entry: &messaging.EmailProvider{},
			opts:  &Options{},
		},
		{
			name:  "test messaging.Config struct",
			entry: &messaging.Config{},
			opts:  &Options{},
		},
		{
			name:  "test requests.Query struct",
			entry: &requests.Query{},
			opts:  &Options{},
		},
		{
			name:  "test requests.User struct",
			entry: &requests.User{},
			opts:  &Options{},
		},
		{
			name:  "test requests.Key struct",
			entry: &requests.Key{},
			opts:  &Options{},
		},
		{
			name:  "test requests.MfaToken struct",
			entry: &requests.MfaToken{},
			opts:  &Options{},
		},
		{
			name:  "test requests.Request struct",
			entry: &requests.Request{},
			opts:  &Options{},
		},
		{
			name:  "test requests.Upstream struct",
			entry: &requests.Upstream{},
			opts:  &Options{},
		},
		{
			name:  "test requests.Flags struct",
			entry: &requests.Flags{},
			opts:  &Options{},
		},
		{
			name:  "test requests.Response struct",
			entry: &requests.Response{},
			opts:  &Options{},
		},
		{
			name:  "test requests.Sandbox struct",
			entry: &requests.Sandbox{},
			opts:  &Options{},
		},
		{
			name:  "test requests.WebAuthn struct",
			entry: &requests.WebAuthn{},
			opts:  &Options{},
		},
		{
			name:  "test public key",
			entry: &identity.PublicKey{},
		},
		{
			name:  "test AttestationObject struct",
			entry: &identity.AttestationObject{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test AttestationStatement struct",
			entry: &identity.AttestationStatement{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test AuthData struct",
			entry: &identity.AuthData{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test ClientData struct",
			entry: &identity.ClientData{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test CredentialData struct",
			entry: &identity.CredentialData{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test CreditCard struct",
			entry: &identity.CreditCard{},
		},
		{
			name:  "test CreditCardAssociation struct",
			entry: &identity.CreditCardAssociation{},
		},
		{
			name:  "test CreditCardIssuer struct",
			entry: &identity.CreditCardIssuer{},
		},
		{
			name:  "test Database struct",
			entry: &identity.Database{},
		},
		{
			name:  "test Device struct",
			entry: &identity.Device{},
		},
		{
			name:  "test EmailAddress struct",
			entry: &identity.EmailAddress{},
		},
		{
			name:  "test Handle struct",
			entry: &identity.Handle{},
		},
		{
			name:  "test Image struct",
			entry: &identity.Image{},
		},
		{
			name:  "test Location struct",
			entry: &identity.Location{},
		},
		{
			name:  "test LockoutState struct",
			entry: &identity.LockoutState{},
		},
		{
			name:  "test MfaDevice struct",
			entry: &identity.MfaDevice{},
		},
		{
			name:  "test MfaToken struct",
			entry: &identity.MfaToken{},
		},
		{
			name:  "test MfaTokenBundle struct",
			entry: &identity.MfaTokenBundle{},
		},
		{
			name:  "test Name struct",
			entry: &identity.Name{},
		},
		{
			name:  "test Organization struct",
			entry: &identity.Organization{},
		},
		{
			name:  "test Password struct",
			entry: &identity.Password{},
		},
		{
			name:  "test PublicKey struct",
			entry: &identity.PublicKey{},
		},
		{
			name:  "test PublicKeyBundle struct",
			entry: &identity.PublicKeyBundle{},
		},
		{
			name:  "test Registration struct",
			entry: &identity.Registration{},
		},
		{
			name:  "test Request struct",
			entry: &requests.Request{},
		},
		{
			name:  "test Role struct",
			entry: &identity.Role{},
		},
		{
			name:  "test User struct",
			entry: &identity.User{},
		},
		{
			name:  "test Policy struct",
			entry: &identity.Policy{},
		},
		{
			name:  "test UserPolicy struct",
			entry: &identity.UserPolicy{},
			opts: &Options{
				DisableTagOnEmpty: true,
			},
		},
		{
			name:  "test PasswordPolicy struct",
			entry: &identity.PasswordPolicy{},
			opts: &Options{
				DisableTagOnEmpty: true,
			},
		},
		{
			name:  "test WebAuthnRegisterRequest struct",
			entry: &identity.WebAuthnRegisterRequest{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test identity.UserMetadata struct",
			entry: &identity.UserMetadata{},
			opts:  &Options{},
		},
		{
			name:  "test identity.UserMetadataBundle struct",
			entry: &identity.UserMetadataBundle{},
			opts:  &Options{},
		},
		{
			name:  "test qr.Code struct",
			entry: &qr.Code{},
			opts:  &Options{},
		},
		{
			name:  "test identity.WebAuthnAuthenticateRequest struct",
			entry: &identity.WebAuthnAuthenticateRequest{},
			opts:  &Options{},
		},
		{
			name:  "test identity.APIKeyBundle struct",
			entry: &identity.APIKeyBundle{},
			opts:  &Options{},
		},
		{
			name:  "test identity.APIKey struct",
			entry: &identity.APIKey{},
			opts:  &Options{},
		},
		{
			name:  "test authn.PortalConfig struct",
			entry: &authn.PortalConfig{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"sso_providers": true,
				},
			},
		},
		{
			name:  "test requests.AuthorizationRequest struct",
			entry: &requests.AuthorizationRequest{},
			opts:  &Options{},
		},
		{
			name:  "test ui.Link struct",
			entry: &ui.Link{},
			opts:  &Options{},
		},
		{
			name:  "test ui.Args struct",
			entry: &ui.Args{},
			opts:  &Options{},
		},
		{
			name:  "test requests.AuthorizationResponse struct",
			entry: &requests.AuthorizationResponse{},
			opts: &Options{
				Disabled: true,
			},
		},
		{
			name:  "test cache.SessionCache struct",
			entry: &authncache.SessionCache{},
			opts:  &Options{},
		},
		{
			name:  "test ui.Template struct",
			entry: &ui.Template{},
			opts:  &Options{},
		},
		{
			name:  "test authproxy.BasicAuthConfig struct",
			entry: &authproxy.BasicAuthConfig{},
			opts:  &Options{},
		},
		{
			name:  "test user.Claims struct",
			entry: &user.Claims{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test acl.RuleConfiguration struct",
			entry: &acl.RuleConfiguration{},
			opts:  &Options{},
		},
		{
			name:  "test ldap.Authenticator struct",
			entry: &ldap.Authenticator{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKeyOperator struct",
			entry: &kms.CryptoKeyOperator{},
			opts:  &Options{},
		},
		{
			name:  "test cache.SandboxCacheEntry struct",
			entry: &authncache.SandboxCacheEntry{},
			opts:  &Options{},
		},
		{
			name:  "test local.Config struct",
			entry: &local.Config{},
			opts:  &Options{},
		},
		{
			name:  "test local.User struct",
			entry: &local.User{},
			opts:  &Options{},
		},
		{
			name:  "test credentials.Config struct",
			entry: &credentials.Config{},
			opts:  &Options{},
		},
		{
			name:  "test registry.UserRegistryConfig struct",
			entry: &registry.UserRegistryConfig{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"require_domain_mx": true,
				},
			},
		},
		{
			name:  "test ui.UserRealm struct",
			entry: &ui.UserRealm{},
			opts:  &Options{},
		},
		{
			name:  "test ui.Parameters struct",
			entry: &ui.Parameters{},
			opts:  &Options{},
		},
		{
			name:  "test ui.StaticAsset struct",
			entry: &ui.StaticAsset{},
			opts:  &Options{},
		},
		{
			name:  "test local.Backend struct",
			entry: &local.IdentityStore{},
			opts:  &Options{},
		},
		{
			name:  "test local.Authenticator struct",
			entry: &local.Authenticator{},
			opts:  &Options{},
		},
		{
			name:  "test options.TokenGrantorOptions struct",
			entry: &options.TokenGrantorOptions{},
			opts:  &Options{},
		},
		{
			name:  "test oauth.Config struct",
			entry: &oauth.Config{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"user_roles": true,
				},
			},
		},
		{
			name:  "test cookie.Factory struct",
			entry: &cookie.Factory{},
			opts:  &Options{},
		},
		{
			name:  "test user.Checkpoint struct",
			entry: &user.Checkpoint{},
			opts:  &Options{},
		},
		{
			name:  "test transformer.Factory struct",
			entry: &transformer.Factory{},
			opts:  &Options{},
		},
		{
			name:  "test user.AccessListClaim struct",
			entry: &user.AccessListClaim{},
			opts:  &Options{},
		},
		{
			name:  "test testutils.InjectedTestToken struct",
			entry: &testutils.InjectedTestToken{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKey struct",
			entry: &kms.CryptoKey{},
			opts:  &Options{},
		},
		{
			name:  "test cache.SandboxCache struct",
			entry: &authncache.SandboxCache{},
			opts:  &Options{},
		},
		{
			name:  "test cookie.Config struct",
			entry: &cookie.Config{},
			opts:  &Options{},
		},
		{
			name:  "test ldap.UserAttributes struct",
			entry: &ldap.UserAttributes{},
			opts:  &Options{},
		},
		{
			name:  "test ui.StaticAssetLibrary struct",
			entry: &ui.StaticAssetLibrary{},
			opts:  &Options{},
		},
		{
			name:  "test credentials.Generic struct",
			entry: &credentials.Generic{},
			opts:  &Options{},
		},
		{
			name:  "test oauth.Backend struct",
			entry: &oauth.IdentityProvider{},
			opts:  &Options{},
		},
		{
			name:  "test authproxy.Config struct",
			entry: &authproxy.Config{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKeyStore struct",
			entry: &kms.CryptoKeyStore{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKeyConfig struct",
			entry: &kms.CryptoKeyConfig{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"token_secret":      true,
					"token_sign_method": true,
					"token_eval_expr":   true,
				},
			},
		},
		{
			name:  "test cache.SessionCacheEntry struct",
			entry: &authncache.SessionCacheEntry{},
			opts:  &Options{},
		},
		{
			name:  "test saml.Backend struct",
			entry: &saml.IdentityProvider{},
			opts:  &Options{},
		},
		{
			name:  "test transformer.Config struct",
			entry: &transformer.Config{},
			opts:  &Options{},
		},
		{
			name:  "test authcrunch.Config struct",
			entry: &authcrunch.Config{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"auth_portal_configs":  true,
					"authz_policy_configs": true,
					"sso_providers":        true,
				},
			},
		},
		{
			name:  "test cache.TokenCache struct",
			entry: &cache.TokenCache{},
			opts:  &Options{},
		},
		{
			name:  "test ui.Factory struct",
			entry: &ui.Factory{},
			opts:  &Options{},
		},
		{
			name:  "test authproxy.Response struct",
			entry: &authproxy.Response{},
			opts:  &Options{},
		},
		{
			name:  "test user.Authenticator struct",
			entry: &user.Authenticator{},
			opts:  &Options{},
		},
		{
			name:  "test cfg.ArgRule struct",
			entry: &cfg.ArgRule{},
			opts:  &Options{},
		},
		{
			name:  "test oauth.JwksKey struct",
			entry: &oauth.JwksKey{},
			opts: &Options{
				DisableTagMismatch: true,
			},
		},
		{
			name:  "test authproxy.Request struct",
			entry: &authproxy.Request{},
			opts:  &Options{},
		},
		{
			name:  "test kms.CryptoKeyTokenOperator struct",
			entry: &kms.CryptoKeyTokenOperator{},
			opts:  &Options{},
		},
		{
			name:  "test options.TokenValidatorOptions struct",
			entry: &options.TokenValidatorOptions{},
			opts:  &Options{},
		},
		{
			name:  "test ldap.Backend struct",
			entry: &ldap.IdentityStore{},
			opts:  &Options{},
		},
		{
			name:  "test validator.TokenValidator struct",
			entry: &validator.TokenValidator{},
			opts:  &Options{},
		},
		{
			name:  "test saml.Config struct",
			entry: &saml.Config{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"acs_urls": true,
				},
			},
		},
		{
			name:  "test ldap.AuthServer struct",
			entry: &ldap.AuthServer{},
			opts:  &Options{},
		},
		{
			name:  "test user.User struct",
			entry: &user.User{},
			opts:  &Options{},
		},
		{
			name:  "test ldap.UserGroup struct",
			entry: &ldap.UserGroup{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"dn": true,
				},
			},
		},
		{
			name:  "test authproxy.APIKeyAuthConfig struct",
			entry: &authproxy.APIKeyAuthConfig{},
			opts:  &Options{},
		},
		{
			name:  "test ldap.Config struct",
			entry: &ldap.Config{},
			opts:  &Options{},
		},
		{
			name:  "test acl.AccessList struct",
			entry: &acl.AccessList{},
			opts:  &Options{},
		},
		{
			name:  "test authz.PolicyConfig struct",
			entry: &authz.PolicyConfig{},
			opts: &Options{
				AllowFieldMismatch: true,
				AllowedFields: map[string]interface{}{
					"disable_auth_redirect":       true,
					"disable_auth_redirect_query": true,
					"auth_redirect_query_param":   true,
				},
			},
		},
		{
			name:  "test bypass.Config struct",
			entry: &bypass.Config{},
			opts:  &Options{},
		},
		{
			name:  "test injector.Config struct",
			entry: &injector.Config{},
			opts:  &Options{},
		},
		{
			name:  "test authn.AuthRequest struct",
			entry: &authn.AuthRequest{},
			opts:  &Options{},
		},
		{
			name:  "test authn.AccessDeniedResponse struct",
			entry: &authn.AccessDeniedResponse{},
			opts:  &Options{},
		},
		{
			name:  "test authn.Portal struct",
			entry: &authn.Portal{},
			opts:  &Options{},
		},
		{
			name:  "test authn.AuthResponse struct",
			entry: &authn.AuthResponse{},
			opts:  &Options{},
		},
		{
			name:  "test authcrunch.Server struct",
			entry: &authcrunch.Server{},
			opts:  &Options{},
		},
		{
			name:  "test requests.RedirectResponse struct",
			entry: &requests.RedirectResponse{},
			opts:  &Options{},
		},
		{
			name:  "test authz.Gatekeeper struct",
			entry: &authz.Gatekeeper{},
			opts:  &Options{},
		},
		{
			name:  "test requests.AuthorizationToken struct",
			entry: &requests.AuthorizationToken{},
			opts:  &Options{},
		},
		{
			name:  "test redirects.RedirectURIMatchConfig struct",
			entry: &redirects.RedirectURIMatchConfig{},
			opts:  &Options{},
		},
		{
			name:  "test tagging.Tag struct",
			entry: &tagging.Tag{},
			opts:  &Options{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, err := GetTagCompliance(tc.entry, tc.opts)
			if tests.EvalErrWithLog(t, err, nil, tc.shouldErr, tc.err, msgs) {
				return
			}
		})
	}
}

func TestStructTagCompliance(t *testing.T) {
	var files []string
	structMap := make(map[string]bool)
	walkFn := func(path string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fileInfo.IsDir() {
			return nil
		}
		fileName := filepath.Base(path)
		fileExt := filepath.Ext(fileName)
		if fileExt != ".go" {
			return nil
		}
		if strings.Contains(fileName, "_test.go") {
			return nil
		}
		if strings.Contains(path, "/tag/") || strings.Contains(path, "/errors/") {
			return nil
		}
		// t.Logf("%s %d", path, fileInfo.Size())
		files = append(files, path)
		return nil
	}
	if err := filepath.Walk("../../", walkFn); err != nil {
		t.Error(err)
	}

	excludedFiles := []string{
		"authn/ui/content.go",
		"cmd/authdbctl/user.go",
		"cmd/authdbctl/config.go",
	}

	for _, fp := range files {
		// t.Logf("file %s", fp)
		var skip bool
		for _, excludedFile := range excludedFiles {
			if strings.HasSuffix(fp, excludedFile) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		var pkgFound bool
		var pkgName string
		fh, _ := os.Open(fp)
		defer fh.Close()
		scanner := bufio.NewScanner(fh)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "package ") {
				pkgFound = true
				pkgName = strings.Split(line, " ")[1]
				// t.Logf("package %s", pkgName)
				continue
			}
			if !pkgFound {
				continue
			}
			if strings.HasPrefix(line, "type") && strings.Contains(line, "struct") {
				structName := strings.Split(line, " ")[1]
				// t.Logf("%s.%s", pkgName, structName)
				if !unicode.IsUpper(rune(structName[0])) {
					// Skip unexported structs.
					continue
				}
				structMap[pkgName+"."+structName] = false
			}

			//fmt.Println(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("failed reading %q: %v", fp, err)
		}
	}

	fp := "../../internal/tag/tag_test.go"
	fh, _ := os.Open(fp)
	defer fh.Close()
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		for k := range structMap {
			if strings.Contains(line, k+"{}") {
				structMap[k] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Errorf("failed reading %q: %v", fp, err)
	}

	if len(structMap) > 0 {
		var msgs []string
		for k, v := range structMap {
			if v == false {
				t.Logf("Found struct %s", k)
				msgs = append(msgs, fmt.Sprintf("{\nname: \"test %s struct\",\nentry: &%s{},\nopts: &Options{},\n},", k, k))
			}
		}
		if len(msgs) > 0 {
			t.Logf("Add the following tests:\n" + strings.Join(msgs, "\n"))
			t.Fatal("Fix above structs")
		}
	}
}
