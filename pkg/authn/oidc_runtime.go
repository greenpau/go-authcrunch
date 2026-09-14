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

package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// GetOIDCProvider returns the configured provider, or nil when OIDC is disabled.
func (p *Portal) GetOIDCProvider() oidc.OpenIDProvider { return p.oidc }

func validateOIDCPortalConfig(config *oidc.Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if config == nil || !config.Enabled {
		return nil
	}
	issuer, _ := url.Parse(config.Issuer)
	// Portal routes inspect segments before login/sandbox dispatch. This is a
	// portal restriction; standalone providers can use other canonical mounts.
	for _, marker := range []string{"/api/", "/qrcode/", "/profile/", "/assets/", "/favicon", "/portal", "/register/", "/apps/sso", "/apps/mobile-access", "/saml/", "/oauth2/", "/basic/login/", "/barcode/mfa/", "/sandbox/"} {
		if strings.Contains(issuer.Path+"/", marker) {
			return fmt.Errorf("oidc issuer mount contains a reserved portal route")
		}
	}
	return nil
}

func (p *Portal) configureOIDC() error {
	config := p.config.OIDCProvider
	if err := validateOIDCPortalConfig(config); err != nil {
		return err
	}
	if config == nil || !config.Enabled {
		return nil
	}
	for _, realm := range config.Realms {
		matches := 0
		for _, store := range p.identityStores {
			if store.GetRealm() == realm {
				if store.GetKind() != "local" {
					return fmt.Errorf("oidc realm must use a local identity store")
				}
				if _, ok := store.(refreshIdentityStore); !ok {
					return fmt.Errorf("oidc realm lacks transactional identity verification")
				}
				matches++
			}
		}
		if matches != 1 || p.getIdentityProviderByRealm(realm) != nil {
			return fmt.Errorf("oidc realm must identify exactly one local store")
		}
	}
	options := oidc.Options{SessionCookieName: p.cookie.OIDCSessionIDCookieName, RequestCookieName: p.cookie.OIDCRequestIDCookieName}
	if p.refresh != nil {
		issuer, _ := url.Parse(config.Issuer)
		if p.config.RefreshTokens.PublicOrigin != issuer.Scheme+"://"+issuer.Host || strings.TrimSuffix(p.config.RefreshTokens.BasePath, "/") != issuer.Path {
			return fmt.Errorf("oidc issuer and refresh origin/mount must agree")
		}
	}
	for _, key := range p.keystore.GetVerifyKeys() {
		public, err := key.ProvideKey(jwtlib.New(jwtlib.SigningMethodRS256))
		if err == nil {
			options.ExcludedSigningKeys = append(options.ExcludedSigningKeys, public)
		}
	}
	provider, err := oidc.NewProvider(config, &portalOIDCIdentityVerifier{portal: p}, options)
	if err != nil {
		return err
	}
	p.oidc = provider
	return nil
}

// The portal adapter keeps transformation and checkpoint policy inside authn.
// The provider never imports or accesses Portal, user sandboxes, or local stores.
type portalOIDCIdentityVerifier struct{ portal *Portal }

func (v *portalOIDCIdentityVerifier) WithIdentity(ctx context.Context, proof oidc.Authentication, apply func(oidc.Identity) error) error {
	store := v.portal.getIdentityStoreByRealm(proof.Realm)
	if store == nil || store.GetName() != proof.Backend {
		return oidc.ErrIdentityDenied
	}
	backend, ok := store.(refreshIdentityStore)
	if !ok {
		return oidc.ErrIdentityDenied
	}
	err := backend.WithRefreshIdentity(ctx, proof.Evidence, func(current identity.RefreshIdentity) error {
		if current.Username != proof.Username {
			return oidc.ErrIdentityDenied
		}
		rr := requests.NewRequest()
		rr.Upstream.Realm = proof.Realm
		claims := map[string]any{"sub": current.Username, "name": current.Name, "email": current.Email, "roles": current.Roles, "origin": proof.Realm}
		if err := v.portal.transformUser(ctx, rr, claims); err != nil {
			return oidc.ErrIdentityDenied
		}
		candidate := &user.User{}
		if err := v.portal.injectUserChallenges(candidate, claims, current.Challenges); err != nil {
			return oidc.ErrIdentityDenied
		}
		for _, required := range candidate.Checkpoints {
			if !satisfiedRefreshChallenge(required, proof.Challenges) {
				return oidc.ErrIdentityDenied
			}
		}
		return apply(oidc.Identity{Username: current.Username, Name: current.Name, Email: current.Email})
	})
	if errors.Is(err, identity.ErrRefreshIdentityDenied) {
		return oidc.ErrIdentityDenied
	}
	return err
}

func (p *Portal) oidcRealm(realm string) bool {
	return p.oidc != nil && p.oidc.SupportsRealm(realm)
}

func (p *Portal) finishOIDCLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, proof *user.User) error {
	if p.oidc == nil || proof.RefreshTransport == tokenrefresh.BodyTransport {
		return nil
	}
	authentication := oidc.Authentication{Realm: proof.Authenticator.Realm, Backend: proof.Authenticator.Name, Username: proof.LoginUsername, Evidence: proof.LoginEvidence, Methods: proof.LoginMethods}
	for _, checkpoint := range proof.Checkpoints {
		if !checkpoint.Passed {
			return oidc.ErrIdentityDenied
		}
		authentication.Challenges = append(authentication.Challenges, checkpoint.Type+":"+checkpoint.Parameters)
	}
	return p.oidc.CompleteLogin(ctx, w, r, authentication)
}

func (p *Portal) revokeOIDCBrowser(w http.ResponseWriter, r *http.Request) {
	if p.oidc != nil {
		p.oidc.Logout(w, r)
	}
}

func (p *Portal) replaceOIDCBrowserSession(w http.ResponseWriter, r *http.Request) {
	if p.oidc != nil {
		p.oidc.ClearSession(w, r)
	}
}
