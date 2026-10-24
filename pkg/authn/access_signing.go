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
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/internal/accessclaims"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func (p *Portal) accessLifetimeSeconds() int {
	if p.accessSigner == nil {
		return p.keystore.GetTokenLifetime(nil, nil)
	}
	lifetime := p.config.CryptoKeyStoreConfig.TokenLifetime
	if lifetime == 0 {
		lifetime = 900
	}
	return min(lifetime, p.accessSigner.Config.Policy.MaxLifetimeSeconds)
}
func (p *Portal) validateAccessAudience(claims map[string]any) error {
	if p.accessSigner != nil && !p.config.AccessTokenProfile.AllowsAudience(claims["aud"]) {
		return tokenrefresh.ErrDenied
	}
	return nil
}

// Normalize after current policy approval and before NewUser can coerce numeric
// values. Never replenish an omitted audience or extend a shorter expiry.
func (p *Portal) normalizeAccessClaims(claims map[string]any) (map[string]any, error) {
	if p.accessSigner == nil {
		return claims, nil
	}
	if err := p.validateAccessAudience(claims); err != nil {
		return nil, err
	}
	iat, e1 := accessclaims.Integer(claims["iat"])
	nbf, e2 := accessclaims.Integer(claims["nbf"])
	exp, e3 := accessclaims.Integer(claims["exp"])
	now := time.Now().Unix()
	if e1 != nil || e2 != nil || e3 != nil || iat > math.MaxInt64-int64(p.accessLifetimeSeconds()) || iat <= 0 || iat > now || nbf > now || nbf <= 0 || exp <= now || exp <= iat {
		return nil, fmt.Errorf("invalid approved access lifetime")
	}
	_, snapshot, err := accessclaims.Encode(claims)
	if err != nil {
		return nil, err
	}
	snapshot["iat"], snapshot["nbf"] = iat, iat
	snapshot["exp"] = min(exp, iat+int64(p.accessLifetimeSeconds()))
	snapshot["iss"] = p.accessSigner.Config.Policy.Issuer
	if err := p.config.AccessTokenProfile.ValidateClaims(snapshot, now); err != nil {
		return nil, err
	}
	return snapshot, nil
}
func (p *Portal) newAccessUser(claims map[string]any) (*user.User, error) {
	normalized, err := p.normalizeAccessClaims(claims)
	if err != nil {
		return nil, err
	}
	return user.NewUser(normalized)
}
func (p *Portal) signAccessUser(ctx context.Context, usr *user.User) error {
	if p.managedRefreshUnavailable() {
		return tokenrefresh.ErrUnavailable
	}
	if p.accessSigner == nil {
		return p.keystore.SignToken(nil, nil, usr)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, approved, err := accessclaims.Encode(usr.AsMap())
	if err != nil {
		return err
	}
	if err = p.config.AccessTokenProfile.ValidateClaims(approved, time.Now().Unix()); err != nil {
		return err
	}
	_, input, err := accessclaims.Encode(approved)
	if err != nil {
		return err
	}
	token, err := p.accessSigner.Sign(ctx, input)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if err != nil || token == "" {
		return fmt.Errorf("access signing failed")
	}
	verified, err := p.keystore.VerifyAccessToken(ctx, token)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || !accessclaims.Equal(approved, verified) {
		return fmt.Errorf("staged access token does not match approved claims")
	}
	usr.Token = token
	usr.TokenName = p.accessTokenName()
	return nil
}
func (p *Portal) configureAccessSigner() error {
	if p.accessSigner == nil {
		return nil
	}
	if p.accessSigner.Config.Name != p.config.AccessSigner {
		return fmt.Errorf("access signer selection does not match binding")
	}
	if err := p.keystore.MatchAccessSigner(p.accessSigner); err != nil {
		return err
	}
	if p.keystore.AccessTokenTrust() != p.validator.AccessTokenTrust() {
		return fmt.Errorf("portal access verification keys changed during construction")
	}
	if refresh := p.config.RefreshTokens; refresh != nil && refresh.Enabled && p.accessSigner.Config.Policy.Issuer != refresh.PublicOrigin+strings.TrimSuffix(refresh.BasePath, "/") {
		return fmt.Errorf("renewable access issuer does not match portal")
	}
	public, err := p.keystore.AccessTokenJWKS()
	if err != nil {
		return err
	}
	p.accessJWKS = public
	return nil
}

// AccessTokenTrust returns loaded profile keys plus the selected current key's
// role. No key file is reopened while constructing the root persistence epoch.
func (p *Portal) AccessTokenTrust() string {
	if p.accessSigner == nil {
		return ""
	}
	return p.keystore.AccessTokenTrust() + ":" + p.accessSigner.Config.Policy.KeyID
}
func (p *Portal) accessTokenCookie(host string, usr *user.User) (string, error) {
	raw := p.cookie.GetAccessTokenCookie(host, usr.Token)
	if p.accessSigner == nil {
		return raw, nil
	}
	expires, err := accessclaims.Integer(usr.AsMap()["exp"])
	remaining := expires - time.Now().Unix()
	if err != nil || remaining <= 0 {
		return "", fmt.Errorf("staged access token expired")
	}
	cookie, err := http.ParseSetCookie(raw)
	if err != nil {
		return "", fmt.Errorf("invalid access cookie")
	}
	if cookie.MaxAge > 0 {
		cookie.MaxAge = min(cookie.MaxAge, int(remaining))
	}
	// Omission retains a session cookie; never invent persistent Expires.
	if !cookie.Expires.IsZero() && cookie.Expires.After(time.Unix(expires, 0)) {
		cookie.Expires = time.Unix(expires, 0)
	}
	return cookie.String(), nil
}

func (p *Portal) accessTokenName() string {
	if name := p.config.CryptoKeyStoreConfig.TokenName; name != "" {
		return name
	}
	return "access_token"
}
