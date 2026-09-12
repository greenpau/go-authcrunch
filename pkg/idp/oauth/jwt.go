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

package oauth

import (
	"context"
	stderrors "errors"
	"fmt"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/greenpau/go-authcrunch/internal/jwtutil"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func isOAuthSigningMethod(token *jwtlib.Token) bool {
	if token == nil {
		return false
	}
	algorithm, ok := token.Header["alg"].(string)
	if !ok {
		return false
	}
	switch algorithm {
	case "RS256", "RS384", "RS512":
		m, ok := token.Method.(*jwtlib.SigningMethodRSA)
		return ok && m != nil && m.Alg() == algorithm
	case "PS256", "PS384", "PS512":
		m, ok := token.Method.(*jwtlib.SigningMethodRSAPSS)
		return ok && m != nil && m.Alg() == algorithm
	case "ES256", "ES384", "ES512":
		m, ok := token.Method.(*jwtlib.SigningMethodECDSA)
		return ok && m != nil && m.Alg() == algorithm
	case "EdDSA", "Ed25519":
		return jwtutil.IsEd25519Method(token.Method) && token.Method.Alg() == algorithm
	default:
		return false
	}
}

func (b *IdentityProvider) parseOAuthJWT(ctx context.Context, tokenName, text string) (*jwtlib.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, version := b.snapshotKeys()
	refreshed := false
	selectedRemote := false
	keyfunc := func(token *jwtlib.Token) (any, error) {
		if !isOAuthSigningMethod(token) {
			return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(tokenName, token.Header["alg"])
		}
		rawID, hasID := token.Header["kid"]
		id, isString := rawID.(string)
		if hasID && (!isString || id == "") {
			return nil, fmt.Errorf("OAuth %s kid must be a nonempty string", tokenName)
		}
		_, pinned := b.staticKeys.byID[id]
		canRefresh := b.canFetchKeys() && !(hasID && pinned)
		candidates := keys.verificationKeys(token.Method.Alg(), id, hasID)
		if len(candidates.Keys) == 0 && !refreshed && canRefresh {
			refreshed = true
			if err := b.refreshKeys(ctx, &version); err != nil {
				return nil, errors.ErrIdentityProviderOauthKeyFetchFailed.WithArgs(err)
			}
			keys, version = b.snapshotKeys()
			candidates = keys.verificationKeys(token.Method.Alg(), id, hasID)
		}
		if len(candidates.Keys) == 0 {
			return nil, errors.ErrIdentityProviderOAuthAccessTokenKeyIDNotRegistered.WithArgs(tokenName, id)
		}
		selectedRemote = canRefresh
		return candidates, nil
	}
	parse := func() (*jwtlib.Token, error) {
		// Preserve RSA-PSS with unlabelled RSA keys, supported by the old parser.
		return jwtlib.Parse(text, keyfunc, jwtlib.WithValidMethods([]string{
			"RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
			"ES256", "ES384", "ES512", "EdDSA", "Ed25519",
		}))
	}
	token, err := parse()
	// A provider can replace material while retaining kid. Only a cryptographic
	// failure with an eligible remote key permits one rate-limited retry. Claim
	// failures, malformed headers, static pins, and unsupported methods do not.
	if err != nil && selectedRemote && !refreshed && stderrors.Is(err, jwtlib.ErrTokenSignatureInvalid) {
		refreshed = true
		if fetchErr := b.refreshKeys(ctx, &version); fetchErr != nil {
			return nil, errors.ErrIdentityProviderOauthKeyFetchFailed.WithArgs(fetchErr)
		}
		keys, version = b.snapshotKeys()
		return parse()
	}
	return token, err
}
