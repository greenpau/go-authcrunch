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

package oauth

import (
	"fmt"
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func (b *IdentityProvider) validateAccessToken(state string, data map[string]interface{}) (map[string]interface{}, error) {
	if data == nil {
		return nil, errors.ErrIdentityProviderOAuthClaimsParserClaimsNotFound
	}

	parsedData := make(map[string]interface{})

	for tokenName, tokenStringRaw := range data {
		if tokenName != "id_token" && tokenName != b.config.IdentityTokenFieldName && tokenName != "access_token" {
			continue
		}

		tokenString, ok := tokenStringRaw.(string)
		if !ok {
			return nil, errors.ErrIdentityProviderOAuthParseToken.WithArgs(tokenName, fmt.Errorf("not a string"))
		}

		if tokenName == "access_token" {
			token, _, err := new(jwtlib.Parser).ParseUnverified(tokenString, jwtlib.MapClaims{})
			if err != nil {
				return nil, errors.ErrIdentityProviderOAuthParseToken.WithArgs(tokenName, err)
			}
			if claims, ok := token.Claims.(jwtlib.MapClaims); ok {
				if err := b.parseTokenClaims(tokenName, claims, data, parsedData); err != nil {
					return nil, err
				}
			}
			continue
		}

		token, err := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
			switch {
			case strings.HasPrefix(token.Method.Alg(), "RS"):
				if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
					return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(tokenName, token.Header["alg"])
				}
			case strings.HasPrefix(token.Method.Alg(), "ES"):
				if _, validMethod := token.Method.(*jwtlib.SigningMethodECDSA); !validMethod {
					return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(tokenName, token.Header["alg"])
				}
			case strings.HasPrefix(token.Method.Alg(), "HS"):
				return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(tokenName, token.Method.Alg())
			}

			keyID, found := token.Header["kid"].(string)
			if !found {
				// If key id is not found in the header, then try the first available key.
				for _, key := range b.keys {
					return key.GetPublic(), nil
				}
				// return nil, errors.ErrIdentityProviderOAuthAccessTokenKeyIDNotFound.WithArgs(b.config.IdentityTokenName)
			}
			key, exists := b.keys[keyID]
			if !exists {
				if !b.disableKeyVerification {
					if err := b.fetchKeysURL(); err != nil {
						return nil, errors.ErrIdentityProviderOauthKeyFetchFailed.WithArgs(err)
					}
				}

				key, exists = b.keys[keyID]
				if !exists {
					return nil, errors.ErrIdentityProviderOAuthAccessTokenKeyIDNotRegistered.WithArgs(tokenName, keyID)
				}
			}
			return key.GetPublic(), nil
		})

		if err != nil {
			return nil, errors.ErrIdentityProviderOAuthParseToken.WithArgs(tokenName, err)
		}

		if !token.Valid {
			return nil, errors.ErrIdentityProviderOAuthInvalidToken.WithArgs(tokenName, tokenString)
		}

		claims := token.Claims.(jwtlib.MapClaims)
		if tokenName == b.config.IdentityTokenFieldName || tokenName == "id_token" {
			if _, exists := claims["nonce"]; !exists {
				return nil, errors.ErrIdentityProviderOAuthNonceValidationFailed.WithArgs(tokenName, "nonce not found")
			}
			if err := b.state.validateNonce(state, claims["nonce"].(string)); err != nil {
				return nil, errors.ErrIdentityProviderOAuthNonceValidationFailed.WithArgs(tokenName, err)
			}

			if !b.disableEmailClaimCheck {
				if _, exists := claims["email"]; !exists {
					return nil, errors.ErrIdentityProviderOAuthEmailNotFound.WithArgs(tokenName)
				}
			}
		}

		if err := b.parseTokenClaims(tokenName, claims, data, parsedData); err != nil {
			return nil, err
		}
	}

	if len(parsedData) == 0 {
		return nil, errors.ErrIdentityProviderOAuthClaimsParserClaimsNotFound
	}

	if _, exists := parsedData["name"]; !exists {
		if _, exists := parsedData["given_name"]; exists {
			if _, exists := parsedData["family_name"]; exists {
				parsedData["name"] = fmt.Sprintf("%s %s", parsedData["given_name"].(string), parsedData["family_name"].(string))
				delete(parsedData, "given_name")
				delete(parsedData, "family_name")
			}
		}
	}

	return parsedData, nil
}
