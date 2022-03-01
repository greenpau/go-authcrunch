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

package oauth2

import (
	"fmt"
	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"strings"
)

var (
	tokenFields = []string{
		"sub", "name", "email", "iat", "exp", "jti",
		"iss", "groups", "picture",
		"roles", "role", "groups", "group",
		"given_name", "family_name",
	}
)

func (b *Backend) validateAccessToken(state string, data map[string]interface{}) (map[string]interface{}, error) {
	var tokenString string
	if v, exists := data[b.Config.IdentityTokenName]; exists {
		tokenString = v.(string)
	} else {
		return nil, errors.ErrBackendOAuthAccessTokenNotFound.WithArgs(b.Config.IdentityTokenName)
	}

	token, err := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
		switch {
		case strings.HasPrefix(token.Method.Alg(), "RS"):
			if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
				return nil, errors.ErrBackendOAuthAccessTokenSignMethodNotSupported.WithArgs(b.Config.IdentityTokenName, token.Header["alg"])
			}
		case strings.HasPrefix(token.Method.Alg(), "ES"):
			if _, validMethod := token.Method.(*jwtlib.SigningMethodECDSA); !validMethod {
				return nil, errors.ErrBackendOAuthAccessTokenSignMethodNotSupported.WithArgs(b.Config.IdentityTokenName, token.Header["alg"])
			}
		case strings.HasPrefix(token.Method.Alg(), "HS"):
			return nil, errors.ErrBackendOAuthAccessTokenSignMethodNotSupported.WithArgs(b.Config.IdentityTokenName, token.Method.Alg())
		}

		keyID, found := token.Header["kid"].(string)
		if !found {
			return nil, errors.ErrBackendOAuthAccessTokenKeyIDNotFound.WithArgs(b.Config.IdentityTokenName)
		}
		key, exists := b.keys[keyID]
		if !exists {
			if !b.disableKeyVerification {
				if err := b.fetchKeysURL(); err != nil {
					return nil, errors.ErrBackendOauthKeyFetchFailed.WithArgs(err)
				}
			}
			key, exists = b.keys[keyID]
			if !exists {
				return nil, errors.ErrBackendOAuthAccessTokenKeyIDNotRegistered.WithArgs(b.Config.IdentityTokenName, keyID)
			}
		}
		return key.GetPublic(), nil
	})

	if err != nil {
		return nil, errors.ErrBackendOAuthParseToken.WithArgs(b.Config.IdentityTokenName, err)
	}

	if _, ok := token.Claims.(jwtlib.Claims); !ok && !token.Valid {
		return nil, errors.ErrBackendOAuthInvalidToken.WithArgs(b.Config.IdentityTokenName, tokenString)
	}
	claims := token.Claims.(jwtlib.MapClaims)
	if _, exists := claims["nonce"]; !exists {
		return nil, errors.ErrBackendOAuthNonceValidationFailed.WithArgs(b.Config.IdentityTokenName, "nonce not found")
	}
	if err := b.state.validateNonce(state, claims["nonce"].(string)); err != nil {
		return nil, errors.ErrBackendOAuthNonceValidationFailed.WithArgs(b.Config.IdentityTokenName, err)
	}

	m := make(map[string]interface{})
	for _, k := range tokenFields {
		if _, exists := claims[k]; !exists {
			continue
		}
		m[k] = claims[k]
	}

	if _, exists := m["name"]; !exists {
		if _, exists := m["given_name"]; exists {
			if _, exists := m["family_name"]; exists {
				m["name"] = fmt.Sprintf("%s %s", m["given_name"].(string), m["family_name"].(string))
				delete(m, "given_name")
				delete(m, "family_name")
			}
		}
	}

	return m, nil
}
