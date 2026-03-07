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
	jwtlib "github.com/golang-jwt/jwt/v4"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"strings"
)

type tokenField struct {
	name string   // key used in resulting claim map
	path []string // path inside the JWT claims, supporting nested paths
}

var tokenFields = []tokenField{
	{name: "sub",     path: []string{"sub"}},
	{name: "name",    path: []string{"name"}},
	{name: "email",   path: []string{"email"}},
	{name: "iat",     path: []string{"iat"}},
	{name: "exp",     path: []string{"exp"}},
	{name: "jti",     path: []string{"jti"}},
	{name: "iss",     path: []string{"iss"}},
	{name: "groups",  path: []string{"groups"}},
	{name: "picture", path: []string{"picture"}},
	// Multiple potential paths we need to look for roles in the access token claims
	{name: "roles", path: []string{"roles"}},
	{name: "roles", path: []string{"realm_access", "roles"}}, // Keycloak
	{name: "roles", path: []string{"app_metadata", "authorization", "roles"}},
	{name: "given_name",  path: []string{"given_name"}},
	{name: "family_name", path: []string{"family_name"}},
}


func getNestedClaim(data map[string]interface{}, path []string) (interface{}, bool) {
	var current interface{} = data

	for _, p := range path {
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}

		current, ok = m[p]
		if !ok {
			return nil, false
		}
	}

	return current, true
}


func mergeClaims(a interface{}, b interface{}) interface{} {
	aSlice, aOk := a.([]interface{})
	bSlice, bOk := b.([]interface{})

	if aOk && bOk {
		return append(aSlice, bSlice...)
	}

	return b
}


func (b *IdentityProvider) validateAccessToken(state string, data map[string]interface{}) (map[string]interface{}, error) {
	var tokenString string
	if v, exists := data[b.config.IdentityTokenName]; exists {
		tokenString = v.(string)
	} else {
		return nil, errors.ErrIdentityProviderOAuthAccessTokenNotFound.WithArgs(b.config.IdentityTokenName)
	}

	token, err := jwtlib.Parse(tokenString, func(token *jwtlib.Token) (interface{}, error) {
		switch {
		case strings.HasPrefix(token.Method.Alg(), "RS"):
			if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
				return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(b.config.IdentityTokenName, token.Header["alg"])
			}
		case strings.HasPrefix(token.Method.Alg(), "ES"):
			if _, validMethod := token.Method.(*jwtlib.SigningMethodECDSA); !validMethod {
				return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(b.config.IdentityTokenName, token.Header["alg"])
			}
		case strings.HasPrefix(token.Method.Alg(), "HS"):
			return nil, errors.ErrIdentityProviderOAuthAccessTokenSignMethodNotSupported.WithArgs(b.config.IdentityTokenName, token.Method.Alg())
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
				return nil, errors.ErrIdentityProviderOAuthAccessTokenKeyIDNotRegistered.WithArgs(b.config.IdentityTokenName, keyID)
			}
		}
		return key.GetPublic(), nil
	})

	if err != nil {
		return nil, errors.ErrIdentityProviderOAuthParseToken.WithArgs(b.config.IdentityTokenName, err)
	}

	if _, ok := token.Claims.(jwtlib.Claims); !ok && !token.Valid {
		return nil, errors.ErrIdentityProviderOAuthInvalidToken.WithArgs(b.config.IdentityTokenName, tokenString)
	}
	claims := token.Claims.(jwtlib.MapClaims)
	if _, exists := claims["nonce"]; !exists {
		return nil, errors.ErrIdentityProviderOAuthNonceValidationFailed.WithArgs(b.config.IdentityTokenName, "nonce not found")
	}
	if err := b.state.validateNonce(state, claims["nonce"].(string)); err != nil {
		return nil, errors.ErrIdentityProviderOAuthNonceValidationFailed.WithArgs(b.config.IdentityTokenName, err)
	}

	if !b.disableEmailClaimCheck {
		if _, exists := claims["email"]; !exists {
			return nil, errors.ErrIdentityProviderOAuthEmailNotFound.WithArgs(b.config.IdentityTokenName)
		}
	}

	m := make(map[string]interface{})

	for _, field := range tokenFields {
		value, ok := getNestedClaim(claims, field.path)
		if !ok {
			continue
		}

		if existing, exists := m[field.name]; exists {
			m[field.name] = mergeClaims(existing, value)
		} else {
			m[field.name] = value
		}
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

	switch b.config.Driver {
	case "cognito":
		if v, exists := data["id_token"]; exists {
			if tp, err := kms.ParsePayloadFromToken(v.(string)); err == nil {
				roles := []string{}
				for k, val := range tp {
					switch k {
					case "custom:roles", "cognito:groups", "cognito:roles":
						switch values := val.(type) {
						case string:
							if k == "custom:roles" {
								for _, roleName := range strings.Split(values, "|") {
									roles = append(roles, roleName)
								}
							} else {
								roles = append(roles, values)
							}
						case []interface{}:
							for _, value := range values {
								switch roleName := value.(type) {
								case string:
									roles = append(roles, roleName)
								}
							}
						}
					case "custom:timezone":
						m["timezone"] = val.(string)
					case "cognito:username":
						m["username"] = val.(string)
					case "zoneinfo":
						m["timezone"] = val.(string)
					}
				}
				if len(roles) > 0 {
					m["roles"] = roles
				}
			}
		}
	}

	return m, nil
}
