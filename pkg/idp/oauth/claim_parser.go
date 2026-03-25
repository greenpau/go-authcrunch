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
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/kms"
)

const rolesKeyword = "roles"

type tokenField struct {
	name string   // key used in resulting claim map
	path []string // path inside the JWT claims, supporting nested paths
}

var tokenFields = []tokenField{
	{name: "sub", path: []string{"sub"}},
	{name: "name", path: []string{"name"}},
	{name: "email", path: []string{"email"}},
	{name: "iat", path: []string{"iat"}},
	{name: "exp", path: []string{"exp"}},
	{name: "jti", path: []string{"jti"}},
	{name: "iss", path: []string{"iss"}},
	{name: "groups", path: []string{"groups"}},
	{name: "picture", path: []string{"picture"}},
	// Multiple potential paths we need to look for roles in the access token claims
	{name: rolesKeyword, path: []string{"role"}},
	{name: rolesKeyword, path: []string{"group"}},
	{name: rolesKeyword, path: []string{rolesKeyword}},
	{name: rolesKeyword, path: []string{"realm_access", rolesKeyword}}, // Keycloak
	{name: rolesKeyword, path: []string{"app_metadata", "authorization", rolesKeyword}},
	{name: "given_name", path: []string{"given_name"}},
	{name: "family_name", path: []string{"family_name"}},
}

func unique[T comparable](input []T) []T {
	seen := make(map[T]struct{})
	output := []T{}

	for _, value := range input {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			output = append(output, value)
		}
	}
	return output
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

func (b *IdentityProvider) parseTokenClaims(tokenName string, claims jwtlib.MapClaims, data map[string]interface{}, parsedData map[string]interface{}) error {
	if claims == nil {
		return errors.ErrIdentityProviderOAuthClaimsParserClaimsNotFound
	}

	roles := []string{}

	for _, field := range tokenFields {
		value, ok := getNestedClaim(claims, field.path)
		if !ok {
			continue
		}

		switch field.name {
		case rolesKeyword:
			switch values := value.(type) {
			case string:
				roles = append(roles, values)
			case []string:
				for _, roleName := range values {
					roles = append(roles, roleName)
				}
			case []interface{}:
				for _, roleNameRaw := range values {
					switch roleName := roleNameRaw.(type) {
					case string:
						roles = append(roles, roleName)
					}
				}
			}
		default:
			if existing, exists := parsedData[field.name]; exists {
				parsedData[field.name] = mergeClaims(existing, value)

			} else {
				parsedData[field.name] = value
			}
		}
	}

	switch b.config.Driver {
	case "cognito":
		if tokenName == "id_token" || tokenName == b.config.IdentityTokenFieldName {
			if v, exists := data[tokenName]; exists {
				if tp, err := kms.ParsePayloadFromToken(v.(string)); err == nil {
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
							parsedData["timezone"] = val.(string)
						case "cognito:username":
							parsedData["username"] = val.(string)
						case "zoneinfo":
							parsedData["timezone"] = val.(string)
						}
					}
				}
			}
		}
	}

	if len(roles) > 0 {
		if _, exists := parsedData[rolesKeyword]; !exists {
			parsedData[rolesKeyword] = unique(roles)
		} else {
			switch existingRoles := parsedData[rolesKeyword].(type) {
			case []string:
				parsedData[rolesKeyword] = unique(append(existingRoles, roles...))
			}
		}
	}

	return nil
}
