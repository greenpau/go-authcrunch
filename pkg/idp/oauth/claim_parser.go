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

func parseCognitoClaims(claims jwtlib.MapClaims, parsedData map[string]any, roles []string) ([]string, error) {
	mergedRoles := append([]string(nil), roles...)
	for _, key := range []string{"custom:roles", "cognito:groups", "cognito:roles"} {
		value, exists := claims[key]
		if !exists {
			continue
		}
		switch values := value.(type) {
		case string:
			if key == "custom:roles" {
				mergedRoles = append(mergedRoles, strings.Split(values, "|")...)
			} else {
				mergedRoles = append(mergedRoles, values)
			}
		case []string:
			mergedRoles = append(mergedRoles, values...)
		case []any:
			for i, rawRole := range values {
				role, ok := rawRole.(string)
				if !ok {
					return nil, fmt.Errorf("cognito claim %s entry %d must be a string", key, i)
				}
				mergedRoles = append(mergedRoles, role)
			}
		default:
			return nil, fmt.Errorf("cognito claim %s must be a string or string array", key)
		}
	}

	updates := make(map[string]string)
	for _, field := range []struct {
		claim, output string
	}{
		{claim: "zoneinfo", output: "timezone"},
		{claim: "custom:timezone", output: "timezone"},
		{claim: "cognito:username", output: "username"},
	} {
		value, exists := claims[field.claim]
		if !exists {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("cognito claim %s must be a string", field.claim)
		}
		updates[field.output] = text
	}
	for key, value := range updates {
		parsedData[key] = value
	}
	return mergedRoles, nil
}

func (b *IdentityProvider) parseTokenClaims(tokenName string, claims jwtlib.MapClaims, parsedData map[string]interface{}) error {
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
			var err error
			roles, err = parseCognitoClaims(claims, parsedData, roles)
			if err != nil {
				return err
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
